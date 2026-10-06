//go:build linux

package environment

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func noEffectCandidate(request BuildRequest) BuildRequest {
	request.OperationID, request.Role = "candidate-0", Candidate
	request.Patch, request.PatchDigest = candidatePatch(), digest(candidatePatch())
	return request
}

func requireUnknownBuild(t *testing.T, err error) {
	t.Helper()
	var proof *NotSubmitted
	require.False(t, errors.As(err, &proof))
	var failure *Error
	require.ErrorAs(t, err, &failure)
	require.Equal(t, Unknown, failure.Kind)
}

func TestBuildAdmissionRejectionDurablyProvesNoSubmission(t *testing.T) {
	for _, stage := range []string{"validation", "preparation", "fresh-preparation"} {
		t.Run(stage, func(t *testing.T) {
			f := newJobFixture(t, true)
			request := f.request()
			if stage != "fresh-preparation" {
				_, err := f.adapter.Build(t.Context(), request)
				require.NoError(t, err)
			}
			request = noEffectCandidate(request)
			if stage == "validation" {
				request.Patch = []byte{0xff}
			} else {
				request.Patch = []byte("--- a/main\n+++ b/main\n@@ invalid synthetic hunk @@\n+not-submitted\n")
			}
			request.PatchDigest = digest(request.Patch)
			f.kube.ClearActions()
			result, err := f.adapter.Build(t.Context(), request)
			var proof *NotSubmitted
			require.ErrorAs(t, err, &proof)
			require.Equal(t, BuildResult{}, result)
			require.True(t, proof.Matches(request))
			require.Empty(t, f.kube.Actions(), "validation and preparation must not call the Kubernetes API")
			state, err := f.adapter.loadRun(request.RunID, request.Plan.Bind)
			require.NoError(t, err)
			require.NotContains(t, state.Builds, f.adapter.buildIdentity(request))
			require.Equal(t, proof, state.BuildCancellations[request.OperationID].NotSubmitted)
			raw, err := json.Marshal(proof)
			require.NoError(t, err)
			require.NotContains(t, string(raw), "not-submitted")
			require.NotContains(t, string(raw), "hunk")
			require.NotContains(t, string(raw), `"patch"`)
			require.NoError(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
			for _, existing := range []bool{false, true} {
				request.RequireExisting = existing
				_, err := f.restart(t).Build(t.Context(), request)
				require.Error(t, err)
				require.False(t, errors.As(err, &proof), "a cancelled call is not another admission rejection")
			}
			require.Empty(t, f.kube.Actions())
		})
	}
}

func TestBuildNoSubmissionCleanupDoesNotRequireKubernetesClient(t *testing.T) {
	f := newJobFixture(t, false)
	f.adapter.kube = nil
	request := noEffectCandidate(f.request())
	request.Patch = nil
	_, err := f.adapter.Build(t.Context(), request)
	var proof *NotSubmitted
	require.ErrorAs(t, err, &proof)
	cleanup, err := newCleanupAdapter(f.config)
	require.NoError(t, err)
	require.Nil(t, cleanup.kube)
	require.NoError(t, cleanup.CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	require.Empty(t, f.kube.Actions())
}

func TestCancelBuildDescriptorAbsenceFencesLateWorker(t *testing.T) {
	f := newJobFixture(t, true)
	control := f.request()
	_, err := f.adapter.Build(t.Context(), control)
	require.NoError(t, err)
	request := noEffectCandidate(control)
	f.kube.ClearActions()
	state, unlock, err := f.adapter.lockRun(t.Context(), request.RunID, request.Plan.Bind, false)
	require.NoError(t, err)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	worker := f.restart(t)
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		_, err := worker.Build(t.Context(), request)
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("worker escaped the held run flock: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	// Exercise the same locked cancellation step as CancelBuild, while the
	// old caller cannot progress past its flock acquisition.
	require.NoError(t, f.adapter.cancelBuildRun(t.Context(), request.RunID, request.OperationID, request.Plan, state))
	unlock()
	unlock = nil
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("late worker did not observe durable cancellation")
	}
	require.NoError(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	require.Empty(t, f.kube.Actions())
}

func TestCancelBuildLegacyOriginUnknownFencesWithoutClaimingNoEffects(t *testing.T) {
	for _, lostSubmission := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "lost-submission"}[lostSubmission], func(t *testing.T) {
			f := newJobFixture(t, true)
			control := f.request()
			_, err := f.adapter.Build(t.Context(), control)
			require.NoError(t, err)
			legacy, err := f.adapter.loadRun(control.RunID, control.Plan.Bind)
			require.NoError(t, err)
			request := noEffectCandidate(control)
			if lostSubmission {
				f.terminal = false
				_, done, err := f.adapter.advanceBuildJob(t.Context(), request, f.adapter.buildIdentity(request))
				require.NoError(t, err)
				require.False(t, done)
			}
			// Both histories have exactly the same valid legacy snapshot:
			// completed control only. Old receipt recovery did not record
			// whether other descriptors were lost before reconstruction.
			legacy.RunID, legacy.JournalDigest, legacy.BuildHistoryVersion = "", "", 0
			raw, err := json.Marshal(legacy)
			require.NoError(t, err)
			require.NoError(t, writePrivate(f.config.OutputRoot, runName(control.RunID)+".json", raw))
			f.kube.ClearActions()
			requireUnknownBuild(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
			_, err = f.restart(t).Build(t.Context(), request)
			require.Error(t, err, "even unproven cleanup must fence late callers")
			requireUnknownBuild(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
			saved, err := f.adapter.loadRun(request.RunID, request.Plan.Bind)
			require.NoError(t, err)
			require.Zero(t, saved.BuildHistoryVersion, "saving a legacy journal is not an origin attestation")
			require.NotNil(t, saved.BuildCancellations[request.OperationID])
			require.False(t, saved.BuildCancellations[request.OperationID].NoSubmissionProven)
			require.Nil(t, saved.BuildCancellations[request.OperationID].NotSubmitted)
			require.Empty(t, f.kube.Actions())
		})
	}
}

func TestCancelBuildMissingOrReconstructedHistoryRemainsUnknown(t *testing.T) {
	for _, loss := range []string{"missing", "reconstructed", "corrupt", "missing-digest", "wrong-config", "wrong-run"} {
		t.Run(loss, func(t *testing.T) {
			f := newJobFixture(t, true)
			control := f.request()
			_, err := f.adapter.Build(t.Context(), control)
			require.NoError(t, err)
			request := noEffectCandidate(control)
			path := filepath.Join(f.config.OutputRoot, runName(control.RunID)+".json")
			state, err := f.adapter.loadRun(control.RunID, control.Plan.Bind)
			require.NoError(t, err)
			switch loss {
			case "missing", "reconstructed":
				require.NoError(t, os.Remove(path))
				if loss == "reconstructed" {
					recovered, err := f.adapter.loadRun(control.RunID, control.Plan.Bind)
					require.NoError(t, err)
					require.True(t, recovered.BuildHistoryIncomplete)
					// Even recovering an exact completed control descriptor
					// cannot attest the rest of a lost run's build history.
					recovered.Builds = state.Builds
					require.NoError(t, f.adapter.saveRun(control.RunID, recovered))
				}
			case "corrupt":
				require.NoError(t, os.WriteFile(path, []byte(`{"version":1,"builds":`), 0600))
			case "missing-digest":
				state.JournalDigest = ""
				raw, err := json.Marshal(state)
				require.NoError(t, err)
				require.NoError(t, writePrivate(f.config.OutputRoot, filepath.Base(path), raw))
			case "wrong-config":
				state.ConfigDigest = digest([]byte("different configuration"))
				require.NoError(t, f.adapter.saveRun(control.RunID, state))
			case "wrong-run":
				controlRecord := state.Builds[f.adapter.buildIdentity(control)]
				controlRecord.Job.Input.RunID = "another-run"
				require.NoError(t, f.adapter.saveRun(control.RunID, state))
			}
			f.kube.ClearActions()
			err = f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan)
			requireUnknownBuild(t, err)
			request.RequireExisting = true
			_, err = f.restart(t).Build(t.Context(), request)
			requireUnknownBuild(t, err)
			for _, action := range f.kube.Actions() {
				require.NotEqual(t, "create", action.GetVerb())
				require.NotEqual(t, "delete", action.GetVerb())
			}
		})
	}
}

func TestBuildRejectedResumeCannotMintNoSubmissionProof(t *testing.T) {
	f := newJobFixture(t, true)
	control := f.request()
	_, err := f.adapter.Build(t.Context(), control)
	require.NoError(t, err)
	request := noEffectCandidate(control)
	request.RequireExisting, request.Patch = true, nil
	f.kube.ClearActions()
	_, err = f.adapter.Build(t.Context(), request)
	requireUnknownBuild(t, err)
	state, err := f.adapter.loadRun(control.RunID, control.Plan.Bind)
	require.NoError(t, err)
	require.Empty(t, state.BuildCancellations)
	require.Empty(t, f.kube.Actions())
}

func TestBuildLostSubmissionAcknowledgementsNeverProveAbsence(t *testing.T) {
	for _, resource := range []string{"configmaps", "secrets", "jobs"} {
		t.Run(resource, func(t *testing.T) {
			f := newJobFixture(t, false)
			request := f.request()
			accepted := false
			f.kube.PrependReactor("create", resource, func(action ktesting.Action) (bool, runtime.Object, error) {
				handled, object, err := f.create(action)
				if err != nil {
					return handled, object, err
				}
				accepted = true
				return true, nil, apierrors.NewTimeoutError("synthetic lost acknowledgement", 1)
			})
			f.kube.PrependReactor("get", resource, func(ktesting.Action) (bool, runtime.Object, error) {
				if accepted {
					return true, nil, apierrors.NewServiceUnavailable("synthetic acknowledgement outage")
				}
				return false, nil, nil
			})
			_, err := f.adapter.Build(t.Context(), request)
			require.Error(t, err)
			require.True(t, accepted)
			record := f.record(t, request)
			require.True(t, record.Job.SubmissionAttempted)
			var proof *NotSubmitted
			require.False(t, errors.As(err, &proof))
			f.kube.ClearActions()
			require.Error(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
			for _, action := range f.kube.Actions() {
				require.NotEqual(t, "create", action.GetVerb())
			}
			state, err := f.adapter.loadRun(request.RunID, request.Plan.Bind)
			require.NoError(t, err)
			require.Empty(t, state.BuildCancellations)
		})
	}
}

func TestBuildAcceptedRecordWithoutUIDRemainsUnknown(t *testing.T) {
	f := newJobFixture(t, false)
	request := f.request()
	_, done, err := f.adapter.advanceBuildJob(t.Context(), request, f.adapter.buildIdentity(request))
	require.NoError(t, err)
	require.False(t, done)
	state, err := f.adapter.loadRun(request.RunID, request.Plan.Bind)
	require.NoError(t, err)
	record := state.Builds[f.adapter.buildIdentity(request)]
	require.True(t, record.Job.SubmissionAttempted)
	record.Job.Receipt = nil
	require.NoError(t, f.adapter.saveRun(request.RunID, state))
	f.kube.ClearActions()
	requireUnknownBuild(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	require.Empty(t, f.kube.Actions())
}

func TestBuildPreviouslyAcceptedJobMissingNeverRecreates(t *testing.T) {
	f := newJobFixture(t, false)
	request := f.request()
	_, _, err := f.adapter.advanceBuildJob(t.Context(), request, f.adapter.buildIdentity(request))
	require.NoError(t, err)
	record := f.record(t, request)
	require.NoError(t, f.kube.Tracker().Delete(batchv1.SchemeGroupVersion.WithResource("jobs"),
		record.Job.Receipt.Namespace, record.Job.Receipt.JobName))
	f.kube.ClearActions()
	request.RequireExisting = true
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err = f.restart(t).Build(ctx, request)
	var proof *NotSubmitted
	require.Error(t, err)
	require.False(t, errors.As(err, &proof))
	for _, action := range f.kube.Actions() {
		require.NotEqual(t, "create", action.GetVerb())
	}
}

func TestBuildCancellationDoesNotCrossRunsOrOperations(t *testing.T) {
	f := newJobFixture(t, true)
	control := f.request()
	_, err := f.adapter.Build(t.Context(), control)
	require.NoError(t, err)
	cancelled := noEffectCandidate(control)
	require.NoError(t, f.adapter.CancelBuild(t.Context(), cancelled.RunID, cancelled.OperationID, cancelled.Plan))
	for _, change := range []string{"operation", "run", "role", "patch"} {
		request := cancelled
		switch change {
		case "operation":
			request.OperationID += "-other"
		case "run":
			request.RunID += "-other"
		case "role":
			request.Role, request.Patch, request.PatchDigest = RebuiltControl, nil, ""
		case "patch":
			request.Patch = []byte(strings.ReplaceAll(string(candidatePatch()), "+candidate", "+different"))
			request.PatchDigest = digest(request.Patch)
		}
		result, err := f.restart(t).Build(t.Context(), request)
		if change == "operation" || change == "run" {
			require.NoError(t, err)
			require.NotEmpty(t, result.Subject.Image)
		} else {
			require.Error(t, err)
			require.Empty(t, result.Subject.Image)
		}
	}
	require.EqualValues(t, 3, f.buildCount.Load())
}

func TestBuildNoSubmissionProofRequiresDurableTombstone(t *testing.T) {
	f := newJobFixture(t, true)
	control := f.request()
	_, err := f.adapter.Build(t.Context(), control)
	require.NoError(t, err)
	request := noEffectCandidate(control)
	state, unlock, err := f.adapter.lockRun(t.Context(), request.RunID, request.Plan.Bind, false)
	require.NoError(t, err)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	original := f.config.OutputRoot
	moved := filepath.Join(f.root, "held-journal")
	require.NoError(t, os.Rename(original, moved))
	require.NoError(t, os.WriteFile(original, []byte("synthetic fsync failure"), 0600))
	err = f.adapter.rejectUnsubmittedBuild(state, request, failure(NeedsAdapter, "synthetic-rejection"))
	var proof *NotSubmitted
	require.Error(t, err)
	require.False(t, errors.As(err, &proof))
	require.NoError(t, os.Remove(original))
	require.NoError(t, os.Rename(moved, original))
	unlock()
	unlock = nil
	require.NoError(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
}

func TestBuildJournalDigestRejectsDroppedSubmissionRecord(t *testing.T) {
	f := newJobFixture(t, false)
	request := f.request()
	_, _, err := f.adapter.advanceBuildJob(t.Context(), request, f.adapter.buildIdentity(request))
	require.NoError(t, err)
	state, err := f.adapter.loadRun(request.RunID, request.Plan.Bind)
	require.NoError(t, err)
	state.Builds = map[string]*buildRecord{}
	raw, err := json.Marshal(state)
	require.NoError(t, err)
	require.NoError(t, writePrivate(f.config.OutputRoot, runName(request.RunID)+".json", raw))
	requireUnknownBuild(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	jobs, err := f.kube.Tracker().List(batchv1.SchemeGroupVersion.WithResource("jobs"),
		batchv1.SchemeGroupVersion.WithKind("Job"), f.config.BuildJobs.Namespace)
	require.NoError(t, err)
	require.Len(t, jobs.(*batchv1.JobList).Items, 1)
}
