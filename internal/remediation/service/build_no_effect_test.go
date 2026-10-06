package service

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	runtimeisolation "github.com/orka-agents/orka/internal/remediation/isolation"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type noEffectTestBuilder struct {
	*controllerTestBuilder
	t             *testing.T
	adapter       *environment.Adapter
	session       *Session
	buildCalls    int
	cancellations int
}

func (b *noEffectTestBuilder) Build(ctx context.Context, request environment.BuildRequest) (environment.BuildResult, error) {
	b.buildCalls++
	current, err := b.session.Current(ctx)
	require.NoError(b.t, err)
	var durable pipelineState
	require.NoError(b.t, json.Unmarshal(current.StateJSON, &durable))
	operation := pipelineOperation(&durable, request.OperationID)
	require.NotNil(b.t, operation)
	require.True(b.t, operation.BuildIntent, "the caller intent must precede pure adapter rejection")
	return b.adapter.Build(ctx, request)
}

func (b *noEffectTestBuilder) CancelBuild(ctx context.Context, runID, operationID string, plan environment.Plan) error {
	b.cancellations++
	return b.adapter.CancelBuild(ctx, runID, operationID, plan)
}

func newNoEffectControllerFixture(t *testing.T) (*controllerTestFixture, *Session, *pipelineState, environment.Plan, *noEffectTestBuilder) {
	t.Helper()
	fixture, session, state, checks := newControllerLeaseFixture(t, false)
	root := t.TempDir()
	// An empty approved catalog deliberately rejects the frozen build plan.
	// New never opens a Kubernetes client when Kubernetes is unset.
	rejecting, err := environment.New(environment.Config{
		SyntheticScope: "build-rejection", OutputRoot: filepath.Join(root, "journal"),
		BuildJobs: &environment.BuildJobsConfig{},
	})
	require.NoError(t, err)
	builder := &noEffectTestBuilder{controllerTestBuilder: fixture.builder, t: t, adapter: rejecting, session: session}
	fixture.adapter.ExecutionAdapter, fixture.adapter.builder = builder, builder
	state.Control = executionOperation{ID: "control", Role: environment.RebuiltControl}
	require.NoError(t, fixture.pipeline.save(t.Context(), session, state, state.Stage))
	require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
	plan, err := checks.buildPlan()
	require.NoError(t, err)
	fixture.kube.ClearActions()
	return fixture, session, state, plan, builder
}

func TestBuildAdmissionRejectionAfterIntentSettlesAndReleasesExactLease(t *testing.T) {
	fixture, session, state, plan, builder := newNoEffectControllerFixture(t)
	before := *state.ControllerLease
	buildErr := fixture.pipeline.build(t.Context(), session, session.run, fixture.adapter, plan, state, &state.Control, nil)
	require.ErrorIs(t, buildErr, ErrNeedsInput)
	durable := reloadControllerLeaseState(t, session)
	require.NotNil(t, durable.Control.BuildNoEffect)
	require.Equal(t, session.epoch, durable.Control.BuildNoEffect.ClaimEpoch)
	require.False(t, durable.Control.Cleaned, "the proof must be durable before marking cleanup complete")
	require.False(t, durable.ControllerLease.Released)
	require.Equal(t, before.UID, durable.ControllerLease.UID)
	require.Equal(t, 1, builder.buildCalls)
	for _, action := range fixture.kube.Actions() {
		require.Equal(t, "get", action.GetVerb(), "a rejected build may only verify the existing Lease")
	}
}

func TestBuildNoEffectSettlementDoesNotReplayOrQuarantine(t *testing.T) {
	fixture, session, state, plan, builder := newNoEffectControllerFixture(t)
	before := *state.ControllerLease
	buildErr := fixture.pipeline.build(t.Context(), session, session.run, fixture.adapter, plan, state, &state.Control, nil)
	require.ErrorIs(t, buildErr, ErrNeedsInput)
	require.ErrorIs(t, fixture.pipeline.build(t.Context(), session, session.run, fixture.adapter, plan, state, &state.Control, nil), ErrNeedsInput)
	current, err := session.Current(t.Context())
	require.NoError(t, err)
	require.NoError(t, fixture.service.settle(t.Context(), session, current, buildErr))
	current, err = fixture.store.GetRemediationRun(t.Context(), current.Namespace, current.ID)
	require.NoError(t, err)
	require.Equal(t, "NeedsInput", current.Phase)
	require.NotEqual(t, quarantinedCleanupReason, current.Reason)
	var durable pipelineState
	require.NoError(t, json.Unmarshal(current.StateJSON, &durable))
	require.True(t, durable.Control.Cleaned)
	require.True(t, durable.ControllerLease.Released)
	require.Equal(t, before.UID, durable.ControllerLease.UID)
	require.Equal(t, 1, builder.buildCalls)
	require.Zero(t, builder.cancellations, "a checkpointed no-effect proof does not need a nonexistent Job")
	require.Zero(t, fixture.models.calls)
	for _, action := range fixture.kube.Actions() {
		require.NotEqual(t, "create", action.GetVerb())
		if action.GetVerb() == "delete" {
			require.Equal(t, "leases", action.GetResource().Resource)
		}
	}
	require.Equal(t, 1, controllerLeaseActions(fixture.kube, "delete"))
}

func TestBuildNoEffectCandidateBindsApprovedPatchBeforeCleanup(t *testing.T) {
	for _, changedPatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "approved-patch", true: "changed-patch"}[changedPatch], func(t *testing.T) {
			fixture, session, state, plan, builder := newNoEffectControllerFixture(t)
			patch := []byte("--- a/main\n+++ b/main\n@@ -1 +1 @@\n-before\n+synthetic-candidate-line\n")
			ref, err := session.Put(t.Context(), "approved-candidate.patch", "text/x-diff", patch)
			require.NoError(t, err)
			state.Attempts = []pipelineAttempt{{Patch: ref, Operation: executionOperation{
				ID: "candidate-0", Role: environment.Candidate,
			}}}
			require.NoError(t, fixture.pipeline.save(t.Context(), session, state, "review-approved-candidate"))
			operation := &state.Attempts[0].Operation
			buildErr := fixture.pipeline.build(t.Context(), session, session.run, fixture.adapter, plan, state, operation, patch)
			require.ErrorIs(t, buildErr, ErrNeedsInput)
			require.NotNil(t, operation.BuildNoEffect)
			raw, err := json.Marshal(operation.BuildNoEffect)
			require.NoError(t, err)
			require.NotContains(t, string(raw), "synthetic-candidate-line")
			if changedPatch {
				state.Attempts[0].Patch.Digest = Digest([]byte("different patch"))
				require.NoError(t, fixture.pipeline.save(t.Context(), session, state, state.Stage))
			}
			current, err := session.Current(t.Context())
			require.NoError(t, err)
			require.NoError(t, fixture.service.settle(t.Context(), session, current, buildErr))
			current, err = fixture.store.GetRemediationRun(t.Context(), current.Namespace, current.ID)
			require.NoError(t, err)
			var durable pipelineState
			require.NoError(t, json.Unmarshal(current.StateJSON, &durable))
			if changedPatch {
				require.Equal(t, store.RemediationPhaseCancelling, current.Phase)
				require.False(t, durable.ControllerLease.Released)
				require.Zero(t, controllerLeaseActions(fixture.kube, "delete"))
			} else {
				require.Equal(t, "NeedsInput", current.Phase)
				require.True(t, durable.Attempts[0].Operation.Cleaned)
				require.True(t, durable.ControllerLease.Released)
			}
			require.Equal(t, 1, builder.buildCalls)
			require.Zero(t, builder.cancellations)
			require.Zero(t, fixture.models.calls)
			for _, action := range fixture.kube.Actions() {
				require.NotEqual(t, "create", action.GetVerb())
			}
		})
	}
}

func TestBuildLegacyNoEffectWithoutAttestationKeepsLease(t *testing.T) {
	fixture, session, state, _, builder := newNoEffectControllerFixture(t)
	state.Control.BuildIntent = true
	require.NoError(t, fixture.pipeline.save(t.Context(), session, state, state.Stage))
	current, err := session.Current(t.Context())
	require.NoError(t, err)
	require.NoError(t, fixture.service.settle(t.Context(), session, current, ErrUnknown))
	durable := reloadControllerLeaseState(t, session)
	require.Nil(t, durable.Control.BuildNoEffect)
	require.False(t, durable.Control.Cleaned)
	require.False(t, durable.ControllerLease.Released)
	require.Zero(t, builder.buildCalls, "cleanup recovery must not retry validation or build execution")
	require.Equal(t, 1, builder.cancellations)
	require.Zero(t, fixture.models.calls)
	require.Zero(t, controllerLeaseActions(fixture.kube, "delete"))
}

type buildNoEffectStoreFault struct {
	store.RemediationRunStore
	stage string
	fired bool
}

func (s *buildNoEffectStoreFault) UpdateRemediationRun(ctx context.Context, namespace, id, owner string, epoch, revision uint64,
	update store.RemediationUpdate, now time.Time,
) (*store.RemediationRun, error) {
	var state pipelineState
	proof := json.Unmarshal(update.StateJSON, &state) == nil && state.Control.BuildNoEffect != nil
	fail := !s.fired && proof && ((s.stage == "clean-before" && state.Control.Cleaned) ||
		(s.stage != "clean-before" && !state.Control.Cleaned))
	if !fail {
		return s.RemediationRunStore.UpdateRemediationRun(ctx, namespace, id, owner, epoch, revision, update, now)
	}
	s.fired = true
	if s.stage == "proof-after" {
		if _, err := s.RemediationRunStore.UpdateRemediationRun(ctx, namespace, id, owner, epoch, revision, update, now); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("synthetic checkpoint interruption")
}

func TestBuildNoEffectCheckpointCrashRecoversOnlyCleanup(t *testing.T) {
	for _, stage := range []string{"proof-before", "proof-after", "clean-before"} {
		t.Run(stage, func(t *testing.T) {
			fixture, session, state, plan, builder := newNoEffectControllerFixture(t)
			fault := &buildNoEffectStoreFault{RemediationRunStore: fixture.store, stage: stage}
			session.store = fault
			buildErr := fixture.pipeline.build(t.Context(), session, session.run, fixture.adapter, plan, state, &state.Control, nil)
			require.Error(t, buildErr)
			durable := reloadControllerLeaseState(t, session)
			require.Equal(t, stage != "proof-before", durable.Control.BuildNoEffect != nil)
			require.False(t, durable.Control.Cleaned)
			require.False(t, durable.ControllerLease.Released)
			current, err := session.Current(t.Context())
			require.NoError(t, err)
			require.NoError(t, fixture.service.settle(t.Context(), session, current, buildErr))
			current, err = fixture.store.GetRemediationRun(t.Context(), current.Namespace, current.ID)
			require.NoError(t, err)
			if stage == "clean-before" {
				require.Equal(t, store.RemediationPhaseCancelling, current.Phase)
				require.Zero(t, controllerLeaseActions(fixture.kube, "delete"))
				require.NoError(t, fixture.service.settle(t.Context(), session, current, buildErr))
				current, err = fixture.store.GetRemediationRun(t.Context(), current.Namespace, current.ID)
				require.NoError(t, err)
			}
			require.Contains(t, []string{"Failed", "NeedsInput"}, current.Phase)
			require.NotEqual(t, quarantinedCleanupReason, current.Reason)
			require.NoError(t, json.Unmarshal(current.StateJSON, &durable))
			require.True(t, durable.Control.Cleaned)
			require.True(t, durable.ControllerLease.Released)
			require.Equal(t, 1, builder.buildCalls)
			require.Zero(t, fixture.models.calls)
			if stage == "proof-before" {
				require.Equal(t, 1, builder.cancellations, "lost proof checkpoint must recover the durable adapter tombstone")
			} else {
				require.Zero(t, builder.cancellations)
			}
			for _, action := range fixture.kube.Actions() {
				require.NotEqual(t, "create", action.GetVerb())
			}
		})
	}
}

func TestBuildNoEffectCheckpointRejectsStaleClaimAndForeignRequest(t *testing.T) {
	for _, change := range []string{"claim", "run", "operation", "plan", "existing", "result"} {
		t.Run(change, func(t *testing.T) {
			fixture, session, state, plan, builder := newNoEffectControllerFixture(t)
			state.Control.BuildIntent = true
			require.NoError(t, fixture.pipeline.save(t.Context(), session, state, state.Stage))
			request := environment.BuildRequest{RunID: session.run.ID, OperationID: state.Control.ID, Plan: plan, Role: state.Control.Role}
			built, err := builder.Build(t.Context(), request)
			var proof *environment.NotSubmitted
			require.ErrorAs(t, err, &proof)
			fenced := *session
			switch change {
			case "claim":
				fenced.epoch++
			case "run":
				request.RunID += "-other"
			case "operation":
				request.OperationID += "-other"
			case "plan":
				request.Plan.Bind.SourceTarget.Commit = Digest([]byte("another commit"))
			case "existing":
				request.RequireExisting = true
			case "result":
				built.ID = "unexpected-accepted-build"
			}
			require.Error(t, checkpointBuildNoEffect(t.Context(), &fenced, state, &state.Control, request, built, proof))
			durable := reloadControllerLeaseState(t, session)
			require.Nil(t, durable.Control.BuildNoEffect)
			require.False(t, durable.Control.Cleaned)
			require.Zero(t, controllerLeaseActions(fixture.kube, "delete"))
		})
	}
}

func TestBuildNoEffectCannotReleaseLeaseWithOtherUnsettledProofs(t *testing.T) {
	for _, unsettled := range []string{"controller", "global", "probe", "build", "forged-no-effect"} {
		t.Run(unsettled, func(t *testing.T) {
			fixture, session, state, plan, _ := newNoEffectControllerFixture(t)
			require.ErrorIs(t, fixture.pipeline.build(t.Context(), session, session.run, fixture.adapter, plan, state, &state.Control, nil), ErrNeedsInput)
			state.Control.Cleaned = true
			state.Original.Intent, state.Original.Cleaned = true, true
			state.Original.Controller = &controllerOperation{
				RunID: session.run.ID, InputDigest: session.run.InputDigest, OperationID: state.Original.ID,
				State: controllerlab.State{Version: 1, Revision: 1, Phase: controllerlab.Complete, RunID: session.run.ID, OperationID: state.Original.ID},
			}
			switch unsettled {
			case "controller":
				state.Original.Controller.State.Phase = controllerlab.Quarantined
			case "global":
				state.Original.Controller.State.Receipts = []controllerlab.Receipt{{
					Object:          controllerlab.ObjectRef{Name: "synthetic-global", UID: "known-global-uid"},
					DeleteRequested: true, Deleted: false,
				}}
			case "probe":
				state.Original.Controller.Isolation = &runtimeisolation.Receipt{CleanupComplete: false}
			case "build":
				state.Attempts = []pipelineAttempt{{Operation: executionOperation{ID: "candidate-0", Role: environment.Candidate, BuildIntent: true}}}
			case "forged-no-effect":
				state.Control.BuildNoEffect.ClaimEpoch++
			}
			require.NoError(t, fixture.pipeline.save(t.Context(), session, state, state.Stage))
			require.Error(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state))
			require.False(t, state.ControllerLease.Released)
			require.Zero(t, controllerLeaseActions(fixture.kube, "delete"))
		})
	}
}

func TestBuildMissingOrForeignLeaseNeverAllowsBuildReplay(t *testing.T) {
	for _, changed := range []string{"missing", "foreign"} {
		t.Run(changed, func(t *testing.T) {
			fixture, session, state, plan, builder := newNoEffectControllerFixture(t)
			receipt := *state.ControllerLease
			resource := coordinationv1.SchemeGroupVersion.WithResource("leases")
			require.NoError(t, fixture.kube.Tracker().Delete(resource, receipt.Namespace, receipt.Name))
			if changed == "foreign" {
				require.NoError(t, fixture.kube.Tracker().Add(&coordinationv1.Lease{
					ObjectMeta: metav1.ObjectMeta{Name: receipt.Name, Namespace: receipt.Namespace, UID: types.UID("foreign-lease-uid"), ResourceVersion: "1"},
				}))
			}
			require.Error(t, fixture.pipeline.build(t.Context(), session, session.run, fixture.adapter, plan, state, &state.Control, nil))
			require.Zero(t, builder.buildCalls)
			require.Zero(t, builder.cancellations)
			for _, action := range fixture.kube.Actions() {
				require.NotEqual(t, "create", action.GetVerb())
				require.NotEqual(t, "delete", action.GetVerb())
			}
		})
	}
}
