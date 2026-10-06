//go:build linux

package environment

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/buildjob"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type jobFixture struct {
	fixture
	adapter        *Adapter
	kube           *fake.Clientset
	terminal       bool
	outcome        buildjob.BuildOutcome
	settleOnDelete bool
	sequence       atomic.Int64
	buildCount     atomic.Int64
	lastFiles      map[string][]byte
	onCreate       func(*batchv1.Job)
}

func newJobFixture(t *testing.T, terminal bool) *jobFixture {
	t.Helper()
	f := testFixture(t)
	f.config.ImageBindings = nil
	f.config.BuildJobs = &BuildJobsConfig{
		Namespace: "build-jobs", WorkerImage: "registry.example.invalid/trusted-client@sha256:" + strings.Repeat("c", 64),
		BuildKitAddress: "tcp://buildkit.build-jobs.svc:1234", OutputRepository: "registry.build-jobs.svc:5000/remediation/results",
		WorkerContext: "dalec-azlinux3-worker",
		TLS:           &buildjob.TLS{CASecretName: "buildkit-ca-v1", ClientSecretName: "buildkit-client-v1", ServerName: "buildkit.build-jobs.svc"},
		Limits: buildjob.Limits{APITimeout: time.Second, BuildTimeout: 5 * time.Second,
			CleanupTimeout: 2 * time.Second, PollInterval: time.Millisecond},
	}
	adapter, err := newAdapter(f.config)
	require.NoError(t, err)
	for index := range f.plans {
		f.plans[index], err = adapter.FreezePlan(f.plans[index])
		require.NoError(t, err)
	}
	kube := fake.NewClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: f.config.BuildJobs.Namespace, UID: "build-namespace", ResourceVersion: "1"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "buildkit-ca-v1", Namespace: f.config.BuildJobs.Namespace, UID: "ca-secret", ResourceVersion: "1"},
			Type:       corev1.SecretTypeOpaque, Immutable: new(true),
			Data: map[string][]byte{"ca.crt": []byte("synthetic-ca-material")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "buildkit-client-v1", Namespace: f.config.BuildJobs.Namespace, UID: "client-secret", ResourceVersion: "1"},
			Type:       corev1.SecretTypeTLS, Immutable: new(true),
			Data: map[string][]byte{
				corev1.TLSCertKey:       []byte("synthetic-certificate-material"),
				corev1.TLSPrivateKeyKey: []byte("synthetic-key-material"),
			},
		},
	)
	adapter.kube = kube
	result := &jobFixture{fixture: f, adapter: adapter, kube: kube, terminal: terminal, outcome: buildjob.Success}
	kube.PrependReactor("create", "*", result.create)
	kube.PrependReactor("update", "*", result.update)
	kube.PrependReactor("delete", "*", result.delete)
	return result
}

func (f *jobFixture) request() BuildRequest {
	return BuildRequest{RunID: "job-run", OperationID: "control", Plan: f.plans[0], Role: RebuiltControl}
}

func (f *jobFixture) create(action ktesting.Action) (bool, runtime.Object, error) {
	object := action.(ktesting.CreateAction).GetObject().DeepCopyObject()
	metadata, err := meta.Accessor(object)
	if err != nil {
		return true, nil, err
	}
	version := f.sequence.Add(1)
	metadata.SetUID(types.UID(fmt.Sprintf("%s-%d", action.GetResource().Resource, version)))
	metadata.SetResourceVersion(strconv.FormatInt(version, 10))
	if err := f.kube.Tracker().Create(action.GetResource(), object, action.GetNamespace()); err != nil {
		return true, nil, err
	}
	if job, ok := object.(*batchv1.Job); ok {
		count := f.buildCount.Add(1)
		if err := f.createPod(job, count); err != nil {
			return true, nil, err
		}
		if f.onCreate != nil {
			f.onCreate(job)
		}
	}
	return true, object, nil
}

func (f *jobFixture) createPod(job *batchv1.Job, count int64) error {
	anchorName := job.Spec.Template.Spec.Volumes[0].Secret.SecretName
	object, err := f.kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), job.Namespace, anchorName)
	if err != nil {
		return err
	}
	secret := object.(*corev1.Secret)
	var manifest struct {
		Input buildjob.Input `json:"input"`
	}
	if err := json.Unmarshal(secret.Data["manifest.json"], &manifest); err != nil {
		return err
	}
	f.lastFiles, err = decodeJobArchive(secret.Data["files.tar.gz"])
	if err != nil {
		return err
	}
	pod := &corev1.Pod{ObjectMeta: *job.Spec.Template.ObjectMeta.DeepCopy(), Spec: *job.Spec.Template.Spec.DeepCopy()}
	pod.Namespace, pod.Name, pod.UID, pod.ResourceVersion = job.Namespace, job.Name+"-pod", types.UID(job.Name+"-pod-uid"), "1"
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: new(true), BlockOwnerDeletion: new(true),
	}}
	pod.Labels[batchv1.ControllerUidLabel], pod.Labels[batchv1.JobNameLabel] = string(job.UID), job.Name
	pod.Status.Phase = corev1.PodRunning
	if f.terminal {
		wire := buildjob.WorkerResult{Version: buildjob.Version, InputDigest: manifest.Input.InputDigest, BuildOutcome: f.outcome,
			BuildRef: "fixture-build-ref", DaemonSettled: true}
		exit := int32(0)
		pod.Status.Phase = corev1.PodSucceeded
		if f.outcome == buildjob.Success {
			wire.ImmutableImageDigest = "sha256:" + strings.Repeat(strconv.FormatInt(count+1, 16), 64)
		} else {
			exit, pod.Status.Phase = 1, corev1.PodFailed
			if f.outcome == buildjob.CompileFailure {
				wire.Diagnostics = []buildjob.Diagnostic{{Path: "main", Line: 7, Column: 3}}
			}
			if f.outcome == buildjob.TestFailure {
				wire.BuildExitCode, exit = 7, 7
				wire.Diagnostics = []buildjob.Diagnostic{{TestName: "TestMainResult"}}
			}
		}
		message, err := json.Marshal(wire)
		if err != nil {
			return err
		}
		containerID := "containerd://" + strings.Repeat("d", 64)
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: "build-worker", Image: f.config.BuildJobs.WorkerImage,
			ImageID: "docker-pullable://" + f.config.BuildJobs.WorkerImage, ContainerID: containerID,
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				ExitCode: exit, Message: string(message), ContainerID: containerID,
			}},
		}}
	}
	return f.kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), pod, pod.Namespace)
}

func decodeJobArchive(body []byte) (map[string][]byte, error) {
	zip, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zip.Close() }()
	reader := tar.NewReader(zip)
	files := make(map[string][]byte)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		files[header.Name], err = io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
	}
}

func (f *jobFixture) update(action ktesting.Action) (bool, runtime.Object, error) {
	object := action.(ktesting.UpdateAction).GetObject().DeepCopyObject()
	metadata, err := meta.Accessor(object)
	if err != nil {
		return true, nil, err
	}
	old, err := f.kube.Tracker().Get(action.GetResource(), action.GetNamespace(), metadata.GetName())
	if err != nil {
		return true, nil, err
	}
	previous, err := meta.Accessor(old)
	if err != nil {
		return true, nil, err
	}
	if metadata.GetUID() != previous.GetUID() || metadata.GetResourceVersion() != previous.GetResourceVersion() {
		return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), metadata.GetName(), errors.New("stale update"))
	}
	switch before := old.(type) {
	case *corev1.Secret:
		if !reflect.DeepEqual(before.Data, object.(*corev1.Secret).Data) {
			return true, nil, errors.New("immutable input changed")
		}
	case *corev1.ConfigMap:
		if !reflect.DeepEqual(before.Data, object.(*corev1.ConfigMap).Data) {
			return true, nil, errors.New("immutable ledger changed")
		}
	}
	metadata.SetResourceVersion(strconv.FormatInt(f.sequence.Add(1), 10))
	if metadata.GetDeletionTimestamp() != nil && len(metadata.GetFinalizers()) == 0 {
		return true, object, f.kube.Tracker().Delete(action.GetResource(), action.GetNamespace(), metadata.GetName())
	}
	return true, object, f.kube.Tracker().Update(action.GetResource(), object, action.GetNamespace())
}

func (f *jobFixture) delete(action ktesting.Action) (bool, runtime.Object, error) {
	remove := action.(ktesting.DeleteAction)
	object, err := f.kube.Tracker().Get(action.GetResource(), action.GetNamespace(), remove.GetName())
	if err != nil {
		return true, nil, err
	}
	metadata, err := meta.Accessor(object)
	if err != nil {
		return true, nil, err
	}
	options := remove.GetDeleteOptions()
	if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != metadata.GetUID() ||
		options.PropagationPolicy == nil || *options.PropagationPolicy != metav1.DeletePropagationForeground {
		return true, nil, errors.New("unfenced build cleanup")
	}
	if pod, ok := object.(*corev1.Pod); ok && f.settleOnDelete && pod.Status.Phase == corev1.PodRunning {
		wire := buildjob.WorkerResult{
			Version: buildjob.Version, InputDigest: pod.Annotations["remediation.orka.ai/build-input-digest"],
			BuildOutcome: buildjob.Cancelled, BuildRef: "fixture-cancelled-ref", DaemonSettled: true,
		}
		body, err := json.Marshal(wire)
		if err != nil {
			return true, nil, err
		}
		pod.Status.Phase = corev1.PodFailed
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: "build-worker", Image: f.config.BuildJobs.WorkerImage,
			ImageID: "docker-pullable://" + f.config.BuildJobs.WorkerImage, ContainerID: "containerd://cancelled-worker",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				ExitCode: 1, ContainerID: "containerd://cancelled-worker", Message: string(body),
			}},
		}}
	}
	if len(metadata.GetFinalizers()) != 0 {
		metadata.SetDeletionTimestamp(new(metav1.Now()))
		return true, nil, f.kube.Tracker().Update(action.GetResource(), object, action.GetNamespace())
	}
	return true, nil, f.kube.Tracker().Delete(action.GetResource(), action.GetNamespace(), remove.GetName())
}

func (f *jobFixture) restart(t *testing.T) *Adapter {
	t.Helper()
	adapter, err := newAdapter(f.config)
	require.NoError(t, err)
	adapter.kube = f.kube
	return adapter
}

func (f *jobFixture) record(t *testing.T, request BuildRequest) *buildRecord {
	t.Helper()
	state, err := f.adapter.loadRun(request.RunID, request.Plan.Bind)
	require.NoError(t, err)
	record := state.Builds[f.adapter.buildIdentity(request)]
	require.NotNil(t, record)
	return record
}

func TestJobBuildPreservesVendorSeriesAndSeparatesControlFromCandidate(t *testing.T) {
	f := newJobFixture(t, true)
	require.True(t, f.adapter.HasDurableBuildBackend())
	request := f.request()
	control, err := f.adapter.Build(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, RebuiltControl, control.Subject.Role)
	require.Len(t, control.Built.OrderedPatches, 2)
	require.Len(t, f.lastFiles, 3)
	recipeBytes, err := os.ReadFile(filepath.Join(f.config.Repositories[0].RecipeRoot, request.Plan.Bind.Recipe.Path))
	require.NoError(t, err)
	require.Equal(t, recipeBytes, f.lastFiles[request.Plan.Bind.Recipe.Path])
	require.NotContains(t, string(f.lastFiles[request.Plan.Bind.Recipe.Path]), "network_mode")
	originalVendor := append([]byte{}, f.lastFiles["patches/first.patch"]...)
	record := f.record(t, request)
	require.Equal(t, buildComplete, record.State)
	require.True(t, buildJobCleaned(record.Job))
	require.Nil(t, record.Job.Input.Files)
	require.Equal(t, "dalec-azlinux3-worker", record.Job.Input.WorkerContext)
	require.Empty(t, record.Job.Input.WorkerArg)
	require.Equal(t, request.Plan.Bind.SourceTarget.Commit, control.Baseline.UpstreamCommit)
	require.NotEmpty(t, control.WorkerEvidenceDigest)
	request.Role, request.OperationID, request.Patch, request.PatchDigest = Candidate, "candidate", candidatePatch(), digest(candidatePatch())
	candidate, err := f.adapter.Build(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, Candidate, candidate.Subject.Role)
	require.NotEqual(t, control.Subject.Image, candidate.Subject.Image)
	require.NotEqual(t, control.ID, candidate.ID)
	require.Equal(t, request.PatchDigest, candidate.Subject.PatchDigest)
	require.Len(t, candidate.Built.OrderedPatches, 3)
	require.Equal(t, originalVendor, f.lastFiles["patches/first.patch"])
	require.Len(t, f.lastFiles, 4)
	again, err := f.restart(t).Build(t.Context(), request)
	require.NoError(t, err)
	require.True(t, sameJSON(candidate, again))
	require.EqualValues(t, 2, f.buildCount.Load())
	record = f.record(t, request)
	require.True(t, record.Job.Cleanup.Stopped)
	require.True(t, record.Job.Cleanup.SubmissionSettled)
	require.Equal(t, record.Job.Input.InputDigest, record.Job.Outcome.InputDigest)
	require.Equal(t, record.Job.ConfigurationDigest, record.Job.Outcome.Receipt.ConfigurationDigest)
}

func TestBuildJobsConfigurationRemainsOptInAndDetached(t *testing.T) {
	f := testFixture(t)
	encoded, err := json.Marshal(f.config)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), `"BuildJobs"`)
	legacy, _ := testAdapter(t, f)
	require.False(t, legacy.HasDurableBuildBackend())
	require.NoError(t, legacy.ValidateBuildJobs())
	jobs := newJobFixture(t, false)
	require.NoError(t, jobs.adapter.ValidateBuildJobs())
	require.False(t, jobs.adapter.HasBuildRegistrySecret())
	jobs.config.BuildJobs.WorkerContext = "another-worker"
	require.Equal(t, "dalec-azlinux3-worker", jobs.adapter.config.BuildJobs.WorkerContext)
}

func TestJobBuildFreezesOperatorRegistryReferenceForRestrictedGate(t *testing.T) {
	f := newJobFixture(t, true)
	f.config.BuildJobs.RegistrySecretName = "private-registry-v1"
	require.NoError(t, f.kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("secrets"), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "private-registry-v1", Namespace: "build-jobs", UID: "registry-uid", ResourceVersion: "1"},
		Type:       corev1.SecretTypeDockerConfigJson, Immutable: new(true),
		Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(
			`{"auths":{"registry.build-jobs.svc:5000":{"username":"fixture-user","password":"fixture-password"}}}`)},
	}, "build-jobs"))
	f.adapter = f.restart(t)
	require.True(t, f.adapter.HasBuildRegistrySecret())
	request := f.request()
	result, err := f.adapter.Build(t.Context(), request)
	require.NoError(t, err)
	require.NotEmpty(t, result.Subject.Image)
	record := f.record(t, request)
	require.Equal(t, "private-registry-v1", record.Job.Receipt.RegistrySecret.Name)
	require.Equal(t, types.UID("registry-uid"), record.Job.Receipt.RegistrySecret.UID)
	require.True(t, buildJobCleaned(record.Job))
}

func TestJobBuildRejectsLimitsBeforeRecordingSubmissionIntent(t *testing.T) {
	f := newJobFixture(t, false)
	f.config.BuildJobs.Limits.MaxFileBytes = 16
	adapter := f.restart(t)
	request := f.request()
	result, err := adapter.Build(t.Context(), request)
	require.Error(t, err)
	require.Empty(t, result.Subject.Image)
	state, err := adapter.loadRun(request.RunID, request.Plan.Bind)
	require.NoError(t, err)
	require.Empty(t, state.Builds)
	require.Zero(t, f.buildCount.Load())
}

func TestJobBuildPersistsAcceptedReceiptBeforeObservationAndCallerCancellation(t *testing.T) {
	f := newJobFixture(t, false)
	request := f.request()
	ctx, cancel := context.WithCancel(t.Context())
	f.kube.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		record := f.record(t, request)
		require.True(t, completeJobReceipt(*record.Job.Receipt))
		require.True(t, record.Job.SubmissionAttempted)
		cancel()
		return false, nil, nil
	})
	result, err := f.adapter.Build(ctx, request)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, result.Subject.Image)
	record := f.record(t, request)
	require.Equal(t, buildStarted, record.State)
	require.Nil(t, record.Job.Cleanup)
	require.NotEmpty(t, record.Job.Receipt.JobUID)
	for _, action := range f.kube.Actions() {
		require.NotEqual(t, "delete", action.GetVerb())
	}
	f.kube.ReactionChain = f.kube.ReactionChain[1:]
	request.RequireExisting = true
	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = f.restart(t).Build(ctx, request)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.EqualValues(t, 1, f.buildCount.Load())
	require.Equal(t, buildStarted, f.record(t, request).State)
}

func TestJobBuildRecoversLostCallerAcknowledgementWithoutAnotherJob(t *testing.T) {
	f := newJobFixture(t, true)
	request := f.request()
	var created atomic.Bool
	var failed atomic.Bool
	f.kube.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		handled, object, err := f.create(action)
		if err != nil {
			return handled, object, err
		}
		created.Store(true)
		return true, nil, apierrors.NewTimeoutError("lost create acknowledgement", 1)
	})
	f.kube.PrependReactor("get", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
		if created.Load() && !failed.Swap(true) {
			return true, nil, apierrors.NewServiceUnavailable("temporarily hidden acknowledgement")
		}
		return false, nil, nil
	})
	result, err := f.adapter.Build(t.Context(), request)
	require.Error(t, err)
	require.Empty(t, result.Subject.Image)
	record := f.record(t, request)
	require.Equal(t, buildStarted, record.State)
	require.NotNil(t, record.Job.Receipt)
	require.NotEmpty(t, record.Job.Receipt.AnchorUID)
	require.Empty(t, record.Job.Receipt.JobUID)
	request.RequireExisting = true
	result, err = f.restart(t).Build(t.Context(), request)
	require.NoError(t, err)
	require.NotEmpty(t, result.Subject.Image)
	require.EqualValues(t, 1, f.buildCount.Load())
	require.True(t, buildJobCleaned(f.record(t, request).Job))
}

func TestJobBuildSavesUIDsOnStartErrorAndRecoversMissingLocalReceipt(t *testing.T) {
	f := newJobFixture(t, true)
	request := f.request()
	ctx, cancel := context.WithCancel(t.Context())
	f.onCreate = func(*batchv1.Job) { cancel() }
	result, err := f.adapter.Build(ctx, request)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, result.Subject.Image)
	record := f.record(t, request)
	require.True(t, completeJobReceipt(*record.Job.Receipt))
	require.Nil(t, record.Job.Outcome)
	f.onCreate = nil
	// Model a controller that lost the local acknowledgement after Kubernetes
	// accepted the operation. The durable submission intent forbids replay.
	state, err := f.adapter.loadRun(request.RunID, request.Plan.Bind)
	require.NoError(t, err)
	state.Builds[record.ID].Job.Receipt = nil
	require.NoError(t, f.adapter.saveRun(request.RunID, state))
	request.RequireExisting = true
	result, err = f.restart(t).Build(t.Context(), request)
	require.NoError(t, err)
	require.NotEmpty(t, result.Subject.Image)
	require.EqualValues(t, 1, f.buildCount.Load())
}

func TestCancelBuildRecoversPartialReceiptWithoutSubmitting(t *testing.T) {
	f := newJobFixture(t, false)
	f.settleOnDelete = true
	request := f.request()
	var created atomic.Bool
	var lost atomic.Bool
	f.kube.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		handled, object, err := f.create(action)
		if err != nil {
			return handled, object, err
		}
		created.Store(true)
		return true, nil, apierrors.NewTimeoutError("lost acknowledgement", 1)
	})
	f.kube.PrependReactor("get", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
		if created.Load() && !lost.Swap(true) {
			return true, nil, apierrors.NewServiceUnavailable("receipt unavailable")
		}
		return false, nil, nil
	})
	_, err := f.adapter.Build(t.Context(), request)
	require.Error(t, err)
	require.Empty(t, f.record(t, request).Job.Receipt.JobUID)
	require.NoError(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	record := f.record(t, request)
	require.NotEmpty(t, record.Job.Receipt.JobUID)
	require.True(t, buildJobCleaned(record.Job))
	require.True(t, record.Job.CancelRequested)
	require.EqualValues(t, 1, f.buildCount.Load())
}

func TestJobBuildMissingRecoveryEvidenceCannotCreateNewWork(t *testing.T) {
	f := newJobFixture(t, false)
	request := f.request()
	request.RequireExisting = true
	result, err := f.adapter.Build(t.Context(), request)
	require.Error(t, err)
	require.Empty(t, result.Subject.Image)
	require.Zero(t, f.buildCount.Load())
	record := f.record(t, request)
	require.Equal(t, buildStarted, record.State)
	require.Error(t, f.adapter.CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	require.False(t, buildJobCleaned(f.record(t, request).Job))
	for _, action := range f.kube.Actions() {
		require.NotEqual(t, "create", action.GetVerb())
		require.NotEqual(t, "delete", action.GetVerb())
	}
}

func TestJobBuildResumesSavedTerminalEvidenceAndBlocksImageUntilCleanup(t *testing.T) {
	for _, outcome := range []buildjob.BuildOutcome{buildjob.Success, buildjob.CompileFailure, buildjob.TestFailure, buildjob.Infrastructure} {
		t.Run(string(outcome), func(t *testing.T) {
			f := newJobFixture(t, true)
			f.outcome = outcome
			request := f.request()
			ctx, cancel := context.WithCancel(t.Context())
			var blocked atomic.Bool
			f.kube.PrependReactor("delete", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
				if !blocked.Swap(true) {
					cancel()
					return true, nil, context.Canceled
				}
				return false, nil, nil
			})
			result, err := f.adapter.Build(ctx, request)
			require.ErrorIs(t, err, context.Canceled)
			require.Empty(t, result.Subject.Image)
			require.Empty(t, result.Diagnostics)
			record := f.record(t, request)
			require.Equal(t, buildStarted, record.State)
			require.NotNil(t, record.Job.Outcome)
			require.False(t, buildJobCleaned(record.Job))
			require.Equal(t, outcome, record.Job.Outcome.BuildOutcome)
			result, err = f.restart(t).Build(t.Context(), request)
			switch outcome {
			case buildjob.Success:
				require.NoError(t, err)
				require.NotEmpty(t, result.Subject.Image)
			case buildjob.CompileFailure:
				var failure *Error
				require.ErrorAs(t, err, &failure)
				require.Equal(t, BuildFailed, failure.Kind)
				require.Equal(t, []Diagnostic{{Code: "compiler-diagnostic", Count: 1, Path: "main", Line: 7, Column: 3}}, result.Diagnostics)
				require.Empty(t, result.Subject.Image)
			case buildjob.TestFailure:
				var failure *Error
				require.ErrorAs(t, err, &failure)
				require.Equal(t, BuildFailed, failure.Kind)
				require.Equal(t, "build-job-tests-failed", failure.Code)
				require.Equal(t, []Diagnostic{{Code: "go-test-failure", Count: 1, Identifier: "TestMainResult"}}, result.Diagnostics)
				require.Empty(t, result.Subject.Image)
			default:
				var failure *Error
				require.ErrorAs(t, err, &failure)
				require.Equal(t, Infrastructure, failure.Kind)
				require.Empty(t, result.Subject.Image)
			}

			require.True(t, buildJobCleaned(f.record(t, request).Job))
			require.EqualValues(t, 1, f.buildCount.Load())
		})
	}
}

func TestJobGoTestFailureReplayUsesCapturedDiagnosticScope(t *testing.T) {
	f := newJobFixture(t, true)
	f.outcome = buildjob.TestFailure
	request := f.request()
	first, err := f.adapter.Build(t.Context(), request)
	var buildErr *Error
	require.ErrorAs(t, err, &buildErr)
	require.Equal(t, BuildFailed, buildErr.Kind)
	before := f.record(t, request)
	require.Equal(t, buildFailed, before.State)
	require.True(t, buildJobCleaned(before.Job))
	require.Equal(t, 7, before.Job.Outcome.BuildExitCode)
	require.NotEmpty(t, first.WorkerEvidenceDigest)
	require.Empty(t, first.Subject.Image)
	request.RequireExisting = true
	replayed, err := f.restart(t).Build(t.Context(), request)
	var replayErr *Error
	require.ErrorAs(t, err, &replayErr)
	require.Equal(t, buildErr, replayErr)
	require.Equal(t, first, replayed)
	after := f.record(t, request)
	require.Equal(t, before.Job.SourcePaths, after.Job.SourcePaths)
	require.Equal(t, before.Job.DescriptorDigest, after.Job.DescriptorDigest)
	require.Equal(t, before.Job.Input.BuildOnlyInputs, after.Job.Input.BuildOnlyInputs)
	require.Equal(t, before.Job.Cleanup, after.Job.Cleanup)
	require.EqualValues(t, 1, f.buildCount.Load())
}

func TestCancelBuildStopsActiveBuildWithoutDependingOnCallerCancellation(t *testing.T) {
	f := newJobFixture(t, false)
	f.settleOnDelete = true
	request := f.request()
	ready := make(chan struct{}, 1)
	f.onCreate = func(*batchv1.Job) { ready <- struct{}{} }
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_, err := f.adapter.Build(ctx, request)
		done <- err
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		require.FailNow(t, "build Job was not created")
	}
	require.NoError(t, f.adapter.CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		require.FailNow(t, "build poller ignored explicit cancellation")
	}
	record := f.record(t, request)
	require.True(t, record.Job.CancelRequested)
	require.True(t, buildJobCleaned(record.Job))
	require.Equal(t, buildFailed, record.State)
	require.Empty(t, record.Result.Subject.Image)
	require.NoError(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	require.EqualValues(t, 1, f.buildCount.Load())
}

func TestCancelBuildUnknownOperationCannotManufactureSettlement(t *testing.T) {
	f := newJobFixture(t, false)
	request := f.request()
	err := f.adapter.CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan)
	var failure *Error
	require.ErrorAs(t, err, &failure)
	require.Equal(t, Unknown, failure.Kind)
	require.Zero(t, f.buildCount.Load())
	require.Empty(t, f.kube.Actions())
}

func TestCancelBuildDoesNotHideFailureToPersistCleanup(t *testing.T) {
	f := newJobFixture(t, false)
	f.settleOnDelete = true
	request := f.request()
	_, done, err := f.adapter.advanceBuildJob(t.Context(), request, f.adapter.buildIdentity(request))
	require.NoError(t, err)
	require.False(t, done)
	original := f.config.OutputRoot
	retained := filepath.Join(f.root, "retained-output")
	var moved atomic.Bool
	f.kube.PrependReactor("update", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		record := action.(ktesting.UpdateAction).GetObject().(*corev1.ConfigMap)
		if record.Annotations["remediation.orka.ai/build-state"] == "cleaned" && !moved.Swap(true) {
			if err := os.Rename(original, retained); err != nil {
				return true, nil, err
			}
			if err := os.WriteFile(original, []byte("directory unavailable"), 0600); err != nil {
				return true, nil, err
			}
		}
		return false, nil, nil
	})
	err = f.adapter.CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan)
	require.Error(t, err)
	require.True(t, moved.Load())
	require.NoError(t, os.Remove(original))
	require.NoError(t, os.Rename(retained, original))
	record := f.record(t, request)
	require.Equal(t, buildStarted, record.State)
	require.True(t, record.Job.CancelRequested)
	require.False(t, buildJobCleaned(record.Job))
	require.NoError(t, f.restart(t).CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	require.True(t, buildJobCleaned(f.record(t, request).Job))
}

func TestJobBuildRejectsPersistedInputConfigurationAndCleanupForgeries(t *testing.T) {
	for _, field := range []string{"input", "configuration", "cleanup", "image"} {
		t.Run(field, func(t *testing.T) {
			f := newJobFixture(t, true)
			request := f.request()
			_, err := f.adapter.Build(t.Context(), request)
			require.NoError(t, err)
			state, err := f.adapter.loadRun(request.RunID, request.Plan.Bind)
			require.NoError(t, err)
			record := state.Builds[f.adapter.buildIdentity(request)]
			switch field {
			case "input":
				record.Job.Outcome.InputDigest = "sha256:" + strings.Repeat("f", 64)
			case "configuration":
				record.Job.Outcome.Receipt.ConfigurationDigest = "sha256:" + strings.Repeat("f", 64)
			case "cleanup":
				record.Job.Cleanup.Stopped = false
			case "image":
				record.Result.Subject.Image = "registry.example.invalid/forged@sha256:" + strings.Repeat("f", 64)
			}
			require.NoError(t, f.adapter.saveRun(request.RunID, state))
			result, err := f.restart(t).Build(t.Context(), request)
			require.Error(t, err)
			require.Empty(t, result.Subject.Image)
			require.EqualValues(t, 1, f.buildCount.Load())
		})
	}
}
