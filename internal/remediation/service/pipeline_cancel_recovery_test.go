package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type cleanupProposal struct {
	modelagent.ControllerClient
	fixture   *modelCleanupFixture
	generates int
	snapshots int
	cancels   int
	retires   int
}

func (c *cleanupProposal) Snapshot(context.Context) (modelagent.PlanIdentity, error) {
	c.snapshots++
	return modelagent.PlanIdentity{}, errors.New("cleanup must not inspect current model policy")
}

func (c *cleanupProposal) Generate(context.Context, modelagent.Request) (modelagent.Result, error) {
	c.generates++
	return modelagent.Result{}, errors.New("cleanup must not submit a prompt")
}

func (c *cleanupProposal) Cancel(ctx context.Context, name, uid string) error {
	c.cancels++
	c.fixture.assertPinned()
	return c.ControllerClient.Cancel(ctx, name, uid)
}

func (c *cleanupProposal) Retire(ctx context.Context, name, uid string) error {
	c.retires++
	c.fixture.assertPinned()
	return c.ControllerClient.Retire(ctx, name, uid)
}

type modelCleanupFixture struct {
	t          *testing.T
	pipeline   *Pipeline
	proposer   *cleanupProposal
	session    *Session
	storage    store.RemediationRunStore
	kube       client.WithWatch
	task       *corev1alpha1.Task
	key        string
	readErr    error
	deleteErr  error
	creates    int
	deletes    int
	statuses   int
	taskReads  int
	legacyData json.RawMessage
}

func newModelCleanupFixture(t *testing.T, backend string) *modelCleanupFixture {
	t.Helper()
	return newModelCleanupFixtureState(t, backend, true)
}

func newModelCleanupFixtureState(t *testing.T, backend string, cancelling bool) *modelCleanupFixture {
	t.Helper()
	service, storage := testService(t, processorFunc{})
	submitted, _, err := service.Submit(t.Context(), "testing", "synthetic-caller", requestFixture())
	require.NoError(t, err)
	run, err := storage.ClaimNextRemediationRun(t.Context(), submitted.Namespace, "orphan-cleanup", time.Now(), time.Minute)
	require.NoError(t, err)
	require.NotNil(t, run)
	f := &modelCleanupFixture{t: t, pipeline: &Pipeline{}, storage: storage,
		session:    &Session{store: storage, run: run, owner: run.ClaimOwner, epoch: run.ClaimEpoch},
		legacyData: json.RawMessage(`{"phase":"Cancelled","attempts":2,"startedAt":"2026-01-01T00:00:00Z"}`),
	}
	identity := modelagent.PlanIdentity{
		Backend: backend, Namespace: run.Namespace, AgentName: "proposer", AgentUID: "synthetic-agent-uid", AgentGeneration: 1,
	}
	if backend == remediationpolicy.CopilotBackend {
		identity.CopilotConfigDigest = Digest([]byte("synthetic-config"))
		identity.RuntimeImage = "example.invalid/runtime@sha256:" + strings.Repeat("a", 64)
		identity.RuntimeNamespace, identity.RuntimeNamespaceUID = "proposal-runtime", "synthetic-runtime-uid"
		identity.RuntimeProfileDigest = Digest([]byte("synthetic-profile"))
		identity.ProxyEndpoint, identity.ProxyNamespace = "http://proxy.fixture.invalid:8080", "proposal-proxy"
		identity.ProxyNamespaceUID, identity.ProxyIdentityDigest = "synthetic-proxy-uid", Digest([]byte("synthetic-proxy"))
	} else {
		identity.ProviderName, identity.ProviderUID, identity.ProviderGeneration = "proposal-provider", "synthetic-provider-uid", 1
		identity.SecretRefName, identity.SecretUID, identity.SecretResourceVersion = "proposal-reference", "synthetic-reference-uid", "1"
	}
	identity.Digest, err = remediationpolicy.MetadataDigest(identity)
	require.NoError(t, err)
	prompt := "Use only this synthetic orphan cleanup fixture."
	name := run.ID + "-checks"
	f.key = Digest([]byte(name + "\x00" + prompt))
	state := &pipelineState{Version: Version, Stage: "model-intent", Models: map[string]modelOperation{
		f.key: {Name: name, PromptDigest: Digest([]byte(prompt)), Expected: identity, Intent: true},
	}, ModelCalls: 1, ModelIdentity: &identity}
	require.NoError(t, f.pipeline.save(t.Context(), f.session, state, state.Stage))
	phase := store.RemediationPhaseRunning
	if cancelling {
		_, err = storage.CancelRemediationRun(t.Context(), run.Namespace, run.ID, time.Now())
		require.NoError(t, err)
		phase = store.RemediationPhaseCancelling
	}
	current, err := f.session.Current(t.Context())
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(current.StateJSON, &fields))
	fields["settlement"] = f.legacyData
	fields["unrelatedCleanupState"] = json.RawMessage(`{"preserved":true}`)
	raw, err := json.Marshal(fields)
	require.NoError(t, err)
	require.NoError(t, f.session.Checkpoint(t.Context(), phase, "cleanup-requires-reconciliation", raw, ""))

	f.task = &corev1alpha1.Task{
		TypeMeta: metav1.TypeMeta{Kind: "Task", APIVersion: corev1alpha1.GroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: run.Namespace, UID: "synthetic-orphan-uid", ResourceVersion: "1", Generation: 1,
			Labels: map[string]string{
				labels.LabelCreatedBy: remediationpolicy.CreatedBy, remediationpolicy.RunLabel: labels.SelectorValue(run.ID),
			},
			Annotations: map[string]string{remediationpolicy.RunAnnotation: run.ID, remediationpolicy.IdentityAnnotation: identity.Digest},
			Finalizers:  []string{"fixture.orka.ai/cleanup"},
		},
		Spec:   remediationpolicy.TaskSpec(prompt, identity.AgentName),
		Status: corev1alpha1.TaskStatus{Phase: corev1alpha1.TaskPhaseSucceeded},
	}
	if backend == remediationpolicy.CopilotBackend {
		f.task.Spec = remediationpolicy.CopilotTaskSpec(prompt, identity.AgentName)
		f.task.Annotations[labels.AnnotationAgentReadOnly] = "true"
		f.task.Status.Phase = corev1alpha1.TaskPhasePending
	}
	f.task.Annotations[remediationpolicy.RequestDigestAnnotation], err = remediationpolicy.RequestDigest(
		f.task.Namespace, f.task.Name, run.ID, identity.Digest, f.task.Spec)
	require.NoError(t, err)
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))
	f.kube = fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(f.task).Build()
	reader := interceptor.NewClient(f.kube, interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
			require.IsType(t, &corev1alpha1.Task{}, object, "cleanup must not read current Agent, Provider, or credentials")
			require.Equal(t, client.ObjectKeyFromObject(f.task), key)
			f.taskReads++
			if f.readErr != nil {
				return f.readErr
			}
			return delegate.Get(ctx, key, object, options...)
		},
	})
	writer := interceptor.NewClient(f.kube, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			t.Error("cleanup used the cached client")
			return errors.New("cached reads are forbidden")
		},
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			f.creates++
			return errors.New("cleanup must never create a Task")
		},
		Delete: func(ctx context.Context, delegate client.WithWatch, object client.Object, options ...client.DeleteOption) error {
			f.assertPinned()
			f.deletes++
			parsed := &client.DeleteOptions{}
			for _, option := range options {
				option.ApplyToDelete(parsed)
			}
			require.NotNil(t, parsed.Preconditions)
			require.Equal(t, f.task.UID, *parsed.Preconditions.UID)
			require.Equal(t, object.GetResourceVersion(), *parsed.Preconditions.ResourceVersion)
			if f.deleteErr != nil {
				return f.deleteErr
			}
			return delegate.Delete(ctx, object, options...)
		},
		SubResourceUpdate: func(ctx context.Context, delegate client.Client, subresource string, object client.Object, options ...client.SubResourceUpdateOption) error {
			f.assertPinned()
			f.statuses++
			return delegate.SubResource(subresource).Update(ctx, object, options...)
		},
	})
	f.proposer = &cleanupProposal{fixture: f, ControllerClient: modelagent.ControllerClient{
		Native: modelagent.KubernetesClient{Reader: reader, Client: writer, Namespace: run.Namespace, AgentName: identity.AgentName},
	}}
	f.pipeline.Agents = func(namespace, name string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
		require.Equal(t, run.Namespace, namespace)
		require.Equal(t, identity.AgentName, name)
		require.Nil(t, accepted)
		return f.proposer
	}
	t.Cleanup(func() {
		require.Zero(t, f.creates)
		require.Zero(t, f.proposer.generates)
		require.Zero(t, f.proposer.snapshots)
	})
	return f
}

func (f *modelCleanupFixture) operation() modelOperation {
	f.t.Helper()
	current, err := f.storage.GetRemediationRun(f.t.Context(), f.session.run.Namespace, f.session.run.ID)
	require.NoError(f.t, err)
	var state pipelineState
	require.NoError(f.t, json.Unmarshal(current.StateJSON, &state))
	return state.Models[f.key]
}

func (f *modelCleanupFixture) assertPinned() {
	f.t.Helper()
	require.Equal(f.t, string(f.task.UID), f.operation().UID, "Task mutation preceded the durable UID checkpoint")
	_, raw, err := f.session.Read(f.t.Context(), modelReceiptName(f.task.Name))
	require.NoError(f.t, err)
	var receipt modelagent.Result
	require.NoError(f.t, json.Unmarshal(raw, &receipt))
	require.Equal(f.t, modelagent.Result{TaskName: f.task.Name, TaskUID: string(f.task.UID)}, receipt)
}

func (f *modelCleanupFixture) finishDeletion() {
	f.t.Helper()
	current := &corev1alpha1.Task{}
	require.NoError(f.t, f.kube.Get(f.t.Context(), client.ObjectKeyFromObject(f.task), current))
	require.NotNil(f.t, current.DeletionTimestamp)
	current.Finalizers = nil
	require.NoError(f.t, f.kube.Update(f.t.Context(), current))
	require.NoError(f.t, f.pipeline.Cancel(f.t.Context(), f.session))
	require.True(f.t, f.operation().Retired)
}

func TestPipelineCancelRecoversOrphanBeforeAnyMutation(t *testing.T) {
	for _, backend := range []string{"", remediationpolicy.CopilotBackend} {
		for _, receiptWritten := range []bool{false, true} {
			name := backend + "/missing-receipt"
			if receiptWritten {
				name = backend + "/receipt-before-crash"
			}
			t.Run(name, func(t *testing.T) {
				f := newModelCleanupFixture(t, backend)
				if receiptWritten {
					raw, err := json.Marshal(modelagent.Result{TaskName: f.task.Name, TaskUID: string(f.task.UID)})
					require.NoError(t, err)
					_, err = f.session.Put(t.Context(), modelReceiptName(f.task.Name), "application/json", raw)
					require.NoError(t, err)
				}
				require.Empty(t, f.operation().UID)
				require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrCleanupPending)
				f.assertPinned()
				if backend == remediationpolicy.CopilotBackend {
					require.Zero(t, f.deletes, "cancellation must first be acknowledged")
					require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrCleanupPending)
				}
				require.Equal(t, 1, f.deletes)
				require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrCleanupPending)
				require.False(t, f.operation().Retired, "an outstanding finalizer cannot be treated as settled effects")
				current, err := f.session.Current(t.Context())
				require.NoError(t, err)
				require.Equal(t, store.RemediationPhaseCancelling, current.Phase)
				var fields map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(current.StateJSON, &fields))
				require.JSONEq(t, string(f.legacyData), string(fields["settlement"]))
				require.JSONEq(t, `{"preserved":true}`, string(fields["unrelatedCleanupState"]))
				f.finishDeletion()
				reads := f.taskReads
				require.NoError(t, f.pipeline.Cancel(t.Context(), f.session))
				require.Equal(t, reads, f.taskReads, "retired operation must remain retired")
			})
		}
	}
}

func TestPipelineCancelLegacyEffectsDoNotRequireAdmissionIdentity(t *testing.T) {
	for _, backend := range []string{"", remediationpolicy.CopilotBackend} {
		t.Run("backend="+backend, func(t *testing.T) {
			f := newModelCleanupFixture(t, backend)
			current, err := f.session.Current(t.Context())
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(current.StateJSON, &fields))
			delete(fields, "modelIdentity")
			raw, err := json.Marshal(fields)
			require.NoError(t, err)
			require.NoError(t, f.session.Checkpoint(t.Context(), current.Phase, current.Reason, raw, ""))

			require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrCleanupPending)
			f.assertPinned()
			if backend == remediationpolicy.CopilotBackend {
				require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrCleanupPending)
			}
			f.finishDeletion()

			current, err = f.session.Current(t.Context())
			require.NoError(t, err)
			var state pipelineState
			require.NoError(t, json.Unmarshal(current.StateJSON, &state))
			require.Nil(t, state.ModelIdentity, "cleanup must not snapshot or admit a new model identity")
			require.Equal(t, string(f.task.UID), state.Models[f.key].UID)
			require.True(t, state.Models[f.key].Retired)
		})
	}
}

func TestPipelineCancelRejectsOrphanDriftAndReplacement(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*corev1alpha1.Task)
		rehash bool
	}{
		{"run", func(task *corev1alpha1.Task) {
			task.Annotations[remediationpolicy.RunAnnotation] = "another-run"
			task.Labels[remediationpolicy.RunLabel] = labels.SelectorValue("another-run")
		}, true},
		{"prompt", func(task *corev1alpha1.Task) { task.Spec.Prompt = "a different synthetic request" }, true},
		{"identity", func(task *corev1alpha1.Task) {
			task.Annotations[remediationpolicy.IdentityAnnotation] = Digest([]byte("another-identity"))
		}, true},
		{"request-digest", func(task *corev1alpha1.Task) {
			task.Annotations[remediationpolicy.RequestDigestAnnotation] = Digest([]byte("another-request"))
		}, false},
		{"agent", func(task *corev1alpha1.Task) { task.Spec.AgentRef.Name = "another-agent" }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newModelCleanupFixture(t, remediationpolicy.CopilotBackend)
			current := f.task.DeepCopy()
			test.change(current)
			if test.rehash {
				digest, err := remediationpolicy.RequestDigest(current.Namespace, current.Name,
					current.Annotations[remediationpolicy.RunAnnotation], current.Annotations[remediationpolicy.IdentityAnnotation], current.Spec)
				require.NoError(t, err)
				current.Annotations[remediationpolicy.RequestDigestAnnotation] = digest
			}
			require.NoError(t, f.kube.Update(t.Context(), current))
			require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrUnknown)
			require.Empty(t, f.operation().UID)
			require.Zero(t, f.proposer.cancels)
			require.Zero(t, f.deletes)
			require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.task), &corev1alpha1.Task{}))
		})
	}
	t.Run("same-name-replacement-with-accepted-receipt", func(t *testing.T) {
		f := newModelCleanupFixture(t, remediationpolicy.CopilotBackend)
		receipt, err := json.Marshal(modelagent.Result{TaskName: f.task.Name, TaskUID: string(f.task.UID)})
		require.NoError(t, err)
		_, err = f.session.Put(t.Context(), modelReceiptName(f.task.Name), "application/json", receipt)
		require.NoError(t, err)
		replacement := f.task.DeepCopy()
		replacement.Finalizers = nil
		require.NoError(t, f.kube.Update(t.Context(), replacement))
		require.NoError(t, f.kube.Delete(t.Context(), replacement))
		replacement.UID, replacement.ResourceVersion = "same-name-replacement", ""
		require.NoError(t, f.kube.Create(t.Context(), replacement))
		require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrUnknown)
		require.Empty(t, f.operation().UID)
		require.Zero(t, f.proposer.cancels)
		require.Zero(t, f.deletes)
		require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.task), replacement))
		require.Equal(t, "same-name-replacement", string(replacement.UID))
	})
}

func TestPipelineCancelMissingUnresolvedTaskCannotComplete(t *testing.T) {
	f := newModelCleanupFixture(t, remediationpolicy.CopilotBackend)
	current := f.task.DeepCopy()
	current.Finalizers = nil
	require.NoError(t, f.kube.Update(t.Context(), current))
	require.NoError(t, f.kube.Delete(t.Context(), current))
	require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrUnknown)
	require.Empty(t, f.operation().UID)
	require.False(t, f.operation().Retired)
	require.Zero(t, f.proposer.cancels)
	require.Zero(t, f.proposer.retires)
}

func TestPipelineCancelRecoversDeletingOrphanWithoutCompletingFinalizer(t *testing.T) {
	f := newModelCleanupFixture(t, remediationpolicy.CopilotBackend)
	require.NoError(t, f.kube.Delete(t.Context(), f.task))
	require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrCleanupPending)
	f.assertPinned()
	require.Zero(t, f.deletes)
	require.Zero(t, f.statuses)
	require.False(t, f.operation().Retired)
	f.finishDeletion()
}

func TestPipelineCancelCorruptReceiptCannotFallBackToName(t *testing.T) {
	f := newModelCleanupFixture(t, remediationpolicy.CopilotBackend)
	raw, err := json.Marshal(modelagent.Result{TaskName: "another-task", TaskUID: string(f.task.UID)})
	require.NoError(t, err)
	_, err = f.session.Put(t.Context(), modelReceiptName(f.task.Name), "application/json", raw)
	require.NoError(t, err)
	require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrUnknown)
	require.Empty(t, f.operation().UID)
	require.Zero(t, f.taskReads)
	require.Zero(t, f.proposer.cancels)
	require.Zero(t, f.deletes)
}

func TestPipelineCancelTransientReadAndDeleteRemainRetryable(t *testing.T) {
	for _, failure := range []string{"read", "delete"} {
		t.Run(failure, func(t *testing.T) {
			f := newModelCleanupFixture(t, "")
			if failure == "read" {
				f.readErr = apierrors.NewServiceUnavailable("synthetic-api-response")
			} else {
				f.deleteErr = apierrors.NewTimeoutError("synthetic-api-response", 1)
			}
			err := f.pipeline.Cancel(t.Context(), f.session)
			require.ErrorIs(t, err, ErrRetryable)
			require.NotErrorIs(t, err, ErrCleanupPending)
			require.NotContains(t, err.Error(), "synthetic-api-response")
			if failure == "delete" {
				f.assertPinned()
			} else {
				require.Empty(t, f.operation().UID)
			}
			f.readErr, f.deleteErr = nil, nil
			require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrCleanupPending)
			f.assertPinned()
			f.readErr = apierrors.NewServiceUnavailable("synthetic-api-response")
			require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrRetryable)
			f.assertPinned()
			f.readErr = nil
			f.finishDeletion()
		})
	}
}

type cleanupStoreFault struct {
	store.RemediationRunStore
	putErr       error
	beforeUpdate func()
}

func (s *cleanupStoreFault) PutRemediationArtifact(ctx context.Context, namespace, id, owner string, epoch uint64, name, mediaType string, data []byte, now time.Time) (*store.RemediationArtifact, error) {
	if s.putErr != nil {
		return nil, s.putErr
	}
	return s.RemediationRunStore.PutRemediationArtifact(ctx, namespace, id, owner, epoch, name, mediaType, data, now)
}

func (s *cleanupStoreFault) UpdateRemediationRun(ctx context.Context, namespace, id, owner string, epoch, revision uint64, update store.RemediationUpdate, now time.Time) (*store.RemediationRun, error) {
	if s.beforeUpdate != nil {
		s.beforeUpdate()
	}
	return s.RemediationRunStore.UpdateRemediationRun(ctx, namespace, id, owner, epoch, revision, update, now)
}

func TestPipelineCancelRecoveryRequiresReceiptAndClaimCAS(t *testing.T) {
	for _, failure := range []string{"receipt", "revision", "claim"} {
		t.Run(failure, func(t *testing.T) {
			f := newModelCleanupFixture(t, "")
			fault := &cleanupStoreFault{RemediationRunStore: f.storage}
			f.session.store = fault
			if failure == "receipt" {
				fault.putErr = errors.New("synthetic-store-response")
			} else {
				fault.beforeUpdate = func() {
					current, err := f.storage.GetRemediationRun(t.Context(), f.session.run.Namespace, f.session.run.ID)
					require.NoError(t, err)
					if failure == "claim" {
						_, err = f.storage.ClaimNextRemediationRun(t.Context(), current.Namespace, "replacement-owner",
							current.ClaimUntil.Add(time.Second), time.Minute)
					} else {
						_, err = f.storage.UpdateRemediationRun(t.Context(), current.Namespace, current.ID, f.session.owner, f.session.epoch,
							current.Revision, store.RemediationUpdate{Phase: current.Phase, Reason: "newer-cleanup-revision"}, time.Now())
					}
					require.NoError(t, err)
				}
			}
			err := f.pipeline.Cancel(t.Context(), f.session)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "synthetic-store-response")
			require.Empty(t, f.operation().UID)
			require.Zero(t, f.proposer.cancels)
			require.Zero(t, f.proposer.retires)
			require.Zero(t, f.deletes)
			require.Zero(t, f.statuses)
			if failure == "claim" {
				return
			}
			f.session.store = f.storage
			require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrCleanupPending)
			f.assertPinned()
			f.finishDeletion()
		})
	}
}

func TestCleanupCheckpointCannotEnableRunningOrphanAdmission(t *testing.T) {
	f := newModelCleanupFixtureState(t, "", false)
	require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrUnknown)
	require.Empty(t, f.operation().UID)
	require.Zero(t, f.proposer.cancels)
	require.Zero(t, f.deletes)
}

type cleanupWithoutResolver struct {
	ProposalClient
	cancel func(string) error
}

func (c cleanupWithoutResolver) Cancel(_ context.Context, name, _ string) error {
	return c.cancel(name)
}

func TestPipelineCancelDoesNotGenerateWithoutResolver(t *testing.T) {
	f := newModelCleanupFixture(t, "")
	f.pipeline.Agents = func(string, string, func(context.Context, modelagent.Result) error) ProposalClient {
		return cleanupWithoutResolver{ProposalClient: f.proposer, cancel: func(string) error {
			t.Error("unresolved Task was cancelled")
			return nil
		}}
	}
	require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrUnknown)
	require.Empty(t, f.operation().UID)
	require.Zero(t, f.taskReads)
}

func TestPipelineCancelPendingOperationCannotHideFailure(t *testing.T) {
	f := newModelCleanupFixture(t, "")
	current, err := f.session.Current(t.Context())
	require.NoError(t, err)
	var state pipelineState
	require.NoError(t, json.Unmarshal(current.StateJSON, &state))
	state.Models = map[string]modelOperation{
		"pending": {Name: "pending", UID: "pending-uid", Intent: true},
		"failed":  {Name: "failed", UID: "failed-uid", Intent: true},
	}
	raw, err := json.Marshal(state)
	require.NoError(t, err)
	require.NoError(t, f.session.Checkpoint(t.Context(), current.Phase, current.Reason, raw, ""))
	f.pipeline.Agents = func(string, string, func(context.Context, modelagent.Result) error) ProposalClient {
		return cleanupWithoutResolver{ProposalClient: f.proposer, cancel: func(name string) error {
			if name == "pending" {
				return modelagent.ErrCancellationPending
			}
			return errors.New("synthetic permanent failure")
		}}
	}
	err = f.pipeline.Cancel(t.Context(), f.session)
	require.ErrorIs(t, err, ErrUnknown)
	require.NotErrorIs(t, err, ErrCleanupPending)
}
