package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type noEffectResults struct {
	store.ResultStore
	reads int
}

func (s *noEffectResults) GetResult(ctx context.Context, namespace, name string) ([]byte, error) {
	s.reads++
	return s.ResultStore.GetResult(ctx, namespace, name)
}

type noEffectFixture struct {
	t           *testing.T
	pipeline    *Pipeline
	session     *Session
	storage     store.RemediationRunStore
	state       *pipelineState
	policy      Policy
	adapter     modelagent.CopilotClient
	kube        client.WithWatch
	request     modelagent.Request
	key         string
	results     *noEffectResults
	creates     int
	acceptances int
	create      func() error
}

func newNoEffectFixture(t *testing.T) *noEffectFixture {
	t.Helper()
	service, storage := testService(t, processorFunc{})
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	registered := &corev1alpha1.Agent{ObjectMeta: metav1.ObjectMeta{
		Namespace: "testing", Name: "proposer", UID: "synthetic-agent-uid", Generation: 1,
	}, Spec: corev1alpha1.AgentSpec{
		Model: &corev1alpha1.ModelConfig{Name: "synthetic-model"},
		Runtime: &corev1alpha1.AgentCLIRuntime{
			Type: corev1alpha1.AgentRuntimeCopilot, ContractVersion: new(corev1alpha1.AgentRuntimeContractHarnessV2),
		},
	}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(registered,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "synthetic-runtime", UID: "synthetic-runtime-uid"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "synthetic-proxy", UID: "synthetic-proxy-uid"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "synthetic-proxy", Name: "route", UID: "synthetic-route-uid", ResourceVersion: "1"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "synthetic-proxy", Name: "reference", UID: "synthetic-reference-uid", ResourceVersion: "1"}},
	).Build()
	f := &noEffectFixture{t: t, kube: kube, storage: storage, results: &noEffectResults{ResultStore: storage}}
	f.adapter = modelagent.CopilotClient{
		Namespace: "testing", AgentName: "proposer", Reader: kube, Results: f.results, PollInterval: time.Millisecond,
		Config: modelagent.CopilotConfig{
			Image: "example.invalid/copilot@sha256:" + strings.Repeat("a", 64), RuntimeNamespace: "synthetic-runtime",
			ProxyEndpoint: "http://proxy.fixture.invalid:8080", ProxyNamespace: "synthetic-proxy",
			IdentityReferences: []modelagent.CopilotIdentityReference{
				{Kind: "ConfigMap", Namespace: "synthetic-proxy", Name: "route"},
				{Kind: "Secret", Namespace: "synthetic-proxy", Name: "reference"},
			},
		},
	}
	f.adapter.Client = interceptor.NewClient(kube, interceptor.Funcs{
		Create: func(ctx context.Context, delegate client.WithWatch, object client.Object, options ...client.CreateOption) error {
			f.creates++
			if f.create != nil {
				return f.create()
			}
			object.SetUID("synthetic-task-uid")
			object.SetGeneration(1)
			return delegate.Create(ctx, object, options...)
		},
	})
	identity, err := f.adapter.Snapshot(t.Context())
	require.NoError(t, err)
	f.policy = service.policies["approved"]
	f.policy.ProposalBackend, f.policy.Copilot = remediationpolicy.CopilotBackend, &f.adapter.Config
	service.policies[f.policy.Name] = f.policy
	submitted, _, err := service.Submit(t.Context(), "testing", "synthetic-caller", requestFixture())
	require.NoError(t, err)
	run, err := storage.ClaimNextRemediationRun(t.Context(), submitted.Namespace, "no-effect-worker", time.Now(), time.Minute)
	require.NoError(t, err)
	require.NotNil(t, run)
	f.session = &Session{store: storage, run: run, owner: run.ClaimOwner, epoch: run.ClaimEpoch}
	f.state = &pipelineState{Version: Version, Stage: "model-intent", Models: map[string]modelOperation{}, ModelIdentity: &identity}
	f.pipeline = &Pipeline{Agents: func(namespace, name string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
		require.Equal(t, f.adapter.Namespace, namespace)
		require.Equal(t, f.adapter.AgentName, name)
		adapter := f.adapter
		if accepted != nil {
			adapter.OnAccepted = func(ctx context.Context, result modelagent.Result) error {
				f.acceptances++
				return accepted(ctx, result)
			}
		}
		return adapter
	}}
	require.NoError(t, f.pipeline.save(t.Context(), f.session, f.state, f.state.Stage))
	f.request = modelagent.Request{TaskName: run.ID + "-checks", Prompt: "Return a synthetic bounded proposal."}
	f.key = Digest([]byte(f.request.TaskName + "\x00" + f.request.Prompt))
	return f
}

func (f *noEffectFixture) current() (*store.RemediationRun, pipelineState) {
	f.t.Helper()
	current, err := f.storage.GetRemediationRun(f.t.Context(), f.session.run.Namespace, f.session.run.ID)
	require.NoError(f.t, err)
	var state pipelineState
	require.NoError(f.t, json.Unmarshal(current.StateJSON, &state))
	return current, state
}

func (f *noEffectFixture) seedIntent() modelOperation {
	f.t.Helper()
	operation := modelOperation{Name: f.request.TaskName, PromptDigest: Digest([]byte(f.request.Prompt)),
		Expected: *f.state.ModelIdentity, Intent: true}
	f.state.Models[f.key], f.state.ModelCalls = operation, 1
	require.NoError(f.t, f.pipeline.save(f.t.Context(), f.session, f.state, f.state.Stage))
	return operation
}

func TestPipelineCancelledPreCreateReadClearsOnlyProvenNoEffect(t *testing.T) {
	for _, mode := range []string{"cancel", "disabled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newNoEffectFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
			defer cancel()
			taskReads := 0
			var budget *store.RemediationCleanup
			f.adapter.Reader = interceptor.NewClient(f.kube, interceptor.Funcs{
				Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
					if _, task := object.(*corev1alpha1.Task); !task {
						return delegate.Get(ctx, key, object, options...)
					}
					taskReads++
					current, saved := f.current()
					require.True(t, saved.Models[f.key].Intent)
					require.Empty(t, saved.Models[f.key].UID)
					if mode == "cancel" {
						var err error
						current, err = f.storage.CancelRemediationRun(t.Context(), current.Namespace, current.ID, time.Now())
						require.NoError(t, err)
					}
					if mode != "deadline" {
						target := store.RemediationPhaseCancelled
						if mode == "disabled" {
							target = store.RemediationPhaseFailed
						}
						var err error
						current, err = f.storage.UpdateRemediationCleanup(t.Context(), current.Namespace, current.ID,
							f.session.owner, f.session.epoch, current.Revision,
							store.RemediationCleanup{Phase: target, Attempts: 2, StartedAt: time.Now().UTC().Add(-time.Second)}, false, time.Now())
						require.NoError(t, err)
						budget = current.Cleanup
					}
					var fields map[string]json.RawMessage
					require.NoError(t, json.Unmarshal(current.StateJSON, &fields))
					fields["preservedDuringCancellation"] = json.RawMessage(`{"latest":true}`)
					raw, err := json.Marshal(fields)
					require.NoError(t, err)
					require.NoError(t, f.session.Checkpoint(t.Context(), current.Phase, current.Reason, raw, ""))
					if mode != "deadline" {
						cancel()
					}
					<-ctx.Done()
					return ctx.Err()
				},
			})
			_, err := f.pipeline.generate(ctx, f.session, f.session.run, f.policy, f.state, f.request)
			if mode == "deadline" {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			} else {
				require.ErrorIs(t, err, context.Canceled)
			}
			current, state := f.current()
			require.False(t, state.Models[f.key].Intent)
			require.False(t, f.state.Models[f.key].Intent)
			require.Equal(t, 1, state.ModelCalls)
			require.Empty(t, state.Models[f.key].UID)
			require.Nil(t, state.Models[f.key].Output)
			require.Equal(t, mode == "cancel", current.CancelRequested)
			if mode == "deadline" {
				require.Equal(t, store.RemediationPhaseRunning, current.Phase)
			} else {
				require.Equal(t, store.RemediationPhaseCancelling, current.Phase)
				require.Equal(t, budget, current.Cleanup)
			}
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(current.StateJSON, &fields))
			require.JSONEq(t, `{"latest":true}`, string(fields["preservedDuringCancellation"]))
			require.NoError(t, f.pipeline.Cancel(t.Context(), f.session))
			require.Equal(t, 1, taskReads, "cleanup must use the positive no-effect checkpoint, not infer absence")
			require.Zero(t, f.creates)
			require.Zero(t, f.acceptances)
			require.Zero(t, f.results.reads)
			tasks := &corev1alpha1.TaskList{}
			require.NoError(t, f.kube.List(t.Context(), tasks))
			require.Empty(t, tasks.Items)
		})
	}
}

func TestPipelineFreshPreCreateDependencyRequeuesWithoutNewLogicalCall(t *testing.T) {
	for _, stage := range []string{"snapshot", "task"} {
		t.Run(stage, func(t *testing.T) {
			f := newNoEffectFixture(t)
			agentReads := 0
			f.adapter.PollInterval = time.Hour
			f.adapter.Reader = interceptor.NewClient(f.kube, interceptor.Funcs{
				Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
					if _, agent := object.(*corev1alpha1.Agent); agent {
						agentReads++
						if stage == "snapshot" && agentReads > 1 {
							return apierrors.NewServiceUnavailable("synthetic-api-response")
						}
					}
					if _, task := object.(*corev1alpha1.Task); task && stage == "task" {
						return apierrors.NewServiceUnavailable("synthetic-api-response")
					}
					return delegate.Get(ctx, key, object, options...)
				},
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			for range 2 {
				_, err := f.pipeline.generate(ctx, f.session, f.session.run, f.policy, f.state, f.request)
				require.ErrorIs(t, err, ErrRetryable)
				require.NotContains(t, err.Error(), "synthetic-api-response")
				require.NoError(t, ctx.Err())
				_, state := f.current()
				require.False(t, state.Models[f.key].Intent)
				require.Equal(t, 1, state.ModelCalls)
				require.Equal(t, f.request.TaskName, state.Models[f.key].Name)
			}
			require.NoError(t, f.pipeline.Cancel(t.Context(), f.session))
			require.Zero(t, f.creates)
			require.Zero(t, f.acceptances)
			require.Zero(t, f.results.reads)
		})
	}
}

func TestPipelineUncertainCreateRetainsIntentAndNeverRecreates(t *testing.T) {
	f := newNoEffectFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.create = func() error {
		cancel()
		return apierrors.NewTimeoutError("synthetic uncertain create", 1)
	}
	_, err := f.pipeline.generate(ctx, f.session, f.session.run, f.policy, f.state, f.request)
	require.ErrorIs(t, err, context.Canceled)
	_, state := f.current()
	require.True(t, state.Models[f.key].Intent)
	require.Empty(t, state.Models[f.key].UID)
	require.Equal(t, f.request.TaskName, state.Models[f.key].Name)
	require.Equal(t, 1, f.creates)
	require.ErrorIs(t, f.pipeline.Cancel(t.Context(), f.session), ErrUnknown, "absence after an uncertain create is not no-effect proof")
	_, err = f.pipeline.generate(t.Context(), f.session, f.session.run, f.policy, f.state, f.request)
	require.ErrorIs(t, err, ErrUnknown)
	require.Equal(t, 1, f.creates)
	require.True(t, f.state.Models[f.key].Intent)
	require.Equal(t, 1, f.state.ModelCalls)
	require.Zero(t, f.results.reads)
}

func TestClearUnsubmittedModelIntentPreservesAcceptedEvidence(t *testing.T) {
	for _, evidence := range []string{"uid", "output", "retired", "receipt"} {
		t.Run(evidence, func(t *testing.T) {
			f := newNoEffectFixture(t)
			expected := f.seedIntent()
			current, state := f.current()
			accepted := state.Models[f.key]
			switch evidence {
			case "uid":
				accepted.UID = "accepted-uid"
			case "output":
				ref, err := f.session.Put(t.Context(), "accepted-output.json", "application/json", []byte(`{"summary":"synthetic"}`))
				require.NoError(t, err)
				accepted.Output = ref
			case "retired":
				accepted.Retired = true
			case "receipt":
				raw, err := json.Marshal(modelagent.Result{TaskName: expected.Name, TaskUID: "accepted-uid"})
				require.NoError(t, err)
				_, err = f.session.Put(t.Context(), modelReceiptName(expected.Name), "application/json", raw)
				require.NoError(t, err)
			}
			state.Models[f.key] = accepted
			raw, err := json.Marshal(state)
			require.NoError(t, err)
			require.NoError(t, f.session.Checkpoint(t.Context(), current.Phase, current.Reason, raw, ""))
			before, _ := f.current()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			require.ErrorIs(t, clearUnsubmittedModelIntent(ctx, f.session, f.state, f.key, expected), ErrUnknown)
			after, _ := f.current()
			require.JSONEq(t, string(before.StateJSON), string(after.StateJSON))
			require.Equal(t, before.Revision, after.Revision)
			require.True(t, f.state.Models[f.key].Intent)
			if evidence == "receipt" {
				_, _, err := f.session.Read(t.Context(), modelReceiptName(expected.Name))
				require.NoError(t, err)
			}
		})
	}
}

type noEffectCheckpointStore struct {
	store.RemediationRunStore
	beforeUpdate func(context.Context)
	updates      int
	updateErr    error
	readErr      error
}

func (s *noEffectCheckpointStore) UpdateRemediationRun(ctx context.Context, namespace, id, owner string, epoch, revision uint64, update store.RemediationUpdate, now time.Time) (*store.RemediationRun, error) {
	s.updates++
	if s.beforeUpdate != nil {
		s.beforeUpdate(ctx)
	}
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	return s.RemediationRunStore.UpdateRemediationRun(ctx, namespace, id, owner, epoch, revision, update, now)
}

func (s *noEffectCheckpointStore) GetRemediationArtifact(ctx context.Context, namespace, id, name string) (*store.RemediationArtifact, []byte, error) {
	if s.readErr != nil {
		return nil, nil, s.readErr
	}
	return s.RemediationRunStore.GetRemediationArtifact(ctx, namespace, id, name)
}

func TestClearUnsubmittedModelIntentFencesConcurrentChanges(t *testing.T) {
	for _, change := range []string{"cancel", "accepted-uid", "claim"} {
		t.Run(change, func(t *testing.T) {
			f := newNoEffectFixture(t)
			expected := f.seedIntent()
			injected := &noEffectCheckpointStore{RemediationRunStore: f.storage}
			injected.beforeUpdate = func(ctx context.Context) {
				require.NoError(t, ctx.Err(), "checkpoint must survive caller cancellation")
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.Positive(t, time.Until(deadline))
				require.LessOrEqual(t, time.Until(deadline), 2*time.Second)
				if injected.updates != 1 {
					return
				}
				current, state := f.current()
				switch change {
				case "cancel":
					_, err := f.storage.CancelRemediationRun(t.Context(), current.Namespace, current.ID, time.Now())
					require.NoError(t, err)
				case "accepted-uid":
					accepted := state.Models[f.key]
					accepted.UID = "concurrent-accepted-uid"
					state.Models[f.key] = accepted
					raw, err := json.Marshal(state)
					require.NoError(t, err)
					_, err = f.storage.UpdateRemediationRun(t.Context(), current.Namespace, current.ID, f.session.owner, f.session.epoch,
						current.Revision, store.RemediationUpdate{Phase: current.Phase, StateJSON: raw}, time.Now())
					require.NoError(t, err)
				case "claim":
					_, err := f.storage.ClaimNextRemediationRun(t.Context(), current.Namespace, "replacement-owner",
						current.ClaimUntil.Add(time.Second), time.Minute)
					require.NoError(t, err)
				}
			}
			f.session.store = injected
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			err := clearUnsubmittedModelIntent(ctx, f.session, f.state, f.key, expected)
			current, state := f.current()
			switch change {
			case "cancel":
				require.NoError(t, err)
				require.Equal(t, 2, injected.updates)
				require.False(t, state.Models[f.key].Intent)
				require.True(t, current.CancelRequested)
				require.Equal(t, store.RemediationPhaseCancelling, current.Phase)
			case "accepted-uid":
				require.ErrorIs(t, err, ErrUnknown)
				require.Equal(t, "concurrent-accepted-uid", state.Models[f.key].UID)
				require.True(t, state.Models[f.key].Intent)
			case "claim":
				require.ErrorIs(t, err, ErrClaimLost)
				require.True(t, state.Models[f.key].Intent)
			}
			require.Zero(t, f.creates)
		})
	}
}

func TestClearUnsubmittedModelIntentOutagesAreBoundedAndPreserveIntent(t *testing.T) {
	for _, failure := range []string{"conflict", "checkpoint", "receipt-read"} {
		t.Run(failure, func(t *testing.T) {
			f := newNoEffectFixture(t)
			expected := f.seedIntent()
			injected := &noEffectCheckpointStore{RemediationRunStore: f.storage}
			updates := 0
			switch failure {
			case "conflict":
				injected.updateErr, updates = store.ErrConflict, 3
			case "checkpoint":
				injected.updateErr, updates = errors.New("synthetic-store-response"), 1
			case "receipt-read":
				injected.readErr = errors.New("synthetic-store-response")
			}
			f.session.store = injected
			err := clearUnsubmittedModelIntent(t.Context(), f.session, f.state, f.key, expected)
			require.ErrorIs(t, err, ErrRetryable)
			require.NotErrorIs(t, err, ErrCleanupPending)
			require.NotContains(t, err.Error(), "synthetic-store-response")
			require.Equal(t, updates, injected.updates)
			_, state := f.current()
			require.True(t, state.Models[f.key].Intent)
			require.True(t, f.state.Models[f.key].Intent)
			require.Zero(t, f.creates)
		})
	}
}

func TestClearUnsubmittedModelIntentPreservesOpaqueState(t *testing.T) {
	f := newNoEffectFixture(t)
	expected := f.seedIntent()
	current, _ := f.current()
	var fields, models, operation map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(current.StateJSON, &fields))
	require.NoError(t, json.Unmarshal(fields["models"], &models))
	require.NoError(t, json.Unmarshal(models[f.key], &operation))
	operation["opaqueAuditTag"] = json.RawMessage(`{"retained":true}`)
	original := json.RawMessage(`{"opaqueResourceFence":{"epoch":18446744073709551615}}`)
	fields["original"] = original
	raw, err := json.Marshal(operation)
	require.NoError(t, err)
	models[f.key] = raw
	fields["models"], err = json.Marshal(models)
	require.NoError(t, err)
	raw, err = json.Marshal(fields)
	require.NoError(t, err)
	require.NoError(t, f.session.Checkpoint(t.Context(), current.Phase, current.Reason, raw, ""))
	require.NoError(t, clearUnsubmittedModelIntent(t.Context(), f.session, f.state, f.key, expected))
	current, _ = f.current()
	require.NoError(t, json.Unmarshal(current.StateJSON, &fields))
	require.Equal(t, string(original), string(fields["original"]), "opaque epochs must not round-trip through float64")
	require.NoError(t, json.Unmarshal(fields["models"], &models))
	require.NoError(t, json.Unmarshal(models[f.key], &operation))
	require.JSONEq(t, `{"retained":true}`, string(operation["opaqueAuditTag"]))
	require.Equal(t, "false", string(operation["intent"]))
}

type noEffectResultClient struct {
	ProposalClient
	result   modelagent.Result
	accepted func(context.Context, modelagent.Result) error
}

func (c noEffectResultClient) Generate(ctx context.Context, request modelagent.Request) (modelagent.Result, error) {
	if c.accepted != nil {
		if err := c.accepted(ctx, modelagent.Result{TaskName: request.TaskName, TaskUID: "accepted-uid"}); err != nil {
			return modelagent.Result{}, err
		}
	}
	return c.result, errors.Join(modelagent.ErrNotSubmitted, modelagent.ErrDependencyUnavailable)
}

func TestPipelineNotSubmittedCannotDiscardReturnedAcceptance(t *testing.T) {
	for _, test := range []struct {
		name     string
		result   modelagent.Result
		callback bool
	}{
		{name: "uid", result: modelagent.Result{TaskUID: "accepted-uid"}},
		{name: "output", result: modelagent.Result{Output: `{"summary":"synthetic accepted result"}`}},
		{name: "callback", callback: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newNoEffectFixture(t)
			f.pipeline.Agents = func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
				if !test.callback {
					accepted = nil
				}
				return noEffectResultClient{ProposalClient: f.adapter, result: test.result, accepted: accepted}
			}
			_, err := f.pipeline.generate(t.Context(), f.session, f.session.run, f.policy, f.state, f.request)
			require.ErrorIs(t, err, ErrRetryable)
			_, state := f.current()
			require.True(t, state.Models[f.key].Intent)
			require.False(t, state.Models[f.key].Retired)
			require.Equal(t, 1, state.ModelCalls)
			require.Zero(t, f.creates)
			if test.callback {
				require.Equal(t, "accepted-uid", state.Models[f.key].UID)
				_, _, err := f.session.Read(t.Context(), modelReceiptName(f.request.TaskName))
				require.NoError(t, err)
			}
		})
	}
}
