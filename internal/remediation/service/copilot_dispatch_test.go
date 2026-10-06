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
	"github.com/orka-agents/orka/internal/store/sqlite"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type copilotDispatchModel struct {
	identity modelagent.PlanIdentity
	err      error
}

func (m *copilotDispatchModel) Snapshot(context.Context) (modelagent.PlanIdentity, error) {
	return m.identity, m.err
}
func (*copilotDispatchModel) Generate(context.Context, modelagent.Request) (modelagent.Result, error) {
	return modelagent.Result{}, modelagent.ErrUnsupported
}
func (*copilotDispatchModel) Cancel(context.Context, string, string) error { return nil }
func (*copilotDispatchModel) Retire(context.Context, string, string) error { return nil }

func copilotDispatchFixture(t *testing.T, expired bool) (*Service, *sqlite.Store, *copilotDispatchModel, *corev1alpha1.Task, *corev1alpha1.RuntimePool) {
	t.Helper()
	model := &copilotDispatchModel{identity: modelagent.PlanIdentity{
		Backend: remediationpolicy.CopilotBackend, Namespace: "testing", AgentName: "proposer",
		AgentUID: "agent-uid", AgentGeneration: 1, RuntimeNamespace: "private-runtime", RuntimeNamespaceUID: "runtime-ns-uid",
		RuntimeImage: "example.invalid/copilot@sha256:" + strings.Repeat("a", 64), RuntimeProfileDigest: Digest([]byte("profile")),
		ProxyEndpoint: "http://approved-proxy.proxy.svc:8080", ProxyNamespace: "proxy", ProxyNamespaceUID: "proxy-ns-uid",
		ProxyIdentityDigest: Digest([]byte("proxy")),
	}}
	var err error
	config := modelagent.CopilotConfig{
		Image: model.identity.RuntimeImage, RuntimeNamespace: model.identity.RuntimeNamespace,
		ProxyEndpoint: model.identity.ProxyEndpoint, ProxyNamespace: model.identity.ProxyNamespace,
		IdentityReferences: []modelagent.CopilotIdentityReference{
			{Kind: "ConfigMap", Namespace: "proxy", Name: "route"}, {Kind: "Secret", Namespace: "proxy", Name: "credential"},
		},
	}
	model.identity.CopilotConfigDigest, err = config.Digest()
	if err != nil {
		t.Fatal(err)
	}
	model.identity.Digest, err = remediationpolicy.MetadataDigest(model.identity)
	if err != nil {
		t.Fatal(err)
	}
	pipeline := &Pipeline{Agents: func(string, string, func(context.Context, modelagent.Result) error) ProposalClient { return model }}
	service, storage := testService(t, pipeline)
	policy := service.policies["approved"]
	policy.ProposalBackend, policy.Copilot = remediationpolicy.CopilotBackend, &config
	if err := validatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	service.policies[policy.Name] = policy
	status, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	lease := time.Minute
	if expired {
		now, lease = now.Add(-10*time.Second), time.Second
	}
	run, err := storage.ClaimNextRemediationRun(t.Context(), "testing", "worker", now, lease)
	if err != nil {
		t.Fatal(err)
	}
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testing", Name: status.ID + "-checks", UID: "proposal-uid", Generation: 1},
		Spec:       remediationpolicy.CopilotTaskSpec("synthetic bounded prompt", "proposer"),
	}
	task.Labels = map[string]string{labels.LabelCreatedBy: remediationpolicy.CreatedBy, remediationpolicy.RunLabel: labels.SelectorValue(status.ID)}
	task.Annotations = map[string]string{
		remediationpolicy.RunAnnotation: status.ID, remediationpolicy.IdentityAnnotation: model.identity.Digest,
		labels.AnnotationAgentReadOnly: "true",
	}
	task.Annotations[remediationpolicy.RequestDigestAnnotation], err = remediationpolicy.RequestDigest(
		task.Namespace, task.Name, status.ID, model.identity.Digest, task.Spec)
	if err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(pipelineState{
		Version: Version, ModelIdentity: &model.identity,
		Models: map[string]modelOperation{"checks": {
			Name: task.Name, UID: string(task.UID), Intent: true, Expected: model.identity,
			PromptDigest: Digest([]byte(task.Spec.Prompt)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = storage.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, run.ClaimOwner,
		run.ClaimEpoch, run.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning, StateJSON: state}, now)
	if err != nil {
		t.Fatal(err)
	}
	pool := &corev1alpha1.RuntimePool{ObjectMeta: metav1.ObjectMeta{Namespace: "testing", Name: "governed", UID: "pool-uid"}}
	pool.Spec.RuntimeNamespace = model.identity.RuntimeNamespace
	pool.Spec.Runtime.Image = model.identity.RuntimeImage
	pool.Spec.Runtime.Profile.Digest = model.identity.RuntimeProfileDigest
	pool.Spec.Runtime.Profile.ResourceClass = remediationpolicy.CopilotResourceClass
	pool.Spec.Capacity = &corev1alpha1.RuntimePoolCapacitySpec{MaxResidentSessions: 1, MaxRunningPrompts: 1}
	pool.Status.ActiveInstance = &corev1alpha1.RuntimePoolActiveInstanceStatus{
		PodNamespace: model.identity.RuntimeNamespace, PodName: "runtime", PodUID: "runtime-pod-uid",
	}
	task.Status.Execution = &corev1alpha1.TaskExecutionStatus{RuntimePoolUID: string(pool.UID)}
	task.Status.AgentExecutionBinding = &corev1alpha1.AgentExecutionBinding{RuntimeProfileDigest: model.identity.RuntimeProfileDigest}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: model.identity.RuntimeNamespace, Name: "runtime", UID: "runtime-pod-uid"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "runtime", Image: model.identity.RuntimeImage, Env: []corev1.EnvVar{
			{Name: "ORKA_ACP_PROVIDER_PROXY_BASE_URL", Value: model.identity.ProxyEndpoint},
		}}}}}
	service.config.DispatchReader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	return service, storage, model, task, pool
}

func TestCopilotAdmissionRetainsExpiredClaimForRecovery(t *testing.T) {
	service, storage, _, task, _ := copilotDispatchFixture(t, true)
	if err := service.CopilotQueueValidator(t.Context(), task); !apierrors.IsServiceUnavailable(err) {
		t.Fatal("expired live run claim permanently failed its queued Task", err)
	}
	if _, err := storage.ClaimNextRemediationRun(t.Context(), "testing", "restarted-worker", time.Now(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := service.CopilotQueueValidator(t.Context(), task); err != nil {
		t.Fatal("claim recovery did not restore admission", err)
	}
}

type unavailableCopilotStore struct{ store.RemediationRunStore }

func (unavailableCopilotStore) GetRemediationRun(context.Context, string, string) (*store.RemediationRun, error) {
	return nil, errors.New("synthetic private database diagnostic")
}

func TestCopilotAdmissionSeparatesDependencyOutageFromDenial(t *testing.T) {
	service, storage, model, task, _ := copilotDispatchFixture(t, false)
	service.config.Store = unavailableCopilotStore{storage}
	if err := service.CopilotQueueValidator(t.Context(), task); !apierrors.IsServiceUnavailable(err) || strings.Contains(err.Error(), "private database") {
		t.Fatal("store outage was terminal or leaked diagnostics", err)
	}
	service.config.Store = storage
	model.err = modelagent.ErrDependencyUnavailable
	if err := service.CopilotQueueValidator(t.Context(), task); !apierrors.IsServiceUnavailable(err) {
		t.Fatal("model identity read outage was terminal", err)
	}
	model.err = remediationpolicy.ErrIdentityChanged
	if err := service.CopilotQueueValidator(t.Context(), task); !errors.Is(err, ErrPolicy) {
		t.Fatal("identity drift became a retryable authority grant", err)
	}
	model.err = nil
	if err := service.CopilotQueueValidator(t.Context(), task); err != nil {
		t.Fatal(err)
	}
	delete(service.policies, "approved")
	if err := service.CopilotQueueValidator(t.Context(), task); !errors.Is(err, ErrPolicy) {
		t.Fatal("removed policy retained dispatch authority", err)
	}
}

func TestCopilotDispatchChecksActualRuntimeProxy(t *testing.T) {
	service, _, model, task, pool := copilotDispatchFixture(t, false)
	if err := service.CopilotDispatchValidator(t.Context(), task, pool); err != nil {
		t.Fatal(err)
	}
	kube := service.config.DispatchReader.(client.Client)
	pod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: model.identity.RuntimeNamespace, Name: "runtime"}
	if err := kube.Get(t.Context(), key, pod); err != nil {
		t.Fatal(err)
	}
	pod.Spec.Containers[0].Env[0].Value = "http://unapproved-proxy.proxy.svc:8080"
	if err := kube.Update(t.Context(), pod); err != nil {
		t.Fatal(err)
	}
	if err := service.CopilotDispatchValidator(t.Context(), task, pool); !errors.Is(err, ErrPolicy) {
		t.Fatal("nominal policy endpoint hid a different actual runtime endpoint", err)
	}
	pod.Spec.Containers[0].Env[0].Value = model.identity.ProxyEndpoint
	pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
		Name: "ORKA_ACP_PROVIDER_PROXY_BASE_URL", Value: "http://unapproved-proxy.proxy.svc:8080",
	})
	if err := kube.Update(t.Context(), pod); err != nil {
		t.Fatal(err)
	}
	if err := service.CopilotDispatchValidator(t.Context(), task, pool); !errors.Is(err, ErrPolicy) {
		t.Fatal("duplicate environment override bypassed the runtime endpoint pin", err)
	}
}
