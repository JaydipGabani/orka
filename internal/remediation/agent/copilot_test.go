package agent

import (
	"context"
	"strings"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/controller"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store/sqlite"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func copilotFixture(t *testing.T) (CopilotClient, client.WithWatch, *corev1alpha1.Agent, *int) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	agent := &corev1alpha1.Agent{ObjectMeta: metav1.ObjectMeta{Namespace: "private", Name: "copilot", UID: "copilot-agent", Generation: 1},
		Spec: corev1alpha1.AgentSpec{
			Model:   &corev1alpha1.ModelConfig{Name: "approved-model"},
			Runtime: &corev1alpha1.AgentCLIRuntime{Type: corev1alpha1.AgentRuntimeCopilot, ContractVersion: new(corev1alpha1.AgentRuntimeContractHarnessV2)},
		}}
	route := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: "route", UID: "route-uid", ResourceVersion: "1"}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "proxy", Name: "credential", UID: "secret-uid", ResourceVersion: "1"}}
	runtimeNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "private-runtimes", UID: "runtime-namespace-uid"}}
	proxyNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "proxy", UID: "proxy-namespace-uid"}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&corev1alpha1.Task{}).
		WithObjects(agent, route, secret, runtimeNamespace, proxyNamespace).Build()
	db, err := sqlite.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	creates := new(int)
	adapter := CopilotClient{Namespace: "private", AgentName: "copilot", Reader: kube, Results: sqlite.NewStore(db, ":memory:"),
		Config: CopilotConfig{Image: "example.invalid/copilot@sha256:" + strings.Repeat("a", 64), RuntimeNamespace: "private-runtimes",
			ProxyEndpoint: "http://approved-proxy.proxy.svc:8080", ProxyNamespace: "proxy", IdentityReferences: []CopilotIdentityReference{
				{Kind: "ConfigMap", Namespace: "proxy", Name: "route"}, {Kind: "Secret", Namespace: "proxy", Name: "credential"},
			}}}
	adapter.Client = interceptor.NewClient(kube, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.CreateOption) error {
		*creates++
		o.SetUID("copilot-task-uid")
		o.SetGeneration(1)
		return c.Create(ctx, o, opts...)
	}})
	return adapter, kube, agent, creates
}

func TestCopilotProposalUsesActualRestrictedACPProfile(t *testing.T) {
	adapter, kube, agent, creates := copilotFixture(t)
	identity, err := adapter.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if identity.Backend != remediationpolicy.CopilotBackend || identity.RuntimeProfileDigest == "" {
		t.Fatal("missing governed profile identity")
	}
	request := Request{TaskName: "rm-" + strings.Repeat("b", 32) + "-checks", RunID: "rm-" + strings.Repeat("b", 32),
		Prompt: "Return a synthetic bounded JSON proposal", ExpectedIdentity: identity.Digest}
	adapter.OnAccepted = func(ctx context.Context, r Result) error {
		if r.TaskUID == "" {
			t.Fatal("acceptance lacks Task UID")
		}
		task := &corev1alpha1.Task{}
		if err := kube.Get(ctx, client.ObjectKey{Namespace: adapter.Namespace, Name: r.TaskName}, task); err != nil {
			return err
		}
		if task.Spec.Workspace != nil || task.Spec.SessionRef != nil || task.Spec.SecretRef != nil || len(task.Spec.Env) != 0 ||
			task.Spec.AgentRuntime == nil || task.Spec.AgentRuntime.AllowedTools == nil || len(task.Spec.AgentRuntime.AllowedTools) != 0 ||
			task.Spec.AgentRuntime.AllowBash == nil || *task.Spec.AgentRuntime.AllowBash {
			t.Fatal("Copilot proposal gained workspace, credential or tool authority")
		}
		plan, err := controller.PlanRemediationCopilot(ctx, kube, task, agent, adapter.Config.Image)
		if err != nil {
			return err
		}
		if string(plan.Digest) != identity.RuntimeProfileDigest || plan.Profile.ResourceClass != remediationpolicy.CopilotResourceClass {
			t.Fatal("snapshot and actual dispatch profiles differ")
		}
		task.Status.Phase = corev1alpha1.TaskPhaseSucceeded
		task.Status.Execution = &corev1alpha1.TaskExecutionStatus{State: corev1alpha1.TaskExecutionStateSucceeded}
		if err := kube.Status().Update(ctx, task); err != nil {
			return err
		}
		return adapter.Results.SaveResult(ctx, task.Namespace, task.Name, []byte(`{"summary":"synthetic"}`))
	}
	result, err := adapter.Generate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Output != `{"summary":"synthetic"}` || *creates != 1 {
		t.Fatal("unexpected model result or duplicate submission")
	}
	request.ExpectedTaskUID, result.Output = result.TaskUID, ""
	request.RequireExisting = true
	adapter.OnAccepted = nil
	if _, err := adapter.Generate(t.Context(), request); err != nil || *creates != 1 {
		t.Fatal("resume replaced an accepted Task", err)
	}
	if err := adapter.Retire(t.Context(), request.TaskName, request.ExpectedTaskUID); err != ErrCancellationPending {
		t.Fatal(err)
	}
	if err := adapter.Retire(t.Context(), request.TaskName, request.ExpectedTaskUID); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Generate(t.Context(), request); err == nil || *creates != 1 {
		t.Fatal("deleted accepted Task was replayed")
	}
}

func TestCopilotRoutingDriftIsDetectedBeforeCreation(t *testing.T) {
	adapter, kube, _, creates := copilotFixture(t)
	identity, err := adapter.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	route := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: "proxy", Name: "route"}
	if err := kube.Get(t.Context(), key, route); err != nil {
		t.Fatal(err)
	}
	route.Data = map[string]string{"route": "changed"}
	if err := kube.Update(t.Context(), route); err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Generate(t.Context(), Request{TaskName: "request", RunID: "run", Prompt: "synthetic", ExpectedIdentity: identity.Digest})
	if err == nil || *creates != 0 {
		t.Fatal("changed model routing was used")
	}
}
