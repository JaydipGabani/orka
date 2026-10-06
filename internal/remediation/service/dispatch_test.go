package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDispatchRefusesChangedProviderBeforeRendering(t *testing.T) {
	service, storage := testService(t, processorFunc{})
	run, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := storage.ClaimNextRemediationRun(t.Context(), "testing", "worker", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	agent := &corev1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testing", Name: "proposer", UID: "agent-uid", Generation: 1},
		Spec:       corev1alpha1.AgentSpec{ProviderRef: &corev1alpha1.ProviderReference{Name: "approved"}},
	}
	provider := &corev1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testing", Name: "approved", UID: "provider-uid", Generation: 1},
		Spec:       corev1alpha1.ProviderSpec{SecretRef: corev1alpha1.ProviderSecretRef{Name: "credential", Key: "token"}},
		Status:     corev1alpha1.ProviderStatus{Ready: true},
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "testing", Name: "credential", UID: "credential-uid", ResourceVersion: "1"}}
	service.config.DispatchReader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	identity, err := remediationpolicy.MetadataIdentity(t.Context(), service.config.DispatchReader, agent, provider)
	if err != nil {
		t.Fatal(err)
	}
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testing", Name: run.ID + "-checks", UID: "task-uid", Generation: 1},
		Spec:       remediationpolicy.TaskSpec("bounded private synthetic prompt", "proposer"),
	}
	task.Labels = map[string]string{
		labels.LabelCreatedBy: remediationpolicy.CreatedBy, remediationpolicy.RunLabel: labels.SelectorValue(run.ID),
	}
	requestDigest, err := remediationpolicy.RequestDigest(task.Namespace, task.Name, run.ID, identity.Digest, task.Spec)
	if err != nil {
		t.Fatal(err)
	}
	task.Annotations = map[string]string{
		remediationpolicy.RunAnnotation: run.ID, remediationpolicy.IdentityAnnotation: identity.Digest,
		remediationpolicy.RequestDigestAnnotation: requestDigest,
	}
	state := pipelineState{
		Version: Version, ModelIdentity: &identity,
		Models: map[string]modelOperation{"operation": {
			Name: task.Name, Expected: identity, Intent: true, UID: string(task.UID), PromptDigest: Digest([]byte(task.Spec.Prompt)),
		}},
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	_, err = storage.UpdateRemediationRun(t.Context(), "testing", run.ID, "worker", claimed.ClaimEpoch, claimed.Revision,
		store.RemediationUpdate{Phase: store.RemediationPhaseRunning, StateJSON: raw}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.DispatchValidator(t.Context(), task, agent, provider); err != nil {
		t.Fatal("unchanged approved Task was rejected", err)
	}
	provider.Generation++
	provider.Spec.BaseURL = "https://different.example.invalid"
	if err := service.DispatchValidator(t.Context(), task, agent, provider); err == nil {
		t.Fatal("changed endpoint reached Job rendering")
	}
	provider.Generation--
	task.Spec.Prompt += " replaced"
	if err := service.DispatchValidator(t.Context(), task, agent, provider); err == nil {
		t.Fatal("changed prompt was accepted")
	}
}

func TestProposalMetadataRemovalCannotBypassGuard(t *testing.T) {
	task := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Name: "rm-" + strings.Repeat("a", 32) + "-checks"}}
	if !remediationpolicy.IsNativeProposal(task) {
		t.Fatal("reserved proposal name bypassed dispatch after metadata removal")
	}
	task.Name = "ordinary-ai-task"
	if remediationpolicy.IsNativeProposal(task) {
		t.Fatal("ordinary Task behavior was tightened")
	}
}
