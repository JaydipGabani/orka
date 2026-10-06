package agent

import (
	"errors"
	"strings"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestCopilotCleanupResumesAfterRetirement(t *testing.T) {
	for _, state := range []corev1alpha1.TaskExecutionState{
		corev1alpha1.TaskExecutionStateFailed,
		corev1alpha1.TaskExecutionStateCancelled,
		corev1alpha1.TaskExecutionStateOutcomeUnknown,
	} {
		t.Run(string(state), func(t *testing.T) {
			adapter, kube, _, _ := copilotFixture(t)
			task, err := adapter.task(Request{
				TaskName: "rm-" + strings.Repeat("b", 32) + "-checks",
				RunID:    "rm-" + strings.Repeat("b", 32), Prompt: "synthetic",
				ExpectedIdentity: "sha256:" + strings.Repeat("a", 64),
			})
			if err != nil {
				t.Fatal(err)
			}
			task.UID, task.Generation = "exact-task", 1
			task.Finalizers = []string{"fixture.orka.ai/cleanup"}
			task.Status.Phase = corev1alpha1.TaskPhaseFailed
			task.Status.Execution = &corev1alpha1.TaskExecutionStatus{State: state}
			if err := kube.Create(t.Context(), task); err != nil {
				t.Fatal(err)
			}
			// Policy removal must not change the cleanup backend.
			dispatch := ControllerClient{Native: KubernetesClient{
				Client: kube, Reader: kube, Results: adapter.Results,
				Namespace: adapter.Namespace, AgentName: adapter.AgentName,
			}}
			if err := dispatch.Cancel(t.Context(), task.Name, string(task.UID)); err != nil {
				t.Fatal("terminal/unknown execution could not enter retirement", err)
			}
			if err := dispatch.Retire(t.Context(), task.Name, string(task.UID)); !errors.Is(err, ErrCancellationPending) {
				t.Fatal("retirement claimed completion before finalization", err)
			}
			if err := dispatch.Cancel(t.Context(), task.Name, string(task.UID)); !errors.Is(err, ErrCancellationPending) {
				t.Fatal("deleting Task was treated as a changed identity", err)
			}
			deleting := &corev1alpha1.Task{}
			if err := kube.Get(t.Context(), client.ObjectKeyFromObject(task), deleting); err != nil {
				t.Fatal(err)
			}
			if deleting.DeletionTimestamp == nil {
				t.Fatal("retirement did not request finalizer-gated deletion")
			}
			deleting.Finalizers = nil
			if err := kube.Update(t.Context(), deleting); err != nil {
				t.Fatal(err)
			}
			if err := kube.Get(t.Context(), client.ObjectKeyFromObject(task), &corev1alpha1.Task{}); !apierrors.IsNotFound(err) {
				t.Fatal("synthetic finalizer did not release the exact Task", err)
			}
			if err := dispatch.Cancel(t.Context(), task.Name, string(task.UID)); err != nil {
				t.Fatal("finished retirement blocked a later cleanup pass", err)
			}
			if err := dispatch.Retire(t.Context(), task.Name, string(task.UID)); err != nil {
				t.Fatal(err)
			}
			if err := adapter.Cancel(t.Context(), task.Name, string(task.UID)); err != nil {
				t.Fatal("direct Copilot cleanup did not converge", err)
			}
			if err := dispatch.Cancel(t.Context(), task.Name, ""); err == nil {
				t.Fatal("cleanup accepted a missing durable UID")
			}
		})
	}
}
