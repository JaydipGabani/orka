package remediationpolicy

import (
	"strings"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCopilotPolicyRejectsEveryExtraAuthority(t *testing.T) {
	task := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Name: "rm-" + strings.Repeat("a", 32) + "-checks", Namespace: "private", UID: "uid", Generation: 1},
		Spec: CopilotTaskSpec("synthetic bounded prompt", "copilot")}
	run := "rm-" + strings.Repeat("a", 32)
	identity := "sha256:" + strings.Repeat("b", 64)
	task.Labels = map[string]string{labels.LabelCreatedBy: CreatedBy, RunLabel: labels.SelectorValue(run)}
	task.Annotations = map[string]string{RunAnnotation: run, IdentityAnnotation: identity, labels.AnnotationAgentReadOnly: "true"}
	digest, err := RequestDigest(task.Namespace, task.Name, run, identity, task.Spec)
	if err != nil {
		t.Fatal(err)
	}
	task.Annotations[RequestDigestAnnotation] = digest
	if err := ValidateCopilotTask(task); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*corev1alpha1.Task){
		"implicit tools":  func(t *corev1alpha1.Task) { t.Spec.AgentRuntime.AllowedTools = nil },
		"shell":           func(t *corev1alpha1.Task) { t.Spec.AgentRuntime.AllowBash = new(true) },
		"read tool":       func(t *corev1alpha1.Task) { t.Spec.AgentRuntime.AllowedTools = []string{"Read"} },
		"session history": func(t *corev1alpha1.Task) { t.Spec.SessionRef = &corev1alpha1.SessionReference{Name: "previous"} },
		"repository": func(t *corev1alpha1.Task) {
			t.Spec.Workspace = &corev1alpha1.WorkspaceConfig{GitRepo: "https://github.com/example/project"}
		},
		"removed readonly": func(t *corev1alpha1.Task) { delete(t.Annotations, labels.AnnotationAgentReadOnly) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := task.DeepCopy()
			mutate(changed)
			if ValidateCopilotTask(changed) == nil {
				t.Fatal("unexpected authority accepted")
			}
		})
	}
}
