package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRemediationJobDispatchFailsClosedBeforeRender(t *testing.T) {
	builder := setupJobBuilder()
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultNS, Name: "rm-" + strings.Repeat("a", 32) + "-checks"},
		Spec:       remediationpolicy.TaskSpec("synthetic private input", "approved"),
	}
	if job, err := builder.Build(t.Context(), task, nil, nil); err == nil || job != nil {
		t.Fatal("disabled remediation dispatched a proposal")
	}
	denied := errors.New("frozen model identity mismatch")
	calls := 0
	agent, provider := &corev1alpha1.Agent{}, &corev1alpha1.Provider{}
	builder.RemediationDispatchValidator = func(_ context.Context, got *corev1alpha1.Task, a *corev1alpha1.Agent, p *corev1alpha1.Provider) error {
		calls++
		if got != task || a != agent || p != provider {
			t.Fatal("dispatch guard was not given the exact rendered objects")
		}
		return denied
	}
	if job, err := builder.Build(t.Context(), task, agent, provider); !errors.Is(err, denied) || job != nil || calls != 1 {
		t.Fatal("failed policy check did not stop Job rendering", err)
	}
	// Even a missing reserved label cannot bypass the name-based guard.
	task.Labels = map[string]string{labels.LabelCreatedBy: ""}
	if job, err := builder.Build(t.Context(), task, agent, provider); !errors.Is(err, denied) || job != nil {
		t.Fatal("stripped proposal metadata bypassed dispatch", err)
	}
	ordinary := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultNS, Name: testTask},
		Spec:       corev1alpha1.TaskSpec{Type: corev1alpha1.TaskTypeContainer, Image: testBusyboxImage},
	}
	before := calls
	if _, err := builder.Build(t.Context(), ordinary, nil, nil); err != nil || calls != before {
		t.Fatal("ordinary Task behavior changed", err)
	}
}
