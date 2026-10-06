package api

import (
	"context"

	"github.com/gofiber/fiber/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubelabels "k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
)

func remediationTaskPrivate(task *corev1alpha1.Task) bool {
	if remediationpolicy.IsNativeProposal(task) {
		return true
	}
	if task == nil {
		return false
	}
	_, run := task.Annotations[remediationpolicy.RunAnnotation]
	_, request := task.Annotations[remediationpolicy.RequestDigestAnnotation]
	_, label := task.Labels[remediationpolicy.RunLabel]
	return run || request || label
}

func denyRemediationTaskPublicAccess(task *corev1alpha1.Task) error {
	// Generic Task DTOs, results, and events may contain the source report.
	// Even remediation artifact readers must use the bounded private run API.
	if remediationTaskPrivate(task) {
		return fiber.NewError(fiber.StatusNotFound, "task not found")
	}
	return nil
}

func (h *Handlers) checkRemediationTaskPublicAccess(ctx context.Context, namespace, name string) error {
	if remediationTaskPrivate(&corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Name: name}}) {
		return fiber.NewError(fiber.StatusNotFound, "task not found")
	}
	reader := client.Reader(h.client)
	if reader == nil {
		reader = h.apiReader
	}
	if reader == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "task visibility is unavailable")
	}
	task := &corev1alpha1.Task{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, task); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fiber.NewError(fiber.StatusServiceUnavailable, "task visibility is unavailable")
	}
	return denyRemediationTaskPublicAccess(task)
}

type remediationTaskVisibility struct {
	tasks    map[string]bool
	sessions map[string]bool
}

// Native proposals cannot use Sessions. Still suppress associations from a
// malformed or previously stored Task instead of publishing their transcripts.
func (h *Handlers) remediationVisibility(ctx context.Context, namespace string) (remediationTaskVisibility, error) {
	visibility := remediationTaskVisibility{tasks: make(map[string]bool), sessions: make(map[string]bool)}
	if !h.remediationAvailable() {
		return visibility, nil
	}
	if h.apiReader == nil && h.client == nil {
		return visibility, fiber.NewError(fiber.StatusServiceUnavailable, "task visibility is unavailable")
	}
	options := &client.ListOptions{Namespace: namespace, Limit: MaxLimit,
		LabelSelector: kubelabels.SelectorFromSet(map[string]string{labels.LabelCreatedBy: remediationpolicy.CreatedBy})}
	for range maxAuthorizedListPages {
		var tasks corev1alpha1.TaskList
		if err := h.listPage(ctx, &tasks, options, "task visibility"); err != nil {
			return visibility, fiber.NewError(fiber.StatusServiceUnavailable, "task visibility is unavailable")
		}
		for i := range tasks.Items {
			task := &tasks.Items[i]
			if task.Namespace != namespace || !remediationTaskPrivate(task) {
				continue
			}
			visibility.tasks[task.Name] = true
			if task.Spec.SessionRef != nil {
				visibility.sessions[task.Spec.SessionRef.Name] = true
			}
		}
		if tasks.Continue == "" {
			return visibility, nil
		}
		options.Continue = tasks.Continue
	}
	return visibility, fiber.NewError(fiber.StatusServiceUnavailable, "task visibility scan exceeds its safety limit")
}

func (v remediationTaskVisibility) sessionPrivate(name, activeTask string) bool {
	return v.sessions[name] || v.tasks[activeTask] ||
		remediationTaskPrivate(&corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Name: activeTask}})
}

func (v remediationTaskVisibility) recordPrivate(session *store.SessionRecord) bool {
	if v.sessionPrivate(session.Name, session.ActiveTask) {
		return true
	}
	for _, message := range session.Messages {
		if v.tasks[message.SourceRef] || remediationTaskPrivate(&corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Name: message.SourceRef}}) {
			return true
		}
	}
	return false
}

func (h *Handlers) checkRemediationSessionEvents(ctx context.Context, namespace string, events []store.SessionExecutionEvent) error {
	checked := make(map[string]bool)
	for _, event := range events {
		for _, name := range []string{event.TaskName, event.StreamID} {
			if name == "" || checked[name] {
				continue
			}
			checked[name] = true
			if err := h.checkRemediationTaskPublicAccess(ctx, namespace, name); err != nil {
				return err
			}
		}
	}
	return nil
}
