package tools

import (
	"context"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/store"
)

const (
	repositorySecurityCreatedBy     = "repository-security"
	harnessWrapperAttemptAnnotation = "orka.ai/harness-wrapper-attempt"
)

func toolTaskOutputAttempt(task *corev1alpha1.Task) int64 {
	if task == nil {
		return 0
	}
	attempt := int64(task.Status.Attempts)
	if task.Status.Phase == corev1alpha1.TaskPhasePending || task.Status.Phase == corev1alpha1.TaskPhaseScheduled {
		attempt++
	}
	if task.Annotations != nil {
		if planned, err := strconv.ParseInt(strings.TrimSpace(task.Annotations[harnessWrapperAttemptAnnotation]), 10, 64); err == nil &&
			planned > 0 && planned >= attempt {
			return planned
		}
	}
	return attempt
}

func toolTaskRequiresBoundOutput(task *corev1alpha1.Task) bool {
	if task == nil {
		return false
	}
	if strings.TrimSpace(task.Labels[labels.LabelCreatedBy]) == repositorySecurityCreatedBy {
		return true
	}
	owner := metav1.GetControllerOf(task)
	return owner != nil && owner.UID != "" && owner.Kind == "RepositoryScan" &&
		owner.APIVersion == corev1alpha1.GroupVersion.String()
}

func toolTaskResult(ctx context.Context, toolCtx *ToolContext, task *corev1alpha1.Task) ([]byte, error) {
	if toolCtx == nil || toolCtx.ResultStore == nil || task == nil {
		return nil, store.ErrNotFound
	}
	requireBound := toolTaskRequiresBoundOutput(task)
	if task.UID != "" {
		if bound, ok := any(toolCtx.ResultStore).(store.BoundOutputStore); ok {
			result, err := bound.GetBoundResult(ctx, task.Namespace, task.Name, string(task.UID), toolTaskOutputAttempt(task))
			if err == nil {
				return result.Data, nil
			}
			if requireBound {
				return nil, err
			}
		} else if requireBound {
			return nil, store.ErrNotReady
		}
	} else if requireBound {
		return nil, store.ErrNotReady
	}
	return toolCtx.ResultStore.GetResult(ctx, task.Namespace, task.Name)
}
