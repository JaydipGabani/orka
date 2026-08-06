/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package admission

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

func newCoexistenceTestValidatorForTasks(t *testing.T) *CoexistenceTaskProvenanceValidator {
	t.Helper()
	return NewCoexistenceTaskProvenanceValidator(coexistenceTestScheme(t), coexistenceTestConfig())
}

func newCoexistenceTestTask() *corev1alpha1.Task {
	return &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "coexistence-task",
			Namespace: coexistenceTestNamespace,
		},
		Spec: corev1alpha1.TaskSpec{
			Type:  corev1alpha1.TaskTypeContainer,
			Image: "busybox",
		},
	}
}

func withExecutionBinding(task *corev1alpha1.Task, digest string) *corev1alpha1.Task {
	task.Status.AgentExecutionBinding = &corev1alpha1.AgentExecutionBinding{
		SchemaVersion:   1,
		Mode:            corev1alpha1.AgentExecutionBindingModeExecute,
		ContractVersion: corev1alpha1.AgentRuntimeContractHarnessV2,
		Backend:         corev1alpha1.AgentExecutionBackendRuntimePool,
		Provenance:      corev1alpha1.AgentExecutionProvenanceNewlyBound,
		BindingDigest:   digest,
		Task: corev1alpha1.AgentExecutionBindingTaskRef{
			NamespaceUID:        types.UID("ns-uid"),
			UID:                 types.UID("task-uid"),
			BoundSpecGeneration: 1,
		},
	}
	return task
}

func withExecutionNoExecution(task *corev1alpha1.Task) *corev1alpha1.Task {
	task.Status.AgentExecutionNoExecution = &corev1alpha1.AgentExecutionNoExecution{
		SchemaVersion:        1,
		State:                corev1alpha1.AgentExecutionNoExecutionUnbound,
		MigrationInventoryID: "inventory-1",
		RecordedAt:           metav1.Now(),
	}
	return task
}

func withExecutionQuarantine(task *corev1alpha1.Task) *corev1alpha1.Task {
	task.Status.AgentExecutionQuarantine = &corev1alpha1.AgentExecutionQuarantine{
		SchemaVersion:        1,
		Reason:               corev1alpha1.AgentExecutionQuarantineMixedEvidence,
		MigrationInventoryID: "inventory-1",
		RecordedAt:           metav1.Now(),
	}
	return task
}

func withExecutionResolutionRef(task *corev1alpha1.Task) *corev1alpha1.Task {
	task.Status.AgentExecutionResolutionRef = &corev1alpha1.AgentExecutionResolutionRef{
		AdjudicationName: "adjudication-1",
		AdjudicationUID:  types.UID("adjudication-uid"),
		Action:           corev1alpha1.AgentExecutionAdjudicationCleanupBoth,
		AppliedAt:        metav1.Now(),
	}
	return task
}

func TestCoexistenceTaskProvenanceValidator_Create(t *testing.T) {
	validator := newCoexistenceTestValidatorForTasks(t)

	tests := []struct {
		name     string
		user     string
		task     *corev1alpha1.Task
		allowed  bool
		contains string
	}{
		{
			name:    "non-controller create without provenance allowed",
			user:    coexistenceTenantUser,
			task:    newCoexistenceTestTask(),
			allowed: true,
		},
		{
			name:     "non-controller create with binding denied",
			user:     coexistenceTenantUser,
			task:     withExecutionBinding(newCoexistenceTestTask(), "sha256:aaaa"),
			contains: fieldStatusAgentExecutionBinding,
		},
		{
			name:     "non-controller create with noExecution denied",
			user:     coexistenceTenantUser,
			task:     withExecutionNoExecution(newCoexistenceTestTask()),
			contains: fieldStatusAgentExecutionNoExecution,
		},
		{
			name:     "non-controller create with quarantine denied",
			user:     coexistenceTenantUser,
			task:     withExecutionQuarantine(newCoexistenceTestTask()),
			contains: fieldStatusAgentExecutionQuarantine,
		},
		{
			name:     "non-controller create with resolutionRef denied",
			user:     coexistenceTenantUser,
			task:     withExecutionResolutionRef(newCoexistenceTestTask()),
			contains: fieldStatusAgentExecutionResolutionRef,
		},
		{
			name:    "controller create with binding allowed",
			user:    coexistenceControllerUser,
			task:    withExecutionBinding(newCoexistenceTestTask(), "sha256:aaaa"),
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Create, "Task", coexistenceUser(tt.user), tt.task, nil, ""))
			require.Equal(t, tt.allowed, resp.Allowed)
			if tt.contains != "" {
				require.Contains(t, resp.Result.Message, tt.contains)
			}
		})
	}
}

func TestCoexistenceTaskProvenanceValidator_Update(t *testing.T) {
	validator := newCoexistenceTestValidatorForTasks(t)

	plain := newCoexistenceTestTask()
	bound := withExecutionBinding(newCoexistenceTestTask(), "sha256:aaaa")
	quarantined := withExecutionQuarantine(newCoexistenceTestTask())

	tests := []struct {
		name        string
		user        string
		oldTask     *corev1alpha1.Task
		newTask     *corev1alpha1.Task
		subresource string
		allowed     bool
		contains    string
	}{
		{
			name:        "non-controller status update adding binding denied",
			user:        coexistenceTenantUser,
			oldTask:     plain,
			newTask:     withExecutionBinding(plain.DeepCopy(), "sha256:aaaa"),
			subresource: "status",
			contains:    fieldStatusAgentExecutionBinding,
		},
		{
			name:        "non-controller status update changing binding denied",
			user:        coexistenceTenantUser,
			oldTask:     bound,
			newTask:     withExecutionBinding(newCoexistenceTestTask(), "sha256:bbbb"),
			subresource: "status",
			contains:    fieldStatusAgentExecutionBinding,
		},
		{
			name:        "non-controller status update removing quarantine denied",
			user:        coexistenceTenantUser,
			oldTask:     quarantined,
			newTask:     newCoexistenceTestTask(),
			subresource: "status",
			contains:    fieldStatusAgentExecutionQuarantine,
		},
		{
			name:     "non-controller main update adding noExecution denied",
			user:     coexistenceTenantUser,
			oldTask:  plain,
			newTask:  withExecutionNoExecution(plain.DeepCopy()),
			contains: fieldStatusAgentExecutionNoExecution,
		},
		{
			name:     "non-controller main update adding resolutionRef denied",
			user:     coexistenceTenantUser,
			oldTask:  plain,
			newTask:  withExecutionResolutionRef(plain.DeepCopy()),
			contains: fieldStatusAgentExecutionResolutionRef,
		},
		{
			name:        "non-controller status update leaving provenance unchanged allowed",
			user:        coexistenceTenantUser,
			oldTask:     bound,
			newTask:     bound.DeepCopy(),
			subresource: "status",
			allowed:     true,
		},
		{
			name:    "non-controller spec-only update allowed",
			user:    coexistenceTenantUser,
			oldTask: plain,
			newTask: func() *corev1alpha1.Task {
				task := plain.DeepCopy()
				task.Spec.Image = "alpine"
				return task
			}(),
			allowed: true,
		},
		{
			name:        "controller status update adding binding allowed",
			user:        coexistenceControllerUser,
			oldTask:     plain,
			newTask:     withExecutionBinding(plain.DeepCopy(), "sha256:aaaa"),
			subresource: "status",
			allowed:     true,
		},
		{
			name:        "controller status update removing quarantine allowed",
			user:        coexistenceControllerUser,
			oldTask:     quarantined,
			newTask:     newCoexistenceTestTask(),
			subresource: "status",
			allowed:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Update, "Task", coexistenceUser(tt.user), tt.newTask, tt.oldTask, tt.subresource))
			require.Equal(t, tt.allowed, resp.Allowed)
			if tt.contains != "" {
				require.Contains(t, resp.Result.Message, tt.contains)
			}
		})
	}
}

func TestCoexistenceTaskProvenanceValidator_DeleteAllowed(t *testing.T) {
	validator := newCoexistenceTestValidatorForTasks(t)
	resp := validator.Handle(context.Background(),
		coexistenceRequest(t, admissionv1.Delete, "Task", coexistenceUser(coexistenceTenantUser),
			nil, withExecutionBinding(newCoexistenceTestTask(), "sha256:aaaa"), ""))
	require.True(t, resp.Allowed)
}

func TestCoexistenceTaskProvenanceValidator_FailClosedWithoutControllerIdentities(t *testing.T) {
	validator := NewCoexistenceTaskProvenanceValidator(coexistenceTestScheme(t), NewCoexistenceConfig("", ""))
	resp := validator.Handle(context.Background(),
		coexistenceRequest(t, admissionv1.Update, "Task", coexistenceUser(coexistenceControllerUser),
			withExecutionBinding(newCoexistenceTestTask(), "sha256:aaaa"), newCoexistenceTestTask(), "status"))
	require.False(t, resp.Allowed)
}
