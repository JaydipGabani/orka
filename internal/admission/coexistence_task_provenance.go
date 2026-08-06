/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package admission

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	ctrladmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

// Task status execution provenance fields protected by the coexistence
// admission boundary.
const (
	fieldStatusAgentExecutionBinding       = "status.agentExecutionBinding"
	fieldStatusAgentExecutionNoExecution   = "status.agentExecutionNoExecution"
	fieldStatusAgentExecutionQuarantine    = "status.agentExecutionQuarantine"
	fieldStatusAgentExecutionResolutionRef = "status.agentExecutionResolutionRef"
)

// CoexistenceTaskProvenanceValidator rejects Task writes from non-controller
// identities that add, change, or remove agent execution provenance fields.
// Status subresource writes carry the full Task object and are validated the
// same way as main-resource writes.
type CoexistenceTaskProvenanceValidator struct {
	decoder ctrladmission.Decoder
	config  CoexistenceConfig
}

// NewCoexistenceTaskProvenanceValidator creates the Task execution provenance
// admission handler.
func NewCoexistenceTaskProvenanceValidator(scheme *runtime.Scheme, cfg CoexistenceConfig) *CoexistenceTaskProvenanceValidator {
	return &CoexistenceTaskProvenanceValidator{
		decoder: ctrladmission.NewDecoder(scheme),
		config:  cfg,
	}
}

// Handle implements admission.Handler.
func (v *CoexistenceTaskProvenanceValidator) Handle(_ context.Context, req ctrladmission.Request) ctrladmission.Response {
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		return ctrladmission.Allowed("operation cannot write Task execution provenance")
	}
	if v.config.isControllerIdentity(req.UserInfo) {
		return ctrladmission.Allowed("controller identity may write Task execution provenance")
	}

	task := &corev1alpha1.Task{}
	if err := v.decoder.Decode(req, task); err != nil {
		return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode Task: %w", err))
	}

	switch req.Operation {
	case admissionv1.Create:
		if fields := presentAgentExecutionProvenanceFields(task); len(fields) > 0 {
			return ctrladmission.Denied(
				"only controller identities may set Task execution provenance: " + strings.Join(fields, ", "))
		}
	case admissionv1.Update:
		oldTask := &corev1alpha1.Task{}
		if err := v.decoder.DecodeRaw(req.OldObject, oldTask); err != nil {
			return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode old Task: %w", err))
		}
		if fields := changedAgentExecutionProvenanceFields(oldTask, task); len(fields) > 0 {
			return ctrladmission.Denied(
				"only controller identities may add, change, or remove Task execution provenance: " +
					strings.Join(fields, ", "))
		}
	}

	return ctrladmission.Allowed("Task execution provenance unchanged")
}

func presentAgentExecutionProvenanceFields(task *corev1alpha1.Task) []string {
	fields := []string{}
	if task.Status.AgentExecutionBinding != nil {
		fields = append(fields, fieldStatusAgentExecutionBinding)
	}
	if task.Status.AgentExecutionNoExecution != nil {
		fields = append(fields, fieldStatusAgentExecutionNoExecution)
	}
	if task.Status.AgentExecutionQuarantine != nil {
		fields = append(fields, fieldStatusAgentExecutionQuarantine)
	}
	if task.Status.AgentExecutionResolutionRef != nil {
		fields = append(fields, fieldStatusAgentExecutionResolutionRef)
	}
	return fields
}

func changedAgentExecutionProvenanceFields(oldTask, task *corev1alpha1.Task) []string {
	fields := []string{}
	if !apiequality.Semantic.DeepEqual(oldTask.Status.AgentExecutionBinding, task.Status.AgentExecutionBinding) {
		fields = append(fields, fieldStatusAgentExecutionBinding)
	}
	if !apiequality.Semantic.DeepEqual(oldTask.Status.AgentExecutionNoExecution, task.Status.AgentExecutionNoExecution) {
		fields = append(fields, fieldStatusAgentExecutionNoExecution)
	}
	if !apiequality.Semantic.DeepEqual(oldTask.Status.AgentExecutionQuarantine, task.Status.AgentExecutionQuarantine) {
		fields = append(fields, fieldStatusAgentExecutionQuarantine)
	}
	if !apiequality.Semantic.DeepEqual(oldTask.Status.AgentExecutionResolutionRef, task.Status.AgentExecutionResolutionRef) {
		fields = append(fields, fieldStatusAgentExecutionResolutionRef)
	}
	return fields
}
