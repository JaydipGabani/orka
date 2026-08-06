/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package admission

import (
	"context"
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrladmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

// CoexistenceAgentRuntimeValidator enforces explicit, immutable harness
// contract classification on AgentRuntime registrations. A registration
// without spec.contractVersion is unclassified and fails closed.
type CoexistenceAgentRuntimeValidator struct {
	decoder ctrladmission.Decoder
}

// NewCoexistenceAgentRuntimeValidator creates the AgentRuntime coexistence
// classification admission handler.
func NewCoexistenceAgentRuntimeValidator(scheme *runtime.Scheme) *CoexistenceAgentRuntimeValidator {
	return &CoexistenceAgentRuntimeValidator{decoder: ctrladmission.NewDecoder(scheme)}
}

// Handle implements admission.Handler.
func (v *CoexistenceAgentRuntimeValidator) Handle(_ context.Context, req ctrladmission.Request) ctrladmission.Response {
	if req.SubResource != "" {
		return ctrladmission.Allowed("subresource writes cannot change AgentRuntime contract classification")
	}

	switch req.Operation {
	case admissionv1.Create:
		agentRuntime := &corev1alpha1.AgentRuntime{}
		if err := v.decoder.Decode(req, agentRuntime); err != nil {
			return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode AgentRuntime: %w", err))
		}
		if agentRuntime.RegisteredContractVersion() == "" {
			return ctrladmission.Denied(
				"AgentRuntime registrations must declare spec.contractVersion on create: " +
					"a missing selector is never protocol evidence and classification fails closed")
		}
		return ctrladmission.Allowed("AgentRuntime registration declares an explicit contract version")
	case admissionv1.Update:
		agentRuntime := &corev1alpha1.AgentRuntime{}
		if err := v.decoder.Decode(req, agentRuntime); err != nil {
			return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode AgentRuntime: %w", err))
		}
		oldAgentRuntime := &corev1alpha1.AgentRuntime{}
		if err := v.decoder.DecodeRaw(req.OldObject, oldAgentRuntime); err != nil {
			return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode old AgentRuntime: %w", err))
		}
		return validateCoexistenceAgentRuntimeUpdate(oldAgentRuntime, agentRuntime)
	default:
		return ctrladmission.Allowed("operation does not change AgentRuntime contract classification")
	}
}

func validateCoexistenceAgentRuntimeUpdate(oldAgentRuntime, agentRuntime *corev1alpha1.AgentRuntime) ctrladmission.Response {
	oldContract := oldAgentRuntime.RegisteredContractVersion()
	newContract := agentRuntime.RegisteredContractVersion()

	if oldContract == "" {
		// One-time bridge classification of a previously unclassified
		// registration is allowed.
		return ctrladmission.Allowed("bridge classification of a previously unclassified AgentRuntime")
	}
	if newContract == "" {
		return ctrladmission.Denied(fmt.Sprintf(
			"spec.contractVersion is immutable once classified: %q may not be removed", oldContract))
	}
	if newContract != oldContract {
		return ctrladmission.Denied(fmt.Sprintf(
			"spec.contractVersion is immutable once classified: %q may not be changed to %q",
			oldContract, newContract))
	}
	return ctrladmission.Allowed("AgentRuntime contract classification unchanged")
}
