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

// CoexistenceAgentValidator enforces explicit, immutable harness contract
// classification on built-in runtime Agents. runtime.type alone is never
// protocol evidence; a missing selector fails closed.
type CoexistenceAgentValidator struct {
	decoder ctrladmission.Decoder
}

// NewCoexistenceAgentValidator creates the Agent coexistence classification
// admission handler.
func NewCoexistenceAgentValidator(scheme *runtime.Scheme) *CoexistenceAgentValidator {
	return &CoexistenceAgentValidator{decoder: ctrladmission.NewDecoder(scheme)}
}

// Handle implements admission.Handler.
func (v *CoexistenceAgentValidator) Handle(_ context.Context, req ctrladmission.Request) ctrladmission.Response {
	if req.SubResource != "" {
		return ctrladmission.Allowed("subresource writes cannot change Agent contract classification")
	}

	switch req.Operation {
	case admissionv1.Create:
		agent := &corev1alpha1.Agent{}
		if err := v.decoder.Decode(req, agent); err != nil {
			return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode Agent: %w", err))
		}
		return validateCoexistenceAgentCreate(agent)
	case admissionv1.Update:
		agent := &corev1alpha1.Agent{}
		if err := v.decoder.Decode(req, agent); err != nil {
			return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode Agent: %w", err))
		}
		oldAgent := &corev1alpha1.Agent{}
		if err := v.decoder.DecodeRaw(req.OldObject, oldAgent); err != nil {
			return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode old Agent: %w", err))
		}
		return validateCoexistenceAgentUpdate(oldAgent, agent)
	default:
		return ctrladmission.Allowed("operation does not change Agent contract classification")
	}
}

func validateCoexistenceAgentCreate(agent *corev1alpha1.Agent) ctrladmission.Response {
	agentRuntime := agent.Spec.Runtime
	if agentRuntime == nil || agentRuntime.Type == "" {
		// Not a built-in runtime Agent: either a native AI Agent or a
		// runtimeRef Agent whose protocol derives from the referenced
		// AgentRuntime registration.
		return ctrladmission.Allowed("Agent does not select a built-in runtime type")
	}

	contract := agent.BuiltInContractVersion()
	if contract == "" {
		return ctrladmission.Denied(
			"built-in runtime Agents must declare spec.runtime.contractVersion on create: " +
				"a missing selector is never protocol evidence and classification fails closed")
	}
	if agentRuntime.Type == corev1alpha1.AgentRuntimeOpencode && contract == corev1alpha1.AgentRuntimeContractHarnessV1 {
		return ctrladmission.Denied(
			"new v1 OpenCode bindings are prohibited; legacy v1 OpenCode is sealed-inventory adoption only")
	}
	return ctrladmission.Allowed("built-in runtime Agent declares an explicit contract version")
}

func validateCoexistenceAgentUpdate(oldAgent, agent *corev1alpha1.Agent) ctrladmission.Response {
	oldContract := oldAgent.BuiltInContractVersion()
	newContract := agent.BuiltInContractVersion()

	if oldContract == "" {
		// One-time bridge classification of a previously unclassified Agent is
		// allowed; this is also the only path that may adopt sealed-inventory
		// legacy v1 OpenCode Agents.
		return ctrladmission.Allowed("bridge classification of a previously unclassified Agent")
	}
	if newContract == "" {
		return ctrladmission.Denied(fmt.Sprintf(
			"spec.runtime.contractVersion is immutable once classified: %q may not be removed", oldContract))
	}
	if newContract != oldContract {
		return ctrladmission.Denied(fmt.Sprintf(
			"spec.runtime.contractVersion is immutable once classified: %q may not be changed to %q",
			oldContract, newContract))
	}
	return ctrladmission.Allowed("Agent contract classification unchanged")
}
