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

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

func newCoexistenceTestAgentRuntime(contract *corev1alpha1.AgentRuntimeContractVersion) *corev1alpha1.AgentRuntime {
	return &corev1alpha1.AgentRuntime{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "coexistence-runtime",
			Namespace: coexistenceTestNamespace,
		},
		Spec: corev1alpha1.AgentRuntimeRegistrySpec{
			ContractVersion: contract,
		},
	}
}

func TestCoexistenceAgentRuntimeValidator_Create(t *testing.T) {
	validator := NewCoexistenceAgentRuntimeValidator(coexistenceTestScheme(t))

	tests := []struct {
		name         string
		agentRuntime *corev1alpha1.AgentRuntime
		allowed      bool
		contains     string
	}{
		{
			name:         "create without contractVersion denied",
			agentRuntime: newCoexistenceTestAgentRuntime(nil),
			contains:     coexistenceMissingSelectorMsg,
		},
		{
			name:         "create with v1 contract allowed",
			agentRuntime: newCoexistenceTestAgentRuntime(contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)),
			allowed:      true,
		},
		{
			name:         "create with v2 contract allowed",
			agentRuntime: newCoexistenceTestAgentRuntime(contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			allowed:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Create, "AgentRuntime", coexistenceUser(coexistenceTenantUser), tt.agentRuntime, nil, ""))
			require.Equal(t, tt.allowed, resp.Allowed)
			if tt.contains != "" {
				require.Contains(t, resp.Result.Message, tt.contains)
			}
		})
	}
}

func TestCoexistenceAgentRuntimeValidator_Update(t *testing.T) {
	validator := NewCoexistenceAgentRuntimeValidator(coexistenceTestScheme(t))

	tests := []struct {
		name        string
		oldRuntime  *corev1alpha1.AgentRuntime
		newRuntime  *corev1alpha1.AgentRuntime
		subresource string
		allowed     bool
		contains    string
	}{
		{
			name:       "bridge classification absent to present allowed",
			oldRuntime: newCoexistenceTestAgentRuntime(nil),
			newRuntime: newCoexistenceTestAgentRuntime(contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			allowed:    true,
		},
		{
			name:       "unclassified no-op update allowed",
			oldRuntime: newCoexistenceTestAgentRuntime(nil),
			newRuntime: newCoexistenceTestAgentRuntime(nil),
			allowed:    true,
		},
		{
			name:       "changing contract denied",
			oldRuntime: newCoexistenceTestAgentRuntime(contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)),
			newRuntime: newCoexistenceTestAgentRuntime(contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			contains:   "immutable once classified",
		},
		{
			name:       "removing contract denied",
			oldRuntime: newCoexistenceTestAgentRuntime(contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			newRuntime: newCoexistenceTestAgentRuntime(nil),
			contains:   "may not be removed",
		},
		{
			name:       "unchanged contract allowed",
			oldRuntime: newCoexistenceTestAgentRuntime(contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			newRuntime: newCoexistenceTestAgentRuntime(contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			allowed:    true,
		},
		{
			name:        "status subresource write allowed",
			oldRuntime:  newCoexistenceTestAgentRuntime(contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)),
			newRuntime:  newCoexistenceTestAgentRuntime(contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			subresource: "status",
			allowed:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Update, "AgentRuntime", coexistenceUser(coexistenceTenantUser), tt.newRuntime, tt.oldRuntime, tt.subresource))
			require.Equal(t, tt.allowed, resp.Allowed)
			if tt.contains != "" {
				require.Contains(t, resp.Result.Message, tt.contains)
			}
		})
	}
}
