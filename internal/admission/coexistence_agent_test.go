/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package admission

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrladmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

const (
	coexistenceTestNamespace      = "tenant-b"
	coexistenceControllerUser     = "system:serviceaccount:orka-system:orka-controller-manager"
	coexistenceTenantUser         = "system:serviceaccount:tenant-b:tenant-editor"
	coexistenceAdminUser          = "cluster-admin-user"
	coexistenceMissingSelectorMsg = "missing selector is never protocol evidence"
)

func coexistenceTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha1.AddToScheme(scheme))
	return scheme
}

func coexistenceTestConfig() CoexistenceConfig {
	return NewCoexistenceConfig(coexistenceControllerUser, "")
}

func coexistenceUser(username string, groups ...string) authenticationv1.UserInfo {
	return authenticationv1.UserInfo{Username: username, Groups: groups}
}

func coexistenceAdminIdentity() authenticationv1.UserInfo {
	return coexistenceUser(coexistenceAdminUser, "system:masters", "system:authenticated")
}

func coexistenceRawObject(t *testing.T, obj runtime.Object, kind string) runtime.RawExtension {
	t.Helper()
	obj = obj.DeepCopyObject()
	obj.GetObjectKind().SetGroupVersionKind(corev1alpha1.GroupVersion.WithKind(kind))
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	return runtime.RawExtension{Raw: data}
}

func coexistenceRequest(
	t *testing.T,
	operation admissionv1.Operation,
	kind string,
	user authenticationv1.UserInfo,
	obj, oldObj runtime.Object,
	subresource string,
) ctrladmission.Request {
	t.Helper()
	req := ctrladmission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: operation,
		Kind: metav1.GroupVersionKind{
			Group:   corev1alpha1.GroupVersion.Group,
			Version: corev1alpha1.GroupVersion.Version,
			Kind:    kind,
		},
		Namespace:   coexistenceTestNamespace,
		SubResource: subresource,
		UserInfo:    user,
	}}
	if obj != nil {
		req.Object = coexistenceRawObject(t, obj, kind)
	}
	if oldObj != nil {
		req.OldObject = coexistenceRawObject(t, oldObj, kind)
	}
	return req
}

func newCoexistenceTestAgent(runtimeType corev1alpha1.AgentRuntimeType, contract *corev1alpha1.AgentRuntimeContractVersion) *corev1alpha1.Agent {
	agent := &corev1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "coexistence-agent",
			Namespace: coexistenceTestNamespace,
		},
	}
	if runtimeType != "" || contract != nil {
		agent.Spec.Runtime = &corev1alpha1.AgentCLIRuntime{
			Type:            runtimeType,
			ContractVersion: contract,
		}
	}
	return agent
}

func contractPtr(contract corev1alpha1.AgentRuntimeContractVersion) *corev1alpha1.AgentRuntimeContractVersion {
	return new(contract)
}

func newCoexistenceRuntimeRefAgent() *corev1alpha1.Agent {
	agent := newCoexistenceTestAgent("", nil)
	agent.Spec.Runtime = &corev1alpha1.AgentCLIRuntime{
		RuntimeRef: &corev1alpha1.AgentRuntimeReference{Name: "custom-runtime"},
	}
	return agent
}

func TestCoexistenceAgentValidator_Create(t *testing.T) {
	validator := NewCoexistenceAgentValidator(coexistenceTestScheme(t))

	tests := []struct {
		name     string
		agent    *corev1alpha1.Agent
		allowed  bool
		contains string
	}{
		{
			name:     "built-in create without contractVersion denied",
			agent:    newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, nil),
			contains: coexistenceMissingSelectorMsg,
		},
		{
			name:    "built-in create with v2 contract allowed",
			agent:   newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			allowed: true,
		},
		{
			name:    "built-in create with v1 contract allowed for non-opencode",
			agent:   newCoexistenceTestAgent(corev1alpha1.AgentRuntimeCodex, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)),
			allowed: true,
		},
		{
			name:     "opencode create with v1 contract denied",
			agent:    newCoexistenceTestAgent(corev1alpha1.AgentRuntimeOpencode, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)),
			contains: "sealed-inventory adoption only",
		},
		{
			name:    "opencode create with v2 contract allowed",
			agent:   newCoexistenceTestAgent(corev1alpha1.AgentRuntimeOpencode, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			allowed: true,
		},
		{
			name:     "opencode create without contractVersion denied",
			agent:    newCoexistenceTestAgent(corev1alpha1.AgentRuntimeOpencode, nil),
			contains: coexistenceMissingSelectorMsg,
		},
		{
			name:    "runtimeRef agent create allowed without contract",
			agent:   newCoexistenceRuntimeRefAgent(),
			allowed: true,
		},
		{
			name:    "native AI agent without runtime allowed",
			agent:   newCoexistenceTestAgent("", nil),
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Create, "Agent", coexistenceUser(coexistenceTenantUser), tt.agent, nil, ""))
			require.Equal(t, tt.allowed, resp.Allowed)
			if tt.contains != "" {
				require.Contains(t, resp.Result.Message, tt.contains)
			}
		})
	}
}

func TestCoexistenceAgentValidator_Update(t *testing.T) {
	validator := NewCoexistenceAgentValidator(coexistenceTestScheme(t))

	tests := []struct {
		name        string
		oldAgent    *corev1alpha1.Agent
		newAgent    *corev1alpha1.Agent
		subresource string
		allowed     bool
		contains    string
	}{
		{
			name:     "changing contract denied",
			oldAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)),
			newAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			contains: "immutable once classified",
		},
		{
			name:     "removing contract denied",
			oldAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			newAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, nil),
			contains: "may not be removed",
		},
		{
			name:     "removing whole runtime block denied when classified",
			oldAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			newAgent: newCoexistenceTestAgent("", nil),
			contains: "may not be removed",
		},
		{
			name:     "bridge classification to v2 allowed",
			oldAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, nil),
			newAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			allowed:  true,
		},
		{
			name:     "bridge classification of legacy opencode to v1 allowed",
			oldAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeOpencode, nil),
			newAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeOpencode, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)),
			allowed:  true,
		},
		{
			name:     "unchanged contract allowed",
			oldAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeCodex, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)),
			newAgent: newCoexistenceTestAgent(corev1alpha1.AgentRuntimeCodex, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)),
			allowed:  true,
		},
		{
			name:        "status subresource write allowed",
			oldAgent:    newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)),
			newAgent:    newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV2)),
			subresource: "status",
			allowed:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Update, "Agent", coexistenceUser(coexistenceTenantUser), tt.newAgent, tt.oldAgent, tt.subresource))
			require.Equal(t, tt.allowed, resp.Allowed)
			if tt.contains != "" {
				require.Contains(t, resp.Result.Message, tt.contains)
			}
		})
	}
}

func TestCoexistenceAgentValidator_DeleteAllowed(t *testing.T) {
	validator := NewCoexistenceAgentValidator(coexistenceTestScheme(t))
	resp := validator.Handle(context.Background(),
		coexistenceRequest(t, admissionv1.Delete, "Agent", coexistenceUser(coexistenceTenantUser),
			nil, newCoexistenceTestAgent(corev1alpha1.AgentRuntimeClaude, contractPtr(corev1alpha1.AgentRuntimeContractHarnessV1)), ""))
	require.True(t, resp.Allowed)
}
