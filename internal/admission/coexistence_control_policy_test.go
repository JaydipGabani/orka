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
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

func newCoexistenceTestControl(v1Mode corev1alpha1.AgentExecutionDesiredMode) *corev1alpha1.AgentExecutionControl {
	return &corev1alpha1.AgentExecutionControl{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "coexistence-control",
			Namespace: coexistenceTestNamespace,
		},
		Spec: corev1alpha1.AgentExecutionControlSpec{
			Backends: corev1alpha1.AgentExecutionBackendsSpec{
				V1: corev1alpha1.AgentExecutionBackendSpec{DesiredMode: v1Mode},
				V2: corev1alpha1.AgentExecutionBackendSpec{DesiredMode: corev1alpha1.AgentExecutionModeEnabled},
			},
		},
	}
}

func newCoexistenceTestPolicy(allowNewV1 bool) *corev1alpha1.AgentExecutionPolicy {
	return &corev1alpha1.AgentExecutionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "coexistence-policy",
			Namespace: coexistenceTestNamespace,
		},
		Spec: corev1alpha1.AgentExecutionPolicySpec{
			AllowNewV1Bindings: allowNewV1,
		},
	}
}

func newCoexistenceTestControlPolicyValidator(t *testing.T) *CoexistenceControlPolicyValidator {
	t.Helper()
	return NewCoexistenceControlPolicyValidator(coexistenceTestScheme(t), coexistenceTestConfig())
}

func coexistenceControllerGroupsIdentity() authenticationv1.UserInfo {
	// The controller ServiceAccount is in system:serviceaccounts but not in an
	// admin group; it must never be blocked on status writes.
	return coexistenceUser(coexistenceControllerUser, "system:serviceaccounts", "system:authenticated")
}

func TestCoexistenceControlPolicyValidator_Create(t *testing.T) {
	validator := newCoexistenceTestControlPolicyValidator(t)

	tests := []struct {
		name     string
		kind     string
		user     authenticationv1.UserInfo
		obj      runtime.Object
		allowed  bool
		contains string
	}{
		{
			name:    "admin control create allowed",
			kind:    kindAgentExecutionControl,
			user:    coexistenceAdminIdentity(),
			obj:     newCoexistenceTestControl(corev1alpha1.AgentExecutionModeEnabled),
			allowed: true,
		},
		{
			name:     "non-admin control create denied",
			kind:     kindAgentExecutionControl,
			user:     coexistenceControllerGroupsIdentity(),
			obj:      newCoexistenceTestControl(corev1alpha1.AgentExecutionModeEnabled),
			contains: "restricted to admin groups",
		},
		{
			name:    "admin policy create allowed",
			kind:    kindAgentExecutionPolicy,
			user:    coexistenceAdminIdentity(),
			obj:     newCoexistenceTestPolicy(true),
			allowed: true,
		},
		{
			name:     "non-admin policy create denied",
			kind:     kindAgentExecutionPolicy,
			user:     coexistenceUser(coexistenceTenantUser, "system:serviceaccounts"),
			obj:      newCoexistenceTestPolicy(true),
			contains: "restricted to admin groups",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Create, tt.kind, tt.user, tt.obj, nil, ""))
			require.Equal(t, tt.allowed, resp.Allowed)
			if tt.contains != "" {
				require.Contains(t, resp.Result.Message, tt.contains)
			}
		})
	}
}

func TestCoexistenceControlPolicyValidator_Update(t *testing.T) {
	validator := newCoexistenceTestControlPolicyValidator(t)

	control := newCoexistenceTestControl(corev1alpha1.AgentExecutionModeEnabled)
	controlSpecEdit := newCoexistenceTestControl(corev1alpha1.AgentExecutionModeDrainOnly)
	controlMetadataEdit := control.DeepCopy()
	controlMetadataEdit.Labels = map[string]string{"managed": "true"}

	policy := newCoexistenceTestPolicy(true)
	policySpecEdit := newCoexistenceTestPolicy(false)

	tests := []struct {
		name        string
		kind        string
		user        authenticationv1.UserInfo
		oldObj      runtime.Object
		newObj      runtime.Object
		subresource string
		allowed     bool
		contains    string
	}{
		{
			name:    "admin control spec update allowed",
			kind:    kindAgentExecutionControl,
			user:    coexistenceAdminIdentity(),
			oldObj:  control,
			newObj:  controlSpecEdit,
			allowed: true,
		},
		{
			name:     "non-admin control spec update denied",
			kind:     kindAgentExecutionControl,
			user:     coexistenceControllerGroupsIdentity(),
			oldObj:   control,
			newObj:   controlSpecEdit,
			contains: "restricted to admin groups",
		},
		{
			name:    "non-admin control metadata-only update allowed",
			kind:    kindAgentExecutionControl,
			user:    coexistenceControllerGroupsIdentity(),
			oldObj:  control,
			newObj:  controlMetadataEdit,
			allowed: true,
		},
		{
			name:        "controller control status subresource update allowed",
			kind:        kindAgentExecutionControl,
			user:        coexistenceControllerGroupsIdentity(),
			oldObj:      control,
			newObj:      controlSpecEdit,
			subresource: "status",
			allowed:     true,
		},
		{
			name:     "non-admin policy spec update denied",
			kind:     kindAgentExecutionPolicy,
			user:     coexistenceUser(coexistenceTenantUser, "system:serviceaccounts"),
			oldObj:   policy,
			newObj:   policySpecEdit,
			contains: "restricted to admin groups",
		},
		{
			name:    "admin policy spec update allowed",
			kind:    kindAgentExecutionPolicy,
			user:    coexistenceAdminIdentity(),
			oldObj:  policy,
			newObj:  policySpecEdit,
			allowed: true,
		},
		{
			name:        "controller policy status subresource update allowed",
			kind:        kindAgentExecutionPolicy,
			user:        coexistenceControllerGroupsIdentity(),
			oldObj:      policy,
			newObj:      policySpecEdit,
			subresource: "status",
			allowed:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Update, tt.kind, tt.user, tt.newObj, tt.oldObj, tt.subresource))
			require.Equal(t, tt.allowed, resp.Allowed)
			if tt.contains != "" {
				require.Contains(t, resp.Result.Message, tt.contains)
			}
		})
	}
}

func TestCoexistenceControlPolicyValidator_UnexpectedKindErrored(t *testing.T) {
	validator := newCoexistenceTestControlPolicyValidator(t)
	resp := validator.Handle(context.Background(),
		coexistenceRequest(t, admissionv1.Create, "Task", coexistenceAdminIdentity(), newCoexistenceTestTask(), nil, ""))
	require.False(t, resp.Allowed)
	require.Contains(t, resp.Result.Message, "unexpected kind")
}
