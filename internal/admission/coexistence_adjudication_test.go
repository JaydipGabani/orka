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
	"k8s.io/apimachinery/pkg/types"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

const coexistenceAdjudicationKind = "AgentExecutionAdjudication"

func newCoexistenceTestAdjudication(requestedBy string) *corev1alpha1.AgentExecutionAdjudication {
	return &corev1alpha1.AgentExecutionAdjudication{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "coexistence-adjudication",
			Namespace: coexistenceTestNamespace,
		},
		Spec: corev1alpha1.AgentExecutionAdjudicationSpec{
			TaskRef: corev1alpha1.AgentExecutionSubjectReference{
				Name: "coexistence-task",
				UID:  types.UID("task-uid"),
			},
			ExpectedState: corev1alpha1.AgentExecutionExpectedSubjectState{
				SubjectResourceVersion:   "42",
				EvidenceClosureWatermark: "sha256:" + coexistenceTestDigest,
			},
			QuarantineDigest: "sha256:" + coexistenceTestDigest,
			Action:           corev1alpha1.AgentExecutionAdjudicationCleanupBoth,
			EvidenceDigests:  []string{"sha256:" + coexistenceTestDigest},
			Justification:    "operator resolved quarantine after manual verification",
			RequestedBy:      requestedBy,
		},
	}
}

const coexistenceTestDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newCoexistenceTestAdjudicationValidator(t *testing.T) *CoexistenceAdjudicationValidator {
	t.Helper()
	return NewCoexistenceAdjudicationValidator(coexistenceTestScheme(t), coexistenceTestConfig())
}

func TestCoexistenceAdjudicationValidator_Create(t *testing.T) {
	validator := newCoexistenceTestAdjudicationValidator(t)

	tests := []struct {
		name         string
		user         authenticationv1.UserInfo
		adjudication *corev1alpha1.AgentExecutionAdjudication
		allowed      bool
		contains     string
	}{
		{
			name:         "non-admin create denied",
			user:         coexistenceUser(coexistenceTenantUser, "system:serviceaccounts", "system:authenticated"),
			adjudication: newCoexistenceTestAdjudication(coexistenceTenantUser),
			contains:     "restricted to admin groups",
		},
		{
			name:         "admin create with matching requestedBy allowed",
			user:         coexistenceAdminIdentity(),
			adjudication: newCoexistenceTestAdjudication(coexistenceAdminUser),
			allowed:      true,
		},
		{
			name:         "admin create with mismatched requestedBy denied",
			user:         coexistenceAdminIdentity(),
			adjudication: newCoexistenceTestAdjudication("someone-else"),
			contains:     "verified requester identity",
		},
		{
			name:         "admin create with empty requestedBy denied",
			user:         coexistenceAdminIdentity(),
			adjudication: newCoexistenceTestAdjudication(""),
			contains:     "verified requester identity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Create, coexistenceAdjudicationKind, tt.user, tt.adjudication, nil, ""))
			require.Equal(t, tt.allowed, resp.Allowed)
			if tt.contains != "" {
				require.Contains(t, resp.Result.Message, tt.contains)
			}
		})
	}
}

func TestCoexistenceAdjudicationValidator_Update(t *testing.T) {
	validator := newCoexistenceTestAdjudicationValidator(t)

	original := newCoexistenceTestAdjudication(coexistenceAdminUser)
	specEdit := newCoexistenceTestAdjudication(coexistenceAdminUser)
	specEdit.Spec.Action = corev1alpha1.AgentExecutionAdjudicationCleanupV1
	metadataEdit := original.DeepCopy()
	metadataEdit.Labels = map[string]string{"resolution": "tracked"}
	statusEdit := original.DeepCopy()
	statusEdit.Status.State = corev1alpha1.AgentExecutionAdjudicationApplied

	tests := []struct {
		name        string
		user        authenticationv1.UserInfo
		oldObj      *corev1alpha1.AgentExecutionAdjudication
		newObj      *corev1alpha1.AgentExecutionAdjudication
		subresource string
		allowed     bool
		contains    string
	}{
		{
			name:     "spec update denied even for admins",
			user:     coexistenceAdminIdentity(),
			oldObj:   original,
			newObj:   specEdit,
			contains: "spec is immutable",
		},
		{
			name:    "metadata-only update allowed",
			user:    coexistenceUser(coexistenceTenantUser, "system:serviceaccounts"),
			oldObj:  original,
			newObj:  metadataEdit,
			allowed: true,
		},
		{
			name:        "controller status subresource update allowed",
			user:        coexistenceUser(coexistenceControllerUser, "system:serviceaccounts"),
			oldObj:      original,
			newObj:      statusEdit,
			subresource: "status",
			allowed:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Update, coexistenceAdjudicationKind, tt.user, tt.newObj, tt.oldObj, tt.subresource))
			require.Equal(t, tt.allowed, resp.Allowed)
			if tt.contains != "" {
				require.Contains(t, resp.Result.Message, tt.contains)
			}
		})
	}
}

func TestCoexistenceAdjudicationValidator_Delete(t *testing.T) {
	validator := newCoexistenceTestAdjudicationValidator(t)
	existing := newCoexistenceTestAdjudication(coexistenceAdminUser)

	tests := []struct {
		name    string
		user    authenticationv1.UserInfo
		allowed bool
	}{
		{
			name:    "admin delete allowed",
			user:    coexistenceAdminIdentity(),
			allowed: true,
		},
		{
			name: "non-admin delete denied",
			user: coexistenceUser(coexistenceTenantUser, "system:serviceaccounts", "system:authenticated"),
		},
		{
			name:    "namespace-controller cleanup delete allowed",
			user:    coexistenceUser("system:serviceaccount:kube-system:namespace-controller", "system:serviceaccounts"),
			allowed: true,
		},
		{
			name:    "garbage-collector cleanup delete allowed",
			user:    coexistenceUser("system:serviceaccount:kube-system:generic-garbage-collector", "system:serviceaccounts"),
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := validator.Handle(context.Background(),
				coexistenceRequest(t, admissionv1.Delete, coexistenceAdjudicationKind, tt.user, nil, existing, ""))
			require.Equal(t, tt.allowed, resp.Allowed)
		})
	}
}
