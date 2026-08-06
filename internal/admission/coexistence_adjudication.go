/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package admission

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	ctrladmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

// kubernetesCleanupUsernames are the built-in Kubernetes garbage-collection
// and namespace-teardown identities allowed to delete adjudication records so
// namespace deletion and owner-reference cleanup are never stranded by the
// fail-closed webhook. Mirrors config/admission/gateway_task_protection.yaml.
var kubernetesCleanupUsernames = []string{
	"system:serviceaccount:kube-system:generic-garbage-collector",
	"system:serviceaccount:kube-system:garbage-collector",
	"system:serviceaccount:kube-system:namespace-controller",
	"system:kube-controller-manager",
}

// CoexistenceAdjudicationValidator restricts AgentExecutionAdjudication
// authorship to admin groups, pins spec.requestedBy to the verified requester
// identity, and keeps the admin-authored spec immutable. Status remains
// controller-owned.
type CoexistenceAdjudicationValidator struct {
	decoder ctrladmission.Decoder
	config  CoexistenceConfig
}

// NewCoexistenceAdjudicationValidator creates the AgentExecutionAdjudication
// admission handler.
func NewCoexistenceAdjudicationValidator(scheme *runtime.Scheme, cfg CoexistenceConfig) *CoexistenceAdjudicationValidator {
	return &CoexistenceAdjudicationValidator{
		decoder: ctrladmission.NewDecoder(scheme),
		config:  cfg,
	}
}

// Handle implements admission.Handler.
func (v *CoexistenceAdjudicationValidator) Handle(_ context.Context, req ctrladmission.Request) ctrladmission.Response {
	switch req.Operation {
	case admissionv1.Create:
		return v.validateCreate(req)
	case admissionv1.Update:
		return v.validateUpdate(req)
	case admissionv1.Delete:
		return v.validateDelete(req)
	default:
		return ctrladmission.Allowed("operation does not author adjudication state")
	}
}

func (v *CoexistenceAdjudicationValidator) validateCreate(req ctrladmission.Request) ctrladmission.Response {
	if !v.config.isAdminIdentity(req.UserInfo) {
		return ctrladmission.Denied(fmt.Sprintf(
			"AgentExecutionAdjudication creation is restricted to admin groups %v",
			v.config.AdminGroups))
	}

	adjudication := &corev1alpha1.AgentExecutionAdjudication{}
	if err := v.decoder.Decode(req, adjudication); err != nil {
		return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode AgentExecutionAdjudication: %w", err))
	}

	username := strings.TrimSpace(req.UserInfo.Username)
	if username == "" || adjudication.Spec.RequestedBy != username {
		return ctrladmission.Denied(fmt.Sprintf(
			"spec.requestedBy %q must equal the verified requester identity %q",
			adjudication.Spec.RequestedBy, username))
	}
	return ctrladmission.Allowed("admin-authored adjudication with verified requester identity")
}

func (v *CoexistenceAdjudicationValidator) validateUpdate(req ctrladmission.Request) ctrladmission.Response {
	if req.SubResource == "status" {
		return ctrladmission.Allowed("adjudication status is controller-owned")
	}

	adjudication := &corev1alpha1.AgentExecutionAdjudication{}
	if err := v.decoder.Decode(req, adjudication); err != nil {
		return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode AgentExecutionAdjudication: %w", err))
	}
	oldAdjudication := &corev1alpha1.AgentExecutionAdjudication{}
	if err := v.decoder.DecodeRaw(req.OldObject, oldAdjudication); err != nil {
		return ctrladmission.Errored(http.StatusBadRequest, fmt.Errorf("decode old AgentExecutionAdjudication: %w", err))
	}

	if !apiequality.Semantic.DeepEqual(oldAdjudication.Spec, adjudication.Spec) {
		return ctrladmission.Denied(
			"AgentExecutionAdjudication spec is immutable; create a new adjudication instead of editing an existing one")
	}
	return ctrladmission.Allowed("adjudication spec unchanged")
}

func (v *CoexistenceAdjudicationValidator) validateDelete(req ctrladmission.Request) ctrladmission.Response {
	if v.config.isAdminIdentity(req.UserInfo) {
		return ctrladmission.Allowed("admin-authorized adjudication deletion")
	}
	if slices.Contains(kubernetesCleanupUsernames, strings.TrimSpace(req.UserInfo.Username)) {
		return ctrladmission.Allowed("Kubernetes garbage-collection or namespace-teardown deletion")
	}
	return ctrladmission.Denied(fmt.Sprintf(
		"AgentExecutionAdjudication deletion is restricted to admin groups %v and Kubernetes cleanup controllers",
		v.config.AdminGroups))
}
