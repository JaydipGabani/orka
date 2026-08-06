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
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	ctrladmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

const (
	kindAgentExecutionControl = "AgentExecutionControl"
	kindAgentExecutionPolicy  = "AgentExecutionPolicy"
)

// CoexistenceControlPolicyValidator restricts AgentExecutionControl and
// AgentExecutionPolicy spec authorship to admin groups. Status writes stay
// unrestricted because status is controller-owned and the controller is not
// an admin-group member.
type CoexistenceControlPolicyValidator struct {
	decoder ctrladmission.Decoder
	config  CoexistenceConfig
}

// NewCoexistenceControlPolicyValidator creates the AgentExecutionControl and
// AgentExecutionPolicy admission handler.
func NewCoexistenceControlPolicyValidator(scheme *runtime.Scheme, cfg CoexistenceConfig) *CoexistenceControlPolicyValidator {
	return &CoexistenceControlPolicyValidator{
		decoder: ctrladmission.NewDecoder(scheme),
		config:  cfg,
	}
}

// Handle implements admission.Handler.
func (v *CoexistenceControlPolicyValidator) Handle(_ context.Context, req ctrladmission.Request) ctrladmission.Response {
	if req.SubResource != "" {
		// Status (the only subresource on these kinds) is controller-owned;
		// spec changes cannot enter through a subresource write.
		return ctrladmission.Allowed("subresource writes are controller-owned")
	}
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		return ctrladmission.Allowed("operation does not author backend control or policy specs")
	}

	kind := req.Kind.Kind
	if kind != kindAgentExecutionControl && kind != kindAgentExecutionPolicy {
		return ctrladmission.Errored(http.StatusBadRequest,
			fmt.Errorf("unexpected kind %q for the coexistence control/policy webhook", kind))
	}

	isAdmin := v.config.isAdminIdentity(req.UserInfo)
	if req.Operation == admissionv1.Create {
		if !isAdmin {
			return ctrladmission.Denied(fmt.Sprintf(
				"%s creation is restricted to admin groups %v", kind, v.config.AdminGroups))
		}
		return ctrladmission.Allowed("admin-authored spec creation")
	}

	specChanged, err := v.specChanged(req, kind)
	if err != nil {
		return ctrladmission.Errored(http.StatusBadRequest, err)
	}
	if specChanged && !isAdmin {
		return ctrladmission.Denied(fmt.Sprintf(
			"%s spec updates are restricted to admin groups %v", kind, v.config.AdminGroups))
	}
	return ctrladmission.Allowed("no restricted spec change")
}

func (v *CoexistenceControlPolicyValidator) specChanged(req ctrladmission.Request, kind string) (bool, error) {
	switch kind {
	case kindAgentExecutionControl:
		control := &corev1alpha1.AgentExecutionControl{}
		if err := v.decoder.Decode(req, control); err != nil {
			return false, fmt.Errorf("decode AgentExecutionControl: %w", err)
		}
		oldControl := &corev1alpha1.AgentExecutionControl{}
		if err := v.decoder.DecodeRaw(req.OldObject, oldControl); err != nil {
			return false, fmt.Errorf("decode old AgentExecutionControl: %w", err)
		}
		return !apiequality.Semantic.DeepEqual(oldControl.Spec, control.Spec), nil
	case kindAgentExecutionPolicy:
		policy := &corev1alpha1.AgentExecutionPolicy{}
		if err := v.decoder.Decode(req, policy); err != nil {
			return false, fmt.Errorf("decode AgentExecutionPolicy: %w", err)
		}
		oldPolicy := &corev1alpha1.AgentExecutionPolicy{}
		if err := v.decoder.DecodeRaw(req.OldObject, oldPolicy); err != nil {
			return false, fmt.Errorf("decode old AgentExecutionPolicy: %w", err)
		}
		return !apiequality.Semantic.DeepEqual(oldPolicy.Spec, policy.Spec), nil
	default:
		return false, fmt.Errorf("unexpected kind %q for the coexistence control/policy webhook", kind)
	}
}
