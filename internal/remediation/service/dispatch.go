package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// DispatchValidator binds the exact objects being rendered to the durable
// model operation before a worker can receive restricted prompt data.
func (s *Service) DispatchValidator(ctx context.Context, task *corev1alpha1.Task, agent *corev1alpha1.Agent, provider *corev1alpha1.Provider) error {
	if s == nil || s.config.AdmissionDisabled || s.config.DispatchReader == nil {
		return ErrDisabled
	}
	if task == nil || task.Namespace != s.config.Namespace {
		return ErrPolicy
	}
	runID := task.Annotations[remediationpolicy.RunAnnotation]
	run, err := s.config.Store.GetRemediationRun(ctx, task.Namespace, runID)
	if err != nil || run.CancelRequested || run.Phase != store.RemediationPhaseRunning ||
		run.ClaimOwner == "" || !time.Now().Before(run.ClaimUntil) || !time.Now().Before(run.Deadline) {
		return ErrPolicy
	}
	var state pipelineState
	var policy Policy
	if json.Unmarshal(run.StateJSON, &state) != nil || state.Version != Version ||
		json.Unmarshal(run.PolicyJSON, &policy) != nil || Digest(run.PolicyJSON) != run.PolicyDigest ||
		policy.Namespace != task.Namespace || agent == nil || policy.AgentName != agent.Name {
		return ErrPolicy
	}
	if s.config.Authorize != nil {
		var request StoredRequest
		if json.Unmarshal(run.RequestJSON, &request) != nil {
			return ErrPolicy
		}
		if err := s.config.Authorize(ctx, task.Namespace, policy.Name, request.Actor); err != nil {
			if errors.Is(err, ErrRetryable) {
				return apierrors.NewServiceUnavailable("proposal authorization is temporarily unavailable")
			}
			return err
		}
	}
	for _, operation := range state.Models {
		if operation.Name != task.Name {
			continue
		}
		if !matchesModelDispatch(operation, task, state.ModelIdentity) || !matchesApprovedModelBoundary(policy, operation.Expected) {
			return ErrPolicy
		}
		if operation.Expected.Backend == remediationpolicy.CopilotBackend {
			return ErrPolicy
		}
		return remediationpolicy.ValidateNativeDispatch(ctx, s.config.DispatchReader, task, agent, provider)
	}
	return ErrPolicy
}

func matchesModelDispatch(operation modelOperation, task *corev1alpha1.Task, identity *remediationpolicy.PlanIdentity) bool {
	return operation.Intent && operation.Output == nil && operation.PromptDigest == Digest([]byte(task.Spec.Prompt)) &&
		(operation.UID == "" || operation.UID == string(task.UID)) &&
		operation.Expected.Digest == task.Annotations[remediationpolicy.IdentityAnnotation] &&
		identity != nil && identity.Digest == operation.Expected.Digest
}
