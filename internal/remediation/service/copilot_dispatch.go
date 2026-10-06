package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (s *Service) CopilotDispatchValidator(ctx context.Context, task *corev1alpha1.Task, pool *corev1alpha1.RuntimePool) error {
	identity, err := s.copilotOperation(ctx, task)
	if err != nil {
		return copilotAdmissionError(err)
	}
	if pool == nil || task.Status.AgentExecutionBinding == nil || task.Status.Execution == nil ||
		task.Status.AgentExecutionBinding.RuntimeProfileDigest != identity.RuntimeProfileDigest ||
		pool.Spec.Runtime.Profile.Digest != identity.RuntimeProfileDigest ||
		pool.Spec.Runtime.Profile.ResourceClass != remediationpolicy.CopilotResourceClass ||
		pool.Spec.Runtime.Image != identity.RuntimeImage || pool.Spec.RuntimeNamespace != identity.RuntimeNamespace ||
		pool.Spec.Capacity == nil || pool.Spec.Capacity.MaxResidentSessions != 1 || pool.Spec.Capacity.MaxRunningPrompts != 1 ||
		string(pool.UID) != task.Status.Execution.RuntimePoolUID || pool.Namespace != task.Namespace {
		return ErrPolicy
	}
	return s.validateCopilotRuntimeProxy(ctx, pool, identity)
}

func (s *Service) validateCopilotRuntimeProxy(ctx context.Context, pool *corev1alpha1.RuntimePool, identity modelagent.PlanIdentity) error {
	if s.config.DispatchReader == nil || pool.Status.ActiveInstance == nil {
		return ErrPolicy
	}
	active := pool.Status.ActiveInstance
	if active.PodNamespace != identity.RuntimeNamespace || active.PodName == "" || active.PodUID == "" {
		return ErrPolicy
	}
	pod := &corev1.Pod{}
	if err := s.config.DispatchReader.Get(ctx, client.ObjectKey{Namespace: active.PodNamespace, Name: active.PodName}, pod); err != nil {
		return copilotAdmissionError(ErrRetryable)
	}
	if string(pod.UID) != active.PodUID || pod.DeletionTimestamp != nil {
		return copilotAdmissionError(ErrRetryable)
	}
	for _, container := range pod.Spec.Containers {
		if container.Name != "runtime" {
			continue
		}
		if container.Image != identity.RuntimeImage {
			return ErrPolicy
		}
		matched := false
		for _, env := range container.Env {
			if env.Name == "ORKA_ACP_PROVIDER_PROXY_BASE_URL" {
				if matched || env.ValueFrom != nil || env.Value != identity.ProxyEndpoint {
					return ErrPolicy
				}
				matched = true
			}
		}
		if matched {
			return nil
		}
	}
	return ErrPolicy
}

func (s *Service) CopilotQueueValidator(ctx context.Context, task *corev1alpha1.Task) error {
	_, err := s.copilotOperation(ctx, task)
	return copilotAdmissionError(err)
}

func copilotAdmissionError(err error) error {
	if errors.Is(err, ErrRetryable) {
		return apierrors.NewServiceUnavailable("Copilot proposal authority is temporarily unavailable")
	}
	return err
}

func (s *Service) copilotOperation(ctx context.Context, task *corev1alpha1.Task) (modelagent.PlanIdentity, error) {
	if s == nil || s.config.AdmissionDisabled {
		return modelagent.PlanIdentity{}, ErrDisabled
	}
	if task == nil || task.Namespace != s.config.Namespace || remediationpolicy.ValidateCopilotTask(task) != nil {
		return modelagent.PlanIdentity{}, ErrPolicy
	}
	run, err := s.config.Store.GetRemediationRun(ctx, task.Namespace, task.Annotations[remediationpolicy.RunAnnotation])
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrValidation) || errors.Is(err, store.ErrRemediationIntegrity) {
			return modelagent.PlanIdentity{}, ErrPolicy
		}
		return modelagent.PlanIdentity{}, ErrRetryable
	}
	if run == nil || run.CancelRequested || run.Phase != store.RemediationPhaseRunning || !time.Now().Before(run.Deadline) {
		return modelagent.PlanIdentity{}, ErrPolicy
	}
	if run.ClaimOwner == "" || !time.Now().Before(run.ClaimUntil) {
		return modelagent.PlanIdentity{}, ErrRetryable
	}
	operation, policy, actor, err := copilotStoredOperation(run, task)
	if err != nil {
		return modelagent.PlanIdentity{}, err
	}
	if _, exists := s.policies[policy.Name]; !exists {
		return modelagent.PlanIdentity{}, ErrPolicy
	}
	if s.config.Authorize != nil {
		if err := s.config.Authorize(ctx, task.Namespace, policy.Name, actor); err != nil {
			return modelagent.PlanIdentity{}, err
		}
	}
	pipeline, ok := s.config.Processor.(*Pipeline)
	if !ok || pipeline.Agents == nil {
		return modelagent.PlanIdentity{}, ErrPolicy
	}
	actual, err := pipeline.Agents(task.Namespace, policy.AgentName, nil).Snapshot(ctx)
	if errors.Is(err, modelagent.ErrDependencyUnavailable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return modelagent.PlanIdentity{}, ErrRetryable
	}
	if err != nil || actual.Digest != operation.Expected.Digest {
		return modelagent.PlanIdentity{}, ErrPolicy
	}
	return actual, nil
}

func copilotStoredOperation(run *store.RemediationRun, task *corev1alpha1.Task) (modelOperation, Policy, ActorIdentity, error) {
	var state pipelineState
	var request StoredRequest
	var policy Policy
	if json.Unmarshal(run.StateJSON, &state) != nil || state.Version != Version || json.Unmarshal(run.RequestJSON, &request) != nil ||
		json.Unmarshal(run.PolicyJSON, &policy) != nil || Digest(run.PolicyJSON) != run.PolicyDigest ||
		policy.Namespace != task.Namespace || policy.AgentName != task.Spec.AgentRef.Name ||
		policy.Name != request.Policy || policy.ProposalBackend != remediationpolicy.CopilotBackend {
		return modelOperation{}, Policy{}, ActorIdentity{}, ErrPolicy
	}
	for _, operation := range state.Models {
		if operation.Name != task.Name {
			continue
		}
		if operation.Expected.Backend != remediationpolicy.CopilotBackend ||
			!matchesModelDispatch(operation, task, state.ModelIdentity) || !matchesApprovedModelBoundary(policy, operation.Expected) {
			return modelOperation{}, Policy{}, ActorIdentity{}, ErrPolicy
		}
		if operation.UID == "" {
			return modelOperation{}, Policy{}, ActorIdentity{}, ErrRetryable
		}
		return operation, policy, request.Actor, nil
	}
	return modelOperation{}, Policy{}, ActorIdentity{}, ErrPolicy
}
