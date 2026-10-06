package agent

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (c CopilotClient) pause(ctx context.Context) error {
	interval := c.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	return wait(ctx, interval)
}

func (c CopilotClient) snapshotWhenAvailable(ctx context.Context) (PlanIdentity, error) {
	for {
		identity, err := c.Snapshot(ctx)
		if !errors.Is(err, ErrDependencyUnavailable) {
			return identity, err
		}
		if err := c.pause(ctx); err != nil {
			return PlanIdentity{}, err
		}
	}
}

func (c CopilotClient) readCopilotTask(ctx context.Context, key client.ObjectKey, acceptancePending bool) (*corev1alpha1.Task, error) {
	for {
		task := &corev1alpha1.Task{}
		err := c.Reader.Get(ctx, key, task)
		if err == nil || (apierrors.IsNotFound(err) && !acceptancePending) {
			return task, err
		}
		if !apierrors.IsNotFound(err) && !errors.Is(copilotIdentityReadError(ctx, err), ErrDependencyUnavailable) {
			return nil, copilotIdentityReadError(ctx, err)
		}
		if err := c.pause(ctx); err != nil {
			return nil, err
		}
	}
}

func (c CopilotClient) acceptTask(ctx context.Context, request Request, expected *corev1alpha1.Task, result *Result, attempted *bool) error {
	var task *corev1alpha1.Task
	var err error
	if request.RequireExisting || request.ExpectedTaskUID != "" {
		task, err = c.readCopilotTask(ctx, client.ObjectKeyFromObject(expected), false)
	} else {
		task = &corev1alpha1.Task{}
		err = c.Reader.Get(ctx, client.ObjectKeyFromObject(expected), task)
		if err != nil && !apierrors.IsNotFound(err) {
			return copilotIdentityReadError(ctx, err)
		}
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if apierrors.IsNotFound(err) {
		if request.RequireExisting || request.ExpectedTaskUID != "" {
			return errors.New("accepted Copilot Task is missing; replacement is forbidden")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		*attempted = true
		created := expected.DeepCopy()
		createErr := c.Client.Create(ctx, created)
		if apierrors.IsInvalid(createErr) || apierrors.IsForbidden(createErr) ||
			apierrors.IsUnauthorized(createErr) || apierrors.IsBadRequest(createErr) {
			*attempted = false
			return nativePublicError(ctx, createErr, "Copilot proposal creation was rejected")
		}
		if createErr == nil {
			// Persist the acknowledged UID before any follow-up read can fail.
			// Observation still revalidates uncached identity before using output.
			return c.recordCopilotAcceptance(ctx, created, expected, result)
		}
		// An uncertain Create is never repeated; observe the exact named object.
		task, err = c.readCopilotTask(ctx, client.ObjectKeyFromObject(expected), true)
		if err != nil {
			return err
		}
	}
	return c.recordCopilotAcceptance(ctx, task, expected, result)
}

func (c CopilotClient) recordCopilotAcceptance(ctx context.Context, task, expected *corev1alpha1.Task, result *Result) error {
	if err := matchCopilotTask(task, expected, result); err != nil {
		return err
	}
	if c.OnAccepted != nil {
		if err := c.OnAccepted(ctx, *result); err != nil {
			return nativePublicError(ctx, err, "Copilot acceptance checkpoint failed")
		}
	}
	return nil
}

func (c CopilotClient) observeCopilotResult(ctx context.Context, expected *corev1alpha1.Task, identity PlanIdentity, result *Result) (string, error) {
	for {
		current, err := c.snapshotWhenAvailable(ctx)
		if err != nil {
			return "", err
		}
		if current.Digest != identity.Digest {
			return "", remediationpolicy.ErrIdentityChanged
		}
		task, err := c.readCopilotTask(ctx, client.ObjectKeyFromObject(expected), false)
		if apierrors.IsNotFound(err) {
			return "", remediationpolicy.ErrIdentityChanged
		}
		if err != nil {
			return "", err
		}
		if err := matchCopilotTask(task, expected, result); err != nil {
			return "", err
		}
		switch task.Status.Phase {
		case corev1alpha1.TaskPhaseSucceeded:
			output, err := c.completedCopilotResult(ctx, expected, task, identity, result)
			if !errors.Is(err, ErrDependencyUnavailable) {
				return output, err
			}
		case corev1alpha1.TaskPhaseFailed, corev1alpha1.TaskPhaseCancelled:
			return "", errors.New("copilot proposal ended without usable output")
		}
		if err := c.pause(ctx); err != nil {
			return "", err
		}
	}
}

func (c CopilotClient) completedCopilotResult(ctx context.Context, expected, task *corev1alpha1.Task, identity PlanIdentity, result *Result) (string, error) {
	if task.Status.Execution == nil || task.Status.Execution.State != corev1alpha1.TaskExecutionStateSucceeded {
		return "", errors.New("copilot completion lacks fenced ACP evidence")
	}
	raw, err := c.Results.GetResult(ctx, c.Namespace, task.Name)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if errors.Is(err, store.ErrRemediationIntegrity) || errors.Is(err, store.ErrValidation) {
			return "", remediationpolicy.ErrIdentityChanged
		}
		return "", ErrDependencyUnavailable
	}
	after, err := c.readCopilotTask(ctx, client.ObjectKeyFromObject(expected), false)
	if apierrors.IsNotFound(err) {
		return "", remediationpolicy.ErrIdentityChanged
	}
	if err != nil {
		return "", err
	}
	if err := matchCopilotTask(after, expected, result); err != nil {
		return "", err
	}
	if after.Status.Execution == nil {
		return "", errors.New("copilot completion lost its fenced ACP evidence")
	}
	beforeExecution, afterExecution := *task.Status.Execution, *after.Status.Execution
	// Terminal projections refresh diagnostics. Recovery can advance ownership
	// and append cleanup evidence without changing the completed execution.
	beforeExecution.LastTransitionTime, afterExecution.LastTransitionTime = nil, nil
	beforeExecution.Reason, afterExecution.Reason = "", ""
	beforeExecution.Message, afterExecution.Message = "", ""
	if afterExecution.ControllerEpoch > beforeExecution.ControllerEpoch {
		beforeExecution.ControllerEpoch = afterExecution.ControllerEpoch
	}
	if beforeExecution.RuntimeSessionCleanupDigest == "" && remediationpolicy.ValidDigest(afterExecution.RuntimeSessionCleanupDigest) {
		beforeExecution.RuntimeSessionCleanupDigest = afterExecution.RuntimeSessionCleanupDigest
	}
	if after.Status.Phase != corev1alpha1.TaskPhaseSucceeded || beforeExecution != afterExecution ||
		len(raw) > maxResponseBytes || !utf8.Valid(raw) || strings.TrimSpace(string(raw)) == "" || string(raw) == emptyProposalOutput {
		return "", errors.New("copilot result is incomplete or its execution changed")
	}
	current, err := c.snapshotWhenAvailable(ctx)
	if err != nil {
		return "", err
	}
	if current.Digest != identity.Digest {
		return "", remediationpolicy.ErrIdentityChanged
	}
	return string(raw), nil
}
