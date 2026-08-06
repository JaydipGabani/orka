/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"fmt"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/store"
)

const acpBindingConflictReason = corev1alpha1.TaskExecutionReason("BindingConflict")

// verifyAttemptBindingDigest enforces executor exclusivity through the
// immutable Task binding: durable demand created for a different binding is
// never processed. Both the durable attempt and the Task must agree on the
// binding digest; a Task bound cleanup-only never dispatches. Attempts and
// Tasks created before the binding stage was enabled carry no digest and pass
// unchanged.
func (d *ACPDispatcher) verifyAttemptBindingDigest(
	ctx context.Context,
	task *corev1alpha1.Task,
	attemptID string,
	fence store.ControllerEpochFence,
) error {
	binding := task.Status.AgentExecutionBinding
	taskDigest := ""
	if binding != nil {
		taskDigest = binding.BindingDigest
	}

	attempt, err := d.Store.GetPromptAttempt(ctx, attemptID)
	if err != nil {
		return fmt.Errorf("read durable attempt for binding verification: %w", err)
	}

	var conflict string
	switch {
	case binding != nil && binding.Mode != corev1alpha1.AgentExecutionBindingModeExecute:
		conflict = fmt.Sprintf("task binding mode %s does not authorize execution", binding.Mode)
	case binding != nil && binding.ContractVersion != corev1alpha1.AgentRuntimeContractHarnessV2:
		conflict = fmt.Sprintf("task binding contract %s is not dispatchable by the ACP executor", binding.ContractVersion)
	case attempt.BindingDigest != taskDigest:
		conflict = fmt.Sprintf("durable demand binding digest %q does not match the task's immutable binding %q; demand created for another binding is never processed",
			attempt.BindingDigest, taskDigest)
	default:
		return nil
	}

	agentExecutionBindingConflicts.WithLabelValues("demand-digest-mismatch").Inc()
	if store.IsTerminalPromptExecutionState(attempt.ExecutionState) {
		return d.failTask(ctx, task, corev1alpha1.TaskExecutionStateFailed,
			corev1alpha1.TaskExecutionOutcomeFailed, acpBindingConflictReason, conflict)
	}
	if err := d.transitionAttemptToTerminal(ctx, attemptID, fence, store.PromptExecutionFailed, "binding-conflict"); err != nil {
		return fmt.Errorf("settle binding-conflicted attempt: %w", err)
	}
	return d.failTask(ctx, task, corev1alpha1.TaskExecutionStateFailed,
		corev1alpha1.TaskExecutionOutcomeFailed, acpBindingConflictReason, conflict)
}
