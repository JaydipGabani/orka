package controller

import (
	"context"
	"errors"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/remediationpolicy"
)

func (d *ACPDispatcher) validateRemediationACPDispatch(ctx context.Context, task *corev1alpha1.Task, pool *corev1alpha1.RuntimePool) error {
	if !remediationpolicy.IsNativeProposal(task) {
		return nil
	}
	if d.RemediationDispatchValidator == nil {
		return errors.New("remediation ACP dispatch is disabled")
	}
	return d.RemediationDispatchValidator(ctx, task, pool)
}

func (d *ACPDispatcher) validateRemediationACPQueue(ctx context.Context, task *corev1alpha1.Task) error {
	if !remediationpolicy.IsNativeProposal(task) {
		return nil
	}
	if d.RemediationQueueValidator == nil {
		return errors.New("remediation ACP admission is disabled")
	}
	return d.RemediationQueueValidator(ctx, task)
}
