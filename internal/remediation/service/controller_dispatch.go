package service

import (
	"context"
	"errors"

	"github.com/orka-agents/orka/internal/store"
)

func (p *Pipeline) cleanupExecutionAdapter(ctx context.Context, policy Policy, selection AdapterSelection) (ExecutionAdapter, error) {
	if factory, ok := p.Environments.(interface {
		Cleanup(context.Context, Policy, AdapterSelection) (ExecutionAdapter, error)
	}); ok {
		return factory.Cleanup(ctx, policy, selection)
	}
	return p.Environments.Resume(ctx, policy, selection)
}

func (p *Pipeline) cancelHTTPExecutions(ctx context.Context, session *Session, run *store.RemediationRun, policy Policy, state *pipelineState) error {
	operations := make([]executionOperation, 0, 2+len(state.Attempts))
	operations = append(operations, state.Original, state.Control)
	for _, attempt := range state.Attempts {
		operations = append(operations, attempt.Operation)
	}
	pending := false
	for _, operation := range operations {
		pending = pending || !operation.Cleaned && (operation.BuildIntent || operation.Intent)
	}
	if !pending {
		return nil
	}
	adapter, err := p.cleanupExecutionAdapter(ctx, policy, *state.Selection)
	if err != nil {
		return err
	}
	checks, err := loadExecutionPlan(ctx, session, state.Checks)
	if err != nil {
		return err
	}
	if checks.HTTP == nil {
		return ErrInvalid
	}
	var failures []error
	for _, operation := range operations {
		if operation.BuildIntent && !operation.Cleaned {
			failures = append(failures, p.cancelOperationBuild(ctx, session, run, adapter, *checks.HTTP, state, &operation))
		}
		if operation.Receipt == nil && operation.Intent {
			receipt, err := readExecutionReceipt(ctx, session, operation.ID, run.ID)
			if err == nil {
				operation.Receipt = receipt
			}
		}
		if operation.Receipt != nil && !operation.Cleaned {
			failures = append(failures, adapter.Cancel(ctx, *operation.Receipt))
		} else if operation.Intent && operation.Receipt == nil {
			failures = append(failures, ErrUnknown)
		}
	}
	return errors.Join(failures...)
}
