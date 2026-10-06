package service

import (
	"context"
	"errors"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	runtimeisolation "github.com/orka-agents/orka/internal/remediation/isolation"
	"github.com/orka-agents/orka/internal/store"
)

func (p *Pipeline) cancelController(ctx context.Context, session *Session, run *store.RemediationRun, policy Policy, state *pipelineState) error {
	operations := make([]*executionOperation, 0, 2+len(state.Attempts))
	operations = append(operations, &state.Original, &state.Control)
	for i := range state.Attempts {
		operations = append(operations, &state.Attempts[i].Operation)
	}
	pending := false
	for _, operation := range operations {
		pending = pending || !operation.Cleaned && (operation.Intent || operation.BuildIntent)
	}
	if !pending {
		return p.cancelControllerLease(ctx, session, state)
	}
	checks, err := loadExecutionPlan(ctx, session, state.Checks)
	if err != nil || checks.Controller == nil {
		return ErrInvalid
	}
	buildPlan, err := checks.buildPlan()
	if err != nil {
		return err
	}
	execution, err := p.cleanupExecutionAdapter(ctx, policy, *state.Selection)
	if err != nil {
		return err
	}
	adapter, ok := execution.(*controllerExecutionAdapter)
	if !ok {
		return ErrNeedsAdapter
	}
	var failures []error
	for _, operation := range operations {
		if operation.Cleaned || (!operation.Intent && !operation.BuildIntent) {
			continue
		}
		if operation.BuildIntent {
			if err := p.cancelOperationBuild(ctx, session, run, adapter, buildPlan, state, operation); err != nil {
				failures = append(failures, err)
				// A controller may already be active; a builder error must not
				// prevent its independently fenced cleanup from being requested.
			}
		}
		if operation.Controller != nil {
			if err := p.cancelControllerOperation(ctx, session, adapter, checks, state, operation); err != nil {
				failures = append(failures, err)
				continue
			}
		} else if operation.Intent {
			failures = append(failures, ErrUnknown)
			continue
		}
		if len(failures) == 0 {
			operation.Cleaned = true
			if err := checkpointControllerCleanup(ctx, session, state); err != nil {
				return err
			}
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	return p.cancelControllerLease(ctx, session, state)
}

func (p *Pipeline) cancelControllerLease(ctx context.Context, session *Session, state *pipelineState) error {
	err := p.releaseControllerLease(ctx, session, state)
	if errors.Is(err, ErrRetryable) {
		return ErrCleanupPending
	}
	return err
}

func (p *Pipeline) cancelControllerOperation(ctx context.Context, session *Session, adapter *controllerExecutionAdapter, plan ExecutionPlan, state *pipelineState, operation *executionOperation) error {
	if _, err := controllerAcceptance(ctx, session, operation, true); err != nil {
		return err
	}
	if err := adapter.verifyControllerLease(ctx, session, state, true); err != nil {
		return err
	}
	if operation.Controller.State.Version == 0 {
		if operation.Controller.Control != nil || operation.Controller.Isolation != nil {
			return ErrUnknown
		}
		return nil
	}
	if operation.Subject == nil {
		return ErrUnknown
	}
	evidence := jsonIdentity(struct {
		Binding environment.Bind
		Subject environment.Subject
	}{plan.Binding, *operation.Subject})
	if operation.Role != environment.PublishedOriginal {
		if operation.Build == nil {
			return ErrUnknown
		}
		evidence = operation.Build.Digest
	}
	lab, err := adapter.labForSubject(*operation.Subject, operation.ID, evidence, controllerHooks(session, state, operation, true))
	if err != nil {
		return err
	}
	prover, err := runtimeisolation.New(adapter.kube)
	if err != nil {
		return ErrNeedsAdapter
	}
	for {
		if _, err := controllerAcceptance(ctx, session, operation, true); err != nil {
			return err
		}
		if err := adapter.verifyControllerLab(ctx, session, state, true); err != nil {
			return err
		}
		if proof := operation.Controller.Isolation; proof != nil && !proof.CleanupComplete {
			if _, err := prover.Cancel(ctx, *proof, adapter.controllerIsolationCallback(session, state, operation, true)); err != nil {
				return ErrUnknown
			}
			if err := p.controllerPoll(ctx); err != nil {
				return err
			}
			continue
		}
		current := operation.Controller.State
		request := controllerlab.Request{
			RunID: operation.Controller.RunID, OperationID: operation.ID, Plan: *plan.Controller,
			BindingID: operation.ID, Cancel: true, Placement: current.Placement,
		}
		if current.Terminal() {
			if current.Phase != controllerlab.Complete || lab.ValidateState(current, request) != nil {
				return ErrUnknown
			}
			if err := adapter.cleanupControllerNamespace(ctx, session, state, operation, true); err != nil {
				return err
			}
			if controllerNamespaceClean(operation.Controller) {
				return nil
			}
		} else if _, err := lab.Step(ctx, current, request); err != nil {
			return classifyController(err)
		}
		if err := p.controllerPoll(ctx); err != nil {
			return err
		}
	}
}

func checkpointControllerCleanup(ctx context.Context, session *Session, state *pipelineState) error {
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	raw, err := marshalControllerPipeline(current.StateJSON, state)
	if err != nil {
		return err
	}
	_, err = session.store.UpdateRemediationRun(ctx, current.Namespace, current.ID, session.owner, session.epoch, current.Revision,
		store.RemediationUpdate{Phase: current.Phase, Reason: current.Reason, StateJSON: raw}, time.Now().UTC())
	return err
}
