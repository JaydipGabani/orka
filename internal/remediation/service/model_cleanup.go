package service

import (
	"context"
	"errors"
	"time"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/store"
)

func (p *Pipeline) retireModel(ctx context.Context, session *Session, run *store.RemediationRun, policy Policy, state *pipelineState, key string) error {
	operation := state.Models[key]
	if operation.Retired {
		return nil
	}
	proposer := p.Agents(run.Namespace, policy.AgentName, nil)
	for {
		if _, err := session.Current(ctx); err != nil {
			return err
		}
		err := proposer.Retire(ctx, operation.Name, operation.UID)
		if err == nil {
			operation.Retired = true
			state.Models[key] = operation
			return p.save(ctx, session, state, state.Stage)
		}
		if !errors.Is(err, modelagent.ErrCancellationPending) && !errors.Is(err, modelagent.ErrDependencyUnavailable) {
			return ErrUnknown
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
