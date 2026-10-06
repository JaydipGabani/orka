package service

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/store"
)

type buildNoEffect struct {
	ClaimEpoch  uint64                   `json:"claimEpoch"`
	InputDigest string                   `json:"inputDigest"`
	Proof       environment.NotSubmitted `json:"proof"`
}

func buildIntentRequest(runID string, plan environment.Plan, state *pipelineState, operation *executionOperation) (environment.BuildRequest, error) {
	request := environment.BuildRequest{RunID: runID, OperationID: operation.ID, Plan: plan, Role: operation.Role}
	switch operation.Role {
	case environment.RebuiltControl:
		return request, nil
	case environment.Candidate:
		for _, attempt := range state.Attempts {
			if attempt.Operation.ID == operation.ID && attempt.Operation.Role == operation.Role && attempt.Patch != nil {
				request.PatchDigest = attempt.Patch.Digest
				return request, nil
			}
		}
	}
	return request, ErrUnknown
}

func validateBuildNoEffect(run *store.RemediationRun, plan environment.Plan, state *pipelineState, operation *executionOperation) error {
	if operation.BuildNoEffect == nil || !operation.BuildIntent || operation.Build != nil || operation.Subject != nil ||
		operation.Intent || operation.Controller != nil || operation.Receipt != nil || operation.Observation != nil {
		return ErrUnknown
	}
	disposition := operation.BuildNoEffect
	request, err := buildIntentRequest(run.ID, plan, state, operation)
	if err != nil || disposition.ClaimEpoch == 0 || disposition.ClaimEpoch > run.ClaimEpoch ||
		disposition.InputDigest != run.InputDigest || !disposition.Proof.Matches(request) {
		return ErrUnknown
	}
	return nil
}

// Checkpoint the proof under the current claim and exact persisted build
// intent before cleanup can mark the operation clean or release a lab Lease.
// Merge the current envelope so cleanup-only recovery cannot resume execution.
func checkpointBuildNoEffect(ctx context.Context, session *Session, state *pipelineState, operation *executionOperation,
	request environment.BuildRequest, built environment.BuildResult, proof *environment.NotSubmitted,
) error {
	if proof == nil || request.RequireExisting || !proof.Matches(request) || !reflect.DeepEqual(built, environment.BuildResult{}) {
		return ErrUnknown
	}
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	var durable pipelineState
	if json.Unmarshal(current.StateJSON, &durable) != nil {
		return ErrInvalid
	}
	saved := pipelineOperation(&durable, operation.ID)
	if saved == nil || saved.Role != operation.Role || request.RunID != current.ID ||
		!reflect.DeepEqual(durable.Checks, state.Checks) || saved.Cleaned {
		return ErrUnknown
	}
	next := &buildNoEffect{ClaimEpoch: session.epoch, InputDigest: current.InputDigest, Proof: *proof}
	if saved.BuildNoEffect != nil && !reflect.DeepEqual(saved.BuildNoEffect, next) {
		return ErrUnknown
	}
	saved.BuildNoEffect = next
	if err := validateBuildNoEffect(current, request.Plan, &durable, saved); err != nil {
		return err
	}
	raw, err := marshalControllerPipeline(current.StateJSON, &durable)
	if err != nil {
		return err
	}
	_, err = session.store.UpdateRemediationRun(ctx, current.Namespace, current.ID, session.owner, session.epoch, current.Revision,
		store.RemediationUpdate{Phase: current.Phase, Reason: current.Reason, StateJSON: raw}, time.Now().UTC())
	if err == nil {
		operation.BuildNoEffect = next
	}
	return err
}

func (p *Pipeline) cancelOperationBuild(ctx context.Context, session *Session, run *store.RemediationRun, adapter ExecutionAdapter,
	plan environment.Plan, state *pipelineState, operation *executionOperation,
) error {
	if operation.BuildNoEffect == nil {
		return adapter.CancelBuild(ctx, run.ID, operation.ID, plan)
	}
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	var durable pipelineState
	if current.ID != run.ID || json.Unmarshal(current.StateJSON, &durable) != nil {
		return ErrUnknown
	}
	saved := pipelineOperation(&durable, operation.ID)
	if saved == nil || !reflect.DeepEqual(saved.BuildNoEffect, operation.BuildNoEffect) ||
		!reflect.DeepEqual(durable.Checks, state.Checks) {
		return ErrUnknown
	}
	return validateBuildNoEffect(current, plan, &durable, saved)
}
