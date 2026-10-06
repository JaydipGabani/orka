package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/store"
)

func (p *Pipeline) baseline(ctx context.Context, session *Session, adapter ExecutionAdapter, checks ExecutionPlan, source investigate.Plan, state *pipelineState) (executionResult, error) {
	run, err := session.Current(ctx)
	if err != nil {
		return executionResult{}, err
	}
	result := executionResult{Version: Version, Source: source.Target, ChecksDigest: checks.Binding.ChecksDigest}
	if state.Original.ID == "" {
		original := state.Selection.Original
		state.Original = executionOperation{ID: "original", Role: environment.PublishedOriginal, Subject: &original}
		state.Control = executionOperation{ID: "control", Role: environment.RebuiltControl}
		if err := p.save(ctx, session, state, "reproducing-original"); err != nil {
			return result, err
		}
	}
	result.Original, err = p.execute(ctx, session, run, adapter, checks, state, &state.Original, nil)
	if err != nil {
		return result, err
	}
	result.Control, err = p.execute(ctx, session, run, adapter, checks, state, &state.Control, nil)
	if err != nil {
		return result, err
	}
	if err := validateExecutionObservations(checks, result.Original, result.Control, nil); err != nil {
		if checks.Controller != nil && (errors.Is(err, ErrUnknown) || errors.Is(err, ErrRetryable)) {
			return result, err
		}
		return result, ErrNeedsInput
	}
	if _, err := p.putJSON(ctx, session, "baseline", result); err != nil {
		return result, err
	}
	return result, p.save(ctx, session, state, "baseline-reproduced")
}

func (p *Pipeline) executeHTTP(ctx context.Context, session *Session, run *store.RemediationRun, adapter ExecutionAdapter, checks environment.Plan, state *pipelineState, operation *executionOperation, patch []byte) (environment.Observation, error) {
	var observation environment.Observation
	if operation.Observation != nil {
		err := readJSON(ctx, session, operation.Observation, &observation)
		return observation, err
	}
	if operation.Subject == nil {
		if err := p.build(ctx, session, run, adapter, checks, state, operation, patch); err != nil {
			return observation, err
		}
	}
	if operation.Receipt == nil {
		existing := operation.Intent
		operation.Intent = true
		if err := p.save(ctx, session, state, "observing-"+string(operation.Role)); err != nil {
			return observation, err
		}
		receipt, err := adapter.Start(ctx, environment.Request{
			RunID: run.ID, OperationID: operation.ID, Plan: checks, Subject: *operation.Subject, RequireExisting: existing,
		})
		if receipt.Version == environment.Version && receipt.OperationDigest != "" &&
			receipt.Request.RunID == run.ID && receipt.Request.OperationID == operation.ID && receipt.Request.Plan.Bind == checks.Bind {
			receiptContext, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			ackErr := p.persistExecutionReceipt(receiptContext, session, receipt)
			stop()
			if ackErr != nil {
				return observation, ackErr
			}
			operation.Receipt = &receipt
		}
		if err != nil {
			return observation, classifyExecution(err)
		}
		operation.Receipt = &receipt
		if err := p.save(ctx, session, state, state.Stage); err != nil {
			return observation, err
		}
	}
	interval := p.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	for {
		if _, err := session.Current(ctx); err != nil {
			return observation, err
		}
		next, err := adapter.Observe(ctx, *operation.Receipt)
		if err != nil {
			return next, classifyExecution(err)
		}
		operation.Receipt = &next.Receipt
		if err := p.save(ctx, session, state, state.Stage); err != nil {
			return next, err
		}
		if next.Phase == environment.Completed {
			if !next.CleanupComplete {
				return next, ErrUnknown
			}
			ref, err := p.putJSON(ctx, session, "observed-"+operation.ID, next)
			if err != nil {
				return next, err
			}
			operation.Observation, operation.Cleaned = ref, true
			if err := p.save(ctx, session, state, state.Stage); err != nil {
				return next, err
			}
			return next, nil
		}
		if next.Failure != nil {
			return next, classifyExecution(next.Failure)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return next, ctx.Err()
		case <-timer.C:
		}
	}
}

func (p *Pipeline) build(ctx context.Context, session *Session, run *store.RemediationRun, adapter ExecutionAdapter, checks environment.Plan, state *pipelineState, operation *executionOperation, patch []byte) error {
	if operation.BuildNoEffect != nil {
		if err := p.cancelOperationBuild(ctx, session, run, adapter, checks, state, operation); err != nil {
			return err
		}
		return ErrNeedsInput
	}
	if controller, ok := adapter.(*controllerExecutionAdapter); ok && state.ControllerLease != nil {
		if err := controller.verifyControllerLease(ctx, session, state, false); err != nil {
			return err
		}
	}
	existing := operation.BuildIntent
	operation.BuildIntent = true
	if err := p.save(ctx, session, state, "building-"+string(operation.Role)); err != nil {
		return err
	}
	request := environment.BuildRequest{
		RunID: run.ID, OperationID: operation.ID, Plan: checks, Role: operation.Role,
		Patch: patch, RequireExisting: existing,
	}
	if len(patch) > 0 {
		request.PatchDigest = Digest(patch)
	}
	built, buildErr := adapter.Build(ctx, request)
	if proof, ok := errors.AsType[*environment.NotSubmitted](buildErr); ok {
		proofContext, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		err := checkpointBuildNoEffect(proofContext, session, state, operation, request, built, proof)
		stop()
		if err != nil {
			return err
		}
		return ErrNeedsInput
	}
	if built.ID != "" {
		ref, err := p.putJSON(ctx, session, "build-"+operation.ID, built)
		if err != nil {
			return err
		}
		operation.Build = ref
	}
	if buildErr != nil {
		var failure *environment.Error
		if errors.As(buildErr, &failure) && failure.Kind == environment.BuildFailed && operation.Role == environment.Candidate {
			return &candidateRejected{Code: "candidate-build-failed", Diagnostics: built.Diagnostics}
		}
		return classifyExecution(buildErr)
	}
	if built.Subject.Role != operation.Role || built.Subject.PatchDigest != request.PatchDigest ||
		built.Bind != checks.Bind || built.Subject.Image == "" || built.Subject.BuildID == "" {
		return ErrUnknown
	}
	operation.Subject = &built.Subject
	return p.save(ctx, session, state, "built-"+string(operation.Role))
}

func classifyExecution(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if failure, ok := errors.AsType[*environment.Error](err); ok {
		if failure.Retryable {
			return ErrRetryable
		}
		if failure.Kind == environment.NeedsAdapter {
			return ErrNeedsAdapter
		}
	}
	return ErrUnknown
}

func validateObservations(plan environment.Plan, original, control environment.Observation, patched *environment.Observation) error {
	for _, observation := range []environment.Observation{original, control} {
		if err := validateArm(plan, observation, false); err != nil {
			return err
		}
	}
	if original.Receipt.Request.Subject.Role != environment.PublishedOriginal ||
		control.Receipt.Request.Subject.Role != environment.RebuiltControl {
		return ErrInvalid
	}
	if patched != nil {
		if patched.Receipt.Request.Subject.Role != environment.Candidate ||
			patched.Receipt.Request.Subject.Image == original.Receipt.Request.Subject.Image ||
			patched.Receipt.Request.Subject.Image == control.Receipt.Request.Subject.Image {
			return ErrInvalid
		}
		return validateArm(plan, *patched, true)
	}
	return nil
}

func validateArm(plan environment.Plan, observation environment.Observation, patched bool) error {
	if observation.Phase != environment.Completed || !observation.CleanupComplete ||
		observation.Failure != nil ||
		observation.Receipt.Request.Plan.Bind != plan.Bind ||
		environment.ChecksDigest(observation.Receipt.Request.Plan) != plan.Bind.ChecksDigest ||
		len(observation.Checks) != len(plan.Checks) {
		return ErrInvalid
	}
	checks := make(map[string]environment.Check, len(plan.Checks))
	for _, check := range plan.Checks {
		checks[check.ID] = check
	}
	assertionFailed := false
	for _, observed := range observation.Checks {
		check, found := checks[observed.CheckID]
		if !found {
			return ErrInvalid
		}
		actual, err := verifiedOutcome(observation.Receipt, check, observed)
		if err != nil {
			return err
		}
		if !patched && actual == environment.OutcomeOther {
			return ErrInvalid
		}
		delete(checks, check.ID)
		expected := environment.OutcomeFailure
		if patched || check.Class == environment.Normal {
			expected = environment.OutcomeHealthy
		}
		assertionFailed = assertionFailed || actual != expected
	}
	if assertionFailed {
		return &candidateRejected{Code: "candidate-checks-failed", Checks: observation.Checks}
	}
	return nil
}

func (p *Pipeline) settleRejectedBuild(ctx context.Context, session *Session, checks ExecutionPlan, adapter ExecutionAdapter, state *pipelineState, operation *executionOperation) error {
	// Controller adapters require durable BuildJobs. Legacy HTTP BuildKit
	// adapters have no Job cancellation receipt and retain their existing path.
	if checks.Controller == nil || operation.Cleaned || !operation.BuildIntent {
		return nil
	}
	// A failed build still owns its durable intent. Settle it before another
	// proposal; a later successful observation cannot clean an earlier build.
	if operation.Role != environment.Candidate || operation.Subject != nil || operation.Intent ||
		operation.Controller != nil || operation.Receipt != nil || operation.Observation != nil {
		return ErrUnknown
	}
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	plan, err := checks.buildPlan()
	if err != nil {
		return err
	}
	if err := p.cancelOperationBuild(ctx, session, current, adapter, plan, state, operation); err != nil {
		if errors.Is(err, ErrClaimLost) || errors.Is(err, ErrRetryable) {
			return err
		}
		return classifyExecution(err)
	}
	operation.Cleaned = true
	return p.save(ctx, session, state, "rejected-build-settled")
}

func (p *Pipeline) repair(ctx context.Context, session *Session, run *store.RemediationRun, request StoredRequest, policy Policy, sourcePlan investigate.Plan, checks ExecutionPlan, adapter ExecutionAdapter, baseline executionResult, state *pipelineState) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		for index := range state.Attempts {
			if len(state.Attempts[index].Feedback) == 0 {
				continue
			}
			if err := p.settleRejectedBuild(ctx, session, checks, adapter, state, &state.Attempts[index].Operation); err != nil {
				return err
			}
		}
		if len(state.Attempts) == 0 || len(state.Attempts[len(state.Attempts)-1].Feedback) != 0 {
			if len(state.Attempts) >= policy.MaxCandidates || (request.Mode == Verify && len(state.Attempts) != 0) {
				return ErrAttemptFailed
			}
			index := len(state.Attempts)
			state.Attempts = append(state.Attempts, pipelineAttempt{
				Operation: executionOperation{ID: fmt.Sprintf("candidate-%d", index), Role: environment.Candidate},
			})
			if err := p.save(ctx, session, state, "candidate-pending"); err != nil {
				return err
			}
		}

		index := len(state.Attempts) - 1
		err := p.proposePatch(ctx, session, run, request, policy, sourcePlan, checks, state, index)
		if err == nil {
			_, patch, readErr := session.Read(ctx, state.Attempts[index].Patch.Name)
			if readErr != nil || Digest(patch) != state.Attempts[index].Patch.Digest {
				return ErrInvalid
			}
			observation, review, executeErr := p.executeReviewedCandidate(ctx, session, run, policy, sourcePlan, checks, adapter, state, index, patch)
			err = executeErr
			if err == nil {
				err = validateExecutionObservations(checks, baseline.Original, baseline.Control, &observation)
				if err == nil {
					if state.Attempts[index].Operation.Subject == nil ||
						state.Attempts[index].Operation.Subject.PatchDigest != Digest(patch) ||
						(observation.HTTP != nil && observation.HTTP.Receipt.Request.Subject.PatchDigest != Digest(patch)) {
						return ErrInvalid
					}
					baseline.Patched, baseline.PatchDigest, baseline.Conclusion = &observation, Digest(patch), "Verified for these checks"
					if _, err := session.Put(ctx, "candidate.patch", "text/x-diff", patch); err != nil {
						return err
					}
					var result any = baseline
					if review != nil {
						result = reviewedExecutionResult{executionResult: baseline, AutomatedReview: review, ReviewScope: automatedReviewScope}
					}
					if _, err := p.putJSON(ctx, session, "verification", result); err != nil {
						return err
					}
					return p.complete(ctx, session, state, "verified")
				}
			}
		}
		rejection, ok := rejected(err)
		if !ok {
			return err
		}
		feedback, err := json.Marshal(rejection)
		if err != nil {
			return err
		}
		state.Attempts[index].Feedback = feedback
		name := fmt.Sprintf("candidate-%d-failure-%s.json", index, strings.TrimPrefix(Digest(feedback), "sha256:")[:8])
		if _, err := session.Put(ctx, name, "application/json", feedback); err != nil {
			return err
		}
		if err := p.save(ctx, session, state, "repairing-candidate"); err != nil {
			return err
		}
	}
}
