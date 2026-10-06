package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/provenance"
	"github.com/orka-agents/orka/internal/security"
	"github.com/orka-agents/orka/internal/store"
)

func (p *Pipeline) execute(ctx context.Context, session *Session, run *store.RemediationRun, adapter ExecutionAdapter, checks ExecutionPlan, state *pipelineState, operation *executionOperation, patch []byte) (ExecutionObservation, error) {
	buildPlan, err := checks.buildPlan()
	if err != nil {
		return ExecutionObservation{}, err
	}
	if checks.HTTP != nil {
		observation, err := p.executeHTTP(ctx, session, run, adapter, buildPlan, state, operation, patch)
		return ExecutionObservation{HTTP: &observation}, err
	}
	controller, ok := adapter.(*controllerExecutionAdapter)
	if !ok {
		return ExecutionObservation{}, ErrNeedsAdapter
	}
	return p.executeController(ctx, session, run, controller, checks, state, operation, patch)
}

func (p *Pipeline) executeController(ctx context.Context, session *Session, run *store.RemediationRun, adapter *controllerExecutionAdapter, checks ExecutionPlan, state *pipelineState, operation *executionOperation, patch []byte) (ExecutionObservation, error) {
	plan, err := checks.buildPlan()
	if err != nil {
		return ExecutionObservation{}, err
	}
	if operation.Subject == nil {
		if err := p.build(ctx, session, run, adapter, plan, state, operation, patch); err != nil {
			return ExecutionObservation{}, err
		}
	}
	evidence, err := validateControllerSubject(ctx, session, checks, state, operation, patch)
	if err != nil {
		return ExecutionObservation{}, err
	}
	if err := adapter.prepareControllerLease(ctx, session, state, operation); err != nil {
		return ExecutionObservation{}, err
	}
	if operation.Controller == nil {
		operation.Controller = &controllerOperation{RunID: run.ID, InputDigest: run.InputDigest, OperationID: operation.ID}
		operation.Intent = true
		if err := p.save(ctx, session, state, "observing-"+string(operation.Role)); err != nil {
			return ExecutionObservation{}, err
		}
	}
	lab, err := adapter.labForOperation(session, state, operation, evidence)
	if err != nil {
		return ExecutionObservation{}, err
	}
	request := controllerlab.Request{RunID: run.ID, OperationID: operation.ID, Plan: *checks.Controller, BindingID: operation.ID}
	if operation.Observation != nil {
		return adapter.restoreObservation(ctx, session, lab, operation, request)
	}
	for {
		if _, err := controllerAcceptance(ctx, session, operation, false); err != nil {
			return ExecutionObservation{}, err
		}
		if err := adapter.verifyControllerLab(ctx, session, state, false); err != nil {
			return ExecutionObservation{}, err
		}
		observed := operation.Controller.State
		if observed.Terminal() {
			result, done, err := p.completeControllerObservation(ctx, session, adapter, lab, state, operation, request)
			if err != nil || done {
				return result, err
			}
			if err := p.controllerPoll(ctx); err != nil {
				return ExecutionObservation{}, err
			}
			continue
		}
		if observed.Phase == controllerlab.WaitingPlacement && observed.Placement == nil {
			ready, err := p.proveControllerPlacement(ctx, session, adapter, lab, state, operation)
			if err != nil {
				return ExecutionObservation{}, err
			}
			if !ready {
				if err := p.controllerPoll(ctx); err != nil {
					return ExecutionObservation{}, err
				}
				continue
			}
		}
		request.Placement = operation.Controller.State.Placement
		if operation.Controller.Proof != nil && observed.Phase != controllerlab.Cleaning {
			placement, err := adapter.verifyControllerProof(ctx, session, lab, operation)
			if err != nil {
				return ExecutionObservation{}, err
			}
			request.Placement = &placement
		}
		next, stepErr := lab.Step(ctx, operation.Controller.State, request)
		if stepErr != nil {
			var failure *controllerlab.Error
			if errors.As(stepErr, &failure) && failure.Kind == controllerlab.Infrastructure && next.Phase == controllerlab.Cleaning {
				continue
			}
			return ExecutionObservation{}, classifyController(stepErr)
		}
		if err := p.controllerPoll(ctx); err != nil {
			return ExecutionObservation{}, err
		}
	}
}

func (a *controllerExecutionAdapter) restoreObservation(ctx context.Context, session *Session, lab *controllerlab.Adapter, operation *executionOperation, request controllerlab.Request) (ExecutionObservation, error) {
	var observed controllerlab.State
	if err := readJSON(ctx, session, operation.Observation, &observed); err != nil {
		return ExecutionObservation{}, err
	}
	request.Placement = observed.Placement
	if !reflect.DeepEqual(observed, operation.Controller.State) || !operation.Cleaned ||
		lab.ValidateState(observed, request) != nil || !controllerNamespaceClean(operation.Controller) ||
		(observed.Placement != nil && a.verifyRetainedControllerProof(ctx, session, lab, operation) != nil) {
		return ExecutionObservation{}, ErrInvalid
	}
	return ExecutionObservation{Controller: &observed}, nil
}

func (p *Pipeline) completeControllerObservation(ctx context.Context, session *Session, adapter *controllerExecutionAdapter, lab *controllerlab.Adapter, state *pipelineState, operation *executionOperation, request controllerlab.Request) (ExecutionObservation, bool, error) {
	observed := operation.Controller.State
	if observed.Phase != controllerlab.Complete {
		return ExecutionObservation{}, false, ErrUnknown
	}
	if err := adapter.cleanupControllerNamespace(ctx, session, state, operation, false); err != nil {
		return ExecutionObservation{}, false, err
	}
	if !controllerNamespaceClean(operation.Controller) {
		return ExecutionObservation{}, false, nil
	}
	request.Placement = observed.Placement
	if lab.ValidateState(observed, request) != nil ||
		(observed.Placement != nil && adapter.verifyRetainedControllerProof(ctx, session, lab, operation) != nil) {
		return ExecutionObservation{}, false, ErrInvalid
	}
	ref, err := p.putJSON(ctx, session, "observed-"+operation.ID, observed)
	if err != nil {
		return ExecutionObservation{}, false, err
	}
	operation.Observation, operation.Cleaned = ref, true
	if err := p.save(ctx, session, state, state.Stage); err != nil {
		return ExecutionObservation{}, false, err
	}
	return ExecutionObservation{Controller: &observed}, true, nil
}

func (p *Pipeline) controllerPoll(ctx context.Context) error {
	interval := p.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validateControllerSubject(ctx context.Context, session *Session, checks ExecutionPlan, state *pipelineState, operation *executionOperation, patch []byte) (string, error) {
	subject := operation.Subject
	if subject == nil || subject.Role != operation.Role || !pinnedControllerImage(subject.Image) {
		return "", ErrInvalid
	}
	if subject.Role == environment.PublishedOriginal {
		if state.Selection == nil || *subject != state.Selection.Original || len(patch) != 0 {
			return "", ErrInvalid
		}
		return jsonIdentity(struct {
			Binding environment.Bind
			Subject environment.Subject
		}{checks.Binding, *subject}), nil
	}
	var built environment.BuildResult
	if readJSON(ctx, session, operation.Build, &built) != nil ||
		built.Bind != checks.Binding || built.Subject != *subject || built.ID != subject.BuildID ||
		built.OriginalRecipeDigest != checks.Binding.Recipe.ContentDigest ||
		built.Baseline.ContentDigest != checks.Binding.Recipe.ContentDigest ||
		built.Built.ContentDigest != built.BuildRecipeDigest ||
		security.CanonicalRepositoryCloneURL(built.Baseline.UpstreamRepoURL) != checks.Binding.SourceTarget.Repository ||
		built.Baseline.UpstreamCommit != checks.Binding.SourceTarget.Commit ||
		built.Baseline.RecipeCommit != checks.Binding.Recipe.Commit ||
		built.Baseline.Target != checks.Binding.Recipe.Target || built.Baseline.Platform != checks.Binding.Recipe.Platform ||
		!validDigest(built.MetadataDigest) || !validDigest(built.WorkerEvidenceDigest) {
		return "", ErrInvalid
	}
	switch subject.Role {
	case environment.RebuiltControl:
		if len(patch) != 0 || subject.PatchDigest != "" || provenance.Compare(built.Baseline, built.Built) != nil {
			return "", ErrInvalid
		}
	case environment.Candidate:
		if subject.PatchDigest != Digest(patch) || len(patch) == 0 ||
			provenance.CompareWithAdditionalPatch(built.Baseline, built.Built, subject.PatchDigest) != nil {
			return "", ErrInvalid
		}
	default:
		return "", ErrInvalid
	}
	return operation.Build.Digest, nil
}

func classifyController(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if failure, ok := errors.AsType[*controllerlab.Error](err); ok {
		switch failure.Kind {
		case controllerlab.NeedsAdapter, controllerlab.OutsideScope:
			return ErrNeedsAdapter
		case controllerlab.Infrastructure:
			return ErrRetryable
		}
	}
	return ErrUnknown
}

func validateExecutionObservations(plan ExecutionPlan, original, control ExecutionObservation, candidate *ExecutionObservation) error {
	if plan.HTTP != nil && plan.Controller == nil {
		if original.HTTP == nil || original.Controller != nil || control.HTTP == nil || control.Controller != nil {
			return ErrInvalid
		}
		var patched *environment.Observation
		if candidate != nil {
			if candidate.Controller != nil || candidate.HTTP == nil {
				return ErrInvalid
			}
			patched = candidate.HTTP
		}
		return validateObservations(*plan.HTTP, *original.HTTP, *control.HTTP, patched)
	}
	return validateControllerObservations(plan, original, control, candidate)
}

func validateControllerObservations(plan ExecutionPlan, original, control ExecutionObservation, candidate *ExecutionObservation) error {
	if plan.Controller == nil || original.Controller == nil || control.Controller == nil || original.HTTP != nil || control.HTTP != nil {
		return ErrInvalid
	}
	arms := []controllerlab.State{*original.Controller, *control.Controller}
	roles := []controllerlab.Role{controllerlab.Original, controllerlab.Control}
	for index, arm := range arms {
		if arm.Outcome == controllerlab.Inconclusive {
			return ErrUnknown
		}
		if err := controllerCompletedArm(*plan.Controller, arm, roles[index]); err != nil {
			return err
		}
		if arm.Outcome != controllerlab.Reproduced || !arm.Evidence.CrossObserved ||
			arm.Evidence.InitialNormal != [2]bool{true, true} {
			return ErrNeedsInput
		}
		if plan.Controller.Capability == controllerlab.KEDAEventPublishing {
			publishing := arm.Evidence.Publishing
			if publishing == nil || !controllerNormalControlsComplete(*plan.Controller, arm.Evidence) ||
				!publishing.HTTPCrossObserved || !publishing.HTTPSCrossObserved ||
				!controllerCredentialAttackReproduced(publishing) {
				return ErrNeedsInput
			}
		}
	}
	if arms[0].ConfigDigest != arms[1].ConfigDigest || arms[0].RunID != arms[1].RunID ||
		arms[0].OperationDigest == arms[1].OperationDigest {
		return ErrInvalid
	}
	if candidate == nil {
		return nil
	}
	if candidate.HTTP != nil || candidate.Controller == nil {
		return ErrInvalid
	}
	return validateControllerCandidate(*plan.Controller, arms[0], arms[1], *candidate.Controller)
}

func validateControllerCandidate(plan controllerlab.Plan, original, control, patched controllerlab.State) error {
	if err := controllerCompletedArm(plan, patched, controllerlab.Candidate); err != nil {
		return err
	}
	if patched.ConfigDigest != original.ConfigDigest || patched.RunID != original.RunID ||
		patched.ImageDigest == original.ImageDigest || patched.ImageDigest == control.ImageDigest {
		return ErrInvalid
	}
	if patched.Outcome == controllerlab.StillExposed {
		return &candidateRejected{Code: "candidate-controller-still-exposed"}
	}
	if plan.Capability == controllerlab.KEDAEventPublishing &&
		!controllerCredentialAttackAbsent(patched.Evidence.Publishing) {
		return &candidateRejected{Code: "candidate-controller-credential-still-exposed"}
	}
	if patched.Outcome == controllerlab.Inconclusive && patched.Reason == "observation-deadline-exceeded" &&
		patched.Evidence.Generation == 1 && !patched.WindowStartedAt.IsZero() &&
		!controllerNormalControlsComplete(plan, patched.Evidence) {
		return &candidateRejected{Code: "candidate-controller-normal-controls-failed"}
	}
	if patched.Outcome == controllerlab.Inconclusive {
		return ErrUnknown
	}
	if err := controllerlab.Compare(original, control, patched); err != nil {
		return ErrInvalid
	}
	return nil
}

func controllerCompletedArm(plan controllerlab.Plan, state controllerlab.State, role controllerlab.Role) error {
	if plan.Capability == controllerlab.KEDAEventPublishing {
		if state.Capability != controllerlab.KEDAEventPublishing || state.Evidence.Publishing == nil {
			return ErrInvalid
		}
	} else if state.Capability != "" || state.Evidence.Publishing != nil {
		return ErrInvalid
	}
	if state.Version != controllerlab.Version || state.Revision == 0 || state.Phase != controllerlab.Complete ||
		state.Role != role || state.PlanDigest != controllerlab.PlanDigest(plan) ||
		state.RunID == "" || !validDigest("sha256:"+state.OperationDigest) ||
		!validDigest("sha256:"+state.ConfigDigest) || !validDigest("sha256:"+state.ImageDigest) ||
		state.Intent != nil || state.Placement == nil || state.Placement.OperationDigest != state.OperationDigest ||
		state.SubjectStartedAt.IsZero() || !validDigest("sha256:"+state.Placement.ProofDigest) || state.Placement.NodeName == "" ||
		len(state.Receipts) == 0 {
		return ErrInvalid
	}
	for _, receipt := range state.Receipts {
		if receipt.Object.UID == "" || !receipt.Deleted || !receipt.DeleteRequested {
			return ErrInvalid
		}
	}
	return controllerNamespaceReceipts(state)
}

func controllerNamespaceReceipts(state controllerlab.State) error {
	if state.ObserverNamespace == "" || state.Namespaces[0] == state.Namespaces[1] ||
		state.ObserverNamespace == state.Namespaces[0] || state.ObserverNamespace == state.Namespaces[1] ||
		!validDigest("sha256:"+state.ObserverImageDigest) {
		return ErrInvalid
	}
	for _, namespace := range []string{state.Namespaces[0], state.Namespaces[1], state.ObserverNamespace} {
		found := false
		for _, receipt := range state.Receipts {
			if receipt.Object.Resource.Group == "" && receipt.Object.Resource.Version == "v1" &&
				receipt.Object.Resource.Resource == "namespaces" && receipt.Object.Namespace == "" && receipt.Object.Name == namespace {
				found = true
			}
		}
		if !found {
			return ErrInvalid
		}
	}
	return nil
}

func controllerNamespaceClean(operation *controllerOperation) bool {
	return operation.Control == nil || operation.Control.UID != "" && operation.Control.DeleteRequested && operation.Control.Deleted
}

func controllerProofDigest(value any) string {
	raw, _ := json.Marshal(value)
	return strings.TrimPrefix(Digest(raw), "sha256:")
}
