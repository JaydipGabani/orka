package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/disclosure"
	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/store"
)

func (p *Pipeline) Run(ctx context.Context, session *Session) error {
	run, request, policy, state, err := p.load(ctx, session)
	if err != nil {
		return err
	}
	if state.ModelIdentity == nil {
		return ErrNeedsInput
	}
	if p.Source == nil || p.Environments == nil {
		return ErrNeedsAdapter
	}
	report, err := p.acquire(ctx, session, request, &state)
	if err != nil {
		return err
	}
	if report.Restricted && !policy.AllowRestrictedModel {
		return ErrNeedsInput
	}
	sourcePlan, err := p.investigate(ctx, session, run, policy, report, &state)
	if err != nil {
		return err
	}
	var adapter ExecutionAdapter
	if state.Selection == nil {
		selected, execution, err := p.Environments.Select(ctx, policy, sourcePlan)
		if err != nil {
			return err
		}
		state.Selection, adapter = &selected, execution
		if err := p.save(ctx, session, &state, "planning-checks"); err != nil {
			return err
		}
	} else {
		adapter, err = p.Environments.Resume(ctx, policy, *state.Selection)
		if err != nil {
			return err
		}
	}
	checks, err := p.prepareChecks(ctx, session, run, policy, sourcePlan, adapter, &state)
	if err != nil {
		return err
	}
	if err := p.approvePlan(ctx, session, policy, &state); err != nil {
		return err
	}
	baseline, err := p.baseline(ctx, session, adapter, checks, sourcePlan, &state)
	if err != nil {
		return err
	}
	if request.Mode == Validate {
		baseline.Conclusion = "Reproduced"
		if _, err := p.putJSON(ctx, session, "report-validation", baseline); err != nil {
			return err
		}
		return p.complete(ctx, session, &state, "report-validated")
	}
	return p.repair(ctx, session, run, request, policy, sourcePlan, checks, adapter, baseline, &state)
}

func (p *Pipeline) load(ctx context.Context, session *Session) (*store.RemediationRun, StoredRequest, Policy, pipelineState, error) {
	run, err := session.Current(ctx)
	var request StoredRequest
	var policy Policy
	state := pipelineState{Version: Version, Models: make(map[string]modelOperation)}
	if err != nil {
		return nil, request, policy, state, err
	}
	if json.Unmarshal(run.RequestJSON, &request) != nil || json.Unmarshal(run.PolicyJSON, &policy) != nil ||
		Digest(run.PolicyJSON) != run.PolicyDigest || validatePolicy(policy) != nil {
		return nil, request, policy, state, ErrInvalid
	}
	if len(run.StateJSON) != 0 && json.Unmarshal(run.StateJSON, &state) != nil {
		return nil, request, policy, state, ErrInvalid
	}
	if state.Models == nil {
		state.Models = make(map[string]modelOperation)
	}
	if state.Version != Version || request.RequestID != run.RequestID || string(request.Mode) != run.Mode ||
		policy.Namespace != run.Namespace {
		return nil, request, policy, state, ErrInvalid
	}
	return run, request, policy, state, nil
}

func (p *Pipeline) save(ctx context.Context, session *Session, state *pipelineState, stage string) error {
	state.Stage = stage
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return session.Checkpoint(ctx, store.RemediationPhaseRunning, "", raw, "")
}

func (p *Pipeline) complete(ctx context.Context, session *Session, state *pipelineState, stage string) error {
	if err := p.releaseControllerLease(ctx, session, state); err != nil {
		return err
	}
	state.Stage = stage
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return session.Checkpoint(ctx, store.RemediationPhaseSucceeded, "", raw, "")
}

func (p *Pipeline) putJSON(ctx context.Context, session *Session, prefix string, value any) (*store.RemediationArtifact, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if disclosure.Check(disclosure.Artifact, raw) != nil {
		return nil, ErrNeedsInput
	}
	name := prefix + "-" + strings.TrimPrefix(Digest(raw), "sha256:")[:16] + ".json"
	return session.Put(ctx, name, "application/json", raw)
}

func readJSON(ctx context.Context, session *Session, ref *store.RemediationArtifact, value any) error {
	if ref == nil {
		return ErrInvalid
	}
	found, raw, err := session.Read(ctx, ref.Name)
	if err != nil || found.Digest != ref.Digest || found.Size != ref.Size {
		return ErrInvalid
	}
	if json.Unmarshal(raw, value) != nil {
		return ErrInvalid
	}
	return nil
}

func (p *Pipeline) acquire(ctx context.Context, session *Session, request StoredRequest, state *pipelineState) (intake.Report, error) {
	var report intake.Report
	if state.Report != nil {
		err := readJSON(ctx, session, state.Report, &report)
		return report, err
	}
	if request.Report != nil {
		report = *request.Report
	} else {
		if p.Fetch == nil {
			return report, ErrNeedsInput
		}
		var err error
		report, err = p.Fetch(ctx, request.Incident)
		if err != nil {
			return report, ErrNeedsInput
		}
		if report.SourceID != request.Incident {
			return report, ErrInvalid
		}
	}
	for _, warning := range report.Warnings {
		if warning == "missing_technical_details" || warning == "discussion_snapshot_incomplete" {
			return report, ErrNeedsInput
		}
	}
	ref, err := p.putJSON(ctx, session, "report", report)
	if err != nil {
		return report, err
	}
	state.Report = ref
	return report, p.save(ctx, session, state, "investigating")
}

func (p *Pipeline) investigate(ctx context.Context, session *Session, run *store.RemediationRun, policy Policy, report intake.Report, state *pipelineState) (investigate.Plan, error) {
	var sourcePlan investigate.Plan
	if state.SourcePlan != nil {
		err := readJSON(ctx, session, state.SourcePlan, &sourcePlan)
		return sourcePlan, err
	}
	var investigation investigate.State
	if state.Investigation != nil {
		if err := readJSON(ctx, session, state.Investigation, &investigation); err != nil {
			return sourcePlan, err
		}
	}
	generator := proposalGenerator{pipeline: p, session: session, run: run, policy: policy, state: state}
	engine := investigate.Engine{Source: p.Source, Generator: &generator}
	config := investigate.Config{
		AllowedRepositoryRoots: policy.Repositories, MaxPlanJSONBytes: 128 << 10,
		IncludeAdjacentGoTests: policy.AllowTestChanges,
	}
	if catalog, ok := p.Environments.(interface {
		SourceHints(context.Context, Policy) ([]investigate.SourceCatalogEntry, error)
	}); ok {
		hints, err := catalog.SourceHints(ctx, policy)
		if err != nil {
			return sourcePlan, err
		}
		config.SourceCatalog = hints
		config.AllowDownstreamSourceInvestigation = len(hints) != 0
	}
	for {
		if err := ctx.Err(); err != nil {
			return sourcePlan, err
		}
		config.RequestTaskName = fmt.Sprintf("%s-discovery-%d-%d", run.ID, investigation.DiscoveryRounds, investigation.SelectionRounds)
		config.ExpectedTaskUID = ""
		if last := len(investigation.ModelTasks) - 1; last >= 0 && !investigation.ModelTasks[last].Completed {
			config.RequestTaskName = investigation.ModelTasks[last].TaskName
			config.ExpectedTaskUID = investigation.ModelTasks[last].TaskUID
		}
		next, stepErr := engine.Step(ctx, investigation, report, config)
		ref, err := p.putJSON(ctx, session, "investigation", next)
		if err != nil {
			return sourcePlan, err
		}
		investigation, state.Investigation = next, ref
		if err := p.save(ctx, session, state, "investigating"); err != nil {
			return sourcePlan, err
		}
		if stepErr != nil {
			if generator.lastError != nil {
				return sourcePlan, generator.lastError
			}
			if errors.Is(stepErr, investigate.ErrSourceDeferred) {
				return sourcePlan, ErrRetryable
			}
			if errors.Is(stepErr, investigate.ErrSourceOperation) {
				switch investigation.Stage {
				case investigate.Identifying, investigate.Selecting:
					continue
				case investigate.NeedsInput:
					return sourcePlan, ErrNeedsInput
				case investigate.NeedsAdapter:
					return sourcePlan, ErrNeedsAdapter
				}
			}
			return sourcePlan, stepErr
		}
		switch investigation.Stage {
		case investigate.NeedsInput:
			return sourcePlan, ErrNeedsInput
		case investigate.NeedsAdapter:
			return sourcePlan, ErrNeedsAdapter
		case investigate.Ready:
			if investigation.Plan == nil || investigation.Packet == nil {
				return sourcePlan, ErrInvalid
			}
			sourcePlan = *investigation.Plan
			ref, err := p.putJSON(ctx, session, "source-plan", sourcePlan)
			if err != nil {
				return sourcePlan, err
			}
			state.SourcePlan = ref
			return sourcePlan, p.save(ctx, session, state, "selecting-environment")
		}
	}
}

func (p *Pipeline) approvePlan(ctx context.Context, session *Session, policy Policy, state *pipelineState) error {
	run, err := session.Current(ctx)
	if err != nil {
		return err
	}
	if !policy.RequirePlanApproval || state.PlanApproved {
		return nil
	}
	if run.ApprovedDigest == state.PlanDigest {
		state.PlanApproved = true
		return p.save(ctx, session, state, "plan-approved")
	}
	state.Stage = "awaiting-approval"
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := session.Checkpoint(ctx, store.RemediationPhaseNeedsApproval, "exact-plan-approval-required", raw, state.PlanDigest); err != nil {
		return err
	}
	return ErrAwaitApproval
}

func (p *Pipeline) Cancel(ctx context.Context, session *Session) error {
	run, _, policy, state, err := p.load(ctx, session)
	if err != nil {
		return err
	}
	var failures []error
	pending := false
	record := func(err error) {
		if errors.Is(err, modelagent.ErrCancellationPending) || errors.Is(err, ErrCleanupPending) {
			pending = true
		} else if err != nil {
			failures = append(failures, err)
		}
	}
	var proposer ProposalClient
	if p.Agents != nil {
		proposer = p.Agents(run.Namespace, policy.AgentName, nil)
	}
	for key, operation := range state.Models {
		if operation.Retired {
			if operation.UID == "" {
				record(ErrUnknown)
			}
			continue
		}
		if !operation.Intent && operation.UID == "" {
			continue
		}
		if proposer == nil {
			record(ErrUnknown)
			continue
		}
		record(p.cancelModel(ctx, session, run, &state, key, proposer))
	}
	if state.Selection != nil {
		if state.Selection.Kind == controllerAdapterKind {
			record(p.cancelController(ctx, session, run, policy, &state))
		} else {
			record(p.cancelHTTPExecutions(ctx, session, run, policy, &state))
		}
	}
	// Ordinary progress must not spend the failure budget, but a pending
	// operation must not hide another operation's real failure either.
	if len(failures) == 0 && pending {
		return ErrCleanupPending
	}
	return errors.Join(failures...)
}

func (p *Pipeline) cancelModel(ctx context.Context, session *Session, run *store.RemediationRun, state *pipelineState, key string, proposer ProposalClient) error {
	saved := state.Models[key]
	operation := saved
	if operation.UID == "" {
		artifact, raw, err := session.Read(ctx, modelReceiptName(operation.Name))
		if err == nil {
			var receipt modelagent.Result
			if artifact == nil || artifact.Name != modelReceiptName(operation.Name) ||
				artifact.Digest != Digest(raw) || artifact.Size != int64(len(raw)) ||
				json.Unmarshal(raw, &receipt) != nil || receipt.TaskName != operation.Name ||
				receipt.TaskUID == "" || receipt.Output != "" {
				return ErrUnknown
			}
			operation.UID = receipt.TaskUID
		} else if !errors.Is(err, store.ErrNotFound) {
			return modelCleanupStoreFailure(err)
		}
	}
	if resolver, ok := proposer.(modelagent.AcceptanceResolver); ok {
		accepted, err := resolver.ResolveAccepted(ctx, modelagent.AcceptanceRequest{
			TaskName: operation.Name, ExpectedTaskUID: operation.UID, RunID: run.ID,
			PromptDigest: operation.PromptDigest, Expected: operation.Expected,
		})
		if err != nil {
			return modelCleanupFailure(err)
		}
		if accepted.TaskName != operation.Name || accepted.TaskUID == "" || accepted.Output != "" ||
			(operation.UID != "" && accepted.TaskUID != operation.UID) {
			return ErrUnknown
		}
		operation.UID = accepted.TaskUID
	}
	if operation.UID == "" {
		return ErrUnknown
	}
	if saved.UID == "" {
		receipt, err := json.Marshal(modelagent.Result{TaskName: operation.Name, TaskUID: operation.UID})
		if err != nil {
			return ErrInvalid
		}
		if _, err := session.Put(ctx, modelReceiptName(operation.Name), "application/json", receipt); err != nil {
			return modelCleanupStoreFailure(err)
		}
		// A receipt alone is not an admission record. Pin the exact operation
		// UID under the current claim/CAS before any cancellation or deletion.
		if err := checkpointCleanupModel(ctx, session, state, key, saved, operation); err != nil {
			return err
		}
	}
	if _, err := session.Current(ctx); err != nil {
		return modelCleanupStoreFailure(err)
	}
	if operation.Output == nil {
		if err := proposer.Cancel(ctx, operation.Name, operation.UID); err != nil {
			return modelCleanupFailure(err)
		}
		if _, err := session.Current(ctx); err != nil {
			return modelCleanupStoreFailure(err)
		}
	}
	if err := proposer.Retire(ctx, operation.Name, operation.UID); err != nil {
		return modelCleanupFailure(err)
	}
	retired := operation
	retired.Retired = true
	return checkpointCleanupModel(ctx, session, state, key, operation, retired)
}

func modelCleanupFailure(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, ErrClaimLost):
		return ErrClaimLost
	case errors.Is(err, modelagent.ErrDependencyUnavailable):
		return ErrRetryable
	case errors.Is(err, modelagent.ErrCancellationPending):
		return modelagent.ErrCancellationPending
	default:
		return ErrUnknown
	}
}

func modelCleanupStoreFailure(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrClaimLost) {
		return modelCleanupFailure(err)
	}
	if errors.Is(err, store.ErrRemediationIntegrity) || errors.Is(err, store.ErrValidation) {
		return ErrUnknown
	}
	return ErrRetryable
}

func checkpointCleanupModel(ctx context.Context, session *Session, state *pipelineState, key string, expected, next modelOperation) error {
	current, err := session.Current(ctx)
	if err != nil {
		return modelCleanupStoreFailure(err)
	}
	// Recording a previously unknown UID can enable admission. Cleanup must
	// already be fenced from dispatch before making that identity durable.
	if expected.UID == "" && next.UID != "" && current.Phase != store.RemediationPhaseCancelling &&
		!current.CancelRequested && time.Now().Before(current.Deadline) {
		return ErrUnknown
	}
	var durable pipelineState
	if json.Unmarshal(current.StateJSON, &durable) != nil {
		return ErrInvalid
	}
	stored, found := durable.Models[key]
	if !found || !reflect.DeepEqual(stored, expected) {
		return ErrUnknown
	}
	durable.Models[key] = next
	raw, err := marshalControllerPipeline(current.StateJSON, &durable)
	if err != nil {
		return err
	}
	_, err = session.store.UpdateRemediationRun(ctx, current.Namespace, current.ID, session.owner, session.epoch, current.Revision,
		store.RemediationUpdate{Phase: current.Phase, Reason: current.Reason, StateJSON: raw, ApprovalDigest: current.ApprovalDigest}, time.Now().UTC())
	if err != nil {
		return modelCleanupStoreFailure(err)
	}
	state.Models[key] = next
	return nil
}

type proposalGenerator struct {
	pipeline  *Pipeline
	session   *Session
	run       *store.RemediationRun
	policy    Policy
	state     *pipelineState
	lastError error
}

func (g *proposalGenerator) Generate(ctx context.Context, request modelagent.Request) (modelagent.Result, error) {
	result, err := g.pipeline.generate(ctx, g.session, g.run, g.policy, g.state, request)
	g.lastError = err
	return result, err
}
