package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation/journal"
	"github.com/orka-agents/orka/internal/remediation/lab"
	"github.com/orka-agents/orka/internal/remediation/source"
)

const maxLabProposals = 3

type LabPlan struct {
	Profile       lab.Profile      `json:"profile"`
	ProfileDigest string           `json:"profileDigest"`
	SourcePacket  journal.Artifact `json:"sourcePacket"`
}

type LabAttempt struct {
	Proposal *journal.Artifact `json:"proposal,omitempty"`
	Patch    *journal.Artifact `json:"patch,omitempty"`
	Receipt  *journal.Artifact `json:"receipt,omitempty"`
	Feedback string            `json:"feedback,omitempty"`
	Intent   bool              `json:"intent"`
}

type LabProgress struct {
	RunsDirectory  string            `json:"runsDirectory"`
	BaselineIntent bool              `json:"baselineIntent"`
	Baseline       *journal.Artifact `json:"baseline,omitempty"`
	Attempts       []LabAttempt      `json:"attempts"`
	Supplied       bool              `json:"supplied"`
	Verified       bool              `json:"verified"`
	TrustStatement string            `json:"trustStatement"`
}

func (e *Engine) ProposeLab(ctx context.Context, profileRaw []byte, selectedFiles []string) (Summary, error) {
	checkpoint, state, err := e.load()
	if err != nil {
		return Summary{}, err
	}
	if state.Plan != nil {
		if state.Plan.Lab == nil {
			return summary(checkpoint, state), errors.New("a different workflow plan already exists")
		}
		return summary(checkpoint, state), nil
	}
	report, err := e.report(state)
	if err != nil {
		return summary(checkpoint, state), err
	}
	if err := requireCompleteReport(report); err != nil {
		return summary(checkpoint, state), err
	}
	profile, err := lab.ParseProfile(profileRaw)
	if err != nil {
		return summary(checkpoint, state), err
	}
	if e.Resolver == nil || e.SourcePacket == nil || len(selectedFiles) == 0 {
		return summary(checkpoint, state), errors.New("a public-source resolver and selected source files are required")
	}
	if err := ensurePrivateDirectory(e.WorkDir); err != nil {
		return summary(checkpoint, state), err
	}
	target, err := e.Resolver.Resolve(ctx, profile.Repository, profile.Commit)
	if err != nil || target.Repository.URL != profile.Repository || target.Commit != profile.Commit {
		return summary(checkpoint, state), errors.New("the reviewed profile target could not be confirmed as exact public source")
	}
	proposal := TargetProposal{
		Problem: report.Title,
		Targets: []TargetSuggestion{{
			Repository: target.Repository.URL, Ref: target.Commit,
			Reason: "caller-supplied reviewed lab profile; exact public commit and tree independently resolved",
		}},
		Requirements: []pv.EnvironmentRequirement{{
			Kind: "cluster", Name: "reviewed-lab",
			Description: "the approved driver must reproduce the report on original and unchanged control images before proposing a patch",
		}},
	}
	packet, err := e.SourcePacket(ctx, target, selectedFiles)
	if err != nil {
		return summary(checkpoint, state), err
	}
	packetRaw, err := json.Marshal(packet)
	if err != nil {
		return summary(checkpoint, state), err
	}
	checked, err := source.DecodePacket(packetRaw)
	if err != nil || checked.Target != target {
		return summary(checkpoint, state), errors.New("source packet is not bound to the confirmed target")
	}
	packetRef, err := e.Store.PutArtifact("lab-source-packet.json", packetRaw)
	if err != nil {
		return summary(checkpoint, state), err
	}
	profileDigest, err := lab.DigestProfile(profile)
	if err != nil {
		return summary(checkpoint, state), err
	}
	plan := &Plan{
		Version: 1, ReportDigest: report.SourceDigest, Proposal: proposal, Targets: []source.Target{target},
		Image: profile.OriginalImage, Platform: profile.Platform, Profile: "trusted-lab",
		Lab: &LabPlan{Profile: profile, ProfileDigest: profileDigest, SourcePacket: packetRef},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return summary(checkpoint, state), err
	}
	if _, err := e.Store.PutArtifact("plan.json", raw); err != nil {
		return summary(checkpoint, state), err
	}
	state.Plan, state.PlanDigest = plan, pv.Digest(raw)
	state.Targets = []TargetRun{{Target: target}}
	state.Lab = &LabProgress{
		RunsDirectory: filepath.Join(e.WorkDir, checkpoint.RunID, "lab-runs"),
		Attempts:      []LabAttempt{}, TrustStatement: lab.TrustStatement,
	}
	if err := e.save(&checkpoint, state, "targets-proposed"); err != nil {
		return summary(checkpoint, state), err
	}
	return summary(checkpoint, state), nil
}

func (e *Engine) ValidateLab(ctx context.Context) (Summary, error) {
	return e.runLab(ctx, false, nil)
}

func (e *Engine) ExecuteLab(ctx context.Context) (Summary, error) {
	return e.runLab(ctx, true, nil)
}

func (e *Engine) VerifyLab(ctx context.Context, proposal PatchProposal) (Summary, error) {
	return e.runLab(ctx, true, &proposal)
}

func (e *Engine) runLab(ctx context.Context, generatePatch bool, supplied *PatchProposal) (Summary, error) {
	checkpoint, state, err := e.load()
	if err != nil {
		return Summary{}, err
	}
	if err := e.prepareLabRun(&checkpoint, &state, generatePatch, supplied); err != nil {
		return summary(checkpoint, state), err
	}
	if state.Lab.Verified {
		return summary(checkpoint, state), nil
	}
	if err := ensurePrivateDirectory(state.Lab.RunsDirectory); err != nil {
		return summary(checkpoint, state), err
	}
	bridge, err := lab.New(state.Plan.Lab.Profile, state.Lab.RunsDirectory, state.Plan.Lab.ProfileDigest)
	if err != nil {
		return summary(checkpoint, state), err
	}
	baseline, err := e.labBaseline(ctx, &checkpoint, &state, bridge)
	if err != nil {
		return summary(checkpoint, state), err
	}
	if !generatePatch {
		return summary(checkpoint, state), nil
	}
	packetRaw, err := e.Store.ReadArtifact(state.Plan.Lab.SourcePacket)
	if err != nil {
		return summary(checkpoint, state), err
	}
	packet, err := source.DecodePacket(packetRaw)
	if err != nil || packet.Target != state.Targets[0].Target {
		return summary(checkpoint, state), errors.New("approved source packet integrity failed")
	}
	original := make(map[string][]byte, len(packet.Files))
	for _, file := range packet.Files {
		original[file.Path] = []byte(file.Content)
	}
	if state.Lab.Supplied && len(state.Lab.Attempts) == 1 && state.Lab.Attempts[0].Feedback != "" {
		return summary(checkpoint, state), errors.New("the saved supplied proposal was rejected; it cannot be replaced or automatically regenerated")
	}
	for len(state.Lab.Attempts) < maxLabProposals ||
		(len(state.Lab.Attempts) == maxLabProposals && state.Lab.Attempts[maxLabProposals-1].Feedback == "") {
		if len(state.Lab.Attempts) == 0 || state.Lab.Attempts[len(state.Lab.Attempts)-1].Feedback != "" {
			state.Lab.Attempts = append(state.Lab.Attempts, LabAttempt{})
			if err := e.save(&checkpoint, state, "lab-proposal-pending"); err != nil {
				return summary(checkpoint, state), err
			}
		}
		index := len(state.Lab.Attempts) - 1
		ready, err := e.prepareLabPatch(ctx, &checkpoint, &state, packetRaw, original, baseline.Result, index)
		if err != nil {
			return summary(checkpoint, state), err
		}
		if !ready {
			continue
		}
		if err := e.verifyLabPatch(ctx, &checkpoint, &state, bridge, baseline, index); err != nil {
			return summary(checkpoint, state), err
		}
		return summary(checkpoint, state), nil
	}
	state.Reason = "bounded proposal repair attempts exhausted; no verified patch was produced"
	err = e.save(&checkpoint, state, "blocked")
	return summary(checkpoint, state), errors.Join(err, ErrBlocked)
}

func (e *Engine) stageSuppliedLabProposal(checkpoint *journal.Checkpoint, state *State, proposal PatchProposal) error {
	raw, err := json.Marshal(proposal)
	if err != nil {
		return err
	}
	if _, err := DecodePatchProposal(string(raw)); err != nil {
		return err
	}
	if len(state.Lab.Attempts) != 0 {
		if !state.Lab.Supplied || len(state.Lab.Attempts) != 1 || state.Lab.Attempts[0].Proposal == nil {
			return errors.New("another candidate workflow already exists; create a new run for a different supplied patch")
		}
		previous, err := e.Store.ReadArtifact(*state.Lab.Attempts[0].Proposal)
		if err != nil || pv.Digest(previous) != pv.Digest(raw) {
			return errors.New("supplied patch or declared-change metadata differs from the saved request")
		}
		return nil
	}
	ref, err := e.Store.PutArtifact("lab-supplied-proposal.json", raw)
	if err != nil {
		return err
	}
	state.Lab.Supplied = true
	state.Lab.Attempts = []LabAttempt{{Proposal: &ref}}
	return e.save(checkpoint, *state, "supplied-patch-recorded")
}

func (e *Engine) labBaseline(ctx context.Context, checkpoint *journal.Checkpoint, state *State, bridge *lab.Bridge) (lab.Receipt, error) {
	var receipt lab.Receipt
	var err error
	if state.Lab.BaselineIntent {
		receipt, err = bridge.ReadReceipt("baseline")
	} else {
		state.Lab.BaselineIntent = true
		if err := e.save(checkpoint, *state, "lab-baseline-intent"); err != nil {
			return receipt, err
		}
		receipt, err = bridge.Baseline(ctx, "baseline")
	}
	if err != nil || receipt.State != lab.BaselineReady {
		state.Reason = "trusted lab did not reproduce the report with passing normal-use controls"
		saveErr := e.save(checkpoint, *state, "blocked")
		return receipt, errors.Join(err, saveErr, ErrBlocked)
	}
	if state.Lab.Baseline == nil {
		raw, err := json.Marshal(receipt)
		if err != nil {
			return receipt, err
		}
		ref, err := e.Store.PutArtifact("lab-baseline.json", raw)
		if err != nil {
			return receipt, err
		}
		state.Lab.Baseline, state.Targets[0].Baseline = &ref, &ref
		state.Targets[0].Conclusion = pv.Reproduced
		state.Reason = ""
		if err := e.save(checkpoint, *state, "report-validated"); err != nil {
			return receipt, err
		}
	}
	return receipt, nil
}
