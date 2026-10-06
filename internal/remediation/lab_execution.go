package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation/journal"
	"github.com/orka-agents/orka/internal/remediation/lab"
)

func (e *Engine) prepareLabRun(checkpoint *journal.Checkpoint, state *State, generatePatch bool, supplied *PatchProposal) error {
	if state.Plan == nil || state.Plan.Lab == nil || state.Lab == nil || len(state.Targets) != 1 {
		return errors.New("an exact lab plan is required")
	}
	raw, err := json.Marshal(state.Plan)
	if err != nil || pv.Digest(raw) != state.PlanDigest {
		return errors.New("lab plan integrity failed")
	}
	if !state.Approved {
		if e.ApprovePlanDigest != state.PlanDigest {
			return ErrApprovalRequired
		}
		state.Approved = true
		if err := e.save(checkpoint, *state, "targets-approved"); err != nil {
			return err
		}
	}
	report, err := e.report(*state)
	if err != nil {
		return err
	}
	if generatePatch && supplied == nil && report.Restricted && !e.ModelDataApproved {
		return ErrModelApproval
	}
	if err := requireCompleteReport(report); err != nil {
		return err
	}
	if supplied != nil {
		if err := e.stageSuppliedLabProposal(checkpoint, state, *supplied); err != nil {
			return err
		}
	} else if generatePatch && state.Lab.Supplied {
		return errors.New("resume this supplied-patch workflow with the same explicit proposal")
	}
	if !state.Lab.Verified && filepath.Join(e.WorkDir, checkpoint.RunID, "lab-runs") != state.Lab.RunsDirectory {
		return errors.New("private lab runs directory changed after planning")
	}
	return nil
}

func (e *Engine) prepareLabPatch(ctx context.Context, checkpoint *journal.Checkpoint, state *State, packetRaw []byte, original map[string][]byte, baseline *lab.Result, index int) (bool, error) {
	attempt := &state.Lab.Attempts[index]
	if attempt.Patch != nil {
		return true, nil
	}
	raw, err := e.labProposal(ctx, checkpoint, state, packetRaw, baseline, index)
	if err != nil {
		return false, err
	}
	proposal, parseErr := DecodePatchProposal(string(raw))
	var patch string
	if parseErr == nil {
		if len(proposal.Edits) == 0 && !state.Lab.Supplied {
			parseErr = errors.New("lab proposals must use exact edits against the pinned source packet")
		} else {
			patch, parseErr = CompilePatch(proposal, original)
		}
	}
	if parseErr != nil {
		attempt.Feedback = parseErr.Error()
		if err := e.save(checkpoint, *state, "lab-proposal-rejected"); err != nil {
			return false, err
		}
		if state.Lab.Supplied {
			return false, parseErr
		}
		return false, nil
	}
	ref, err := e.Store.PutArtifact(fmt.Sprintf("lab-candidate-%d.patch", index), []byte(patch))
	if err != nil {
		return false, err
	}
	attempt.Patch = &ref
	state.Targets[0].Patch, state.Targets[0].Candidate = &ref, attempt.Proposal
	return true, e.save(checkpoint, *state, "patch-proposed")
}

func (e *Engine) labProposal(ctx context.Context, checkpoint *journal.Checkpoint, state *State, packetRaw []byte, baseline *lab.Result, index int) ([]byte, error) {
	attempt := &state.Lab.Attempts[index]
	if attempt.Proposal != nil {
		return e.Store.ReadArtifact(*attempt.Proposal)
	}
	report, err := e.report(*state)
	if err != nil {
		return nil, err
	}
	prompt := "Propose a minimal private source fix, not a verification claim. " +
		"Return only JSON {summary,edits:[{path,old,new}],declaredChanges:[{kind,description,paths}],limitations:[]}. " +
		"Use exact unique old text from the pinned source packet, no unchanged edits or invented symbols. " +
		"Preserve normal behavior and source-version compatibility. Update repository tests that require the reported insecure behavior, " +
		"but never alter the frozen external observer, recipe base, or its expectations. Do not execute code or use tools. " +
		"The trusted driver, not model output, determines whether this candidate works.\nREPORT_DATA:\n" + encoded(report) +
		"\nPINNED_SOURCE_PACKET:\n" + string(packetRaw) + "\nBASELINE_OBSERVATIONS:\n" + encoded(baseline) +
		"\nCHECK_SCOPE:\n" + encoded(state.Plan.Lab.Profile.Scope)
	if index > 0 {
		prompt += "\nPREVIOUS_PROPOSAL_REJECTION:\n" + state.Lab.Attempts[index-1].Feedback
	}
	if len(prompt) > 256<<10 {
		return nil, errors.New("report and source packet exceed the bounded proposal prompt")
	}
	result, err := e.generate(ctx, checkpoint, state, fmt.Sprintf("lab-patch-%d", index), prompt, "", "")
	if err != nil {
		return nil, err
	}
	raw := []byte(result.Output)
	ref, err := e.Store.PutArtifact(fmt.Sprintf("lab-proposal-%d.json", index), raw)
	if err != nil {
		return nil, err
	}
	attempt.Proposal = &ref
	return raw, e.save(checkpoint, *state, "lab-proposal-recorded")
}

func (e *Engine) verifyLabPatch(ctx context.Context, checkpoint *journal.Checkpoint, state *State, bridge *lab.Bridge, baseline lab.Receipt, index int) error {
	attempt := &state.Lab.Attempts[index]
	patch, err := e.Store.ReadArtifact(*attempt.Patch)
	if err != nil {
		return err
	}
	patchPath := filepath.Join(filepath.Dir(state.Lab.RunsDirectory), fmt.Sprintf("candidate-%d.patch", index))
	if err := writeExact(patchPath, patch, 0600); err != nil {
		return err
	}
	name := fmt.Sprintf("verify-%d", index)
	var receipt lab.Receipt
	if attempt.Intent {
		receipt, err = bridge.ReadReceipt(name)
	} else {
		attempt.Intent = true
		state.Targets[0].Attempts++
		if err := e.save(checkpoint, *state, "lab-verification-intent"); err != nil {
			return err
		}
		receipt, err = bridge.Verify(ctx, name, baseline, lab.Candidate{Patch: lab.FileIdentity{Path: patchPath, Digest: attempt.Patch.Digest}})
	}
	if err != nil || receipt.State != lab.Verified {
		state.Reason = "lab verification did not establish a verified candidate; inspect private driver evidence without replaying an unknown run"
		saveErr := e.save(checkpoint, *state, "blocked")
		return errors.Join(err, saveErr, ErrBlocked)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	ref, err := e.Store.PutArtifact(fmt.Sprintf("lab-verification-%d.json", index), raw)
	if err != nil {
		return err
	}
	attempt.Receipt = &ref
	state.Targets[0].Verification, state.Targets[0].Conclusion = &ref, pv.Verified
	state.Lab.Verified, state.Reason = true, ""
	return e.save(checkpoint, *state, "completed")
}
