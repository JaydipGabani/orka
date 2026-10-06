package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation/journal"
)

func (e *Engine) prepareTargetChecks(ctx context.Context, checkpoint *journal.Checkpoint, state *State) (CheckProposal, error) {
	index := state.Current
	target := &state.Targets[index]
	if target.Checks == nil {
		var raw []byte
		if state.ChecksInput != nil {
			var err error
			raw, err = e.Store.ReadArtifact(*state.ChecksInput)
			if err != nil {
				return CheckProposal{}, err
			}
		} else {
			key := fmt.Sprintf("checks-%d", index)
			result, err := e.generate(ctx, checkpoint, state, key, checksPrompt(*state.Plan, target.Target),
				target.Target.Repository.URL, target.Target.Commit)
			if err != nil {
				return CheckProposal{}, err
			}
			raw = []byte(result.Output)
		}
		if _, err := DecodeCheckProposal(string(raw)); err != nil {
			return CheckProposal{}, err
		}
		ref, err := e.Store.PutArtifact(fmt.Sprintf("target-%d-checks.json", index), raw)
		if err != nil {
			return CheckProposal{}, err
		}
		target.Checks = &ref
		if err := e.save(checkpoint, *state, "checks-frozen"); err != nil {
			return CheckProposal{}, err
		}
	}
	raw, err := e.Store.ReadArtifact(*target.Checks)
	if err != nil {
		return CheckProposal{}, err
	}
	checks, err := DecodeCheckProposal(string(raw))
	if err != nil {
		return CheckProposal{}, err
	}
	return checks, requireProtectedChecks(checks)
}

func (e *Engine) prepareTargetBaseline(ctx context.Context, checkpoint *journal.Checkpoint, state *State, request pv.Request) (*pv.Record, error) {
	target := &state.Targets[state.Current]
	if target.Baseline == nil {
		if err := e.save(checkpoint, *state, "reproducing"); err != nil {
			return nil, err
		}
		record, err := e.validate(ctx, checkpoint, state, "baseline", request)
		if err != nil {
			return nil, err
		}
		if record == nil || record.State == pv.RunRunning {
			return nil, errors.New("baseline execution has not produced a terminal evidence record")
		}
		ref, err := e.record(fmt.Sprintf("target-%d-baseline.json", state.Current), record)
		if err != nil {
			return nil, err
		}
		target.Baseline = &ref
		target.Intent, target.Receipt = "", nil
		if err := e.save(checkpoint, *state, "baseline-recorded"); err != nil {
			return nil, err
		}
	}
	baseline, err := e.readRecord(*target.Baseline)
	if err != nil {
		return nil, err
	}
	if baseline.State != pv.RunFinalized || baseline.Assessment.Conclusion != pv.Reproduced {
		target.Conclusion = pv.UnableToVerify
		return nil, errors.New("reported behavior was not reproduced; patch generation is blocked")
	}
	return baseline, nil
}

func (e *Engine) prepareTargetPatch(ctx context.Context, checkpoint *journal.Checkpoint, state *State, sourceDirectory string, checks CheckProposal, baseline pv.Assessment) error {
	index := state.Current
	target := &state.Targets[index]
	if target.Patch != nil {
		return nil
	}
	result, err := e.generate(ctx, checkpoint, state, fmt.Sprintf("patch-%d", index), patchPrompt(*state.Plan, checks, baseline),
		target.Target.Repository.URL, target.Target.Commit)
	if err != nil {
		return err
	}
	proposal, err := DecodePatchProposal(result.Output)
	if err != nil {
		return err
	}
	if len(proposal.Edits) != 0 {
		original, err := readTargetEditSources(sourceDirectory, proposal.Edits)
		if err != nil {
			return err
		}
		proposal.Patch, err = CompilePatch(proposal, original)
		if err != nil {
			return err
		}
		proposal.Edits = nil
	}
	raw, err := json.Marshal(proposal)
	if err != nil {
		return err
	}
	candidate, err := e.Store.PutArtifact(fmt.Sprintf("target-%d-patch-proposal.json", index), raw)
	if err != nil {
		return err
	}
	ref, err := e.Store.PutArtifact(fmt.Sprintf("target-%d.patch", index), []byte(proposal.Patch))
	if err != nil {
		return err
	}
	target.Patch, target.Candidate = &ref, &candidate
	return e.save(checkpoint, *state, "patch-proposed")
}

func readTargetEditSources(directory string, edits []SourceEdit) (map[string][]byte, error) {
	original := make(map[string][]byte)
	for _, edit := range edits {
		filename := filepath.Join(directory, filepath.FromSlash(edit.Path))
		resolved, err := filepath.EvalSymlinks(filename)
		if err != nil || resolved != filename {
			return nil, errors.New("candidate edit references an unavailable or aliased source file")
		}
		info, err := os.Stat(filename)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxProposalBytes {
			return nil, errors.New("candidate source file is not a bounded regular file")
		}
		raw, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		original[edit.Path] = raw
	}
	return original, nil
}
