package remediation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

const maxProposalBytes = 256 << 10

type TargetSuggestion struct {
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Reason     string `json:"reason"`
}

type TargetProposal struct {
	Problem          string                      `json:"problem"`
	Trigger          string                      `json:"trigger"`
	ExpectedBehavior string                      `json:"expectedBehavior"`
	Targets          []TargetSuggestion          `json:"targets"`
	Requirements     []pv.EnvironmentRequirement `json:"requirements"`
	Missing          []string                    `json:"missing"`
}

type ProposedFile struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	Executable bool   `json:"executable"`
}

type CheckProposal struct {
	Scope        []string                    `json:"scope"`
	Gaps         []string                    `json:"gaps"`
	Requirements []pv.EnvironmentRequirement `json:"requirements"`
	Files        []ProposedFile              `json:"files"`
	Checks       []pv.Check                  `json:"checks"`
	Services     []pv.Service                `json:"services"`
}

type PatchProposal struct {
	Summary         string              `json:"summary"`
	Patch           string              `json:"patch"`
	Edits           []SourceEdit        `json:"edits,omitempty"`
	DeclaredChanges []pv.DeclaredChange `json:"declaredChanges"`
	Limitations     []string            `json:"limitations"`
}

type SourceEdit struct {
	Path        string `json:"path"`
	Old         string `json:"old"`
	New         string `json:"new"`
	Occurrences *int   `json:"occurrences,omitempty"`
}

const MaxEditOccurrences = 16

func decodeProposal(raw string, destination any) error {
	content := []byte(raw)
	if len(content) == 0 || len(content) > maxProposalBytes || !utf8.Valid(content) {
		return errors.New("agent proposal is empty, oversized, or not UTF-8")
	}
	if err := uniqueProposalJSON(json.NewDecoder(bytes.NewReader(content)), 0); err != nil {
		return errors.New("agent proposal must be one JSON object without duplicate fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("agent proposal does not match the required schema")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("agent proposal contains trailing data")
	}
	return nil
}

func uniqueProposalJSON(decoder *json.Decoder, depth int) error {
	if depth > 20 {
		return errors.New("proposal nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, container := token.(json.Delim)
	if !container {
		if depth == 0 {
			return errors.New("proposal must be an object")
		}
		return nil
	}
	if depth == 0 && delim != '{' {
		return errors.New("proposal must be an object")
	}
	keys := make(map[string]bool)
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[strings.ToLower(name)] {
				return errors.New("duplicate proposal key")
			}
			keys[strings.ToLower(name)] = true
		}
		if err := uniqueProposalJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func DecodeTargetProposal(raw string) (TargetProposal, error) {
	var proposal TargetProposal
	if err := decodeProposal(raw, &proposal); err != nil {
		return proposal, err
	}
	if strings.TrimSpace(proposal.Problem) == "" || len(proposal.Problem) > 32768 ||
		len(proposal.Trigger) > 16384 || len(proposal.ExpectedBehavior) > 16384 ||
		len(proposal.Targets) > 8 || len(proposal.Requirements) > 32 || len(proposal.Missing) > 32 {
		return proposal, errors.New("target proposal exceeds its bounds or lacks a problem")
	}
	if len(proposal.Targets) == 0 && len(proposal.Missing) == 0 {
		return proposal, errors.New("target proposal must provide targets or identify missing information")
	}
	for _, target := range proposal.Targets {
		if target.Repository == "" || len(target.Repository) > 512 || target.Ref == "" ||
			len(target.Ref) > 255 || len(target.Reason) > 8192 {
			return proposal, errors.New("target proposal contains an incomplete or oversized target")
		}
	}
	return proposal, nil
}

func DecodeCheckProposal(raw string) (CheckProposal, error) {
	var proposal CheckProposal
	if err := decodeProposal(raw, &proposal); err != nil {
		return proposal, err
	}
	if len(proposal.Scope) == 0 || len(proposal.Scope) > 100 || len(proposal.Gaps) > 100 ||
		len(proposal.Requirements) > 32 || len(proposal.Files) == 0 || len(proposal.Files) > pv.MaxFrozenFiles ||
		len(proposal.Checks) == 0 || len(proposal.Checks) > 100 || len(proposal.Services) > pv.MaxServices {
		return proposal, errors.New("check proposal is incomplete or exceeds its bounds")
	}
	files := make(map[string]bool)
	for _, file := range proposal.Files {
		if file.Path == "" || path.IsAbs(file.Path) || path.Clean(file.Path) != file.Path ||
			file.Path == "." || file.Path == ".." || strings.HasPrefix(file.Path, "../") ||
			strings.ContainsAny(file.Path, "\\\x00\r\n") || len(file.Path) > 255 {
			return proposal, errors.New("check proposal contains an unsafe file path")
		}
		if _, found := files[file.Path]; found {
			return proposal, errors.New("check proposal contains duplicate files")
		}
		files[file.Path] = file.Executable
	}
	commands := make([][]string, 0, len(proposal.Checks)+len(proposal.Services))
	for _, check := range proposal.Checks {
		if check.HTTP != nil {
			commands = append(commands, check.HTTP.ServerCommand)
		} else {
			commands = append(commands, check.Command)
		}
	}
	for _, service := range proposal.Services {
		commands = append(commands, service.Command)
	}
	for _, command := range commands {
		if len(command) == 0 || !strings.HasPrefix(command[0], "/checks/") ||
			path.Clean(command[0]) != command[0] || !files[strings.TrimPrefix(command[0], "/checks/")] {
			return proposal, errors.New("check commands must use executable frozen files under /checks")
		}
	}
	return proposal, nil
}

func requireProtectedChecks(proposal CheckProposal) error {
	for _, check := range proposal.Checks {
		if check.HTTP == nil {
			return errors.New("automatic remediation requires protected HTTP observations; in-process or command-only assertions are unsupported")
		}
	}
	return nil
}

func DecodePatchProposal(raw string) (PatchProposal, error) {
	var proposal PatchProposal
	if err := decodeProposal(raw, &proposal); err != nil {
		return proposal, err
	}
	if strings.TrimSpace(proposal.Summary) == "" || len(proposal.Summary) > 16384 ||
		(proposal.Patch == "") == (len(proposal.Edits) == 0) || strings.ContainsRune(proposal.Patch, '\x00') ||
		len(proposal.DeclaredChanges) == 0 || len(proposal.DeclaredChanges) > 100 || len(proposal.Limitations) > 100 {
		return proposal, errors.New("patch proposal must contain a bounded summary, Git diff, and declared changes")
	}
	if proposal.Patch != "" && !strings.HasPrefix(proposal.Patch, "diff --git ") {
		return proposal, errors.New("candidate patch must be a Git unified diff")
	}
	if len(proposal.Edits) > 64 {
		return proposal, errors.New("candidate edit count exceeds its limit")
	}
	for index, edit := range proposal.Edits {
		if edit.Old == "" || edit.Old == edit.New || edit.Path == "" || path.IsAbs(edit.Path) ||
			path.Clean(edit.Path) != edit.Path || edit.Path == ".." || strings.HasPrefix(edit.Path, "../") ||
			strings.ContainsAny(edit.Path, "\\\x00\r\n") {
			return proposal, fmt.Errorf("candidate edit %d must change exact source text in a safe relative file; empty and unchanged edits are forbidden", index)
		}
		if edit.Occurrences != nil && (*edit.Occurrences < 1 || *edit.Occurrences > MaxEditOccurrences) {
			return proposal, fmt.Errorf("candidate edit %d occurrences must be between 1 and %d", index, MaxEditOccurrences)
		}
	}
	return proposal, nil
}
