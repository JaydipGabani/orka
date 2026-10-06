package investigate

import (
	"encoding/json"
	"reflect"
	"regexp"
	"slices"

	"github.com/orka-agents/orka/internal/remediation/source"
	"k8s.io/apimachinery/pkg/util/validation"
)

var safeErrorPattern = regexp.MustCompile(`^[a-z_]{1,128}$`)

func validateState(state State, config Config) error {
	if err := validateStateBounds(state, config); err != nil {
		return err
	}
	if !validSourceRetry(state) {
		return ErrState
	}
	switch state.Stage {
	case Identifying, NeedsInput, NeedsAdapter:
		return nil
	case Resolving, Inventory, Selecting, Packet, Ready:
	default:
		return ErrState
	}
	proposal, err := frozenProposal(state, config)
	if err != nil {
		return ErrState
	}
	if state.Stage == Resolving {
		return nil
	}
	if state.Target == nil || !validTarget(*state.Target, proposal.Targets[0]) {
		return ErrState
	}
	if state.Stage == Inventory && len(state.PendingInventoryPaths) == 0 {
		return nil
	}
	if err := validateInventory(state.Inventory, *state.Target); err != nil {
		return err
	}
	if state.Stage == Inventory && !inventoryContains(state.Inventory, state.PendingInventoryPaths, true) {
		return ErrState
	}
	if state.Stage != Packet && state.Stage != Ready {
		return nil
	}
	if err := validateFrozenSelection(state, config); err != nil {
		return ErrState
	}
	if state.Stage == Ready {
		return validateReady(state)
	}
	return nil
}

func validateStateBounds(state State, config Config) error {
	if state.DiscoveryRounds < 0 || state.DiscoveryRounds > config.MaxDiscoveryRounds ||
		state.SelectionRounds < 0 || state.SelectionRounds > config.MaxSelectionRounds ||
		state.InventoryOffset < 0 || state.InventoryOffset > len(state.Inventory) ||
		len(state.SelectedPaths) > config.MaxFiles || len(state.PendingInventoryPaths) > 32 ||
		!validPaths(state.SelectedPaths) || !validPaths(state.PendingInventoryPaths) || !validTestContextBounds(state, config) ||
		(state.SafeError != "" && !safeErrorPattern.MatchString(state.SafeError)) ||
		(state.Feedback != "" && !safeErrorPattern.MatchString(state.Feedback)) ||
		!stringList(state.EvidenceRequired, 16, 1024) || len(state.Choices) > config.MaxCandidates ||
		!stringList(state.ReportWarnings, 128, 256) {
		return ErrState
	}
	for _, choice := range state.Choices {
		if canonicalRepository(choice.Repository) == "" || (choice.Ref != "" && !validRef(choice.Ref)) ||
			!text(choice.ReportedVersion, 256, false) {
			return ErrState
		}
	}
	return validateTaskHistory(state)
}

func frozenProposal(state State, config Config) (Proposal, error) {
	if state.UnverifiedProposal == nil {
		return Proposal{}, ErrState
	}
	data, err := json.Marshal(state.UnverifiedProposal)
	if err != nil {
		return Proposal{}, ErrState
	}
	proposal, err := DecodeProposal(string(data))
	if err != nil || len(proposal.Targets) != 1 || !allowedRepository(config, proposal.Targets[0].Repository) ||
		proposal.Scope == ScopeUnknown || proposal.VersionStatus != versionSingle ||
		(len(proposal.Missing) != 0 && !canInspectContractTarget(proposal, config)) ||
		!text(proposal.Trigger, 16384, true) || !text(proposal.ExpectedBehavior, 16384, true) {
		return Proposal{}, ErrState
	}
	if state.Scope == ScopeDownstream {
		if !config.AllowDownstreamSourceInvestigation || !validObjectID(proposal.Targets[0].Ref) ||
			!slices.Equal(state.EvidenceRequired, downstreamEvidence(proposal)) {
			return Proposal{}, ErrState
		}
	} else if state.Scope != ScopeUpstream || proposal.Scope != ScopeUpstream || len(proposal.DownstreamEvidenceRequired) != 0 {
		return Proposal{}, ErrState
	}
	return proposal, nil
}

func validateReady(state State) error {
	if state.Packet == nil || state.Plan == nil || validatePacket(*state.Packet, state) != nil {
		return ErrState
	}
	if !reflect.DeepEqual(state.Plan, makePlan(state)) {
		return ErrState
	}
	return nil
}

func validateFrozenSelection(state State, config Config) error {
	if state.UnverifiedSelection == nil ||
		!inventoryContains(state.Inventory, state.SelectedPaths, false) {
		return ErrState
	}
	expected, tests := selectedPathsWithTests(state.Inventory, state.UnverifiedSelection.Paths, config.IncludeAdjacentGoTests)
	var omitted []string
	switch state.TestContextOmission {
	case "":
	case testContextBudget:
		expected, tests, omitted = boundedTestContext(state.Inventory, state.UnverifiedSelection.Paths, config)
		if len(omitted) == 0 {
			return ErrState
		}
	case testContextUnavailable:
		if len(tests) == 0 {
			return ErrState
		}
		expected, omitted, tests = state.UnverifiedSelection.Paths, tests, nil
	case testContextEncodedBudget:
		if len(state.OmittedTestPaths) == 0 {
			return ErrState
		}
		expected, tests, omitted = partitionTestContext(state.UnverifiedSelection.Paths, tests, state.OmittedTestPaths)
	default:
		return ErrState
	}
	if !slices.Equal(state.SelectedPaths, expected) || !slices.Equal(state.AddedTestPaths, tests) ||
		!slices.Equal(state.OmittedTestPaths, omitted) {
		return ErrState
	}
	data, err := json.Marshal(state.UnverifiedSelection)
	if err != nil {
		return ErrState
	}
	selection, err := DecodeSelection(string(data))
	if err != nil || len(selection.Missing) != 0 || len(selection.Expand) != 0 || selection.NextPage {
		return ErrState
	}
	return nil
}

func validateTaskHistory(state State) error {
	if len(state.ModelTasks) > 6 {
		return ErrState
	}
	seen := make(map[string]bool)
	discovery, selection := 0, 0
	for index, task := range state.ModelTasks {
		if len(validation.IsDNS1123Subdomain(task.TaskName)) != 0 || seen[task.TaskName] ||
			(task.TaskUID != "" && !validUID(task.TaskUID)) || !validDigest(task.RequestDigest) ||
			(!task.Completed && index != len(state.ModelTasks)-1) || (task.Completed && task.TaskUID == "") {
			return ErrState
		}
		seen[task.TaskName] = true
		switch task.Stage {
		case Identifying:
			discovery++
			if task.Round != discovery {
				return ErrState
			}
		case Selecting:
			selection++
			if task.Round != selection {
				return ErrState
			}
		default:
			return ErrState
		}
	}
	if state.DiscoveryRounds != discovery || state.SelectionRounds != selection {
		return ErrState
	}
	return nil
}

func validatePacket(packet source.Packet, state State) error {
	if packet.Target != *state.Target || len(packet.Files) != len(state.SelectedPaths) {
		return ErrState
	}
	data, err := json.Marshal(packet)
	if err != nil {
		return ErrState
	}
	if _, err := source.DecodePacket(data); err != nil {
		return ErrState
	}
	entries := make(map[string]source.Entry, len(state.Inventory))
	for _, entry := range state.Inventory {
		entries[entry.Path] = entry
	}
	for index, file := range packet.Files {
		entry := entries[file.Path]
		if file.Path != state.SelectedPaths[index] || file.BlobSHA != entry.BlobSHA ||
			int64(len(file.Content)) != entry.Size {
			return ErrState
		}
	}
	return nil
}
