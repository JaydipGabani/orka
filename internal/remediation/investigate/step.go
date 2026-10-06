package investigate

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/remediation/source"
)

// Step returns a new state and never mutates the supplied state. Even on error,
// persist the returned state: it may contain a newly accepted model Task UID.
// A ready/blocked state is terminal and performs no external operation.
func (engine Engine) Step(ctx context.Context, state State, report intake.Report, config Config) (State, error) {
	if ctx == nil {
		return state, ErrState
	}
	if err := ctx.Err(); err != nil {
		return state, err
	}
	config, policyDigest, err := normalizeConfig(config)
	if err != nil {
		return state, err
	}
	data, err := reportData(report)
	if err != nil {
		return state, err
	}
	state, err = prepareState(state, report, digest(data), policyDigest, config)
	if err != nil {
		return state, err
	}
	if missingReport(report) {
		return blocked(state, NeedsInput, "report_evidence_required"), nil
	}
	if state.UnverifiedProposal != nil && state.Scope != investigationScope(report, *state.UnverifiedProposal) {
		return state, ErrState
	}
	if !state.SourceRetryAt.IsZero() {
		if time.Now().UTC().Before(state.SourceRetryAt) {
			return state, ErrSourceDeferred
		}
		state.SourceRetryAt = time.Time{}
		state.SafeError = ""
	}
	switch state.Stage {
	case Identifying:
		return engine.identify(ctx, state, report, data, config)
	case Resolving:
		return engine.resolve(ctx, state, config)
	case Inventory:
		return engine.inventory(ctx, state)
	case Selecting:
		return engine.selectFiles(ctx, state, config)
	case Packet:
		return engine.packet(ctx, state, config)
	default:
		return state, nil
	}
}

func prepareState(state State, report intake.Report, normalizedDigest, policyDigest string, config Config) (State, error) {
	if state.Stage == "" {
		if !reflect.ValueOf(state).IsZero() {
			return state, ErrState
		}
		return State{
			Stage: Identifying, ReportDigest: report.SourceDigest, NormalizedDigest: normalizedDigest, PolicyDigest: policyDigest,
			ReportWarnings: slices.Clone(report.Warnings),
		}, nil
	}
	if state.ReportDigest != report.SourceDigest || state.NormalizedDigest != normalizedDigest || state.PolicyDigest != policyDigest ||
		!slices.Equal(state.ReportWarnings, report.Warnings) {
		return state, ErrState
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > maxStateBytes {
		return state, ErrState
	}
	var cloned State
	if json.Unmarshal(data, &cloned) != nil || validateState(cloned, config) != nil {
		return state, ErrState
	}
	return cloned, nil
}

func (engine Engine) identify(
	ctx context.Context, state State, report intake.Report, reportJSON json.RawMessage, config Config,
) (State, error) {
	prompt, err := identifyPrompt(reportJSON, state, config)
	if err != nil {
		return blocked(state, NeedsInput, "report_context_limit"), nil
	}
	state, output, complete, err := engine.generate(ctx, state, prompt, config)
	if err != nil || !complete {
		return state, err
	}
	proposal, err := DecodeProposal(output)
	if err != nil || len(proposal.Targets) > config.MaxCandidates {
		return retryModel(state, config, "invalid_target_proposal"), nil
	}
	state.UnverifiedProposal = &proposal
	state.Scope = investigationScope(report, proposal)
	state.EvidenceRequired = nil
	if state.Scope == ScopeDownstream {
		state.EvidenceRequired = downstreamEvidence(proposal)
	}
	state.Choices, state.ChoicesTruncated = choices(report, proposal, config.MaxCandidates)
	for _, target := range proposal.Targets {
		if !allowedRepository(config, target.Repository) {
			return blocked(state, NeedsInput, "repository_not_allowed"), nil
		}
	}
	if reason := ambiguity(report, proposal, config); reason != "" {
		return blocked(state, NeedsInput, reason), nil
	}
	state.Stage, state.SafeError, state.Feedback = Resolving, "", ""
	return state, nil
}

func ambiguity(report intake.Report, proposal Proposal, config Config) string {
	downstream := investigationScope(report, proposal) == ScopeDownstream
	if downstream && !config.AllowDownstreamSourceInvestigation {
		return "downstream_source_build_mapping_required"
	}
	if len(proposal.Targets) != 1 {
		return "target_choice_required"
	}
	if ambiguousVersionReport(report) || proposal.VersionStatus == "ambiguous" {
		return "affected_version_choice_required"
	}
	if reportedRepositoryConflict(report, proposal.Targets[0].Repository) {
		return "reported_repository_mapping_required"
	}
	if downstream && !validObjectID(proposal.Targets[0].Ref) {
		return "exact_downstream_source_commit_required"
	}
	if !downstream && len(report.Versions) == 1 && versionLiteral(report.Versions[0]) != versionLiteral(proposal.Targets[0].Ref) {
		return "reported_version_ref_mapping_required"
	}
	if proposal.Scope == ScopeUnknown || proposal.VersionStatus != versionSingle ||
		(len(proposal.Missing) != 0 && !canInspectContractTarget(proposal, config)) ||
		strings.TrimSpace(proposal.Trigger) == "" || strings.TrimSpace(proposal.ExpectedBehavior) == "" {
		return "target_evidence_required"
	}
	return ""
}

func versionLiteral(value string) string {
	value = strings.TrimPrefix(value, "refs/tags/")
	return strings.TrimPrefix(strings.TrimPrefix(value, "v"), "V")
}

func reportedRepositoryConflict(report intake.Report, selected string) bool {
	for _, reported := range report.Repositories {
		repository := canonicalRepository(reported)
		if repository != "" && !strings.EqualFold(repository, canonicalRepository(selected)) {
			return true
		}
	}
	return false
}

func choices(report intake.Report, proposal Proposal, limit int) ([]Choice, bool) {
	result := make([]Choice, 0, limit)
	truncated := false
	add := func(choice Choice) {
		choice.Repository = canonicalRepository(choice.Repository)
		if slices.Contains(result, choice) {
			return
		}
		if len(result) == limit {
			truncated = true
			return
		}
		result = append(result, choice)
	}
	for _, candidate := range proposal.Targets {
		if len(report.Versions) <= 1 {
			add(Choice{Repository: candidate.Repository, Ref: candidate.Ref})
			continue
		}
		for _, version := range report.Versions {
			choice := Choice{Repository: candidate.Repository, ReportedVersion: version}
			if versionLiteral(version) == versionLiteral(candidate.Ref) {
				choice.Ref = candidate.Ref
			}
			add(choice)
		}
	}
	for _, reported := range report.Repositories {
		repository := canonicalRepository(reported)
		if repository == "" || slices.ContainsFunc(result, func(choice Choice) bool {
			return strings.EqualFold(choice.Repository, repository)
		}) {
			continue
		}
		add(Choice{Repository: repository})
	}
	return result, truncated
}

func ambiguousVersionReport(report intake.Report) bool {
	if len(report.Versions) > 1 {
		return true
	}
	for _, section := range report.Sections {
		for _, clause := range affectedVersionClause.FindAllString(section.Text, -1) {
			if versionRangeClaim.MatchString(clause) {
				return true
			}
			versions := versionClaim.FindAllString(clause, -1)
			for index := range versions {
				versions[index] = versionLiteral(versions[index])
			}
			slices.Sort(versions)
			if len(slices.Compact(versions)) > 1 {
				return true
			}
		}
	}
	return false
}

func downstreamReport(report intake.Report) bool {
	parts := make([]string, 0, len(report.Sections)+1)
	parts = append(parts, report.Title)
	for _, section := range report.Sections {
		parts = append(parts, section.Text)
	}
	text := strings.ToLower(strings.Join(parts, "\n"))
	for _, marker := range []string{
		"downstream", "managed image", "container image", "docker image", "image digest",
		"custom build", "vendor-patched", "vendor patched", "distribution build",
		"mcr.microsoft.com/", "ghcr.io/", ".azurecr.io/", "gcr.io/",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func (engine Engine) resolve(ctx context.Context, state State, config Config) (State, error) {
	if engine.Source == nil {
		return blocked(state, NeedsAdapter, "source_adapter_required"), nil
	}
	candidate := state.UnverifiedProposal.Targets[0]
	target, err := engine.Source.Resolve(ctx, candidate.Repository, candidate.Ref)
	if err := cancellation(ctx, err); err != nil {
		return state, err
	}
	if err != nil {
		if deferred, ok := deferRateLimitedSource(state, err); ok {
			return deferred, ErrSourceDeferred
		}
		state.Stage = Identifying
		return retryModel(state, config, "source_resolution_failed"), ErrSourceOperation
	}
	if !validTarget(target, candidate) {
		return blocked(state, NeedsInput, "source_target_identity_mismatch"), ErrState
	}
	state.Target, state.Stage, state.SafeError, state.Feedback = &target, Inventory, "", ""
	return state, nil
}

func (engine Engine) inventory(ctx context.Context, state State) (State, error) {
	if engine.Source == nil {
		return blocked(state, NeedsAdapter, "source_adapter_required"), nil
	}
	var entries []source.Entry
	var err error
	if len(state.PendingInventoryPaths) == 0 {
		entries, err = engine.Source.Inventory(ctx, *state.Target)
	} else {
		expander, supported := engine.Source.(InventoryExpander)
		if !supported {
			return blocked(state, NeedsAdapter, "dependency_inventory_adapter_required"), nil
		}
		entries, err = expander.InventoryPaths(ctx, *state.Target, slices.Clone(state.PendingInventoryPaths))
	}
	if err := cancellation(ctx, err); err != nil {
		return state, err
	}
	if err != nil {
		if deferred, ok := deferRateLimitedSource(state, err); ok {
			return deferred, ErrSourceDeferred
		}
		return blocked(state, NeedsAdapter, "source_inventory_unavailable"), ErrSourceOperation
	}
	if len(state.PendingInventoryPaths) != 0 {
		entries, err = mergeInventory(state, entries)
	}
	if err != nil || validateInventory(entries, *state.Target) != nil {
		return blocked(state, NeedsAdapter, "source_inventory_invalid_or_exhausted"), nil
	}
	state.Inventory = slices.Clone(entries)
	slices.SortFunc(state.Inventory, func(first, second source.Entry) int { return strings.Compare(first.Path, second.Path) })
	state.PendingInventoryPaths = nil
	state.InventoryOffset = 0
	state.Stage, state.SafeError, state.Feedback = Selecting, "", ""
	return state, nil
}

func mergeInventory(state State, entries []source.Entry) ([]source.Entry, error) {
	if len(entries) == 0 || len(entries)+len(state.Inventory)-len(state.PendingInventoryPaths) > source.MaxInventoryEntries {
		return nil, ErrState
	}
	for _, entry := range entries {
		if !slices.ContainsFunc(state.PendingInventoryPaths, func(directory string) bool {
			return strings.HasPrefix(entry.Path, directory+"/")
		}) {
			return nil, ErrState
		}
	}
	merged := slices.Clone(entries)
	for _, entry := range state.Inventory {
		if !slices.Contains(state.PendingInventoryPaths, entry.Path) {
			merged = append(merged, entry)
		}
	}
	return merged, nil
}

func (engine Engine) selectFiles(ctx context.Context, state State, config Config) (State, error) {
	prompt, nextOffset, err := selectionPrompt(state, config)
	if err != nil {
		return blocked(state, NeedsAdapter, "inventory_context_limit"), nil
	}
	state, output, complete, err := engine.generate(ctx, state, prompt, config)
	if err != nil || !complete {
		return state, err
	}
	selection, err := DecodeSelection(output)
	if err != nil || len(selection.Paths) > config.MaxFiles {
		return retryModel(state, config, "invalid_file_selection"), nil
	}
	state.UnverifiedSelection = &selection
	if len(selection.Missing) != 0 {
		return blocked(state, NeedsInput, "source_file_evidence_required"), nil
	}
	switch {
	case selection.NextPage:
		if nextOffset >= len(state.Inventory) {
			return retryModel(state, config, "inventory_page_unavailable"), nil
		}
		state.InventoryOffset = nextOffset
		return retryModel(state, config, "inventory_page_requested"), nil
	case len(selection.Expand) != 0:
		if !inventoryContains(state.Inventory, selection.Expand, true) {
			return retryModel(state, config, "invalid_dependency_selection"), nil
		}
		if state.SelectionRounds >= config.MaxSelectionRounds {
			return blocked(state, NeedsInput, "selection_budget_exhausted"), nil
		}
		state.PendingInventoryPaths = slices.Clone(selection.Expand)
		state.Stage, state.SafeError, state.Feedback = Inventory, "", ""
	default:
		if !inventoryContains(state.Inventory, selection.Paths, false) {
			return retryModel(state, config, "selection_not_in_frozen_inventory"), nil
		}
		if !testContextFits(state.Inventory, selection.Paths, config) {
			return retryModel(state, config, "select_fewer_or_smaller_files_for_encoded_model_context"), nil
		}
		state.SelectedPaths, state.AddedTestPaths, state.OmittedTestPaths = boundedTestContext(state.Inventory, selection.Paths, config)
		state.TestContextOmission = ""
		if len(state.OmittedTestPaths) != 0 {
			state.TestContextOmission = testContextBudget
		}
		state.Stage, state.SafeError, state.Feedback = Packet, "", ""
	}
	return state, nil
}

func inventoryContains(entries []source.Entry, paths []string, directories bool) bool {
	index := make(map[string]source.Entry, len(entries))
	for _, entry := range entries {
		index[entry.Path] = entry
	}
	total := int64(0)
	for _, name := range paths {
		entry, found := index[name]
		if !found || (entry.Mode == "040000") != directories {
			return false
		}
		if !directories {
			if entry.Size <= 0 || entry.Size > maxPacketBytes-total {
				return false
			}
			total += entry.Size
		}
	}
	return len(paths) != 0
}

func (engine Engine) packet(ctx context.Context, state State, config Config) (State, error) {
	if engine.Source == nil {
		return blocked(state, NeedsAdapter, "source_adapter_required"), nil
	}
	packet, err := engine.Source.Packet(ctx, *state.Target, slices.Clone(state.SelectedPaths))
	if err := cancellation(ctx, err); err != nil {
		return state, err
	}
	if err != nil {
		if deferred, ok := deferRateLimitedSource(state, err); ok {
			return deferred, ErrSourceDeferred
		}
		if len(state.AddedTestPaths) != 0 && state.TestContextOmission != testContextUnavailable && source.IsPacketContentRejection(err) {
			return omitAddedTestContext(state, testContextUnavailable), nil
		}
		state.SelectedPaths, state.AddedTestPaths = nil, nil
		state.OmittedTestPaths, state.TestContextOmission = nil, ""
		state.Stage = Selecting
		return retryModel(state, config, "source_packet_unavailable"), ErrSourceOperation
	}
	if validatePacket(packet, state) != nil {
		return blocked(state, NeedsInput, "source_packet_identity_mismatch"), ErrState
	}
	// Copy adapter-owned slices before exposing the immutable expected source.
	packet.Files = slices.Clone(packet.Files)
	state.Packet = &packet
	state.Plan = makePlan(state)
	encoded, err := json.Marshal(state.Plan)
	for err == nil && len(encoded) > config.MaxPlanJSONBytes && len(state.AddedTestPaths) != 0 {
		state, packet, err = dropLargestAddedTest(state, packet)
		if err != nil {
			return state, err
		}
		if validatePacket(packet, state) != nil {
			return blocked(state, NeedsInput, "source_packet_identity_mismatch"), ErrState
		}
		state.Packet = &packet
		state.Plan = makePlan(state)
		encoded, err = json.Marshal(state.Plan)
	}
	if err != nil || len(encoded) > config.MaxPlanJSONBytes {
		state.Packet, state.Plan, state.SelectedPaths, state.AddedTestPaths = nil, nil, nil, nil
		state.OmittedTestPaths, state.TestContextOmission = nil, ""
		state.Stage = Selecting
		return retryModel(state, config, "select_fewer_or_smaller_files_for_encoded_model_context"), nil
	}
	retained := append(slices.Clone(state.SelectedPaths), state.OmittedTestPaths...)
	state.Inventory = selectedInventory(state.Inventory, retained)
	state.InventoryOffset = 0
	state.Stage, state.SafeError, state.Feedback = Ready, "", ""
	return state, nil
}

func makePlan(state State) *Plan {
	proposal := state.UnverifiedProposal
	limitations := slices.Clone(proposal.Limitations)
	if len(state.OmittedTestPaths) != 0 {
		limitations = append(limitations, testContextOmittedLimitation)
	}
	limitations = append(limitations, state.UnverifiedSelection.Limitations...)
	limitations = append(limitations,
		"Model-derived problem, behavior, requirements and hints are unverified claims, not execution instructions.",
		"Public upstream source identity does not establish an affected version, reproduction, or downstream image/build equivalence.",
		"The packet is a bounded source selection, not a complete checkout; dependency metadata and file sizes are not build evidence.",
	)
	packet := *state.Packet
	packet.Files = slices.Clone(packet.Files)
	return &Plan{
		Scope: state.Scope, EvidenceRequired: slices.Clone(state.EvidenceRequired), ReportWarnings: slices.Clone(state.ReportWarnings),
		Problem: proposal.Problem, Trigger: proposal.Trigger, ExpectedBehavior: proposal.ExpectedBehavior,
		Requirements: slices.Clone(proposal.Requirements), Target: *state.Target, Packet: packet,
		Limitations: limitations, Missing: slices.Clone(proposal.Missing),
		LanguageHints: slices.Clone(proposal.LanguageHints), BuildHints: slices.Clone(proposal.BuildHints),
	}
}

func retryModel(state State, config Config, reason string) State {
	if state.Stage == Identifying && state.DiscoveryRounds >= config.MaxDiscoveryRounds {
		return blocked(state, NeedsInput, "discovery_budget_exhausted")
	}
	if state.Stage == Selecting && state.SelectionRounds >= config.MaxSelectionRounds {
		return blocked(state, NeedsInput, "selection_budget_exhausted")
	}
	state.SafeError, state.Feedback = reason, reason
	return state
}

func blocked(state State, stage Stage, reason string) State {
	state.Stage, state.SafeError = stage, reason
	switch reason {
	case "downstream_source_build_mapping_required":
		if state.UnverifiedProposal != nil {
			state.EvidenceRequired = downstreamEvidence(*state.UnverifiedProposal)
		}
	case "exact_downstream_source_commit_required":
		state.EvidenceRequired = append(downstreamEvidence(*state.UnverifiedProposal),
			"One exact full public upstream commit is required for source inspection; branches, version strings and tags are insufficient.")
	case "affected_version_choice_required", "reported_version_ref_mapping_required":
		state.EvidenceRequired = []string{"One affected version and its demonstrated branch/tag-to-commit mapping; do not substitute the default branch."}
	case "target_choice_required", "repository_not_allowed", "target_evidence_required", "reported_repository_mapping_required":
		state.EvidenceRequired = []string{"One operator-allowed public repository/ref supported by report facts, with an explicit trigger and expected behavior."}
	case "discovery_budget_exhausted", "selection_budget_exhausted":
		state.EvidenceRequired = []string{"Additional bounded source evidence or operator input; automatic investigation has exhausted its round budget."}
	case "report_evidence_required":
		state.EvidenceRequired = []string{"Complete normalized technical details and discussion evidence are required before model investigation."}
	}
	if state.Scope == ScopeDownstream && state.UnverifiedProposal != nil {
		required := downstreamEvidence(*state.UnverifiedProposal)
		for _, evidence := range state.EvidenceRequired {
			if !slices.Contains(required, evidence) {
				required = append(required, evidence)
			}
		}
		state.EvidenceRequired = required
	}
	return state
}
