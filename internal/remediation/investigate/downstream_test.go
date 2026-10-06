package investigate

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

func TestInvestigationDownstreamSourceOptInRetainsExecutionRequirements(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			report, config := fixtureReport(t), fixtureConfig()
			report.Sections[0].Text += " The affected artifact is a managed image."
			config.AllowDownstreamSourceInvestigation = enabled
			repository := config.AllowedRepositoryRoots[0]
			sourceClient := fixtureSource(repository, "parser/request.go")
			sourceClient.target.Ref = sourceClient.target.Commit
			config.SourceCatalog = []SourceCatalogEntry{{
				Repository: repository, Commit: sourceClient.target.Commit, Version: "1.2.3", Revision: "r2",
			}}
			proposal := fixtureProposal(repository)
			proposal.Scope, proposal.Targets[0].Ref = ScopeDownstream, sourceClient.target.Commit
			proposal.DownstreamEvidenceRequired = []string{"Associate the reported downstream revision with its immutable original image."}
			generator := &syntheticGenerator{outputs: []string{
				fixtureJSON(t, proposal), fixtureJSON(t, fixtureSelection("parser/request.go")),
			}}
			engine := Engine{Source: sourceClient, Generator: generator}
			state := stepFixture(t, engine, State{}, report, config)
			if !enabled {
				require.Equal(t, NeedsInput, state.Stage)
				require.Equal(t, "downstream_source_build_mapping_required", state.SafeError)
				require.Empty(t, sourceClient.operations)
				return
			}
			for range 4 {
				state = stepFixture(t, engine, state, report, config)
			}
			require.Equal(t, Ready, state.Stage, "public source readiness is not authorization to execute a downstream image")
			require.Equal(t, ScopeDownstream, state.Scope)
			require.Equal(t, ScopeDownstream, state.Plan.Scope)
			require.Equal(t, downstreamEvidence(proposal), state.Plan.EvidenceRequired)
			require.Contains(t, strings.Join(state.Plan.EvidenceRequired, " "), "operator-approved downstream recipe")
			require.Contains(t, strings.Join(state.Plan.EvidenceRequired, " "), "immutable original image digest")
			require.Contains(t, strings.Join(state.Plan.EvidenceRequired, " "), "vanilla upstream source alone")
			require.Equal(t, report.Warnings, state.Plan.ReportWarnings)
			require.Empty(t, state.Plan.Missing, "build evidence is separately outstanding, not silently declared satisfied")
			require.Equal(t, []Stage{Resolving, Inventory, Packet}, sourceClient.operations)
			require.Contains(t, generator.requests[0].Prompt, `"sourceCatalog"`)
			require.Contains(t, generator.requests[0].Prompt, sourceClient.target.Commit)
			require.Contains(t, generator.requests[0].Prompt, `"revision":"r2"`)
			require.NotContains(t, generator.requests[0].Prompt, "AllowDownstreamSourceInvestigation")
			for _, request := range generator.requests {
				require.Zero(t, request.MaxTurns, "native proposal adapters reject explicit turn overrides")
			}
			state = stepFixture(t, engine, state, report, config)
			require.Equal(t, Ready, state.Stage)
			require.Len(t, generator.requests, 2)
			config.AllowDownstreamSourceInvestigation = false
			_, err := engine.Step(t.Context(), state, report, config)
			require.ErrorIs(t, err, ErrState, "operator policy cannot silently change after a target is frozen")
		})
	}
}

func TestInvestigationDownstreamSourceOptInDoesNotOverrideAmbiguityOrMissing(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*intake.Report, *Proposal)
		reason string
	}{
		{"tag-not-commit", func(_ *intake.Report, proposal *Proposal) {
			proposal.Targets[0].Ref = "v1.2.3"
		}, "exact_downstream_source_commit_required"},
		{"multiple-source-candidates", func(_ *intake.Report, proposal *Proposal) {
			other := proposal.Targets[0]
			other.Repository = "https://github.com/another-source/engine"
			proposal.Targets = append(proposal.Targets, other)
		}, "target_choice_required"},
		{"uncertain-source-version", func(_ *intake.Report, proposal *Proposal) {
			proposal.VersionStatus = "ambiguous"
		}, "affected_version_choice_required"},
		{"multiple-reported-versions", func(report *intake.Report, _ *Proposal) {
			report.Versions = append(report.Versions, "1.3.0")
		}, "affected_version_choice_required"},
		{"missing-source-evidence", func(_ *intake.Report, proposal *Proposal) {
			proposal.Missing = []string{"The relationship between the reported parser and this repository is unknown."}
		}, "target_evidence_required"},
		{"missing-trigger", func(_ *intake.Report, proposal *Proposal) {
			proposal.Trigger = ""
		}, "target_evidence_required"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			report, config := fixtureReport(t), fixtureConfig()
			config.AllowDownstreamSourceInvestigation = true
			proposal := fixtureProposal(config.AllowedRepositoryRoots[0])
			proposal.Scope, proposal.Targets[0].Ref = ScopeDownstream, strings.Repeat("c", 40)
			test.mutate(&report, &proposal)
			generator := &syntheticGenerator{outputs: []string{fixtureJSON(t, proposal)}}
			sourceClient := fixtureSource(config.AllowedRepositoryRoots[0], "parser/request.go")
			state := stepFixture(t, Engine{Source: sourceClient, Generator: generator}, State{}, report, config)
			require.Equal(t, NeedsInput, state.Stage)
			require.Equal(t, test.reason, state.SafeError)
			require.Contains(t, strings.Join(state.EvidenceRequired, " "), "immutable original image digest",
				"other missing evidence must not erase downstream binding requirements")
			require.Empty(t, sourceClient.operations)
			require.Nil(t, state.Plan)
		})
	}
}

func TestInvestigationReportScopeCannotBeDowngradedByTheModel(t *testing.T) {
	report, config := fixtureReport(t), fixtureConfig()
	report.Sections[0].Text += " The managed image is the affected artifact."
	config.AllowDownstreamSourceInvestigation = true
	sourceClient := fixtureSource(config.AllowedRepositoryRoots[0], "parser/request.go")
	sourceClient.target.Ref = sourceClient.target.Commit
	proposal := fixtureProposal(config.AllowedRepositoryRoots[0])
	proposal.Targets[0].Ref = sourceClient.target.Commit
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, proposal), fixtureJSON(t, fixtureSelection("parser/request.go")),
	}}
	engine := Engine{Source: sourceClient, Generator: generator}
	state := State{}
	for range 5 {
		state = stepFixture(t, engine, state, report, config)
	}
	require.Equal(t, Ready, state.Stage)
	require.Equal(t, ScopeUpstream, state.UnverifiedProposal.Scope)
	require.Equal(t, ScopeDownstream, state.Plan.Scope, "retain independent report-derived scope despite the model claim")
	require.NotEmpty(t, state.Plan.EvidenceRequired)
	state.EvidenceRequired = nil
	_, err := engine.Step(t.Context(), state, report, config)
	require.ErrorIs(t, err, ErrState)
}

func TestInvestigationMissingReportEvidenceIsGatedButRoutineWarningsRemain(t *testing.T) {
	for _, warning := range []string{"missing_technical_details", "discussion_snapshot_incomplete"} {
		t.Run(warning, func(t *testing.T) {
			report, config := fixtureReport(t), fixtureConfig()
			report.Warnings = append(report.Warnings, warning)
			generator := &syntheticGenerator{}
			state := stepFixture(t, Engine{Generator: generator}, State{}, report, config)
			require.Equal(t, NeedsInput, state.Stage)
			require.Equal(t, "report_evidence_required", state.SafeError)
			require.Equal(t, report.Warnings, state.ReportWarnings)
			require.Empty(t, generator.requests)
		})
	}
	report, err := intake.Parse([]byte(`{"restricted":false}`))
	require.NoError(t, err)
	require.Empty(t, report.Sections)
	state := stepFixture(t, Engine{}, State{}, report, fixtureConfig())
	require.Equal(t, NeedsInput, state.Stage)
	require.Equal(t, "report_evidence_required", state.SafeError)
}

func TestInvestigationCatalogHintsCannotAuthorizeSourcesOrExposeDriverData(t *testing.T) {
	config := fixtureConfig()
	config.SourceCatalog = []SourceCatalogEntry{
		{Repository: config.AllowedRepositoryRoots[1], Commit: strings.Repeat("d", 40), Version: "2.0.0"},
		{Repository: config.AllowedRepositoryRoots[0], Commit: strings.Repeat("c", 40), Version: "1.2.3", Revision: "r1"},
	}
	before := fixtureJSON(t, config)
	normalized, _, err := normalizeConfig(config)
	require.NoError(t, err)
	require.Equal(t, before, fixtureJSON(t, config), "catalog sorting must not mutate operator-owned data")
	normalized.SourceCatalog[0].Version = "changed"
	require.Equal(t, before, fixtureJSON(t, config), "returned catalog metadata must be detached")
	for _, change := range []func(*Config){
		func(config *Config) { config.SourceCatalog[0].Repository = "https://github.com/not-allowed/source" },
		func(config *Config) { config.SourceCatalog[0].Commit = "main" },
		func(config *Config) { config.SourceCatalog[0].Version = "/private/driver/config" },
		func(config *Config) { config.SourceCatalog[0].Revision = "run build command" },
		func(config *Config) { config.MaxTurns = 8 },
	} {
		local := config
		local.SourceCatalog = append([]SourceCatalogEntry(nil), config.SourceCatalog...)
		change(&local)
		generator := &syntheticGenerator{}
		_, err := (Engine{Generator: generator}).Step(t.Context(), State{}, fixtureReport(t), taskConfig(State{}, local))
		require.ErrorIs(t, err, ErrConfig)
		require.Empty(t, generator.requests)
	}
}

func TestInvestigationReadyCheckpointCompactsInventoryWithinArtifactLimit(t *testing.T) {
	report, config := fixtureReport(t), fixtureConfig()
	repository := config.AllowedRepositoryRoots[0]
	sourceClient := fixtureSource(repository, "selected.go")
	content := strings.Repeat("<", maxPacketBytes-1) + "\n"
	blob := sha1.Sum(fmt.Appendf(nil, "blob %d\x00%s", len(content), content))
	sum := sha256.Sum256([]byte(content))
	sourceClient.files[0].Content = content
	sourceClient.files[0].BlobSHA, sourceClient.files[0].SHA256 = hex.EncodeToString(blob[:]), hex.EncodeToString(sum[:])
	sourceClient.entries[0].BlobSHA, sourceClient.entries[0].Size = sourceClient.files[0].BlobSHA, int64(len(content))
	for index := range 30000 {
		sourceClient.entries = append(sourceClient.entries, source.Entry{
			Path: fmt.Sprintf("file-%05d.go", index), Mode: "100644", Size: 18, BlobSHA: strings.Repeat("e", 40),
		})
	}
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, fixtureSelection("selected.go")),
	}}
	engine := Engine{Source: sourceClient, Generator: generator}
	state := State{}
	for range 5 {
		state = stepFixture(t, engine, state, report, config)
		require.Less(t, len(fixtureJSON(t, state)), 8<<20)
	}
	require.Equal(t, Ready, state.Stage)
	require.Len(t, state.Inventory, 1, "a completed selection must not retain the whole discovery listing")
	require.Equal(t, *state.Packet, state.Plan.Packet, "preserve the existing packet API without retaining the full inventory")
	require.Equal(t, content, state.Plan.Packet.Files[0].Content)
	require.Less(t, len(fixtureJSON(t, state)), 4<<20)
	state = stepFixture(t, engine, state, report, config)
	require.Equal(t, Ready, state.Stage)
}
