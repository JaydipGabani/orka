package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

func TestAutomaticInvestigationForDifferentRepositoriesWithoutSuppliedPaths(t *testing.T) {
	cases := []struct{ repository, file string }{
		{"https://github.com/synthetic-source/parser", "parser/request.go"},
		{"https://github.com/another-source/engine", "internal/input/validate.go"},
	}
	for _, test := range cases {
		t.Run(test.repository, func(t *testing.T) {
			report := fixtureReport(t)
			sourceClient := fixtureSource(test.repository, test.file)
			generator := &syntheticGenerator{outputs: []string{
				fixtureJSON(t, fixtureProposal(test.repository)), fixtureJSON(t, fixtureSelection(test.file)),
			}}
			engine := Engine{Source: sourceClient, Generator: generator}
			config := fixtureConfig()
			// Hints are model data, not an override. The second test must still
			// choose the other repository/ref from its unverified proposal.
			if test.repository == cases[1].repository {
				config.RepositoryHint, config.RefHint = cases[0].repository, "not-the-model-ref"
			}
			state := State{}
			for _, stage := range []Stage{Resolving, Inventory, Selecting, Packet, Ready} {
				operations := len(generator.requests) + len(sourceClient.operations)
				state = stepFixture(t, engine, state, report, config)
				require.Equal(t, stage, state.Stage)
				require.Equal(t, operations+1, len(generator.requests)+len(sourceClient.operations),
					"exactly one external logical operation per nonterminal step")
			}
			require.Equal(t, []Stage{Resolving, Inventory, Packet}, sourceClient.operations)
			require.Len(t, generator.requests, 2)
			require.Equal(t, 1, state.DiscoveryRounds)
			require.Equal(t, 1, state.SelectionRounds)
			require.Equal(t, sourceClient.target, state.Plan.Target)
			require.Equal(t, sourceClient.target, state.Plan.Packet.Target)
			require.Equal(t, []string{test.file}, state.SelectedPaths)
			require.Equal(t, sourceClient.files, state.Plan.Packet.Files)
			require.Contains(t, strings.Join(state.Plan.Limitations, " "), "unverified claims")
			require.Contains(t, strings.Join(state.Plan.Limitations, " "), "downstream image/build")
			require.Empty(t, state.SafeError)
			require.Empty(t, state.Plan.Missing)

			for _, request := range generator.requests {
				require.Empty(t, request.Repository, "investigation Tasks must never gain a checkout")
				require.Empty(t, request.Commit)
				require.NotContains(t, request.Prompt, request.TaskName)
				require.NotContains(t, request.Prompt, "ExpectedTaskUID")
			}
			require.Contains(t, generator.requests[0].Prompt, `"unverifiedHints"`)
			require.NotContains(t, generator.requests[0].Prompt, test.file, "no caller-supplied file list")
			require.Contains(t, generator.requests[1].Prompt, test.file)
			require.Contains(t, generator.requests[1].Prompt, sourceClient.target.Commit)
			require.NotContains(t, generator.requests[1].Prompt, "package synthetic", "inventory is metadata only")
			require.NotContains(t, fixtureJSON(t, state.ModelTasks), `"output"`, "Task receipts never retain raw model output")
			terminal := stepFixture(t, engine, state, report, config)
			require.Equal(t, state, terminal)
			require.Len(t, generator.requests, 2)
			require.Len(t, sourceClient.operations, 3)
		})
	}
}

func TestInvestigationRefusesAmbiguousAndUnsupportedTargets(t *testing.T) {
	repository := fixtureConfig().AllowedRepositoryRoots[0]
	cases := []struct {
		name   string
		change func(*intake.Report, *Proposal)
		reason string
	}{
		{"multiple-versions", func(report *intake.Report, _ *Proposal) {
			report.Versions = []string{"1.2.3", "1.2.4"}
		}, "affected_version_choice_required"},
		{"model-ambiguous-versions", func(_ *intake.Report, proposal *Proposal) {
			proposal.VersionStatus = "ambiguous"
		}, "affected_version_choice_required"},
		{"text-affected-versions", func(report *intake.Report, _ *Proposal) {
			report.Sections[0].Text += " Affected versions 1.2.3 and 1.3.0 are reported."
		}, "affected_version_choice_required"},
		{"text-affected-range", func(report *intake.Report, _ *Proposal) {
			report.Sections[0].Text += " Affected versions before 1.3.0 are reported."
		}, "affected_version_choice_required"},
		{"reported-repository-conflict", func(report *intake.Report, _ *Proposal) {
			report.Repositories = []string{"https://github.com/another-source/engine"}
		}, "reported_repository_mapping_required"},
		{"multiple-repositories", func(_ *intake.Report, proposal *Proposal) {
			proposal.Targets = append(proposal.Targets, TargetSuggestion{
				Repository: fixtureConfig().AllowedRepositoryRoots[1], Ref: "v1.2.3", Reason: "Another possible target",
			})
		}, "target_choice_required"},
		{"disallowed-repository", func(_ *intake.Report, proposal *Proposal) {
			proposal.Targets[0].Repository = "https://github.com/not-approved/synthetic"
		}, "repository_not_allowed"},
		{"latest-instead-of-reported-version", func(_ *intake.Report, proposal *Proposal) {
			proposal.Targets[0].Ref = "main"
		}, "reported_version_ref_mapping_required"},
		{"downstream-model-scope", func(_ *intake.Report, proposal *Proposal) {
			proposal.Scope = "downstream-build"
		}, "downstream_source_build_mapping_required"},
		{"managed-image-despite-upstream-model-claim", func(report *intake.Report, _ *Proposal) {
			report.Sections[0].Text += " The managed image contains custom distribution changes."
		}, "downstream_source_build_mapping_required"},
		{"explicit-image-reference", func(report *intake.Report, _ *Proposal) {
			report.Sections[0].Text += " The affected artifact is ghcr.io/synthetic-source/parser:v1.2.3."
		}, "downstream_source_build_mapping_required"},
		{"unknown-scope", func(_ *intake.Report, proposal *Proposal) {
			proposal.Scope = "unknown"
		}, "target_evidence_required"},
		{"missing-trigger", func(_ *intake.Report, proposal *Proposal) {
			proposal.Trigger = ""
		}, "target_evidence_required"},
		{"missing-evidence", func(_ *intake.Report, proposal *Proposal) {
			proposal.Missing = []string{"The affected target is not demonstrated by the report."}
		}, "target_evidence_required"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			report, proposal := fixtureReport(t), fixtureProposal(repository)
			test.change(&report, &proposal)
			generator := &syntheticGenerator{outputs: []string{fixtureJSON(t, proposal)}}
			sourceClient := fixtureSource(repository, "parser/request.go")
			state := stepFixture(t, Engine{Source: sourceClient, Generator: generator}, State{}, report, fixtureConfig())
			require.Equal(t, NeedsInput, state.Stage)
			require.Equal(t, test.reason, state.SafeError)
			require.Equal(t, proposal.Targets, state.UnverifiedProposal.Targets, "retain choices without choosing one")
			require.Nil(t, state.Target)
			require.Nil(t, state.Plan)
			require.Empty(t, sourceClient.operations)
			require.NotEmpty(t, state.EvidenceRequired)
			require.NotEmpty(t, state.Choices)
			if test.name == "multiple-versions" {
				require.Len(t, state.Choices, 2)
				require.Equal(t, "1.2.4", state.Choices[1].ReportedVersion)
				require.Empty(t, state.Choices[1].Ref, "an unproven version must not silently become a guessed Git ref")
			}
			if test.reason == "downstream_source_build_mapping_required" {
				require.Contains(t, strings.Join(state.EvidenceRequired, " "), "vanilla upstream source alone")
			}
		})
	}
}

func TestInvestigationModelRoundBudgets(t *testing.T) {
	report, config := fixtureReport(t), fixtureConfig()
	for _, limit := range []int{1, 3} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			config.MaxDiscoveryRounds = limit
			generator := &syntheticGenerator{outputs: []string{`{"unknown":"synthetic marker"}`, `{"problem":`, `{}`}}
			engine := Engine{Generator: generator}
			state := State{}
			for range limit {
				state = stepFixture(t, engine, state, report, config)
			}
			require.Equal(t, NeedsInput, state.Stage)
			require.Equal(t, "discovery_budget_exhausted", state.SafeError)
			require.Nil(t, state.UnverifiedProposal)
			require.Len(t, state.ModelTasks, limit)
			state = stepFixture(t, engine, state, report, config)
			require.Equal(t, NeedsInput, state.Stage)
			require.Len(t, generator.requests, limit, "terminal budget exhaustion cannot create another Task")
		})
	}
}

func TestInvestigationRejectsForgedPathsWithoutPacketReads(t *testing.T) {
	repository := fixtureConfig().AllowedRepositoryRoots[0]
	for _, paths := range [][]string{
		{"absent/file.go"}, {"../outside"}, {"/etc/passwd"}, {"parser/.git/config"},
		{"parser/request.go", "parser/request.go"}, {"parser/request.go", "Parser/other.go"},
	} {
		t.Run(strings.Join(paths, ","), func(t *testing.T) {
			report, config := fixtureReport(t), fixtureConfig()
			sourceClient := fixtureSource(repository, "parser/request.go")
			raw := fixtureJSON(t, fixtureSelection(paths...))
			generator := &syntheticGenerator{outputs: []string{fixtureJSON(t, fixtureProposal(repository)), raw, raw, raw}}
			engine := Engine{Source: sourceClient, Generator: generator}
			state := State{}
			for range 6 {
				state = stepFixture(t, engine, state, report, config)
			}
			require.Equal(t, NeedsInput, state.Stage)
			require.Equal(t, "selection_budget_exhausted", state.SafeError)
			require.Equal(t, 3, state.SelectionRounds)
			require.Equal(t, []Stage{Resolving, Inventory}, sourceClient.operations)
			require.Nil(t, state.Packet)
		})
	}
}

func TestInvestigationPacketMustMatchFrozenInventoryAndExactTarget(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*source.Packet)
	}{
		{"wrong-target", func(packet *source.Packet) { packet.Target.Commit = strings.Repeat("e", 40) }},
		{"wrong-tree", func(packet *source.Packet) { packet.Target.Tree = strings.Repeat("a", 40) }},
		{"wrong-file", func(packet *source.Packet) { packet.Files[0].Path = "different.go" }},
		{"wrong-content", func(packet *source.Packet) { packet.Files[0].Content = "package substituted\n" }},
		{"missing-file", func(packet *source.Packet) { packet.Files = nil }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			report, config := fixtureReport(t), fixtureConfig()
			repository := config.AllowedRepositoryRoots[0]
			sourceClient := fixtureSource(repository, "parser/request.go")
			sourceClient.packetMutate = test.mutate
			generator := &syntheticGenerator{outputs: []string{
				fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, fixtureSelection("parser/request.go")),
			}}
			engine := Engine{Source: sourceClient, Generator: generator}
			state := State{}
			for range 4 {
				state = stepFixture(t, engine, state, report, config)
			}
			state, err := engine.Step(t.Context(), state, report, config)
			require.ErrorIs(t, err, ErrState)
			require.Equal(t, NeedsInput, state.Stage)
			require.Equal(t, "source_packet_identity_mismatch", state.SafeError)
			require.Nil(t, state.Packet)
			require.Nil(t, state.Plan)
		})
	}
}

func TestInvestigationCancellationAndAcceptedTaskIdentity(t *testing.T) {
	report, config := fixtureReport(t), fixtureConfig()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	generator := &syntheticGenerator{}
	engine := Engine{Generator: generator}
	state, err := engine.Step(ctx, State{}, report, taskConfig(State{}, config))
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, State{}, state)
	require.Empty(t, generator.requests)

	ctx, cancel = context.WithCancel(t.Context())
	generator.generate = func(request modelagent.Request) (modelagent.Result, error) {
		cancel()
		return modelagent.Result{TaskName: request.TaskName, TaskUID: "accepted-uid", Output: "untrusted partial output"}, context.Canceled
	}
	state, err = engine.Step(ctx, State{}, report, taskConfig(State{}, config))
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, Identifying, state.Stage)
	require.Equal(t, 1, state.DiscoveryRounds)
	require.Equal(t, "accepted-uid", state.ModelTasks[0].TaskUID)
	require.False(t, state.ModelTasks[0].Completed)
	require.NotContains(t, fixtureJSON(t, state), "untrusted partial output")

	generator.generate = func(request modelagent.Request) (modelagent.Result, error) {
		require.Equal(t, "accepted-uid", request.ExpectedTaskUID)
		return modelagent.Result{
			TaskName: request.TaskName, TaskUID: request.ExpectedTaskUID,
			Output: fixtureJSON(t, fixtureProposal(config.AllowedRepositoryRoots[0])),
		}, nil
	}
	state = stepFixture(t, engine, state, report, config)
	require.Equal(t, Resolving, state.Stage)
	require.Equal(t, 1, state.DiscoveryRounds, "resuming an accepted Task is not a new model round")
	require.Len(t, state.ModelTasks, 1)
	require.Equal(t, generator.requests[0].Prompt, generator.requests[1].Prompt)
}

func TestInvestigationErrorsNeverEchoAdapterOrModelInput(t *testing.T) {
	const privateMarker = "SYNTHETIC_INPUT_MUST_NOT_APPEAR_IN_STATUS"
	report, config := fixtureReport(t), fixtureConfig()
	generator := &syntheticGenerator{generate: func(request modelagent.Request) (modelagent.Result, error) {
		return modelagent.Result{TaskName: request.TaskName, TaskUID: "accepted-uid", Output: privateMarker},
			errors.New(privateMarker)
	}}
	engine := Engine{Generator: generator}
	state, err := engine.Step(t.Context(), State{}, report, taskConfig(State{}, config))
	require.ErrorIs(t, err, ErrModelOperation)
	require.NotContains(t, err.Error(), privateMarker)
	require.NotContains(t, fixtureJSON(t, state), privateMarker)
	require.Equal(t, "accepted-uid", state.ModelTasks[0].TaskUID)

	generator.generate = func(request modelagent.Request) (modelagent.Result, error) {
		return modelagent.Result{TaskName: request.TaskName, TaskUID: "replacement-uid", Output: privateMarker}, nil
	}
	state, err = engine.Step(t.Context(), state, report, taskConfig(state, config))
	require.ErrorIs(t, err, ErrState)
	require.Equal(t, NeedsInput, state.Stage)
	require.Equal(t, "accepted-uid", state.ModelTasks[0].TaskUID)
	require.NotContains(t, fixtureJSON(t, state), "replacement-uid")
	require.NotContains(t, fixtureJSON(t, state), privateMarker)
}

func TestInvestigationBindsNormalizedReportPolicyAndTaskRequest(t *testing.T) {
	report, config := fixtureReport(t), fixtureConfig()
	generator := &syntheticGenerator{generate: func(request modelagent.Request) (modelagent.Result, error) {
		return modelagent.Result{TaskName: request.TaskName, TaskUID: "accepted-uid"}, errors.New("synthetic pending")
	}}
	engine := Engine{Generator: generator}
	saved, err := engine.Step(t.Context(), State{}, report, taskConfig(State{}, config))
	require.ErrorIs(t, err, ErrModelOperation)
	savedJSON := fixtureJSON(t, saved)
	for _, change := range []string{"report", "policy", "task-name", "task-uid"} {
		t.Run(change, func(t *testing.T) {
			localReport, localConfig := report, taskConfig(saved, config)
			switch change {
			case "report":
				localReport.Title += " changed after acceptance"
			case "policy":
				localConfig.MaxFiles = 1
			case "task-name":
				localConfig.RequestTaskName = "replacement-task-name"
			case "task-uid":
				localConfig.ExpectedTaskUID = "replacement-uid"
			}
			_, err := engine.Step(t.Context(), saved, localReport, localConfig)
			require.ErrorIs(t, err, ErrState)
			require.Len(t, generator.requests, 1)
			require.Equal(t, savedJSON, fixtureJSON(t, saved))
		})
	}
}

func TestInvestigationConfigurationCannotIncreaseHardLimits(t *testing.T) {
	report := fixtureReport(t)
	for _, change := range []func(*Config){
		func(config *Config) { config.MaxCandidates = 5 },
		func(config *Config) { config.MaxFiles = 33 },
		func(config *Config) { config.MaxDiscoveryRounds = 4 },
		func(config *Config) { config.MaxSelectionRounds = 4 },
		func(config *Config) { config.AllowedRepositoryRoots = nil },
		func(config *Config) { config.AllowedRepositoryRoots = []string{"https://github.com/owner"} },
		func(config *Config) { config.RepositoryHint = "https://github.com/unapproved/repository" },
		func(config *Config) { config.RefHint = "main" },
	} {
		config := taskConfig(State{}, fixtureConfig())
		change(&config)
		generator := &syntheticGenerator{}
		_, err := (Engine{Generator: generator}).Step(t.Context(), State{}, report, config)
		require.ErrorIs(t, err, ErrConfig)
		require.Empty(t, generator.requests)
	}
}

func TestInvestigationPromptsFitExistingModelBoundaryAndExposePagination(t *testing.T) {
	config, _, err := normalizeConfig(fixtureConfig())
	require.NoError(t, err)
	sourceClient := fixtureSource(config.AllowedRepositoryRoots[0], "file.go")
	proposal := fixtureProposal(sourceClient.target.Repository.URL)
	state := State{Target: &sourceClient.target, UnverifiedProposal: &proposal}
	for index := range 3000 {
		entry := sourceClient.entries[0]
		entry.Path = fmt.Sprintf("src/file-%04d.go", index)
		state.Inventory = append(state.Inventory, entry)
	}
	prompt, nextOffset, err := selectionPrompt(state, config)
	require.NoError(t, err)
	require.LessOrEqual(t, len(prompt), maxPromptBytes)
	require.Positive(t, nextOffset)
	require.Less(t, nextOffset, len(state.Inventory))
	var payload struct {
		Inventory    []source.Entry `json:"inventory"`
		Offset       int            `json:"offset"`
		NextOffset   int            `json:"nextOffset"`
		TotalEntries int            `json:"totalEntries"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(prompt, selectInstructions)), &payload))
	require.Equal(t, len(state.Inventory), payload.TotalEntries)
	require.Equal(t, nextOffset, payload.NextOffset)
	require.Len(t, payload.Inventory, nextOffset)
	state.InventoryOffset = nextOffset
	second, end, err := selectionPrompt(state, config)
	require.NoError(t, err)
	require.Greater(t, end, nextOffset)
	require.LessOrEqual(t, len(second), maxPromptBytes)
	require.NotEqual(t, prompt, second)
}
