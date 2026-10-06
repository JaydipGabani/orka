package investigate

import (
	"context"
	"errors"
	"strings"
	"testing"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

type syntheticExpander struct {
	*syntheticSource
	expanded []source.Entry
}

func (fixture *syntheticExpander) InventoryPaths(
	ctx context.Context, target source.Target, paths []string,
) ([]source.Entry, error) {
	fixture.operations = append(fixture.operations, Inventory)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target != fixture.target || len(paths) != 1 || paths[0] != "vendor" {
		return nil, errors.New("unexpected synthetic expansion")
	}
	return fixture.expanded, nil
}

func TestInvestigationExplicitDependencyExpansionIsAnotherBoundedStep(t *testing.T) {
	report, config := fixtureReport(t), fixtureConfig()
	repository := config.AllowedRepositoryRoots[0]
	base := fixtureSource(repository, "vendor/parser/request.go")
	expander := &syntheticExpander{syntheticSource: base, expanded: base.entries}
	base.entries = []source.Entry{{Path: "vendor", Mode: "040000", BlobSHA: strings.Repeat("e", 40)}}
	expansion := Selection{Paths: []string{}, Expand: []string{"vendor"}, Missing: []string{}, Limitations: []string{}}
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, expansion),
		fixtureJSON(t, fixtureSelection("vendor/parser/request.go")),
	}}
	engine := Engine{Source: expander, Generator: generator}
	state := State{}
	for _, stage := range []Stage{Resolving, Inventory, Selecting, Inventory, Selecting, Packet, Ready} {
		operations := len(generator.requests) + len(base.operations)
		state = stepFixture(t, engine, state, report, config)
		require.Equal(t, stage, state.Stage)
		require.Equal(t, operations+1, len(generator.requests)+len(base.operations))
	}
	require.Equal(t, 2, state.SelectionRounds)
	require.Contains(t, generator.requests[1].Prompt, `"path":"vendor"`)
	require.NotContains(t, generator.requests[1].Prompt, "vendor/parser/request.go")
	require.Contains(t, generator.requests[2].Prompt, "vendor/parser/request.go")
	require.Equal(t, "vendor/parser/request.go", state.Plan.Packet.Files[0].Path)
}

func TestInvestigationDoesNotGuessDependencyFilesWithoutAdapter(t *testing.T) {
	report, config := fixtureReport(t), fixtureConfig()
	repository := config.AllowedRepositoryRoots[0]
	sourceClient := fixtureSource(repository, "unused.go")
	sourceClient.entries = []source.Entry{{Path: "vendor", Mode: "040000", BlobSHA: strings.Repeat("e", 40)}}
	expansion := Selection{Paths: []string{}, Expand: []string{"vendor"}, Missing: []string{}, Limitations: []string{}}
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, expansion),
	}}
	engine := Engine{Source: sourceClient, Generator: generator}
	state := State{}
	for range 5 {
		state = stepFixture(t, engine, state, report, config)
	}
	require.Equal(t, NeedsAdapter, state.Stage)
	require.Equal(t, "dependency_inventory_adapter_required", state.SafeError)
	require.Equal(t, []Stage{Resolving, Inventory}, sourceClient.operations)
	require.Nil(t, state.Packet)
}

func TestInvestigationFailedResolutionsAreBoundedAndSanitized(t *testing.T) {
	const marker = "SYNTHETIC_REMOTE_BODY_MUST_NOT_ESCAPE"
	report, config := fixtureReport(t), fixtureConfig()
	repository := config.AllowedRepositoryRoots[0]
	sourceClient := fixtureSource(repository, "parser/request.go")
	sourceClient.resolveError = errors.New(marker)
	proposal := fixtureJSON(t, fixtureProposal(repository))
	generator := &syntheticGenerator{outputs: []string{proposal, proposal, proposal}}
	engine := Engine{Source: sourceClient, Generator: generator}
	state := State{}
	for round := range 3 {
		state = stepFixture(t, engine, state, report, config)
		require.Equal(t, Resolving, state.Stage)
		var err error
		state, err = engine.Step(t.Context(), state, report, config)
		require.ErrorIs(t, err, ErrSourceOperation)
		require.NotContains(t, err.Error(), marker)
		require.NotContains(t, fixtureJSON(t, state), marker)
		if round < 2 {
			require.Equal(t, Identifying, state.Stage)
		}
	}
	require.Equal(t, NeedsInput, state.Stage)
	require.Equal(t, "discovery_budget_exhausted", state.SafeError)
	require.Len(t, generator.requests, 3)
	require.Len(t, sourceClient.operations, 3)
	require.Contains(t, generator.requests[1].Prompt, `"previousOutcome":"source_resolution_failed"`)
	require.NotContains(t, generator.requests[1].Prompt, marker)
	state = stepFixture(t, engine, state, report, config)
	require.Len(t, sourceClient.operations, 3)
	require.NotEmpty(t, state.EvidenceRequired)
}

func TestInvestigationFailedPacketOffersOnlySafeFeedbackAndConsumesSelectionBudget(t *testing.T) {
	const marker = "SYNTHETIC_SOURCE_CONTENT_NOT_AN_ERROR"
	report, config := fixtureReport(t), fixtureConfig()
	repository := config.AllowedRepositoryRoots[0]
	sourceClient := fixtureSource(repository, "parser/request.go")
	sourceClient.packetError = errors.New(marker)
	selection := fixtureJSON(t, fixtureSelection("parser/request.go"))
	generator := &syntheticGenerator{outputs: []string{fixtureJSON(t, fixtureProposal(repository)), selection, selection, selection}}
	engine := Engine{Source: sourceClient, Generator: generator}
	state := State{}
	for range 3 {
		state = stepFixture(t, engine, state, report, config)
	}
	for range 3 {
		state = stepFixture(t, engine, state, report, config)
		require.Equal(t, Packet, state.Stage)
		var err error
		state, err = engine.Step(t.Context(), state, report, config)
		require.ErrorIs(t, err, ErrSourceOperation)
		require.NotContains(t, err.Error(), marker)
		require.NotContains(t, fixtureJSON(t, state), marker)
		require.Empty(t, state.SelectedPaths)
		require.Nil(t, state.Plan)
	}
	require.Equal(t, NeedsInput, state.Stage)
	require.Equal(t, "selection_budget_exhausted", state.SafeError)
	require.Equal(t, 3, state.SelectionRounds)
	require.Contains(t, generator.requests[2].Prompt, `"previousOutcome":"source_packet_unavailable"`)
	require.NotContains(t, generator.requests[2].Prompt, marker)
	require.Equal(t, []Stage{Resolving, Inventory, Packet, Packet, Packet}, sourceClient.operations)
}

func TestInvestigationPendingModelKeepsTheSameFeedbackAndFrozenRequest(t *testing.T) {
	report, config := fixtureReport(t), fixtureConfig()
	output := fixtureJSON(t, fixtureProposal(config.AllowedRepositoryRoots[0]))
	calls := 0
	generator := &syntheticGenerator{generate: func(request modelagent.Request) (modelagent.Result, error) {
		calls++
		result := modelagent.Result{TaskName: request.TaskName, TaskUID: "uid-" + request.TaskName}
		switch calls {
		case 1:
			result.Output = `{"unknown":true}`
		case 2:
			return result, errors.New("synthetic transport failure after acceptance")
		default:
			result.Output = output
		}
		return result, nil
	}}
	engine := Engine{Generator: generator}
	state := stepFixture(t, engine, State{}, report, config)
	require.Equal(t, "invalid_target_proposal", state.Feedback)
	state, err := engine.Step(t.Context(), state, report, taskConfig(state, config))
	require.ErrorIs(t, err, ErrModelOperation)
	require.Equal(t, "invalid_target_proposal", state.Feedback)
	state = stepFixture(t, engine, state, report, config)
	require.Equal(t, Resolving, state.Stage)
	require.Equal(t, 2, state.DiscoveryRounds)
	require.Equal(t, generator.requests[1].Prompt, generator.requests[2].Prompt)
	require.Equal(t, generator.requests[1].TaskName, generator.requests[2].TaskName)
	require.NotEmpty(t, generator.requests[2].ExpectedTaskUID)
}

func TestInvestigationMetadataCannotSelectOverlargeOrEmptyFiles(t *testing.T) {
	config := fixtureConfig()
	fixture := fixtureSource(config.AllowedRepositoryRoots[0], "selected.go")
	for _, size := range []int64{0, maxPacketBytes + 1} {
		fixture.entries[0].Size = size
		require.False(t, inventoryContains(fixture.entries, []string{"selected.go"}, false))
	}
	fixture.entries[0].Size = maxPacketBytes
	require.True(t, inventoryContains(fixture.entries, []string{"selected.go"}, false))
	extra := fixture.entries[0]
	extra.Path, extra.Size = "second.go", 1
	fixture.entries = append(fixture.entries, extra)
	require.False(t, inventoryContains(fixture.entries, []string{"selected.go", "second.go"}, false))
}

func TestInvestigationPendingTaskCannotBeReplacedByBlankUIDOrReusedName(t *testing.T) {
	report, config := fixtureReport(t), fixtureConfig()
	generator := &syntheticGenerator{generate: func(request modelagent.Request) (modelagent.Result, error) {
		return modelagent.Result{TaskName: request.TaskName, Output: "{}"}, nil
	}}
	state, err := (Engine{Generator: generator}).Step(t.Context(), State{}, report, taskConfig(State{}, config))
	require.ErrorIs(t, err, ErrState)
	require.Equal(t, NeedsInput, state.Stage)
	require.Empty(t, state.ModelTasks[0].TaskUID)

	generator = &syntheticGenerator{outputs: []string{`{}`}}
	engine := Engine{Generator: generator}
	state = stepFixture(t, engine, State{}, report, config)
	config.RequestTaskName = state.ModelTasks[0].TaskName
	_, err = engine.Step(t.Context(), state, report, config)
	require.ErrorIs(t, err, ErrState)
	require.Len(t, generator.requests, 1, "a completed named Task must not become a new discovery round")
}

func TestInvestigationVersionChoicesAreBoundedAndExplicitlyIncomplete(t *testing.T) {
	report, config := fixtureReport(t), fixtureConfig()
	report.Versions = []string{"1.2.3", "1.2.4", "1.3.0", "2.0.0", "3.0.0"}
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, fixtureProposal(config.AllowedRepositoryRoots[0])),
	}}
	state := stepFixture(t, Engine{Generator: generator}, State{}, report, config)
	require.Equal(t, NeedsInput, state.Stage)
	require.Equal(t, "affected_version_choice_required", state.SafeError)
	require.Len(t, state.Choices, 4)
	require.True(t, state.ChoicesTruncated)
	require.Nil(t, state.Target)
	require.Nil(t, state.Plan)
}
