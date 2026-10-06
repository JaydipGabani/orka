package investigate

import (
	"testing"

	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

func TestAdjacentGoTestsAreVerifiedContextNotModelClaims(t *testing.T) {
	config := fixtureConfig()
	config.IncludeAdjacentGoTests = true
	repository := config.AllowedRepositoryRoots[0]
	client := fixtureSource(repository, "src/file.go")
	companion := fixtureSource(repository, "src/file_test.go")
	client.files = append(client.files, companion.files...)
	client.entries = append(client.entries, companion.entries...)
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, fixtureSelection("src/file.go")),
	}}
	engine := Engine{Source: client, Generator: generator}
	state := State{}
	report := fixtureReport(t)
	for range 5 {
		state = stepFixture(t, engine, state, report, config)
	}
	require.Equal(t, Ready, state.Stage)
	require.Equal(t, []string{"src/file.go"}, state.UnverifiedSelection.Paths)
	require.Equal(t, []string{"src/file_test.go"}, state.AddedTestPaths)
	require.Equal(t, []string{"src/file.go", "src/file_test.go"}, state.SelectedPaths)
	require.Equal(t, client.files, state.Plan.Packet.Files)
	_, _, err := normalizeConfig(config)
	require.NoError(t, err)
	restored := stepFixture(t, engine, state, report, config)
	require.Equal(t, state, restored)
	require.Len(t, generator.requests, 2)
	state.AddedTestPaths = []string{"src/unselected_test.go"}
	_, err = engine.Step(t.Context(), state, report, taskConfig(state, config))
	require.ErrorIs(t, err, ErrState)
}

func TestAdjacentTestsStayInsideCountAndByteLimitsBeforeFetch(t *testing.T) {
	for _, countLimit := range []bool{false, true} {
		config := fixtureConfig()
		config.IncludeAdjacentGoTests = true
		repository := config.AllowedRepositoryRoots[0]
		client := fixtureSource(repository, "src/file.go")
		companion := fixtureSource(repository, "src/file_test.go")
		client.files = append(client.files, companion.files...)
		client.entries = append(client.entries, companion.entries...)
		if countLimit {
			config.MaxFiles = 1
		} else {
			config.MaxPlanJSONBytes = int(client.entries[0].Size + companion.entries[0].Size - 1)
		}
		generator := &syntheticGenerator{outputs: []string{
			fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, fixtureSelection("src/file.go")),
		}}
		engine := Engine{Source: client, Generator: generator}
		state := State{}
		report := fixtureReport(t)
		for range 4 {
			state = stepFixture(t, engine, state, report, config)
		}
		require.Equal(t, Packet, state.Stage)
		require.Equal(t, []string{"src/file.go"}, state.SelectedPaths)
		require.Empty(t, state.AddedTestPaths)
		require.Equal(t, []string{"src/file_test.go"}, state.OmittedTestPaths)
		require.Equal(t, testContextBudget, state.TestContextOmission)
		require.Equal(t, []Stage{Resolving, Inventory}, client.operations)
	}
}

func TestAdjacentTestsCannotIntroduceUnlistedOrNonregularFiles(t *testing.T) {
	selected := make([]string, 2, 3)
	selected[0], selected[1] = "src/file.go", "src/other_test.go"
	entries := []source.Entry{
		{Path: "src/file.go", Mode: "100644", Size: 1},
		{Path: "src/file_test.go", Mode: "120000", Size: 1},
		{Path: "src/other_test.go", Mode: "100644", Size: 1},
	}
	paths, added := selectedPathsWithTests(entries, selected, true)
	require.Equal(t, selected, paths)
	require.Empty(t, added)
	entries[1].Mode = "100644"
	paths, added = selectedPathsWithTests(entries, selected, false)
	require.Equal(t, selected, paths)
	require.Empty(t, added)
	selected = append(selected, "src/file_test.go")
	paths, added = selectedPathsWithTests(entries, selected, true)
	require.Equal(t, selected, paths)
	require.Empty(t, added, "an explicitly selected test is not added twice")
}
