package investigate

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

type screenedAdjacentSource struct {
	*syntheticSource
	blocked error
	paths   [][]string
}

func (s *screenedAdjacentSource) Packet(ctx context.Context, target source.Target, paths []string) (source.Packet, error) {
	s.paths = append(s.paths, slices.Clone(paths))
	if slices.Contains(paths, "src/file_test.go") {
		return source.Packet{}, s.blocked
	}
	return s.syntheticSource.Packet(ctx, target, paths)
}

func TestScreenedOptionalTestIsOmittedWithoutWeakeningRequiredPacket(t *testing.T) {
	config := fixtureConfig()
	config.IncludeAdjacentGoTests = true
	repository := config.AllowedRepositoryRoots[0]
	base := fixtureSource(repository, "src/file.go")
	companion := fixtureSource(repository, "src/file_test.go")
	base.files = append(base.files, companion.files...)
	base.entries = append(base.entries, companion.entries...)
	unsafeFile := companion.files[0]
	unsafeFile.Content = "password: synthetic-fixture-only\n"
	raw, err := json.Marshal(source.Packet{Version: 1, Target: base.target, Files: []source.PacketFile{unsafeFile}})
	require.NoError(t, err)
	_, contentError := source.DecodePacket(raw)
	require.True(t, source.IsPacketContentRejection(contentError))
	client := &screenedAdjacentSource{syntheticSource: base, blocked: contentError}
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, fixtureSelection("src/file.go")),
	}}
	engine := Engine{Source: client, Generator: generator}
	report := fixtureReport(t)
	state := State{}
	for range 5 {
		state = stepFixture(t, engine, state, report, config)
	}
	require.Equal(t, Packet, state.Stage)
	require.Equal(t, []string{"src/file.go"}, state.SelectedPaths)
	require.Empty(t, state.AddedTestPaths)
	require.Equal(t, []string{"src/file_test.go"}, state.OmittedTestPaths)
	require.Equal(t, testContextUnavailable, state.TestContextOmission)
	state = stepFixture(t, engine, state, report, config)
	require.Equal(t, Ready, state.Stage)
	require.Equal(t, [][]string{{"src/file.go", "src/file_test.go"}, {"src/file.go"}}, client.paths)
	require.Len(t, generator.requests, 2)
	require.Len(t, state.Plan.Packet.Files, 1)
	require.Equal(t, base.files[0], state.Plan.Packet.Files[0])
	require.Contains(t, state.Plan.Limitations, testContextOmittedLimitation)
	require.Equal(t, state, stepFixture(t, engine, state, report, config), "omissions must survive ready-state validation")
	state.OmittedTestPaths = []string{"src/other.go"}
	_, err = engine.Step(t.Context(), state, report, taskConfig(state, config))
	require.ErrorIs(t, err, ErrState)
}
