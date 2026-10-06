package investigate

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

type rateLimitedSource struct {
	*syntheticSource
	stage Stage
	until time.Time
	calls int
}

func (s *rateLimitedSource) limited(stage Stage) error {
	s.calls++
	if stage == s.stage && !s.until.IsZero() {
		return &source.RateLimitError{RetryAt: s.until}
	}
	return nil
}

func (s *rateLimitedSource) Resolve(ctx context.Context, repository, ref string) (source.Target, error) {
	if err := s.limited(Resolving); err != nil {
		return source.Target{}, err
	}
	return s.syntheticSource.Resolve(ctx, repository, ref)
}

func (s *rateLimitedSource) Inventory(ctx context.Context, target source.Target) ([]source.Entry, error) {
	if err := s.limited(Inventory); err != nil {
		return nil, err
	}
	return s.syntheticSource.Inventory(ctx, target)
}

func (s *rateLimitedSource) Packet(ctx context.Context, target source.Target, paths []string) (source.Packet, error) {
	if err := s.limited(Packet); err != nil {
		return source.Packet{}, err
	}
	return s.syntheticSource.Packet(ctx, target, paths)
}

func TestSourceRateLimitSurvivesStateRoundTripWithoutNewModelOrRequest(t *testing.T) {
	for _, stage := range []Stage{Resolving, Inventory, Packet} {
		t.Run(string(stage), func(t *testing.T) {
			config := fixtureConfig()
			repository := config.AllowedRepositoryRoots[0]
			report := fixtureReport(t)
			client := &rateLimitedSource{syntheticSource: fixtureSource(repository, "src/file.go")}
			generator := &syntheticGenerator{outputs: []string{
				fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, fixtureSelection("src/file.go")),
			}}
			engine := Engine{Source: client, Generator: generator}
			state := State{}
			for state.Stage != stage {
				state = stepFixture(t, engine, state, report, config)
			}
			before := state
			client.stage, client.until = stage, time.Now().UTC().Add(time.Minute)
			state, err := engine.Step(t.Context(), state, report, taskConfig(state, config))
			require.ErrorIs(t, err, ErrSourceDeferred)
			require.Equal(t, stage, state.Stage)
			require.Equal(t, before.Target, state.Target)
			require.Equal(t, before.SelectedPaths, state.SelectedPaths)
			require.Equal(t, before.DiscoveryRounds, state.DiscoveryRounds)
			require.Equal(t, before.SelectionRounds, state.SelectionRounds)
			require.Equal(t, before.ModelTasks, state.ModelTasks)
			raw, err := json.Marshal(state)
			require.NoError(t, err)
			var restored State
			require.NoError(t, json.Unmarshal(raw, &restored))
			calls, models := client.calls, len(generator.requests)
			waiting, err := engine.Step(t.Context(), restored, report, taskConfig(restored, config))
			require.ErrorIs(t, err, ErrSourceDeferred)
			require.Equal(t, restored, waiting)
			require.Equal(t, calls, client.calls)
			require.Len(t, generator.requests, models)
			restored.SourceRetryAt = time.Now().UTC().Add(-time.Second)
			client.until = time.Time{}
			next, err := engine.Step(t.Context(), restored, report, taskConfig(restored, config))
			require.NoError(t, err)
			require.True(t, next.SourceRetryAt.IsZero())
			require.NotEqual(t, stage, next.Stage)
			require.Equal(t, calls+1, client.calls)
			require.Len(t, generator.requests, models)
		})
	}
}

func TestSelectionRejectsImpossibleEncodedBudgetBeforeFetchingBlobs(t *testing.T) {
	config := fixtureConfig()
	config.MaxPlanJSONBytes = 4096
	repository := config.AllowedRepositoryRoots[0]
	client := fixtureSource(repository, "src/file.go")
	client.entries[0].Size = 4097
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, fixtureSelection("src/file.go")),
	}}
	engine := Engine{Source: client, Generator: generator}
	state := State{}
	report := fixtureReport(t)
	for range 4 {
		state = stepFixture(t, engine, state, report, config)
	}
	require.Equal(t, Selecting, state.Stage)
	require.Equal(t, "select_fewer_or_smaller_files_for_encoded_model_context", state.Feedback)
	require.Empty(t, state.SelectedPaths)
	require.Equal(t, []Stage{Resolving, Inventory}, client.operations)
}
