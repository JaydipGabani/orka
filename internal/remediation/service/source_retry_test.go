package service

import (
	"context"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

type throttledPipelineSource struct {
	investigate.Source
	limited bool
}

func (s *throttledPipelineSource) Packet(ctx context.Context, target source.Target, paths []string) (source.Packet, error) {
	if !s.limited {
		s.limited = true
		return source.Packet{}, &source.RateLimitError{RetryAt: time.Now().UTC().Add(-time.Second)}
	}
	return s.Source.Packet(ctx, target, paths)
}

func TestPipelineResumesRateLimitedSourceWithoutRepeatingModel(t *testing.T) {
	fixture := newControllerFixture(t)
	fixture.pipeline.Source = &throttledPipelineSource{Source: fixture.pipeline.Source}
	run := fixture.submit(Validate)
	require.NoError(t, fixture.service.RunOnce(t.Context()))
	waiting, err := fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseRunning, waiting.Phase)
	require.Equal(t, "waiting-for-infrastructure", waiting.Reason)
	require.False(t, waiting.CancelRequested)
	require.Nil(t, waiting.Cleanup)
	require.Equal(t, 2, fixture.models.calls)
	time.Sleep(fixture.service.config.Lease + 20*time.Millisecond)
	require.NoError(t, fixture.service.RunOnce(t.Context()))
	finished, err := fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseSucceeded, finished.Phase, finished.Reason)
	require.Equal(t, 3, fixture.models.calls, "resume must reuse discovery and file selection; only checks need a new model call")
}
