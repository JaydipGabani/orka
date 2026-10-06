package service

import (
	"testing"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func TestControllerPipelinePreservesCanonicalCloneIdentity(t *testing.T) {
	for _, same := range []bool{true, false} {
		fixture := newControllerFixture(t)
		fixture.builder.baseline.UpstreamRepoURL += ".git"
		if !same {
			fixture.builder.baseline.UpstreamRepoURL = "https://github.com/kedacore/different.git"
		}
		run := fixture.submit(Validate)
		require.NoError(t, fixture.service.RunOnce(t.Context()))
		result, err := fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
		require.NoError(t, err)
		if same {
			require.Equal(t, store.RemediationPhaseSucceeded, result.Phase, result.Reason)
		} else {
			require.NotEqual(t, store.RemediationPhaseSucceeded, result.Phase)
		}
	}
}
