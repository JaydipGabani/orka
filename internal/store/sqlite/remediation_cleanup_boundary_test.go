package sqlite

import (
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func TestRemediationCleanupExpiryPreservesUnusedRecoveryAttempt(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant", 1)
	started := remediationTestTime().Add(time.Hour)
	claim := claimRemediationTestRun(t, s, run.Namespace, "first-worker", started)
	cleanup := store.RemediationCleanup{
		Phase: store.RemediationPhaseFailed, Reason: "execution-failed", StartedAt: started,
	}
	claim, err := s.BeginRemediationCleanupAttempt(t.Context(), run.Namespace, run.ID, claim.ClaimOwner,
		claim.ClaimEpoch, claim.Revision, cleanup, started)
	require.NoError(t, err)
	cleanup = *claim.Cleanup
	cleanup.Attempts++
	_, err = s.UpdateRemediationCleanup(t.Context(), run.Namespace, run.ID, claim.ClaimOwner,
		claim.ClaimEpoch, claim.Revision, cleanup, false, started)
	require.NoError(t, err)

	nearExpiry := started.Add(store.RemediationMaxCleanupDuration - 300*time.Millisecond)
	claim = claimRemediationTestRun(t, s, run.Namespace, "resumed-worker", nearExpiry)
	claim, err = s.BeginRemediationCleanupAttempt(t.Context(), run.Namespace, run.ID, claim.ClaimOwner,
		claim.ClaimEpoch, claim.Revision, *claim.Cleanup, nearExpiry)
	require.NoError(t, err)
	require.Zero(t, claim.Cleanup.RecoveryEpoch)
	cleanup = *claim.Cleanup
	cleanup.Attempts++
	pending, err := s.UpdateRemediationCleanup(t.Context(), run.Namespace, run.ID, claim.ClaimOwner,
		claim.ClaimEpoch, claim.Revision, cleanup, false, nearExpiry.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseCancelling, pending.Phase)
	require.NotEqual(t, store.RemediationReasonCleanupQuarantined, pending.Reason,
		"a truncated ordinary attempt must not consume an unused recovery attempt")
	require.Zero(t, pending.Cleanup.RecoveryEpoch)

	nextTime := nearExpiry.Add(2 * time.Minute)
	recovery := claimRemediationTestRun(t, s, run.Namespace, "recovery-worker", nextTime)
	recovery, err = s.BeginRemediationCleanupAttempt(t.Context(), run.Namespace, run.ID, recovery.ClaimOwner,
		recovery.ClaimEpoch, recovery.Revision, *recovery.Cleanup, nextTime)
	require.NoError(t, err)
	require.Equal(t, recovery.ClaimEpoch, recovery.Cleanup.RecoveryEpoch)
	require.Equal(t, started, recovery.Cleanup.StartedAt)
	complete, err := s.UpdateRemediationCleanup(t.Context(), run.Namespace, run.ID, recovery.ClaimOwner,
		recovery.ClaimEpoch, recovery.Revision, *recovery.Cleanup, true, nextTime.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseFailed, complete.Phase)
	require.Nil(t, complete.Cleanup)
}
