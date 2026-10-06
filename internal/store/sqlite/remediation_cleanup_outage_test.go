package sqlite

import (
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func TestRemediationCleanupRecoveryReservationIsClaimAndRevisionFenced(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant", 1)
	now := remediationTestTime().Add(time.Hour)
	first := claimRemediationTestRun(t, s, run.Namespace, "first-worker", now)
	cleanup := store.RemediationCleanup{Phase: store.RemediationPhaseFailed, Reason: "execution-failed", StartedAt: now}
	first, err := s.BeginRemediationCleanupAttempt(t.Context(), first.Namespace, first.ID, first.ClaimOwner,
		first.ClaimEpoch, first.Revision, cleanup, now)
	require.NoError(t, err)
	cleanup = *first.Cleanup
	cleanup.Attempts++
	first, err = s.UpdateRemediationCleanup(t.Context(), first.Namespace, first.ID, first.ClaimOwner,
		first.ClaimEpoch, first.Revision, cleanup, false, now)
	require.NoError(t, err)
	resumedAt := now.Add(6 * time.Minute)
	second := claimRemediationTestRun(t, s, run.Namespace, "second-worker", resumedAt)
	_, err = s.BeginRemediationCleanupAttempt(t.Context(), second.Namespace, second.ID, first.ClaimOwner,
		first.ClaimEpoch, second.Revision, *second.Cleanup, resumedAt)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = s.BeginRemediationCleanupAttempt(t.Context(), second.Namespace, second.ID, second.ClaimOwner,
		second.ClaimEpoch, second.Revision-1, *second.Cleanup, resumedAt)
	require.ErrorIs(t, err, store.ErrConflict)
	tampered := *second.Cleanup
	tampered.RecoveryEpoch = tampered.LastAttemptEpoch
	_, err = s.BeginRemediationCleanupAttempt(t.Context(), second.Namespace, second.ID, second.ClaimOwner,
		second.ClaimEpoch, second.Revision, tampered, resumedAt)
	require.ErrorIs(t, err, store.ErrConflict, "workers cannot set the store-owned recovery reservation")

	reserved, err := s.BeginRemediationCleanupAttempt(t.Context(), second.Namespace, second.ID, second.ClaimOwner,
		second.ClaimEpoch, second.Revision, *second.Cleanup, resumedAt)
	require.NoError(t, err)
	require.Equal(t, second.ClaimEpoch, reserved.Cleanup.RecoveryEpoch)
	require.Equal(t, second.ClaimEpoch, reserved.Cleanup.LastAttemptEpoch)
	require.Equal(t, now, reserved.Cleanup.StartedAt)
	require.Equal(t, 1, reserved.Cleanup.Attempts)
	require.Equal(t, run.StateJSON, reserved.StateJSON)
	_, err = s.BeginRemediationCleanupAttempt(t.Context(), second.Namespace, second.ID, second.ClaimOwner,
		second.ClaimEpoch, second.Revision, *second.Cleanup, resumedAt)
	require.ErrorIs(t, err, store.ErrConflict)
	tampered = *reserved.Cleanup
	tampered.RecoveryEpoch = 0
	_, err = s.UpdateRemediationCleanup(t.Context(), reserved.Namespace, reserved.ID, reserved.ClaimOwner,
		reserved.ClaimEpoch, reserved.Revision, tampered, false, resumedAt)
	require.ErrorIs(t, err, store.ErrConflict, "workers cannot replenish the recovery allowance")
	quarantined, err := s.UpdateRemediationCleanup(t.Context(), reserved.Namespace, reserved.ID, reserved.ClaimOwner,
		reserved.ClaimEpoch, reserved.Revision, *reserved.Cleanup, false, resumedAt)
	require.NoError(t, err)
	require.Equal(t, store.RemediationReasonCleanupQuarantined, quarantined.Reason)
	require.Empty(t, quarantined.ClaimOwner)
	_, err = s.ClaimNextRemediationRun(t.Context(), run.Namespace, "third-worker", resumedAt.Add(time.Hour), time.Minute)
	require.ErrorIs(t, err, store.ErrNotFound)

	redriven, err := s.ReconcileRemediationCleanup(t.Context(), run.Namespace, run.ID, "operator", quarantined.Revision, resumedAt)
	require.NoError(t, err)
	require.Zero(t, redriven.Cleanup.Attempts)
	require.Zero(t, redriven.Cleanup.LastAttemptEpoch)
	require.Zero(t, redriven.Cleanup.RecoveryEpoch)
	require.Equal(t, resumedAt, redriven.Cleanup.StartedAt)
	require.Equal(t, run.StateJSON, redriven.StateJSON)
	require.Equal(t, store.RemediationPhaseCancelling, redriven.Phase)
	_, err = s.ReconcileRemediationCleanup(t.Context(), run.Namespace, run.ID, "operator", quarantined.Revision, resumedAt)
	require.ErrorIs(t, err, store.ErrConflict, "an acknowledged re-drive cannot be replayed as another reset")
	var audits int
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM remediation_cleanup_audit WHERE namespace=? AND run_id=?`,
		run.Namespace, run.ID).Scan(&audits))
	require.Equal(t, 1, audits)
}

func TestRemediationCleanupFailureLimitCannotUseOutageAllowance(t *testing.T) {
	now := remediationTestTime()
	cleanup := store.RemediationCleanup{
		Phase: store.RemediationPhaseFailed, Attempts: store.RemediationMaxCleanupAttempts,
		StartedAt: now.Add(-6 * time.Minute), LastAttemptEpoch: 1,
	}
	require.False(t, beginRemediationCleanupAttempt(&cleanup, true, 2, now))
	require.Zero(t, cleanup.RecoveryEpoch)
	require.Equal(t, uint64(1), cleanup.LastAttemptEpoch)
	require.Equal(t, store.RemediationMaxCleanupAttempts, cleanup.Attempts)
}
