package sqlite

import (
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func TestRemediationCountsIncludeRunsOutsideListWindow(t *testing.T) {
	storage := newRemediationTestStore(t)
	first := createRemediationTestRun(t, storage, "tenant", 1)
	_, err := storage.db.ExecContext(t.Context(), `WITH RECURSIVE ids(serial) AS (
		VALUES (2) UNION ALL SELECT serial + 1 FROM ids WHERE serial <= 150
	) INSERT INTO remediation_runs (`+remediationRunColumns+`)
	SELECT namespace, printf('rm-%032x', serial), 'terminal-' || serial, submitted_by, mode, policy_digest, input_digest,
		request_json, policy_json, state_json, 'Succeeded', reason, revision, claim_epoch, claim_owner,
		claim_until, created_at + serial, updated_at, deadline, cancel_requested, approval_digest, approved_digest, approved_by,
		cleanup_phase, cleanup_reason, cleanup_attempts, cleanup_started_at, cleanup_last_attempt_epoch, cleanup_recovery_epoch
	FROM remediation_runs, ids WHERE namespace = ? AND id = ?`, first.Namespace, first.ID)
	require.NoError(t, err)
	recent, err := storage.ListRemediationRuns(t.Context(), first.Namespace, store.RemediationMaxListLimit)
	require.NoError(t, err)
	require.Len(t, recent, store.RemediationMaxListLimit)
	for _, run := range recent {
		require.True(t, store.IsRemediationTerminalPhase(run.Phase))
	}
	counts, err := storage.CountRemediationRuns(t.Context(), first.Namespace)
	require.NoError(t, err)
	require.Equal(t, store.RemediationRunCounts{Active: 1}, counts)
	now := remediationTestTime().Add(time.Hour)
	claim := claimRemediationTestRun(t, storage, first.Namespace, "worker", now)
	claim, err = storage.UpdateRemediationRun(t.Context(), first.Namespace, first.ID, claim.ClaimOwner,
		claim.ClaimEpoch, claim.Revision, store.RemediationUpdate{
			Phase: store.RemediationPhaseCancelling, Reason: store.RemediationReasonCleanupQuarantined,
		}, now)
	require.NoError(t, err)
	counts, err = storage.CountRemediationRuns(t.Context(), first.Namespace)
	require.NoError(t, err)
	require.Equal(t, store.RemediationRunCounts{Active: 1, Quarantined: 1}, counts)
	_, err = storage.UpdateRemediationRun(t.Context(), first.Namespace, first.ID, claim.ClaimOwner,
		claim.ClaimEpoch, claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseFailed}, now)
	require.NoError(t, err)
	counts, err = storage.CountRemediationRuns(t.Context(), first.Namespace)
	require.NoError(t, err)
	require.Equal(t, store.RemediationRunCounts{}, counts, "completed history must not prevent a drain forever")
	counts, err = storage.CountRemediationRuns(t.Context(), "foreign")
	require.NoError(t, err)
	require.Equal(t, store.RemediationRunCounts{}, counts)
	_, err = storage.CountRemediationRuns(t.Context(), "")
	require.ErrorIs(t, err, store.ErrValidation)
}
