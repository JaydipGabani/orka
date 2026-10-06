package sqlite

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func TestRemediationMetadataPagesCoverOlderActiveRuns(t *testing.T) {
	s := newRemediationTestStore(t)
	old := createRemediationTestRun(t, s, "tenant", 1)
	for serial := 2; serial <= 104; serial++ {
		input := remediationTestRun("tenant", serial)
		_, _, err := s.CreateRemediationRun(t.Context(), input)
		require.NoError(t, err)
		_, err = s.db.ExecContext(t.Context(), `UPDATE remediation_runs SET phase='Succeeded' WHERE namespace=? AND id=?`,
			input.Namespace, input.ID)
		require.NoError(t, err)
	}
	first, err := s.ListRemediationRunsPage(t.Context(), "tenant", 100, "")
	require.NoError(t, err)
	require.Len(t, first.Items, 100)
	require.Equal(t, first.Items[99].ID, first.Continue)
	second, err := s.ListRemediationRunsPage(t.Context(), "tenant", 100, first.Continue)
	require.NoError(t, err)
	require.Len(t, second.Items, 4)
	require.Empty(t, second.Continue)
	require.Equal(t, old.ID, second.Items[3].ID)
	for _, page := range []store.RemediationRunPage{first, second} {
		for _, run := range page.Items {
			require.Nil(t, run.RequestJSON)
			require.Nil(t, run.PolicyJSON)
			require.Nil(t, run.StateJSON)
		}
	}
	counts, err := s.CountRemediationRuns(t.Context(), "tenant")
	require.NoError(t, err)
	require.EqualValues(t, 1, counts.Active)
	_, err = s.ListRemediationRunsPage(t.Context(), "foreign", 100, first.Continue)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.ListRemediationRunsPage(t.Context(), "tenant", 101, "")
	require.ErrorIs(t, err, store.ErrValidation)
}

func TestRemediationCleanupBudgetCannotBeResetByWorker(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant", 1)
	now := remediationTestTime().Add(time.Hour)
	run = claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	cleanup := store.RemediationCleanup{Phase: store.RemediationPhaseFailed, Reason: "execution-failed", StartedAt: now, Attempts: 1}
	run, err := s.UpdateRemediationCleanup(t.Context(), run.Namespace, run.ID, run.ClaimOwner, run.ClaimEpoch, run.Revision, cleanup, false, now)
	require.NoError(t, err)
	for _, changed := range []store.RemediationCleanup{
		{Phase: cleanup.Phase, Reason: cleanup.Reason, StartedAt: now.Add(time.Second), Attempts: 1},
		{Phase: cleanup.Phase, Reason: cleanup.Reason, StartedAt: now, Attempts: 0},
		{Phase: cleanup.Phase, Reason: cleanup.Reason, StartedAt: now, Attempts: 3},
	} {
		_, err := s.UpdateRemediationCleanup(t.Context(), run.Namespace, run.ID, run.ClaimOwner, run.ClaimEpoch,
			run.Revision, changed, false, now.Add(time.Second))
		require.ErrorIs(t, err, store.ErrConflict)
	}
	cleanup.Reason = "untrusted-secret-payload"
	_, err = s.UpdateRemediationCleanup(t.Context(), run.Namespace, run.ID, run.ClaimOwner, run.ClaimEpoch,
		run.Revision, cleanup, false, now)
	require.ErrorIs(t, err, store.ErrValidation)
	_, err = s.ReconcileRemediationCleanup(t.Context(), run.Namespace, run.ID, "operator", run.Revision, now)
	require.ErrorIs(t, err, store.ErrConflict, "only quarantined cleanup can be explicitly re-driven")
	_, err = s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, run.ClaimOwner, run.ClaimEpoch, run.Revision,
		store.RemediationUpdate{Phase: store.RemediationPhaseCancelling, Reason: store.RemediationReasonCleanupQuarantined,
			StateJSON: json.RawMessage(`{"resourceUID":"synthetic-uid"}`)}, now)
	require.NoError(t, err)
	run, err = s.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	_, err = s.ReconcileRemediationCleanup(t.Context(), run.Namespace, run.ID, "operator", run.Revision, now)
	require.ErrorIs(t, err, store.ErrConflict, "a live legacy claim must expire before a re-drive")
	_, err = s.CancelRemediationRun(t.Context(), run.Namespace, run.ID, now)
	require.NoError(t, err)
	run, err = s.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationReasonCleanupQuarantined, run.Reason, "cancellation must not accidentally re-enable quarantined work")
}

func TestRemediationCleanupMigrationPreservesLegacyQuarantineAndEffects(t *testing.T) {
	s := setupTestStore(t)
	var legacy strings.Builder
	for line := range strings.SplitSeq(remediationRunsSchema, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "cleanup_") {
			legacy.WriteString(line + "\n")
		}
	}
	_, err := s.db.ExecContext(t.Context(), legacy.String())
	require.NoError(t, err)
	input := frozenSourceTestRun(t, 1, "legacy-source")
	now := remediationTestTime().Add(time.Hour)
	state, err := json.Marshal(map[string]any{
		"resourceUID": "synthetic-legacy-uid",
		"settlement": store.RemediationCleanup{
			Phase: store.RemediationPhaseFailed, Reason: "execution-failed",
			Attempts: store.RemediationMaxCleanupAttempts, StartedAt: now.Add(-time.Minute),
		},
	})
	require.NoError(t, err)
	_, err = s.db.ExecContext(t.Context(), `INSERT INTO remediation_runs
		(namespace,id,request_id,submitted_by,mode,policy_digest,input_digest,request_json,policy_json,state_json,
		phase,reason,revision,claim_epoch,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,'Cancelling','cleanup-quarantined',3,2,?,?)`,
		input.Namespace, input.ID, input.RequestID, input.SubmittedBy, input.Mode, input.PolicyDigest, input.InputDigest,
		[]byte(input.RequestJSON), []byte(input.PolicyJSON), state, input.CreatedAt.UnixNano(), now.UnixNano())
	require.NoError(t, err)
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	run, err := s.GetRemediationRun(t.Context(), input.Namespace, input.ID)
	require.NoError(t, err)
	require.Nil(t, run.Cleanup)
	require.JSONEq(t, string(state), string(run.StateJSON))
	require.Equal(t, store.RemediationReasonCleanupQuarantined, run.Reason)
	run, err = s.ReconcileRemediationCleanup(t.Context(), input.Namespace, input.ID, "operator", run.Revision, now)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseCancelling, run.Phase)
	require.Equal(t, store.RemediationPhaseFailed, run.Cleanup.Phase)
	require.Zero(t, run.Cleanup.Attempts)
	require.Equal(t, now, run.Cleanup.StartedAt)
	require.EqualValues(t, 3, run.ClaimEpoch)
	require.JSONEq(t, string(state), string(run.StateJSON))
	require.Equal(t, input.RequestJSON, run.RequestJSON)
	require.Equal(t, input.PolicyJSON, run.PolicyJSON)
	var reservations int
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM remediation_source_claims
		WHERE namespace=? AND source_key=? AND run_id=?`, input.Namespace, input.SourceOperationKey, input.ID).Scan(&reservations))
	require.Equal(t, 1, reservations)
}

func TestRemediationCleanupTimestampHasCanonicalRoundTrip(t *testing.T) {
	s := newRemediationTestStore(t)
	created := createRemediationTestRun(t, s, "tenant", 1)
	now := time.Now()
	claim := claimRemediationTestRun(t, s, created.Namespace, "worker", now)
	cleanup := store.RemediationCleanup{Phase: store.RemediationPhaseFailed, Reason: "execution-failed", StartedAt: now}
	updated, err := s.UpdateRemediationCleanup(t.Context(), claim.Namespace, claim.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, cleanup, false, now)
	require.NoError(t, err)
	stored, err := s.GetRemediationRun(t.Context(), claim.Namespace, claim.ID)
	require.NoError(t, err)
	require.Equal(t, stored, updated, "update results must not retain local/monotonic timestamps absent from persisted state")
	require.True(t, stored.Cleanup.StartedAt.Equal(now))
}
