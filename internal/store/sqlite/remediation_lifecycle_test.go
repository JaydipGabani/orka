package sqlite

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orka-agents/orka/internal/store"
)

func TestRemediationDisabledProbeDoesNotInitializeStore(t *testing.T) {
	s := setupTestStore(t)
	initialized, err := s.RemediationStoreInitialized(t.Context())
	require.NoError(t, err)
	require.False(t, initialized)
	cancelled, err := s.CancelActiveRemediationRuns(t.Context(), "tenant-a", remediationTestTime())
	require.ErrorIs(t, err, store.ErrNotReady)
	require.Zero(t, cancelled)
	var tables int
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'table' AND name LIKE 'remediation_%'`).Scan(&tables))
	require.Zero(t, tables)
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	initialized, err = s.RemediationStoreInitialized(t.Context())
	require.NoError(t, err)
	require.True(t, initialized)
}

func TestRemediationDisabledCancellationPreservesClaimsAndState(t *testing.T) {
	s := newRemediationTestStore(t)
	now := remediationTestTime().Add(time.Hour)
	live := createRemediationTestRun(t, s, "tenant-a", 1)
	claim := claimRemediationTestRun(t, s, live.Namespace, "worker", now)
	live, err := s.UpdateRemediationRun(t.Context(), live.Namespace, live.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning,
			StateJSON: json.RawMessage(`{"uid": "synthetic-accepted-task"}`)}, now)
	require.NoError(t, err)

	input := remediationTestRun("tenant-a", 2)
	input.Deadline = now.Add(24 * time.Hour)
	paused, _, err := s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	claim = claimRemediationTestRun(t, s, paused.Namespace, "worker", now)
	paused, err = s.UpdateRemediationRun(t.Context(), paused.Namespace, paused.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseNeedsApproval, ApprovalDigest: "sha256:pending-plan",
			StateJSON: json.RawMessage(`{"plan": "synthetic-plan"}`)}, now)
	require.NoError(t, err)

	terminals := make([]*store.RemediationRun, 0, 6)
	for index, phase := range []string{store.RemediationPhaseSucceeded, store.RemediationPhaseFailed,
		store.RemediationPhaseCancelled, store.RemediationPhaseTimedOut, store.RemediationPhaseNeedsInput, store.RemediationPhaseNeedsAdapter} {
		run := createRemediationTestRun(t, s, "tenant-a", index+3)
		claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
		terminal, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
			claim.Revision, store.RemediationUpdate{Phase: phase, Reason: "synthetic terminal reason"}, now)
		require.NoError(t, err)
		terminals = append(terminals, terminal)
	}
	alreadyCancelled := createRemediationTestRun(t, s, "tenant-a", 9)
	_ = claimRemediationTestRun(t, s, alreadyCancelled.Namespace, "worker", now)
	alreadyCancelled, err = s.CancelRemediationRun(t.Context(), alreadyCancelled.Namespace, alreadyCancelled.ID, now)
	require.NoError(t, err)
	queued := createRemediationTestRun(t, s, "tenant-a", 10)
	otherNamespace := createRemediationTestRun(t, s, "tenant-b", 1)

	cancelled, err := s.CancelActiveRemediationRuns(t.Context(), "tenant-a", now.Add(time.Second))
	require.NoError(t, err)
	require.EqualValues(t, 3, cancelled)
	for _, previous := range []*store.RemediationRun{live, paused, queued} {
		got, err := s.GetRemediationRun(t.Context(), previous.Namespace, previous.ID)
		require.NoError(t, err)
		expected := *previous
		expected.CancelRequested = true
		expected.Phase = store.RemediationPhaseCancelling
		expected.Reason, expected.ApprovalDigest = "", ""
		expected.Revision++
		expected.UpdatedAt = now.Add(time.Second)
		require.Equal(t, &expected, got)
	}
	for _, previous := range append(terminals, alreadyCancelled, otherNamespace) {
		got, err := s.GetRemediationRun(t.Context(), previous.Namespace, previous.ID)
		require.NoError(t, err)
		require.Equal(t, previous, got)
	}
	_, err = s.UpdateRemediationRun(t.Context(), live.Namespace, live.ID, live.ClaimOwner, live.ClaimEpoch,
		live.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseSucceeded}, now.Add(time.Second))
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = s.UpdateRemediationRun(t.Context(), live.Namespace, live.ID, live.ClaimOwner, live.ClaimEpoch,
		live.Revision+1, store.RemediationUpdate{Phase: store.RemediationPhaseSucceeded}, now.Add(time.Second))
	require.ErrorIs(t, err, store.ErrConflict)
	next := claimRemediationTestRun(t, s, paused.Namespace, "cleanup-worker", now.Add(time.Second))
	require.Equal(t, paused.ID, next.ID, "admission disablement must wake unexpired NeedsApproval")
	require.True(t, next.CancelRequested)
	require.Equal(t, store.RemediationPhaseCancelling, next.Phase)
	cancelled, err = s.CancelActiveRemediationRuns(t.Context(), "tenant-a", now.Add(2*time.Second))
	require.NoError(t, err)
	require.Zero(t, cancelled)
}

func TestRemediationDisabledCancellationIsBoundedAndOldestFirst(t *testing.T) {
	s := newRemediationTestStore(t)
	first := createRemediationTestRun(t, s, "tenant-a", 1)
	// Simulate imported legacy rows beyond today's admission cap.
	_, err := s.db.ExecContext(t.Context(), `WITH RECURSIVE ids(serial) AS (
		VALUES (2) UNION ALL SELECT serial + 1 FROM ids WHERE serial < 1002
	) INSERT INTO remediation_runs (`+remediationRunColumns+`)
	SELECT namespace, printf('rm-%032x', serial), 'legacy-request-' || serial, submitted_by, mode, policy_digest, input_digest,
		request_json, policy_json, state_json, phase, reason, revision, claim_epoch, claim_owner,
		claim_until, created_at + serial, updated_at, deadline, cancel_requested, approval_digest, approved_digest, approved_by,
		cleanup_phase, cleanup_reason, cleanup_attempts, cleanup_started_at, cleanup_last_attempt_epoch, cleanup_recovery_epoch
	FROM remediation_runs, ids WHERE namespace = ? AND id = ?`, first.Namespace, first.ID)
	require.NoError(t, err)
	now := remediationTestTime().Add(time.Hour)
	cancelled, err := s.CancelActiveRemediationRuns(t.Context(), first.Namespace, now)
	require.NoError(t, err)
	require.EqualValues(t, store.RemediationMaxActiveRuns, cancelled)
	oldest, err := s.GetRemediationRunMetadata(t.Context(), first.Namespace, first.ID)
	require.NoError(t, err)
	require.True(t, oldest.CancelRequested)
	newestInput := remediationTestRun(first.Namespace, 1002)
	newest, err := s.GetRemediationRunMetadata(t.Context(), newestInput.Namespace, newestInput.ID)
	require.NoError(t, err)
	require.False(t, newest.CancelRequested)
	cancelled, err = s.CancelActiveRemediationRuns(t.Context(), first.Namespace, now)
	require.NoError(t, err)
	require.EqualValues(t, 2, cancelled)
	cancelled, err = s.CancelActiveRemediationRuns(t.Context(), first.Namespace, now)
	require.NoError(t, err)
	require.Zero(t, cancelled)
}

func TestRemediationDisabledCancellationValidationAndAtomicConflict(t *testing.T) {
	s := newRemediationTestStore(t)
	first := createRemediationTestRun(t, s, "tenant-a", 1)
	second := createRemediationTestRun(t, s, "tenant-a", 2)
	now := remediationTestTime().Add(time.Hour)
	_, err := s.CancelActiveRemediationRuns(t.Context(), "", now)
	require.ErrorIs(t, err, store.ErrValidation)
	_, err = s.CancelActiveRemediationRuns(t.Context(), first.Namespace, time.Time{})
	require.ErrorIs(t, err, store.ErrValidation)
	_, err = s.db.ExecContext(t.Context(), `UPDATE remediation_runs SET revision = ?
		WHERE namespace = ? AND id = ?`, int64(math.MaxInt64), first.Namespace, first.ID)
	require.NoError(t, err)
	cancelled, err := s.CancelActiveRemediationRuns(t.Context(), first.Namespace, now)
	require.ErrorIs(t, err, store.ErrConflict)
	require.Zero(t, cancelled)
	unchanged, err := s.GetRemediationRun(t.Context(), second.Namespace, second.ID)
	require.NoError(t, err)
	require.Equal(t, second, unchanged)
}
