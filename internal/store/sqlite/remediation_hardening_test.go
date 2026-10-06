package sqlite

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orka-agents/orka/internal/store"
)

func TestRemediationExpiredApprovalOnlyAllowsTimeoutSettlement(t *testing.T) {
	s := newRemediationTestStore(t)
	input := remediationTestRun("tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	input.Deadline = now.Add(time.Second)
	run, _, err := s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	pending, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseNeedsApproval, ApprovalDigest: "sha256:plan"}, now)
	require.NoError(t, err)
	_, err = s.ClaimNextRemediationRun(t.Context(), run.Namespace, "other", input.Deadline.Add(-time.Nanosecond), time.Minute)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, pending.ApprovalDigest, "approver", input.Deadline)
	require.ErrorIs(t, err, store.ErrConflict)

	expired := claimRemediationTestRun(t, s, run.Namespace, "other", input.Deadline)
	require.Equal(t, store.RemediationPhaseNeedsApproval, expired.Phase)
	require.Equal(t, pending.Revision, expired.Revision)
	require.Equal(t, claim.ClaimEpoch+1, expired.ClaimEpoch)
	require.NoError(t, s.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, expired.ClaimOwner,
		expired.ClaimEpoch, input.Deadline, time.Minute))
	for _, phase := range []string{store.RemediationPhaseQueued, store.RemediationPhaseRunning,
		store.RemediationPhaseSucceeded, store.RemediationPhaseFailed, store.RemediationPhaseNeedsInput} {
		_, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, expired.ClaimOwner, expired.ClaimEpoch,
			expired.Revision, store.RemediationUpdate{Phase: phase}, input.Deadline)
		require.ErrorIs(t, err, store.ErrConflict)
	}
	timedOut, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, expired.ClaimOwner, expired.ClaimEpoch,
		expired.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseTimedOut}, input.Deadline)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseTimedOut, timedOut.Phase)
	require.Empty(t, timedOut.ApprovalDigest)
	require.Empty(t, timedOut.ClaimOwner)
}

func TestRemediationApprovalReplayIsImmutableAndActorBound(t *testing.T) {
	for _, phase := range []string{store.RemediationPhaseQueued, store.RemediationPhaseRunning,
		store.RemediationPhaseSucceeded, store.RemediationPhaseFailed, store.RemediationPhaseTimedOut,
		store.RemediationPhaseCancelled, store.RemediationPhaseNeedsInput, store.RemediationPhaseNeedsAdapter} {
		t.Run(phase, func(t *testing.T) {
			s := newRemediationTestStore(t)
			run := createRemediationTestRun(t, s, "tenant-a", 1)
			now := remediationTestTime().Add(time.Minute)
			claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
			_, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseNeedsApproval, ApprovalDigest: "sha256:plan"}, now)
			require.NoError(t, err)
			current, err := s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, "sha256:plan", "approver", now)
			require.NoError(t, err)
			if phase != store.RemediationPhaseQueued {
				claim = claimRemediationTestRun(t, s, run.Namespace, "worker", now)
				current, err = s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
					claim.Revision, store.RemediationUpdate{Phase: phase}, now)
				require.NoError(t, err)
			}
			replayed, err := s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, "sha256:plan", "approver", now.Add(time.Hour))
			require.NoError(t, err)
			require.Equal(t, current, replayed)
			_, err = s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, "sha256:plan", "other-approver", now)
			require.ErrorIs(t, err, store.ErrConflict)
			_, err = s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, "sha256:other-plan", "approver", now)
			require.ErrorIs(t, err, store.ErrConflict)
		})
	}
}

func TestRemediationSubmitterCapacityIsAtomicAndNamespaceScoped(t *testing.T) {
	first, second := newRemediationTestStores(t)
	for serial := 1; serial < store.RemediationMaxSubmitterActiveRuns; serial++ {
		createRemediationTestRun(t, first, "tenant-a", serial)
	}
	results := make(chan error, 2)
	start := make(chan struct{})
	var submitters sync.WaitGroup
	for index, s := range []*Store{first, second} {
		submitters.Go(func() {
			<-start
			_, _, err := s.CreateRemediationRun(t.Context(), remediationTestRun("tenant-a", 10+index))
			results <- err
		})
	}
	close(start)
	submitters.Wait()
	close(results)
	succeeded, full := 0, 0
	for err := range results {
		if errors.Is(err, store.ErrCapacity) {
			full++
		} else {
			require.NoError(t, err)
			succeeded++
		}
	}
	require.Equal(t, 1, succeeded)
	require.Equal(t, 1, full)
	_, created, err := first.CreateRemediationRun(t.Context(), remediationTestRun("tenant-a", 1))
	require.NoError(t, err)
	require.False(t, created)
	_, _, err = first.CreateRemediationRun(t.Context(), remediationTestRun("tenant-a", 12))
	require.ErrorIs(t, err, store.ErrCapacity)
	anotherSubmitter := remediationTestRun("tenant-a", 20)
	anotherSubmitter.SubmittedBy = "other-user"
	_, created, err = first.CreateRemediationRun(t.Context(), anotherSubmitter)
	require.NoError(t, err)
	require.True(t, created)
	createRemediationTestRun(t, first, "tenant-b", 20)
	now := remediationTestTime().Add(time.Hour)
	for index, phase := range []string{store.RemediationPhaseNeedsInput, store.RemediationPhaseNeedsAdapter} {
		claim := claimRemediationTestRun(t, first, "tenant-a", "worker", now)
		_, err := first.UpdateRemediationRun(t.Context(), claim.Namespace, claim.ID, claim.ClaimOwner, claim.ClaimEpoch,
			claim.Revision, store.RemediationUpdate{Phase: phase}, now)
		require.NoError(t, err)
		createRemediationTestRun(t, first, "tenant-a", 12+index)
	}
}

func TestRemediationNamespaceByteQuotaIncludesAllPersistentPayloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remediation.db")
	s := openRemediationTestStore(t, path)
	now := remediationTestTime().Add(time.Hour)
	claims := make([]*store.RemediationRun, 0, 8)
	for serial := 1; serial <= cap(claims); serial++ {
		createRemediationTestRun(t, s, "tenant-a", serial)
		claims = append(claims, claimRemediationTestRun(t, s, "tenant-a", fmt.Sprintf("worker-%d", serial), now))
	}
	remaining := int64(store.RemediationMaxNamespaceBytes) - remediationStoredBytes(t, s, "tenant-a")
	data := bytes.Repeat([]byte("x"), store.RemediationMaxArtifactBytes)
	for _, claim := range claims {
		for index := range store.RemediationMaxArtifactTotalBytes / store.RemediationMaxArtifactBytes {
			size := min(int64(len(data)), remaining)
			_, err := s.PutRemediationArtifact(t.Context(), claim.Namespace, claim.ID, claim.ClaimOwner, claim.ClaimEpoch,
				fmt.Sprintf("part-%d.bin", index), "application/octet-stream", data[:size], now)
			require.NoError(t, err)
			remaining -= size
		}
	}
	require.Zero(t, remaining)
	require.EqualValues(t, store.RemediationMaxNamespaceBytes, remediationStoredBytes(t, s, "tenant-a"))
	_, _, err := s.CreateRemediationRun(t.Context(), remediationTestRun("tenant-a", 9))
	require.ErrorIs(t, err, store.ErrCapacity)
	first, last := claims[0], claims[len(claims)-1]
	_, err = s.UpdateRemediationRun(t.Context(), first.Namespace, first.ID, first.ClaimOwner, first.ClaimEpoch,
		first.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning, StateJSON: json.RawMessage(`{ }`)}, now)
	require.ErrorIs(t, err, store.ErrCapacity)
	_, err = s.PutRemediationArtifact(t.Context(), last.Namespace, last.ID, last.ClaimOwner, last.ClaimEpoch,
		"extra.bin", "application/octet-stream", []byte("x"), now)
	require.ErrorIs(t, err, store.ErrCapacity)
	_, err = s.PutRemediationArtifact(t.Context(), first.Namespace, first.ID, first.ClaimOwner, first.ClaimEpoch,
		"part-0.bin", "application/octet-stream", data, now)
	require.NoError(t, err, "exact artifact replay must precede both byte quotas")
	retry := remediationTestRun("tenant-a", 1)
	retry.PolicyJSON, retry.PolicyDigest = json.RawMessage(`{"changed":true}`), "sha256:changed-policy"
	replayed, created, err := s.CreateRemediationRun(t.Context(), retry)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, first.PolicyJSON, replayed.PolicyJSON)
	otherNamespace := createRemediationTestRun(t, s, "tenant-b", 9)
	require.EqualValues(t, len(otherNamespace.RequestJSON)+len(otherNamespace.PolicyJSON)+len(otherNamespace.StateJSON),
		remediationStoredBytes(t, s, otherNamespace.Namespace))

	cancelled, err := s.CancelRemediationRun(t.Context(), first.Namespace, first.ID, now)
	require.NoError(t, err, "capacity must not block cancellation")
	cleanup := store.RemediationCleanup{Phase: store.RemediationPhaseCancelled, StartedAt: now}
	for attempt := 0; attempt <= store.RemediationMaxCleanupAttempts; attempt++ {
		cleanup.Attempts = attempt
		cancelled, err = s.UpdateRemediationCleanup(t.Context(), first.Namespace, first.ID, first.ClaimOwner, first.ClaimEpoch,
			cancelled.Revision, cleanup, false, now)
		require.NoError(t, err, "cleanup bookkeeping must survive a full namespace payload quota")
		require.Equal(t, first.StateJSON, cancelled.StateJSON)
		require.Equal(t, now, cancelled.Cleanup.StartedAt)
		require.Equal(t, attempt, cancelled.Cleanup.Attempts)
	}
	require.Equal(t, store.RemediationReasonCleanupQuarantined, cancelled.Reason)
	require.Empty(t, cancelled.ClaimOwner)
	quarantineRevision := cancelled.Revision
	_, err = s.ReconcileRemediationCleanup(t.Context(), first.Namespace, first.ID, "operator", quarantineRevision-1, now)
	require.ErrorIs(t, err, store.ErrConflict)
	cancelled, err = s.ReconcileRemediationCleanup(t.Context(), first.Namespace, first.ID, "operator", quarantineRevision, now)
	require.NoError(t, err, "the authenticated cleanup audit must also survive payload quota exhaustion")
	require.Equal(t, first.StateJSON, cancelled.StateJSON)
	require.True(t, cancelled.CancelRequested)
	require.Zero(t, cancelled.Cleanup.Attempts)
	var auditRevision, auditEpoch uint64
	var auditActor string
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT revision,claim_epoch,actor
		FROM remediation_cleanup_audit WHERE namespace=? AND run_id=?`, first.Namespace, first.ID).
		Scan(&auditRevision, &auditEpoch, &auditActor))
	require.Equal(t, quarantineRevision, auditRevision)
	require.Equal(t, first.ClaimEpoch, auditEpoch)
	require.Equal(t, "operator", auditActor)
	require.Greater(t, cancelled.ClaimEpoch, first.ClaimEpoch)
	_, err = s.UpdateRemediationCleanup(t.Context(), first.Namespace, first.ID, first.ClaimOwner, first.ClaimEpoch,
		cancelled.Revision, *cancelled.Cleanup, true, now)
	require.ErrorIs(t, err, store.ErrConflict, "a re-drive must fence the previous owner")
	cancelled = claimRemediationTestRun(t, s, first.Namespace, "cleanup-worker", now)
	require.Equal(t, first.ID, cancelled.ID)
	_, err = s.UpdateRemediationCleanup(t.Context(), first.Namespace, first.ID, cancelled.ClaimOwner, cancelled.ClaimEpoch,
		cancelled.Revision, *cancelled.Cleanup, true, now)
	require.NoError(t, err)
	_, _, err = s.CreateRemediationRun(t.Context(), remediationTestRun("tenant-a", 9))
	require.ErrorIs(t, err, store.ErrCapacity, "terminal payloads still consume namespace capacity")

	other := openRemediationTestStore(t, path)
	last, err = other.UpdateRemediationRun(t.Context(), last.Namespace, last.ID, last.ClaimOwner, last.ClaimEpoch,
		last.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning, StateJSON: json.RawMessage(`0`)}, now)
	require.NoError(t, err, "shrinking state must free exactly one byte")
	require.EqualValues(t, store.RemediationMaxNamespaceBytes-1, remediationStoredBytes(t, other, "tenant-a"))
	results := make(chan error, 2)
	start := make(chan struct{})
	var writers sync.WaitGroup
	for index, writer := range []*Store{s, other} {
		writers.Go(func() {
			<-start
			_, err := writer.PutRemediationArtifact(t.Context(), last.Namespace, last.ID, last.ClaimOwner, last.ClaimEpoch,
				fmt.Sprintf("last-byte-%d.bin", index), "application/octet-stream", []byte("x"), now)
			results <- err
		})
	}
	close(start)
	writers.Wait()
	close(results)
	succeeded, full := 0, 0
	for err := range results {
		if errors.Is(err, store.ErrCapacity) {
			full++
		} else {
			require.NoError(t, err)
			succeeded++
		}
	}
	require.Equal(t, 1, succeeded)
	require.Equal(t, 1, full)
	require.EqualValues(t, store.RemediationMaxNamespaceBytes, remediationStoredBytes(t, other, "tenant-a"))
}

func remediationStoredBytes(t *testing.T, s *Store, namespace string) int64 {
	t.Helper()
	var total int64
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT
		(SELECT COALESCE(SUM(length(request_json) + length(policy_json) + length(state_json)), 0)
			FROM remediation_runs WHERE namespace = ?) +
		(SELECT COALESCE(SUM(length(data)), 0) FROM remediation_artifacts WHERE namespace = ?)`,
		namespace, namespace).Scan(&total))
	return total
}

func TestRemediationAcceptanceArtifactDuringCancellation(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	_, err := s.CancelRemediationRun(t.Context(), run.Namespace, run.ID, now)
	require.NoError(t, err)
	receipt, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"accepted-task.json", "application/json", []byte(`{"uid":"synthetic-task-uid"}`), now)
	require.NoError(t, err)
	stored, _, err := s.GetRemediationArtifact(t.Context(), run.Namespace, run.ID, receipt.Name)
	require.NoError(t, err)
	require.Equal(t, receipt, stored)
	current, err := s.GetRemediationRunMetadata(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.True(t, current.CancelRequested)
	require.Equal(t, store.RemediationPhaseCancelling, current.Phase)
}

func TestRemediationInitializationMigratesApprovalClaimConstraintWithoutDataLoss(t *testing.T) {
	s := setupTestStore(t)
	legacySchema := strings.Replace(remediationRunsSchema, "CONSTRAINT remediation_terminal_claims_v2 ", "", 1)
	legacySchema = strings.Replace(legacySchema,
		"'NeedsInput', 'NeedsAdapter', 'Succeeded'", "'NeedsInput', 'NeedsAdapter', 'NeedsApproval', 'Succeeded'", 1)
	_, err := s.db.ExecContext(t.Context(), legacySchema)
	require.NoError(t, err)
	_, err = s.db.ExecContext(t.Context(), remediationArtifactsSchema)
	require.NoError(t, err)
	now := remediationTestTime().Add(time.Hour)
	for serial, phase := range []string{store.RemediationPhaseNeedsApproval, store.RemediationPhaseNeedsInput} {
		input := remediationTestRun("tenant-a", serial+1)
		_, err := s.db.ExecContext(t.Context(), `INSERT INTO remediation_runs
			(namespace, id, request_id, submitted_by, mode, policy_digest, input_digest,
			request_json, policy_json, state_json, phase, revision, created_at, updated_at, deadline, approval_digest)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
			input.Namespace, input.ID, input.RequestID, input.SubmittedBy, input.Mode, input.PolicyDigest, input.InputDigest,
			[]byte(input.RequestJSON), []byte(input.PolicyJSON), []byte(`{}`), phase,
			input.CreatedAt.UnixNano(), input.CreatedAt.UnixNano(), now.UnixNano(), "sha256:legacy-plan")
		require.NoError(t, err)
	}
	input := remediationTestRun("tenant-a", 1)
	_, err = s.db.ExecContext(t.Context(), `UPDATE remediation_runs SET claim_owner = ?, claim_until = ?
		WHERE namespace = ? AND id = ?`, "worker", now.Add(time.Minute).UnixNano(), input.Namespace, input.ID)
	require.Error(t, err, "the original CHECK cannot accept an expired approval claim")
	data := []byte("synthetic legacy evidence")
	_, err = s.db.ExecContext(t.Context(), `INSERT INTO remediation_artifacts
		(namespace, run_id, name, digest, media_type, size, created_at, data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, input.Namespace, input.ID, "legacy.txt",
		remediationArtifactDigest(data), "text/plain", len(data), now.UnixNano(), data)
	require.NoError(t, err)
	before, err := s.GetRemediationRun(t.Context(), input.Namespace, input.ID)
	require.NoError(t, err)
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	after, err := s.GetRemediationRun(t.Context(), input.Namespace, input.ID)
	require.NoError(t, err)
	require.Equal(t, before, after)
	_, stored, err := s.GetRemediationArtifact(t.Context(), input.Namespace, input.ID, "legacy.txt")
	require.NoError(t, err)
	require.Equal(t, data, stored)
	claim := claimRemediationTestRun(t, s, input.Namespace, "worker", now)
	require.Equal(t, input.ID, claim.ID)
	_, err = s.UpdateRemediationRun(t.Context(), claim.Namespace, claim.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseTimedOut}, now)
	require.NoError(t, err)
	blocked := remediationTestRun("tenant-a", 2)
	unchanged, err := s.CancelRemediationRun(t.Context(), blocked.Namespace, blocked.ID, now)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseNeedsInput, unchanged.Phase)
	require.False(t, unchanged.CancelRequested)
	var violationCount int
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pragma_foreign_key_check`).Scan(&violationCount))
	require.Zero(t, violationCount)
}
