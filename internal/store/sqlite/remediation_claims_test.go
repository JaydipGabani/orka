package sqlite

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orka-agents/orka/internal/store"
)

func TestRemediationConcurrentClaimAndStaleEpoch(t *testing.T) {
	first, second := newRemediationTestStores(t)
	run := createRemediationTestRun(t, first, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	type result struct {
		run *store.RemediationRun
		err error
	}
	results := make(chan result, 12)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := range cap(results) {
		workers.Go(func() {
			<-start
			s := first
			if index%2 == 1 {
				s = second
			}
			claimed, err := s.ClaimNextRemediationRun(t.Context(), run.Namespace, fmt.Sprintf("worker-%d", index), now, time.Minute)
			results <- result{claimed, err}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var winner *store.RemediationRun
	for result := range results {
		if errors.Is(result.err, store.ErrNotFound) {
			require.Nil(t, result.run)
			continue
		}
		require.NoError(t, result.err)
		require.Nil(t, winner, "one acquisition must win across independent SQL connections")
		winner = result.run
	}
	require.NotNil(t, winner)
	require.EqualValues(t, 1, winner.ClaimEpoch)
	require.Equal(t, run.Revision, winner.Revision)
	require.Equal(t, run.UpdatedAt, winner.UpdatedAt)

	// Reusing the owner label must not let an earlier lease holder bypass fencing.
	takeover := claimRemediationTestRun(t, second, run.Namespace, winner.ClaimOwner, winner.ClaimUntil)
	require.Equal(t, winner.ID, takeover.ID)
	require.Equal(t, winner.ClaimEpoch+1, takeover.ClaimEpoch)
	require.Equal(t, winner.Revision, takeover.Revision)
	err := first.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, winner.ClaimOwner,
		winner.ClaimEpoch, winner.ClaimUntil, time.Minute)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = first.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, winner.ClaimOwner, winner.ClaimEpoch,
		takeover.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseSucceeded}, winner.ClaimUntil)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = first.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, winner.ClaimOwner, winner.ClaimEpoch,
		"stale.txt", "text/plain", []byte("synthetic"), winner.ClaimUntil)
	require.ErrorIs(t, err, store.ErrConflict)

	updated, err := second.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, takeover.ClaimOwner, takeover.ClaimEpoch,
		takeover.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning}, winner.ClaimUntil)
	require.NoError(t, err)
	require.Equal(t, takeover.Revision+1, updated.Revision)
}

func TestRemediationRenewalPreservesRevisionAndExpiryIsExclusive(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	err := s.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		now.Add(10*time.Second), time.Second)
	require.NoError(t, err)
	unchanged, err := s.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, claim, unchanged, "renewal cannot shorten the lease or change content")

	err = s.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		now.Add(30*time.Second), time.Minute)
	require.NoError(t, err)
	renewed, err := s.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, claim.Revision, renewed.Revision)
	require.Equal(t, claim.UpdatedAt, renewed.UpdatedAt)
	require.Equal(t, now.Add(90*time.Second), renewed.ClaimUntil)
	_, err = s.ClaimNextRemediationRun(t.Context(), run.Namespace, "other", renewed.ClaimUntil.Add(-time.Nanosecond), time.Minute)
	require.ErrorIs(t, err, store.ErrNotFound)

	err = s.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		renewed.ClaimUntil, time.Minute)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseSucceeded}, renewed.ClaimUntil)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"expired.txt", "text/plain", []byte("synthetic"), renewed.ClaimUntil)
	require.ErrorIs(t, err, store.ErrConflict)
	takeover := claimRemediationTestRun(t, s, run.Namespace, "other", renewed.ClaimUntil)
	require.Equal(t, claim.ClaimEpoch+1, takeover.ClaimEpoch)
}

func TestRemediationWorkerCASAndImmutableSubmission(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	require.NoError(t, s.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, claim.ClaimOwner,
		claim.ClaimEpoch, now.Add(time.Second), time.Minute))
	updated, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning, Reason: "fixture stage",
			StateJSON: json.RawMessage(`{"stage":"verified"}`)}, now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, run.Revision+1, updated.Revision)
	require.True(t, sameRemediationSubmission(run, updated))
	require.Equal(t, run.PolicyDigest, updated.PolicyDigest)
	require.Equal(t, run.PolicyJSON, updated.PolicyJSON)
	require.Equal(t, run.CreatedAt, updated.CreatedAt)
	require.Equal(t, run.Deadline, updated.Deadline)
	require.Equal(t, claim.ClaimEpoch, updated.ClaimEpoch)

	cases := []struct {
		owner    string
		epoch    uint64
		revision uint64
	}{
		{claim.ClaimOwner, claim.ClaimEpoch, claim.Revision},
		{"wrong-worker", claim.ClaimEpoch, updated.Revision},
		{claim.ClaimOwner, claim.ClaimEpoch + 1, updated.Revision},
	}
	for _, test := range cases {
		_, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, test.owner, test.epoch, test.revision,
			store.RemediationUpdate{Phase: store.RemediationPhaseSucceeded}, now.Add(time.Second))
		require.ErrorIs(t, err, store.ErrConflict)
	}
	next, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		updated.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning}, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Equal(t, updated.StateJSON, next.StateJSON)
	require.Empty(t, next.Reason)
	require.Equal(t, updated.Revision+1, next.Revision)
}

func TestRemediationConcurrentContentCAS(t *testing.T) {
	first, second := newRemediationTestStores(t)
	run := createRemediationTestRun(t, first, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, first, run.Namespace, "worker", now)
	type result struct {
		run *store.RemediationRun
		err error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var writers sync.WaitGroup
	for index, s := range []*Store{first, second} {
		writers.Go(func() {
			<-start
			updated, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning,
					StateJSON: json.RawMessage(fmt.Sprintf(`{"writer":%d}`, index))}, now)
			results <- result{updated, err}
		})
	}
	close(start)
	writers.Wait()
	close(results)
	var winner *store.RemediationRun
	conflicts := 0
	for result := range results {
		if errors.Is(result.err, store.ErrConflict) {
			require.Nil(t, result.run)
			conflicts++
			continue
		}
		require.NoError(t, result.err)
		require.Nil(t, winner)
		winner = result.run
	}
	require.NotNil(t, winner)
	require.Equal(t, 1, conflicts)
	stored, err := first.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, winner, stored)
	require.Equal(t, claim.Revision+1, stored.Revision)
}

func TestRemediationCancellationWinsAfterClaim(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	cancelled, err := s.CancelRemediationRun(t.Context(), run.Namespace, run.ID, now.Add(time.Second))
	require.NoError(t, err)
	require.True(t, cancelled.CancelRequested)
	require.Equal(t, store.RemediationPhaseCancelling, cancelled.Phase)
	require.Equal(t, claim.Revision+1, cancelled.Revision)
	require.Equal(t, claim.ClaimOwner, cancelled.ClaimOwner)
	require.Equal(t, claim.ClaimUntil, cancelled.ClaimUntil)
	again, err := s.CancelRemediationRun(t.Context(), run.Namespace, run.ID, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Equal(t, cancelled, again)
	require.NoError(t, s.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, claim.ClaimOwner,
		claim.ClaimEpoch, now.Add(time.Second), time.Minute))

	for _, revision := range []uint64{claim.Revision, cancelled.Revision} {
		for _, phase := range []string{store.RemediationPhaseRunning, store.RemediationPhaseSucceeded,
			store.RemediationPhaseFailed, store.RemediationPhaseTimedOut, store.RemediationPhaseQueued} {
			_, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				revision, store.RemediationUpdate{Phase: phase}, now.Add(2*time.Second))
			require.ErrorIs(t, err, store.ErrConflict)
		}
	}
	settled, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		cancelled.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseCancelled}, now.Add(2*time.Second))
	require.NoError(t, err)
	require.True(t, settled.CancelRequested)
	require.Equal(t, store.RemediationPhaseCancelled, settled.Phase)
	require.Empty(t, settled.ClaimOwner)
	require.True(t, settled.ClaimUntil.IsZero())
	require.Equal(t, cancelled.Revision+1, settled.Revision)
}

func TestRemediationPausedRunsReleaseClaimsAndCanBeCancelled(t *testing.T) {
	for _, phase := range []string{store.RemediationPhaseNeedsApproval} {
		t.Run(phase, func(t *testing.T) {
			s := newRemediationTestStore(t)
			run := createRemediationTestRun(t, s, "tenant-a", 1)
			now := remediationTestTime().Add(time.Minute)
			claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
			update := store.RemediationUpdate{Phase: phase}
			if phase == store.RemediationPhaseNeedsApproval {
				update.ApprovalDigest = "sha256:pending-plan"
			}
			paused, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				claim.Revision, update, now)
			require.NoError(t, err)
			require.Empty(t, paused.ClaimOwner)
			require.True(t, paused.ClaimUntil.IsZero())
			require.Equal(t, claim.ClaimEpoch, paused.ClaimEpoch)
			_, err = s.ClaimNextRemediationRun(t.Context(), run.Namespace, "other", claim.ClaimUntil, time.Minute)
			require.ErrorIs(t, err, store.ErrNotFound)
			err = s.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch, now, time.Minute)
			require.ErrorIs(t, err, store.ErrConflict)

			cancelled, err := s.CancelRemediationRun(t.Context(), run.Namespace, run.ID, now)
			require.NoError(t, err)
			require.True(t, cancelled.CancelRequested)
			next := claimRemediationTestRun(t, s, run.Namespace, "other", now)
			require.Equal(t, claim.ClaimEpoch+1, next.ClaimEpoch)
			require.Equal(t, store.RemediationPhaseCancelling, next.Phase)
		})
	}
}

func TestRemediationApprovalIsPlanBoundAndCannotBeForgedByWorker(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	_, err := s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, "sha256:plan", "approver", now)
	require.ErrorIs(t, err, store.ErrConflict)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	_, err = s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseNeedsApproval}, now)
	require.ErrorIs(t, err, store.ErrValidation)
	pending, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseNeedsApproval, ApprovalDigest: "sha256:plan",
			StateJSON: json.RawMessage(`{"plan":"synthetic"}`)}, now)
	require.NoError(t, err)
	_, err = s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, "sha256:wrong-plan", "approver", now)
	require.ErrorIs(t, err, store.ErrConflict)
	unchanged, err := s.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, pending, unchanged)

	approved, err := s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, pending.ApprovalDigest, "approver", now)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseQueued, approved.Phase)
	require.Equal(t, pending.Revision+1, approved.Revision)
	require.Equal(t, "sha256:plan", approved.ApprovedDigest)
	require.Equal(t, "approver", approved.ApprovedBy)
	require.Empty(t, approved.ApprovalDigest)
	require.Equal(t, pending.StateJSON, approved.StateJSON)
	replayed, err := s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, pending.ApprovalDigest, "approver", now)
	require.NoError(t, err)
	require.Equal(t, approved, replayed)
	_, err = s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, pending.ApprovalDigest, "another-approver", now)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		approved.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseSucceeded}, now)
	require.ErrorIs(t, err, store.ErrConflict)

	nextClaim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	require.Equal(t, claim.ClaimEpoch+1, nextClaim.ClaimEpoch)
	require.Equal(t, approved.ApprovedDigest, nextClaim.ApprovedDigest)
	newPlan, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, nextClaim.ClaimOwner, nextClaim.ClaimEpoch,
		nextClaim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseNeedsApproval, ApprovalDigest: "sha256:new-plan"}, now)
	require.NoError(t, err)
	require.Empty(t, newPlan.ApprovedDigest)
	require.Empty(t, newPlan.ApprovedBy)
	_, err = s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, pending.ApprovalDigest, "approver", now)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = s.CancelRemediationRun(t.Context(), run.Namespace, run.ID, now)
	require.NoError(t, err)
	_, err = s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, newPlan.ApprovalDigest, "approver", now)
	require.ErrorIs(t, err, store.ErrConflict)
}

func TestRemediationTerminalRunsAreImmutable(t *testing.T) {
	for _, phase := range []string{store.RemediationPhaseSucceeded, store.RemediationPhaseFailed,
		store.RemediationPhaseCancelled, store.RemediationPhaseTimedOut, store.RemediationPhaseNeedsInput, store.RemediationPhaseNeedsAdapter} {
		t.Run(phase, func(t *testing.T) {
			s := newRemediationTestStore(t)
			run := createRemediationTestRun(t, s, "tenant-a", 1)
			now := remediationTestTime().Add(time.Minute)
			claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
			_, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				"report.txt", "text/plain", []byte("synthetic"), now)
			require.NoError(t, err)
			terminal, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				claim.Revision, store.RemediationUpdate{Phase: phase}, now)
			require.NoError(t, err)
			require.True(t, store.IsRemediationTerminalPhase(terminal.Phase))
			require.Empty(t, terminal.ClaimOwner)
			cancelled, err := s.CancelRemediationRun(t.Context(), run.Namespace, run.ID, now.Add(time.Second))
			require.NoError(t, err)
			require.Equal(t, terminal, cancelled)
			require.False(t, cancelled.CancelRequested)
			_, err = s.ClaimNextRemediationRun(t.Context(), run.Namespace, "other", now.Add(time.Hour), time.Minute)
			require.ErrorIs(t, err, store.ErrNotFound)
			err = s.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch, now, time.Minute)
			require.ErrorIs(t, err, store.ErrConflict)
			_, err = s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				terminal.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning}, now)
			require.ErrorIs(t, err, store.ErrConflict)
			_, err = s.ApproveRemediationRun(t.Context(), run.Namespace, run.ID, "sha256:plan", "approver", now)
			require.ErrorIs(t, err, store.ErrConflict)
			_, err = s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				"report.txt", "text/plain", []byte("synthetic"), now)
			require.ErrorIs(t, err, store.ErrConflict)
			_, data, err := s.GetRemediationArtifact(t.Context(), run.Namespace, run.ID, "report.txt")
			require.NoError(t, err)
			require.Equal(t, []byte("synthetic"), data)
		})
	}
}

func TestRemediationExpiredDeadlineIsClaimedForServiceTimeout(t *testing.T) {
	s := newRemediationTestStore(t)
	input := remediationTestRun("tenant-a", 1)
	input.Deadline = input.CreatedAt.Add(time.Second)
	run, _, err := s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	now := input.Deadline.Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	require.Equal(t, store.RemediationPhaseQueued, claim.Phase)
	require.Equal(t, input.Deadline, claim.Deadline)
	timedOut, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseTimedOut}, now)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseTimedOut, timedOut.Phase)
}
