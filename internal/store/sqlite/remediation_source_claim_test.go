package sqlite

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func TestRemediationSourceClaimSerializesDifferentRequests(t *testing.T) {
	first, second := newRemediationTestStores(t)
	sourceKey := intakeDigest([]byte("synthetic-source-operation"))
	inputs := []*store.RemediationRun{remediationTestRun("tenant", 1), remediationTestRun("tenant", 2)}
	inputs[1].SubmittedBy = "another-user"
	for _, input := range inputs {
		input.SourceOperationKey = sourceKey
	}
	type outcome struct {
		run     *store.RemediationRun
		created bool
		err     error
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index, storage := range []*Store{first, second} {
		workers.Go(func() {
			<-start
			run, created, err := storage.CreateRemediationRun(t.Context(), inputs[index])
			results <- outcome{run, created, err}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var accepted *store.RemediationRun
	conflicts := 0
	for result := range results {
		if errors.Is(result.err, store.ErrConflict) {
			require.False(t, result.created)
			conflicts++
			continue
		}
		require.NoError(t, result.err)
		require.True(t, result.created)
		require.Nil(t, accepted)
		accepted = result.run
	}
	require.NotNil(t, accepted)
	require.Equal(t, 1, conflicts)
	var winner *store.RemediationRun
	for _, input := range inputs {
		if input.ID == accepted.ID {
			winner = input
		}
	}
	replayed, created, err := second.CreateRemediationRun(t.Context(), winner)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, accepted.ID, replayed.ID, "exact submission retries must precede source admission")

	foreign := remediationTestRun("other-tenant", 1)
	foreign.SourceOperationKey = sourceKey
	_, created, err = first.CreateRemediationRun(t.Context(), foreign)
	require.NoError(t, err)
	require.True(t, created, "source claims must not cross namespace boundaries")
}

func TestRemediationSourceClaimWaitsForSettlement(t *testing.T) {
	for _, phase := range []string{store.RemediationPhaseSucceeded, store.RemediationPhaseFailed,
		store.RemediationPhaseCancelled, store.RemediationPhaseTimedOut, store.RemediationPhaseNeedsInput,
		store.RemediationPhaseNeedsAdapter} {
		t.Run(phase, func(t *testing.T) {
			storage := newRemediationTestStore(t)
			input := remediationTestRun("tenant", 1)
			input.SourceOperationKey = intakeDigest([]byte("synthetic-source-operation"))
			_, _, err := storage.CreateRemediationRun(t.Context(), input)
			require.NoError(t, err)
			now := remediationTestTime().Add(time.Hour)
			claim := claimRemediationTestRun(t, storage, input.Namespace, "worker", now)
			claim, err = storage.UpdateRemediationRun(t.Context(), input.Namespace, input.ID, claim.ClaimOwner,
				claim.ClaimEpoch, claim.Revision, store.RemediationUpdate{
					Phase: store.RemediationPhaseCancelling, Reason: "cleanup-quarantined",
				}, now)
			require.NoError(t, err)
			next := remediationTestRun(input.Namespace, 2)
			next.SourceOperationKey = input.SourceOperationKey
			_, _, err = storage.CreateRemediationRun(t.Context(), next)
			require.ErrorIs(t, err, store.ErrConflict, "uncertain cleanup must keep the source reserved")
			_, err = storage.UpdateRemediationRun(t.Context(), input.Namespace, input.ID, claim.ClaimOwner,
				claim.ClaimEpoch, claim.Revision, store.RemediationUpdate{Phase: phase}, now)
			require.NoError(t, err)
			replacement, created, err := storage.CreateRemediationRun(t.Context(), next)
			require.NoError(t, err)
			require.True(t, created)
			require.Equal(t, next.ID, replacement.ID)
		})
	}
}

func TestRemediationSourceClaimRejectsMalformedDigest(t *testing.T) {
	storage := newRemediationTestStore(t)
	input := remediationTestRun("tenant", 1)
	input.SourceOperationKey = "sha256:" + string(make([]byte, 64))
	_, _, err := storage.CreateRemediationRun(t.Context(), input)
	require.ErrorIs(t, err, store.ErrValidation)
	_, err = storage.GetRemediationRun(t.Context(), input.Namespace, input.ID)
	require.ErrorIs(t, err, store.ErrNotFound)
}
