package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

type cleanupQuotaStore struct {
	store.RemediationRunStore
}

func (s cleanupQuotaStore) UpdateRemediationRun(ctx context.Context, namespace, id, owner string, epoch, revision uint64,
	update store.RemediationUpdate, now time.Time,
) (*store.RemediationRun, error) {
	current, err := s.GetRemediationRun(ctx, namespace, id)
	if err != nil {
		return nil, err
	}
	if len(update.StateJSON) > len(current.StateJSON) {
		return nil, store.ErrCapacity
	}
	return s.RemediationRunStore.UpdateRemediationRun(ctx, namespace, id, owner, epoch, revision, update, now)
}

func TestCleanupPayloadQuotaDoesNotBlockBoundedSettlement(t *testing.T) {
	service, storage := testService(t, processorFunc{
		run: func(context.Context, *Session) error {
			t.Fatal("cancelled cleanup attempted new execution")
			return nil
		},
		cancel: func(ctx context.Context, session *Session) error {
			return session.Checkpoint(ctx, store.RemediationPhaseCancelling, "", json.RawMessage(`{"cleanupProgress":true}`), "")
		},
	})
	run, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	require.NoError(t, err)
	_, err = service.Cancel(t.Context(), "testing", run.ID)
	require.NoError(t, err)
	// SQLite's physical 512 MiB boundary is exercised by its namespace-quota
	// test. At the service boundary, reject all growing payload checkpoints.
	service.config.Store = cleanupQuotaStore{storage}
	current, err := storage.ClaimNextRemediationRun(t.Context(), "testing", service.owner, time.Now(), time.Minute)
	require.NoError(t, err)
	for attempt := 1; attempt <= maxSettlementAttempts; attempt++ {
		require.NoError(t, service.process(t.Context(), current))
		current, err = storage.GetRemediationRun(t.Context(), "testing", run.ID)
		require.NoError(t, err)
		require.NotNil(t, current.Cleanup)
		require.Equal(t, attempt, current.Cleanup.Attempts)
		require.Equal(t, json.RawMessage(`{}`), current.StateJSON)
	}
	require.Equal(t, quarantinedCleanupReason, current.Reason)
	drain, err := service.Drain(t.Context())
	require.NoError(t, err)
	require.False(t, drain.Complete)
	require.EqualValues(t, 1, drain.Active)
	require.EqualValues(t, 1, drain.Quarantined)
}

func TestCleanupPendingPreservesFailureBudgetAndOriginalDeadline(t *testing.T) {
	cleanups := 0
	service, storage := testService(t, processorFunc{
		run: func(context.Context, *Session) error { return errors.New("synthetic execution failed") },
		cancel: func(context.Context, *Session) error {
			cleanups++
			return fmt.Errorf("synthetic observation pending: %w", ErrCleanupPending)
		},
	})
	submitted, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	require.NoError(t, err)
	run, err := storage.ClaimNextRemediationRun(t.Context(), "testing", service.owner, time.Now(), time.Minute)
	require.NoError(t, err)
	var started time.Time
	for range maxSettlementAttempts + 3 {
		require.NoError(t, service.process(t.Context(), run))
		run, err = storage.GetRemediationRun(t.Context(), "testing", submitted.ID)
		require.NoError(t, err)
		require.NotNil(t, run.Cleanup)
		require.Zero(t, run.Cleanup.Attempts)
		require.NotEqual(t, quarantinedCleanupReason, run.Reason)
		require.Equal(t, store.RemediationPhaseCancelling, run.Phase)
		if started.IsZero() {
			started = run.Cleanup.StartedAt
		}
		require.Equal(t, started, run.Cleanup.StartedAt, "pending observations must not restart the wall-clock budget")
	}
	require.Equal(t, maxSettlementAttempts+3, cleanups)
}

func TestQuarantinedCleanupRedriveIsFencedAndWorksWithAdmissionDisabled(t *testing.T) {
	executions, cleanups := 0, 0
	settled := false
	state := json.RawMessage(`{"resourceUID":"synthetic-exact-uid","resourceEpoch":17,"stage":"cleanup"}`)
	processor := processorFunc{
		run: func(ctx context.Context, session *Session) error {
			executions++
			if err := session.Checkpoint(ctx, store.RemediationPhaseRunning, "", state, ""); err != nil {
				return err
			}
			return errors.New("synthetic execution failed")
		},
		cancel: func(context.Context, *Session) error {
			cleanups++
			if settled {
				return nil
			}
			return store.ErrCapacity
		},
	}
	service, storage := testService(t, processor)
	submitted, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	require.NoError(t, err)
	run, err := storage.ClaimNextRemediationRun(t.Context(), "testing", service.owner, time.Now(), time.Minute)
	require.NoError(t, err)
	staleOwner, staleEpoch := run.ClaimOwner, run.ClaimEpoch
	for range maxSettlementAttempts {
		require.NoError(t, service.process(t.Context(), run))
		run, err = storage.GetRemediationRun(t.Context(), "testing", submitted.ID)
		require.NoError(t, err)
	}
	require.Equal(t, quarantinedCleanupReason, run.Reason)
	require.Empty(t, run.ClaimOwner)
	require.Equal(t, 1, executions)
	require.Equal(t, state, run.StateJSON)
	require.Equal(t, maxSettlementAttempts, cleanups)
	require.NoError(t, service.RunOnce(t.Context()))
	require.Equal(t, maxSettlementAttempts, cleanups)

	config := service.config
	config.AdmissionDisabled, config.Policies = true, nil
	disabled, err := New(t.Context(), config)
	require.NoError(t, err)
	_, _, err = disabled.Submit(t.Context(), "testing", "caller", requestFixture())
	require.ErrorIs(t, err, ErrDisabled)
	drain, err := disabled.DrainNamespace(t.Context(), "testing")
	require.NoError(t, err)
	require.False(t, drain.Complete)
	require.EqualValues(t, 1, drain.Active)
	require.EqualValues(t, 1, drain.Quarantined)
	require.EqualValues(t, 1, drain.RetainedIntakes)
	page, err := disabled.List(t.Context(), "testing", 1, "")
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, run.Revision, page.Items[0].Revision)
	_, err = disabled.ReconcileCleanup(t.Context(), "foreign", run.ID, "operator", run.Revision)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = disabled.ReconcileCleanup(t.Context(), "testing", run.ID, "operator", run.Revision-1)
	require.ErrorIs(t, err, store.ErrConflict)
	recovered, err := disabled.ReconcileCleanup(t.Context(), "testing", run.ID, "operator", run.Revision)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseCancelling, recovered.Phase)
	require.Zero(t, recovered.Cleanup.Attempts)
	require.Equal(t, run.Revision+1, recovered.Revision)
	_, err = disabled.ReconcileCleanup(t.Context(), "testing", run.ID, "operator", run.Revision)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = storage.UpdateRemediationRun(t.Context(), "testing", run.ID, staleOwner, staleEpoch, recovered.Revision,
		store.RemediationUpdate{Phase: store.RemediationPhaseSucceeded}, time.Now())
	require.ErrorIs(t, err, store.ErrConflict)

	retry := requestFixture()
	retry.RequestID = "different-client-key"
	_, _, err = service.Submit(t.Context(), "testing", "caller", retry)
	require.ErrorIs(t, err, store.ErrConflict, "re-drive cannot release the active source claim")
	settled = true
	require.NoError(t, disabled.RunOnce(t.Context()))
	done, err := storage.GetRemediationRun(t.Context(), "testing", run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseCancelled, done.Phase)
	require.Equal(t, state, done.StateJSON, "cleanup metadata must not overwrite exact effect identities")
	require.Nil(t, done.Cleanup)
	require.Equal(t, 1, executions, "disabled recovery must never run the processor again")
	drain, err = disabled.DrainNamespace(t.Context(), "testing")
	require.NoError(t, err)
	require.True(t, drain.Complete)
	require.False(t, drain.IntakeDrained, "terminal cleanup does not bypass intake retention")
	_, created, err := service.Submit(t.Context(), "testing", "caller", retry)
	require.NoError(t, err)
	require.True(t, created, "only observed completed cleanup releases the source")
}

func TestCleanupWallTimeQuarantinesSameEpochWithoutAnotherEffect(t *testing.T) {
	service, storage := testService(t, processorFunc{
		cancel: func(context.Context, *Session) error {
			t.Fatal("expired cleanup budget called an external effect")
			return nil
		},
	})
	_, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	require.NoError(t, err)
	run, err := storage.ClaimNextRemediationRun(t.Context(), "testing", service.owner, time.Now(), time.Minute)
	require.NoError(t, err)
	legacy, err := json.Marshal(map[string]any{"settlement": settlement{
		Phase: store.RemediationPhaseFailed, Reason: "execution-failed",
		StartedAt: time.Now().Add(-maxSettlementDuration), LastAttemptEpoch: run.ClaimEpoch,
	}})
	require.NoError(t, err)
	run, err = storage.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, run.ClaimOwner, run.ClaimEpoch,
		run.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseCancelling, StateJSON: legacy}, time.Now())
	require.NoError(t, err)
	require.NoError(t, service.process(t.Context(), run))
	result, err := storage.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, quarantinedCleanupReason, result.Reason)
	require.Zero(t, result.Cleanup.Attempts, "elapsed pending work quarantines without inventing a failed attempt")
}

func TestServiceStartupRetainsIntakeOnlyUntilTerminalWindowExpires(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("admission-disabled=%t", disabled), func(t *testing.T) {
			service, storage := testService(t, processorFunc{})
			submitted, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
			require.NoError(t, err)
			require.NoError(t, service.RunOnce(t.Context()))
			_, err = storage.ReadRemediationIntake(t.Context(), "testing", submitted.ID)
			require.NoError(t, err, "successful cleanup must not immediately discard private acquisition input")
			config := service.config
			config.AdmissionDisabled = disabled
			config.IntakeRetention, config.IntakeRetentionInterval = time.Second, time.Second
			if disabled {
				config.Policies = nil
			}
			restarted, err := New(t.Context(), config)
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- restarted.Start(ctx) }()
			require.Eventually(t, func() bool {
				counts, err := storage.CountRemediationRuns(t.Context(), "testing")
				return err == nil && counts.RetainedIntakes == 0
			}, 5*time.Second, 20*time.Millisecond, "production startup must schedule bounded terminal intake retention")
			cancel()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("retention worker did not stop with the service")
			}
			drain, err := restarted.DrainNamespace(t.Context(), "testing")
			require.NoError(t, err)
			require.True(t, drain.Complete)
			require.True(t, drain.IntakeDrained)
		})
	}
}

func TestServiceIntakeRetentionAcceptsExistingPositiveDurationSemantics(t *testing.T) {
	service, _ := testService(t, processorFunc{})
	config := service.config
	config.IntakeRetention, config.IntakeRetentionInterval = time.Nanosecond, time.Nanosecond
	_, err := New(t.Context(), config)
	require.NoError(t, err, "shared snapshot-retention flags accept positive sub-second durations")
	config.IntakeRetention = -time.Nanosecond
	_, err = New(t.Context(), config)
	require.ErrorIs(t, err, ErrPolicy)
	config.IntakeRetention, config.IntakeRetentionInterval = time.Second, -time.Nanosecond
	_, err = New(t.Context(), config)
	require.ErrorIs(t, err, ErrPolicy)
}
