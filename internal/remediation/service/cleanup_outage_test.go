package service

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
	"github.com/stretchr/testify/require"
)

func outageTestService(t *testing.T, processor Processor) (*Service, *sqlite.Store, *sql.DB) {
	t.Helper()
	template, _ := testService(t, processor)
	path := filepath.Join(t.TempDir(), "outage.db")
	db, err := sqlite.NewDB(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	storage := sqlite.NewStore(db, path)
	cipher, err := sqlite.NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("k", 32)))
	require.NoError(t, err)
	require.NoError(t, storage.SetAgentExecutionSnapshotCipher(cipher))
	config := template.config
	config.Store = storage
	service, err := New(t.Context(), config)
	require.NoError(t, err)
	return service, storage, db
}

func simulateCleanupOutage(t *testing.T, db *sql.DB, run *store.RemediationRun) {
	t.Helper()
	// Translate persisted timestamps instead of sleeping through a real outage.
	// Resource identities, claim epoch and every counter stay unchanged.
	outage := (6 * time.Minute).Nanoseconds()
	_, err := db.ExecContext(t.Context(), `UPDATE remediation_runs SET
		created_at=created_at-?, updated_at=updated_at-?, deadline=deadline-?,
		cleanup_started_at=cleanup_started_at-?, claim_until=claim_until-?
		WHERE namespace=? AND id=?`, outage, outage, outage, outage, outage, run.Namespace, run.ID)
	require.NoError(t, err)
}

func TestCleanupRestartAfterOutageAttemptsBeforeTimeQuarantine(t *testing.T) {
	for _, outcome := range []struct {
		name string
		err  error
	}{
		{"complete", nil}, {"pending", ErrCleanupPending}, {"dependency-failed", ErrRetryable},
	} {
		t.Run(outcome.name, func(t *testing.T) {
			calls := 0
			processor := processorFunc{
				run: func(context.Context, *Session) error {
					t.Fatal("cleanup restart attempted execution")
					return nil
				},
				cancel: func(ctx context.Context, session *Session) error {
					calls++
					if calls == 1 {
						return ErrRetryable
					}
					require.NoError(t, ctx.Err(), "a resumed cleanup must receive usable time, not an already-expired context")
					deadline, ok := ctx.Deadline()
					require.True(t, ok)
					require.Positive(t, time.Until(deadline))
					require.LessOrEqual(t, time.Until(deadline), 30*time.Second)
					current, err := session.Current(ctx)
					require.NoError(t, err)
					require.Equal(t, session.epoch, current.Cleanup.RecoveryEpoch, "reserve the recovery attempt before effects")
					require.Equal(t, 1, current.Cleanup.Attempts)
					return outcome.err
				},
			}
			service, storage, db := outageTestService(t, processor)
			status, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
			require.NoError(t, err)
			_, err = service.Cancel(t.Context(), "testing", status.ID)
			require.NoError(t, err)
			require.NoError(t, service.RunOnce(t.Context()))
			before, err := storage.GetRemediationRun(t.Context(), "testing", status.ID)
			require.NoError(t, err)
			require.Equal(t, 1, before.Cleanup.Attempts)
			require.Equal(t, before.ClaimEpoch, before.Cleanup.LastAttemptEpoch)
			require.Zero(t, before.Cleanup.RecoveryEpoch)
			simulateCleanupOutage(t, db, before)

			config := service.config
			config.AdmissionDisabled, config.Policies = true, nil
			restarted, err := New(t.Context(), config)
			require.NoError(t, err)
			require.NoError(t, restarted.RunOnce(t.Context()))
			require.Equal(t, 2, calls, "downtime must not quarantine before one fresh bounded cleanup attempt")
			after, err := storage.GetRemediationRun(t.Context(), "testing", status.ID)
			require.NoError(t, err)
			require.Greater(t, after.ClaimEpoch, before.ClaimEpoch)
			require.Equal(t, before.StateJSON, after.StateJSON)
			if outcome.err == nil {
				require.Equal(t, store.RemediationPhaseCancelled, after.Phase)
				require.Nil(t, after.Cleanup)
				return
			}
			require.Equal(t, quarantinedCleanupReason, after.Reason)
			require.Equal(t, before.Cleanup.StartedAt.Add(-6*time.Minute), after.Cleanup.StartedAt, "restarts must not reset the wall clock")
			wantFailures := 2
			if errors.Is(outcome.err, ErrCleanupPending) {
				wantFailures = 1
			}
			require.Equal(t, wantFailures, after.Cleanup.Attempts)
			require.Equal(t, after.ClaimEpoch, after.Cleanup.RecoveryEpoch)
			for range 3 {
				again, err := New(t.Context(), config)
				require.NoError(t, err)
				require.NoError(t, again.RunOnce(t.Context()))
			}
			require.Equal(t, 2, calls, "repeated restarts must not replenish the recovery allowance")
			drain, err := restarted.Drain(t.Context())
			require.NoError(t, err)
			require.False(t, drain.Complete)
			require.EqualValues(t, 1, drain.Quarantined)
		})
	}
}

func TestCleanupRecoveryReservationSurvivesInterruptedWorker(t *testing.T) {
	calls := 0
	service, storage, db := outageTestService(t, processorFunc{
		cancel: func(context.Context, *Session) error {
			calls++
			return ErrRetryable
		},
	})
	status, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	require.NoError(t, err)
	_, err = service.Cancel(t.Context(), "testing", status.ID)
	require.NoError(t, err)
	require.NoError(t, service.RunOnce(t.Context()))
	current, err := storage.GetRemediationRun(t.Context(), "testing", status.ID)
	require.NoError(t, err)
	simulateCleanupOutage(t, db, current)
	claim, err := storage.ClaimNextRemediationRun(t.Context(), "testing", "interrupted-worker", time.Now(), time.Minute)
	require.NoError(t, err)
	reserved, err := storage.BeginRemediationCleanupAttempt(t.Context(), claim.Namespace, claim.ID, claim.ClaimOwner,
		claim.ClaimEpoch, claim.Revision, *claim.Cleanup, time.Now())
	require.NoError(t, err)
	require.Equal(t, claim.ClaimEpoch, reserved.Cleanup.RecoveryEpoch)
	require.NotEqual(t, quarantinedCleanupReason, reserved.Reason)
	// The worker may have sent cleanup but died before recording its outcome.
	// Do not infer no-effect from the missing checkpoint or reserve another try.
	_, err = db.ExecContext(t.Context(), `UPDATE remediation_runs SET claim_until=? WHERE namespace=? AND id=?`,
		time.Now().Add(-time.Second).UnixNano(), claim.Namespace, claim.ID)
	require.NoError(t, err)
	restarted, err := New(t.Context(), service.config)
	require.NoError(t, err)
	require.NoError(t, restarted.RunOnce(t.Context()))
	require.Equal(t, 1, calls)
	quarantined, err := storage.GetRemediationRun(t.Context(), "testing", claim.ID)
	require.NoError(t, err)
	require.Equal(t, quarantinedCleanupReason, quarantined.Reason)
	require.Equal(t, reserved.Cleanup.RecoveryEpoch, quarantined.Cleanup.RecoveryEpoch)
	require.Equal(t, 1, quarantined.Cleanup.Attempts)
	_, err = storage.UpdateRemediationCleanup(t.Context(), claim.Namespace, claim.ID, claim.ClaimOwner,
		claim.ClaimEpoch, reserved.Revision, *reserved.Cleanup, true, time.Now())
	require.ErrorIs(t, err, store.ErrConflict, "the interrupted worker cannot settle after losing its exact claim")
}
