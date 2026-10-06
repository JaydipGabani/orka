package service

import (
	"context"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func TestCleanupNearExpiryStillGetsOneFullRecoveryAttempt(t *testing.T) {
	calls := 0
	service, storage, db := outageTestService(t, processorFunc{
		cancel: func(ctx context.Context, session *Session) error {
			calls++
			current, err := session.Current(ctx)
			require.NoError(t, err)
			switch calls {
			case 1:
				return ErrRetryable
			case 2:
				require.Zero(t, current.Cleanup.RecoveryEpoch, "exercise an ordinary truncated attempt")
				<-ctx.Done()
				return ctx.Err()
			case 3:
				require.Equal(t, session.epoch, current.Cleanup.RecoveryEpoch)
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.Greater(t, time.Until(deadline), 25*time.Second)
				return nil
			default:
				t.Fatal("cleanup exceeded its one recovery attempt")
				return ErrUnknown
			}
		},
	})
	status, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	require.NoError(t, err)
	_, err = service.Cancel(t.Context(), "testing", status.ID)
	require.NoError(t, err)
	require.NoError(t, service.RunOnce(t.Context()))
	_, err = db.ExecContext(t.Context(), `UPDATE remediation_runs SET cleanup_started_at=?, claim_until=?
		WHERE namespace=? AND id=?`,
		time.Now().UTC().Add(-maxSettlementDuration+2*time.Second).UnixNano(),
		time.Now().Add(-time.Second).UnixNano(), "testing", status.ID)
	require.NoError(t, err)
	require.NoError(t, service.RunOnce(t.Context()))
	pending, err := storage.GetRemediationRun(t.Context(), "testing", status.ID)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	require.NotEqual(t, quarantinedCleanupReason, pending.Reason)
	require.Zero(t, pending.Cleanup.RecoveryEpoch)
	_, err = db.ExecContext(t.Context(), `UPDATE remediation_runs SET claim_until=? WHERE namespace=? AND id=?`,
		time.Now().Add(-time.Second).UnixNano(), "testing", status.ID)
	require.NoError(t, err)
	require.NoError(t, service.RunOnce(t.Context()))
	complete, err := storage.GetRemediationRun(t.Context(), "testing", status.ID)
	require.NoError(t, err)
	require.Equal(t, 3, calls)
	require.Equal(t, store.RemediationPhaseCancelled, complete.Phase)
	require.Nil(t, complete.Cleanup)
}
