package sqlite

import (
	"context"
	"database/sql"
	"math"
	"time"

	"github.com/orka-agents/orka/internal/store"
)

// RemediationStoreInitialized detects existing remediation persistence without
// creating tables or enabling admission on an ordinary Store.
func (s *Store) RemediationStoreInitialized(ctx context.Context) (bool, error) {
	var initialized bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'remediation_runs'
	)`).Scan(&initialized)
	return initialized, err
}

// CancelActiveRemediationRuns durably requests cleanup when admission is disabled.
// It never initializes a fresh store. Each call affects at most 1000 oldest
// nonterminal, not-yet-cancelled runs in the exact namespace and returns that count.
// Claims, immutable inputs, approval receipts, and StateJSON remain untouched.
// Terminal runs and prior cancellation requests are not rewritten.
func (s *Store) CancelActiveRemediationRuns(ctx context.Context, namespace string, now time.Time) (int64, error) {
	if err := validateRemediationNamespace(namespace); err != nil {
		return 0, err
	}
	if err := validateRemediationTime(now); err != nil {
		return 0, err
	}
	initialized, err := s.RemediationStoreInitialized(ctx)
	if err != nil {
		return 0, err
	}
	if !initialized {
		return 0, store.ErrNotReady
	}
	var cancelled int64
	err = s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		var maxRevision int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) FROM (
			SELECT revision FROM remediation_runs
			WHERE namespace = ? AND cancel_requested = 0 AND `+remediationNonterminalSQL+`
			ORDER BY created_at, id LIMIT ?
		)`, namespace, store.RemediationMaxActiveRuns).Scan(&maxRevision); err != nil {
			return err
		}
		if maxRevision == math.MaxInt64 {
			return store.ErrConflict
		}
		result, err := tx.ExecContext(ctx, `UPDATE remediation_runs SET
			cancel_requested = 1, phase = 'Cancelling',
			reason = CASE WHEN reason = 'cleanup-quarantined' THEN reason ELSE '' END, approval_digest = '',
			revision = revision + 1, updated_at = ?
			WHERE namespace = ? AND id IN (
				SELECT id FROM remediation_runs
				WHERE namespace = ? AND cancel_requested = 0 AND `+remediationNonterminalSQL+`
				ORDER BY created_at, id LIMIT ?
			)`, now.UnixNano(), namespace, namespace, store.RemediationMaxActiveRuns)
		if err != nil {
			return err
		}
		cancelled, err = result.RowsAffected()
		if err != nil {
			return err
		}
		if cancelled > store.RemediationMaxActiveRuns {
			return store.ErrConflict
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return cancelled, nil
}
