package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"time"

	"github.com/orka-agents/orka/internal/store"
)

func migrateRemediationCleanupSchema(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(remediation_runs)`)
	if err != nil {
		return err
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var index, notNull, primary int
		var name, kind string
		var value any
		if err := rows.Scan(&index, &name, &kind, &notNull, &value, &primary); err != nil {
			_ = rows.Close()
			return err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, column := range []struct{ name, definition string }{
		{"cleanup_phase", `TEXT NOT NULL DEFAULT '' CHECK (length(cleanup_phase) <= 32)`},
		{"cleanup_reason", `TEXT NOT NULL DEFAULT '' CHECK (length(CAST(cleanup_reason AS BLOB)) <= 1024)`},
		{"cleanup_attempts", `INTEGER NOT NULL DEFAULT 0 CHECK (typeof(cleanup_attempts) = 'integer' AND cleanup_attempts BETWEEN 0 AND 8)`},
		{"cleanup_started_at", `INTEGER`},
		{"cleanup_last_attempt_epoch", `INTEGER NOT NULL DEFAULT 0 CHECK (typeof(cleanup_last_attempt_epoch) = 'integer' AND cleanup_last_attempt_epoch >= 0)`},
		{"cleanup_recovery_epoch", `INTEGER NOT NULL DEFAULT 0 CHECK (typeof(cleanup_recovery_epoch) = 'integer' AND cleanup_recovery_epoch >= 0)`},
	} {
		if !columns[column.name] {
			if _, err := tx.ExecContext(ctx, `ALTER TABLE remediation_runs ADD COLUMN `+column.name+` `+column.definition); err != nil {
				return err
			}
		}
	}
	_, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS remediation_cleanup_audit (
		namespace TEXT NOT NULL, run_id TEXT NOT NULL,
		revision INTEGER NOT NULL CHECK (revision > 0),
		claim_epoch INTEGER NOT NULL CHECK (claim_epoch >= 0),
		actor TEXT NOT NULL CHECK (length(CAST(actor AS BLOB)) BETWEEN 1 AND 512),
		requested_at INTEGER NOT NULL,
		PRIMARY KEY(namespace, run_id, revision)
	)`)
	return err
}

func validateRemediationCleanup(cleanup store.RemediationCleanup, now time.Time) error {
	if !store.IsRemediationTerminalPhase(cleanup.Phase) || cleanup.Phase == store.RemediationPhaseSucceeded ||
		cleanup.Attempts < 0 || cleanup.Attempts > store.RemediationMaxCleanupAttempts ||
		cleanup.LastAttemptEpoch > math.MaxInt64 || cleanup.RecoveryEpoch > cleanup.LastAttemptEpoch ||
		validateRemediationTime(cleanup.StartedAt) != nil || cleanup.StartedAt.After(now) {
		return store.ErrValidation
	}
	switch cleanup.Reason {
	case "", "deadline-exceeded", "execution-failed", "required-environment-not-supported",
		"target-or-input-requires-confirmation", "execution-requires-reconciliation", "invalid-checks-proposal":
		return nil
	default:
		return store.ErrValidation
	}
}

func (s *Store) UpdateRemediationCleanup(ctx context.Context, namespace, id, owner string, epoch, expectedRevision uint64, cleanup store.RemediationCleanup, complete bool, now time.Time) (*store.RemediationRun, error) {
	return s.updateRemediationCleanup(ctx, namespace, id, owner, epoch, expectedRevision, cleanup, false, complete, now)
}

func (s *Store) BeginRemediationCleanupAttempt(ctx context.Context, namespace, id, owner string, epoch, expectedRevision uint64, cleanup store.RemediationCleanup, now time.Time) (*store.RemediationRun, error) {
	return s.updateRemediationCleanup(ctx, namespace, id, owner, epoch, expectedRevision, cleanup, true, false, now)
}

func (s *Store) updateRemediationCleanup(ctx context.Context, namespace, id, owner string, epoch, expectedRevision uint64, cleanup store.RemediationCleanup, begin, complete bool, now time.Time) (*store.RemediationRun, error) {
	if validateRemediationIdentity(namespace, id) != nil || validateRemediationFence(owner, epoch, now) != nil ||
		expectedRevision == 0 || expectedRevision > math.MaxInt64 || validateRemediationCleanup(cleanup, now) != nil {
		return nil, store.ErrValidation
	}
	cleanup.StartedAt = cleanup.StartedAt.UTC()
	var updated *store.RemediationRun
	err := s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		run, err := getRemediationRun(ctx, tx, namespace, id)
		if err != nil {
			return err
		}
		if err := requireRemediationClaim(run, owner, epoch, now); err != nil {
			return err
		}
		if run.Revision != expectedRevision || (run.CancelRequested && cleanup.Phase != store.RemediationPhaseCancelled) {
			return store.ErrConflict
		}
		if cleanup.LastAttemptEpoch > epoch || !remediationCleanupProgressAllowed(run.Cleanup, cleanup) {
			return store.ErrConflict
		}
		next := *run
		next.Phase, next.Reason, next.ApprovalDigest = store.RemediationPhaseCancelling, "cleanup-requires-reconciliation", ""
		next.Cleanup = &cleanup
		if complete {
			next.Phase, next.Reason, next.Cleanup = cleanup.Phase, cleanup.Reason, nil
			next.ClaimOwner, next.ClaimUntil = "", time.Time{}
		} else if !beginRemediationCleanupAttempt(&cleanup, begin, epoch, now) {
			next.Reason = store.RemediationReasonCleanupQuarantined
			next.ClaimOwner, next.ClaimUntil = "", time.Time{}
		}
		if err := saveRemediationCleanup(ctx, tx, run, &next, now); err != nil {
			return err
		}
		updated = &next
		return nil
	})
	return updated, err
}

func remediationCleanupProgressAllowed(previous *store.RemediationCleanup, next store.RemediationCleanup) bool {
	return previous == nil || (previous.StartedAt.Equal(next.StartedAt) &&
		next.Attempts >= previous.Attempts && next.Attempts <= previous.Attempts+1 &&
		next.LastAttemptEpoch == previous.LastAttemptEpoch && next.RecoveryEpoch == previous.RecoveryEpoch)
}

func beginRemediationCleanupAttempt(cleanup *store.RemediationCleanup, begin bool, epoch uint64, now time.Time) bool {
	if cleanup.Attempts >= store.RemediationMaxCleanupAttempts {
		return false
	}
	expired := now.Sub(cleanup.StartedAt) >= store.RemediationMaxCleanupDuration
	if expired {
		if !begin {
			return cleanup.RecoveryEpoch == 0
		}
		if cleanup.LastAttemptEpoch == epoch || cleanup.RecoveryEpoch != 0 {
			return false
		}
		// Persist this reservation before effects. If the worker crashes before
		// recording the outcome, another restart must quarantine, not acquire an
		// unlimited sequence of post-deadline cleanup attempts.
		cleanup.RecoveryEpoch = epoch
	}
	if begin {
		cleanup.LastAttemptEpoch = epoch
	}
	return true
}

func saveRemediationCleanup(ctx context.Context, tx *sql.Tx, previous, next *store.RemediationRun, now time.Time) error {
	// No payload changes are accepted on this path. The typed columns have
	// fixed bounds independent of the request/state/artifact namespace quota.
	if err := saveRemediationState(ctx, tx, previous, next, now); err != nil {
		return err
	}
	var cleanup store.RemediationCleanup
	if next.Cleanup != nil {
		cleanup = *next.Cleanup
	}
	result, err := tx.ExecContext(ctx, `UPDATE remediation_runs SET cleanup_phase=?, cleanup_reason=?,
		cleanup_attempts=?, cleanup_started_at=?, cleanup_last_attempt_epoch=?, cleanup_recovery_epoch=?, claim_epoch=?
		WHERE namespace=? AND id=? AND revision=?`,
		cleanup.Phase, cleanup.Reason, cleanup.Attempts, remediationOptionalTime(cleanup.StartedAt),
		cleanup.LastAttemptEpoch, cleanup.RecoveryEpoch, next.ClaimEpoch,
		next.Namespace, next.ID, next.Revision)
	if err != nil {
		return err
	}
	return rowsAffectedExactlyOne(result, "remediation cleanup")
}

func (s *Store) ReconcileRemediationCleanup(ctx context.Context, namespace, id, actor string, expectedRevision uint64, now time.Time) (*store.RemediationRun, error) {
	if validateRemediationIdentity(namespace, id) != nil || validateRemediationTime(now) != nil ||
		validateRemediationText("cleanup actor", actor, 512, true) != nil ||
		expectedRevision == 0 || expectedRevision >= math.MaxInt64 {
		return nil, store.ErrValidation
	}
	var updated *store.RemediationRun
	err := s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		run, err := getRemediationRun(ctx, tx, namespace, id)
		if err != nil {
			return err
		}
		if run.Phase != store.RemediationPhaseCancelling || run.Reason != store.RemediationReasonCleanupQuarantined ||
			run.Revision != expectedRevision || run.ClaimUntil.After(now) || run.ClaimEpoch == math.MaxInt64 {
			return store.ErrConflict
		}
		cleanup := store.RemediationCleanup{Phase: store.RemediationPhaseFailed, Reason: "execution-failed"}
		if run.Cleanup != nil {
			cleanup = *run.Cleanup
		} else {
			var legacy struct {
				Settlement *store.RemediationCleanup `json:"settlement"`
			}
			if json.Unmarshal(run.StateJSON, &legacy) != nil {
				return store.ErrRemediationIntegrity
			}
			if legacy.Settlement != nil {
				cleanup = *legacy.Settlement
			}
		}
		cleanup.Attempts, cleanup.StartedAt = 0, now.UTC()
		cleanup.LastAttemptEpoch, cleanup.RecoveryEpoch = 0, 0
		if run.CancelRequested {
			cleanup.Phase, cleanup.Reason = store.RemediationPhaseCancelled, ""
		}
		if err := validateRemediationCleanup(cleanup, now); err != nil {
			return err
		}
		// The audit receipt and reset commit together, including when payload
		// storage is full. Only bounded authenticated identity/fence metadata is
		// accepted; operators cannot supply execution state or secret payloads.
		if _, err := tx.ExecContext(ctx, `INSERT INTO remediation_cleanup_audit
			(namespace, run_id, revision, claim_epoch, actor, requested_at) VALUES (?, ?, ?, ?, ?, ?)`,
			namespace, id, run.Revision, run.ClaimEpoch, actor, now.UnixNano()); err != nil {
			return err
		}
		next := *run
		next.Reason, next.Cleanup = "cleanup-requires-reconciliation", &cleanup
		next.ClaimOwner, next.ClaimUntil, next.ClaimEpoch = "", time.Time{}, run.ClaimEpoch+1
		if err := saveRemediationCleanup(ctx, tx, run, &next, now); err != nil {
			return err
		}
		updated = &next
		return nil
	})
	return updated, err
}
