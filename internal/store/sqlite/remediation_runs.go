package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"github.com/orka-agents/orka/internal/store"
)

const remediationRunColumns = `namespace, id, request_id, submitted_by, mode, policy_digest, input_digest,
	request_json, policy_json, state_json, phase, reason, revision, claim_epoch, claim_owner,
	claim_until, created_at, updated_at, deadline, cancel_requested, approval_digest, approved_digest, approved_by,
	cleanup_phase, cleanup_reason, cleanup_attempts, cleanup_started_at, cleanup_last_attempt_epoch, cleanup_recovery_epoch`

const remediationRunMetadataColumns = `namespace, id, request_id, submitted_by, mode, policy_digest, input_digest,
	NULL, NULL, NULL, phase, reason, revision, claim_epoch, claim_owner,
	claim_until, created_at, updated_at, deadline, cancel_requested, approval_digest, approved_digest, approved_by,
	cleanup_phase, cleanup_reason, cleanup_attempts, cleanup_started_at, cleanup_last_attempt_epoch, cleanup_recovery_epoch`

const remediationNonterminalSQL = `phase NOT IN ('Succeeded', 'Failed', 'Cancelled', 'TimedOut', 'NeedsInput', 'NeedsAdapter')`

func (s *Store) CreateRemediationRun(ctx context.Context, input *store.RemediationRun) (*store.RemediationRun, bool, error) {
	run, err := prepareRemediationRun(input)
	if err != nil {
		return nil, false, err
	}
	var result *store.RemediationRun
	var created bool
	err = s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		existing, err := scanRemediationRun(tx.QueryRowContext(ctx, `SELECT `+remediationRunColumns+`
			FROM remediation_runs WHERE namespace = ? AND request_id = ?`, run.Namespace, run.RequestID))
		if err == nil {
			if !sameRemediationSubmission(existing, run) {
				return store.ErrDuplicateMismatch
			}
			result = existing
			return nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := initializeRemediationRun(run); err != nil {
			return err
		}
		if err := admitRemediationRun(ctx, tx, run); err != nil {
			return err
		}
		if err := claimRemediationSource(ctx, tx, run); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO remediation_runs (`+remediationRunColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', 0, NULL, 0, 0)`,
			run.Namespace, run.ID, run.RequestID, run.SubmittedBy, run.Mode, run.PolicyDigest, run.InputDigest,
			[]byte(run.RequestJSON), []byte(run.PolicyJSON), []byte(run.StateJSON), run.Phase, run.Reason,
			run.Revision, run.ClaimEpoch, run.ClaimOwner, remediationOptionalTime(run.ClaimUntil),
			run.CreatedAt.UnixNano(), run.UpdatedAt.UnixNano(), remediationOptionalTime(run.Deadline),
			run.CancelRequested, run.ApprovalDigest, run.ApprovedDigest, run.ApprovedBy,
		)
		if err != nil {
			return err
		}
		if err := s.persistRemediationIntake(ctx, tx, run); err != nil {
			return err
		}
		run.Intake = nil
		result, created = run, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return result, created, nil
}

func admitRemediationRun(ctx context.Context, tx *sql.Tx, run *store.RemediationRun) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM remediation_runs WHERE namespace = ? AND id = ?
	)`, run.Namespace, run.ID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return store.ErrConflict
	}
	var active, submitterActive int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(CASE WHEN submitted_by = ? THEN 1 END)
		FROM remediation_runs WHERE namespace = ? AND `+remediationNonterminalSQL,
		run.SubmittedBy, run.Namespace).Scan(&active, &submitterActive); err != nil {
		return err
	}
	if active >= store.RemediationMaxActiveRuns || submitterActive >= store.RemediationMaxSubmitterActiveRuns {
		return store.ErrCapacity
	}
	intakeBytes := 0
	if len(run.Intake) != 0 {
		intakeBytes = len(run.Intake) + 28
	}
	return requireRemediationNamespaceCapacity(ctx, tx, run.Namespace,
		int64(len(run.RequestJSON)+len(run.PolicyJSON)+len(run.StateJSON)+intakeBytes))
}

func sameRemediationSubmission(existing, candidate *store.RemediationRun) bool {
	return existing.Namespace == candidate.Namespace && existing.RequestID == candidate.RequestID &&
		existing.SubmittedBy == candidate.SubmittedBy && existing.Mode == candidate.Mode &&
		existing.InputDigest == candidate.InputDigest && bytes.Equal(existing.RequestJSON, candidate.RequestJSON)
}

func (s *Store) GetRemediationRun(ctx context.Context, namespace, id string) (*store.RemediationRun, error) {
	if err := validateRemediationIdentity(namespace, id); err != nil {
		return nil, err
	}
	return getRemediationRun(ctx, s.db, namespace, id)
}

func (s *Store) GetRemediationRunByRequestID(ctx context.Context, namespace, requestID string) (*store.RemediationRun, error) {
	if err := validateRemediationNamespace(namespace); err != nil {
		return nil, err
	}
	if err := validateRemediationRequestID(requestID); err != nil {
		return nil, err
	}
	return scanRemediationRun(s.db.QueryRowContext(ctx, `SELECT `+remediationRunColumns+`
		FROM remediation_runs WHERE namespace=? AND request_id=?`, namespace, requestID))
}

func (s *Store) GetRemediationRunMetadata(ctx context.Context, namespace, id string) (*store.RemediationRun, error) {
	if err := validateRemediationIdentity(namespace, id); err != nil {
		return nil, err
	}
	return getRemediationRunMetadata(ctx, s.db, namespace, id)
}

func getRemediationRunMetadata(ctx context.Context, query queryRower, namespace, id string) (*store.RemediationRun, error) {
	return scanRemediationRun(query.QueryRowContext(ctx, `SELECT `+remediationRunMetadataColumns+`
		FROM remediation_runs WHERE namespace = ? AND id = ?`, namespace, id))
}

func getRemediationRun(ctx context.Context, query queryRower, namespace, id string) (*store.RemediationRun, error) {
	return scanRemediationRun(query.QueryRowContext(ctx, `SELECT `+remediationRunColumns+`
		FROM remediation_runs WHERE namespace = ? AND id = ?`, namespace, id))
}

func scanRemediationRun(row gatewayRowScanner) (*store.RemediationRun, error) {
	var run store.RemediationRun
	var requestJSON, policyJSON, stateJSON []byte
	var claimUntil, deadline sql.NullInt64
	var cleanupStarted sql.NullInt64
	var cleanup store.RemediationCleanup
	var createdAt, updatedAt int64
	err := row.Scan(
		&run.Namespace, &run.ID, &run.RequestID, &run.SubmittedBy, &run.Mode, &run.PolicyDigest, &run.InputDigest,
		&requestJSON, &policyJSON, &stateJSON, &run.Phase, &run.Reason, &run.Revision, &run.ClaimEpoch,
		&run.ClaimOwner, &claimUntil, &createdAt, &updatedAt, &deadline, &run.CancelRequested,
		&run.ApprovalDigest, &run.ApprovedDigest, &run.ApprovedBy,
		&cleanup.Phase, &cleanup.Reason, &cleanup.Attempts, &cleanupStarted,
		&cleanup.LastAttemptEpoch, &cleanup.RecoveryEpoch,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	run.RequestJSON, run.PolicyJSON, run.StateJSON = requestJSON, policyJSON, stateJSON
	run.CreatedAt = time.Unix(0, createdAt).UTC()
	run.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if claimUntil.Valid {
		run.ClaimUntil = time.Unix(0, claimUntil.Int64).UTC()
	}
	if deadline.Valid {
		run.Deadline = time.Unix(0, deadline.Int64).UTC()
	}
	if cleanupStarted.Valid {
		cleanup.StartedAt = time.Unix(0, cleanupStarted.Int64).UTC()
		run.Cleanup = &cleanup
	}
	return &run, nil
}

func remediationOptionalTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UnixNano()
}

func (s *Store) ListRemediationRuns(ctx context.Context, namespace string, limit int) ([]store.RemediationRun, error) {
	page, err := s.ListRemediationRunsPage(ctx, namespace, limit, "")
	return page.Items, err
}

func (s *Store) ListRemediationRunsPage(ctx context.Context, namespace string, limit int, beforeID string) (store.RemediationRunPage, error) {
	if err := validateRemediationNamespace(namespace); err != nil {
		return store.RemediationRunPage{}, err
	}
	if limit < 1 || limit > store.RemediationMaxListLimit {
		return store.RemediationRunPage{}, store.ValidationErrorf("remediation list limit must be between one and 100")
	}
	var before int64
	if beforeID != "" {
		if err := validateRemediationIdentity(namespace, beforeID); err != nil {
			return store.RemediationRunPage{}, err
		}
		err := s.db.QueryRowContext(ctx, `SELECT created_at FROM remediation_runs WHERE namespace=? AND id=?`,
			namespace, beforeID).Scan(&before)
		if errors.Is(err, sql.ErrNoRows) {
			return store.RemediationRunPage{}, store.ErrNotFound
		}
		if err != nil {
			return store.RemediationRunPage{}, err
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+remediationRunMetadataColumns+` FROM remediation_runs
		WHERE namespace = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
		ORDER BY created_at DESC, id DESC LIMIT ?`, namespace, beforeID, before, before, beforeID, limit+1)
	if err != nil {
		return store.RemediationRunPage{}, err
	}
	defer func() { _ = rows.Close() }()
	runs := make([]store.RemediationRun, 0, limit)
	for rows.Next() {
		run, err := scanRemediationRun(rows)
		if err != nil {
			return store.RemediationRunPage{}, err
		}
		runs = append(runs, *run)
	}
	if err := rows.Err(); err != nil {
		return store.RemediationRunPage{}, err
	}
	page := store.RemediationRunPage{Items: runs}
	if len(runs) > limit {
		page.Items, page.Continue = runs[:limit], runs[limit-1].ID
	}
	return page, nil
}

func (s *Store) ClaimNextRemediationRun(ctx context.Context, namespace, owner string, now time.Time, lease time.Duration) (*store.RemediationRun, error) {
	if err := validateRemediationNamespace(namespace); err != nil {
		return nil, err
	}
	if err := validateRemediationLease(owner, now, lease); err != nil {
		return nil, err
	}
	var claimed *store.RemediationRun
	err := s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		run, err := scanRemediationRun(tx.QueryRowContext(ctx, `SELECT `+remediationRunColumns+`
			FROM remediation_runs WHERE namespace = ? AND `+remediationNonterminalSQL+`
			AND reason <> 'cleanup-quarantined'
			AND (cancel_requested = 1 OR phase <> 'NeedsApproval' OR deadline <= ?)
			AND (claim_until IS NULL OR claim_until <= ?)
			ORDER BY created_at, id LIMIT 1`, namespace, now.UnixNano(), now.UnixNano()))
		if err != nil {
			return err
		}
		if run.ClaimEpoch == math.MaxInt64 {
			return store.ErrConflict
		}
		until := now.Add(lease).UTC()
		result, err := tx.ExecContext(ctx, `UPDATE remediation_runs
			SET claim_owner = ?, claim_epoch = claim_epoch + 1, claim_until = ?
			WHERE namespace = ? AND id = ? AND claim_epoch = ?
			AND (claim_until IS NULL OR claim_until <= ?)`,
			owner, until.UnixNano(), namespace, run.ID, run.ClaimEpoch, now.UnixNano())
		if err != nil {
			return err
		}
		if err := rowsAffectedExactlyOne(result, "remediation claim"); err != nil {
			return err
		}
		run.ClaimOwner, run.ClaimUntil = owner, until
		run.ClaimEpoch++
		claimed = run
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

func (s *Store) RenewRemediationClaim(ctx context.Context, namespace, id, owner string, epoch uint64, now time.Time, lease time.Duration) error {
	if err := validateRemediationIdentity(namespace, id); err != nil {
		return err
	}
	if err := validateRemediationLease(owner, now, lease); err != nil {
		return err
	}
	if err := validateRemediationFence(owner, epoch, now); err != nil {
		return err
	}
	return s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		run, err := getRemediationRunMetadata(ctx, tx, namespace, id)
		if err != nil {
			return err
		}
		if err := requireRemediationClaim(run, owner, epoch, now); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE remediation_runs SET claim_until = MAX(claim_until, ?)
			WHERE namespace = ? AND id = ? AND claim_owner = ? AND claim_epoch = ? AND claim_until > ?`,
			now.Add(lease).UnixNano(), namespace, id, owner, epoch, now.UnixNano())
		if err != nil {
			return err
		}
		return rowsAffectedExactlyOne(result, "remediation claim renewal")
	})
}

func requireRemediationClaim(run *store.RemediationRun, owner string, epoch uint64, now time.Time) error {
	if store.IsRemediationTerminalPhase(run.Phase) || (remediationPaused(run.Phase) && !remediationDeadlineExpired(run, now)) ||
		run.ClaimOwner != owner || run.ClaimEpoch != epoch || !run.ClaimUntil.After(now) {
		return store.ErrConflict
	}
	return nil
}

func remediationPaused(phase string) bool {
	return phase == store.RemediationPhaseNeedsApproval
}

func remediationDeadlineExpired(run *store.RemediationRun, now time.Time) bool {
	return !run.Deadline.IsZero() && !run.Deadline.After(now)
}

func (s *Store) UpdateRemediationRun(ctx context.Context, namespace, id, owner string, epoch, expectedRevision uint64, update store.RemediationUpdate, now time.Time) (*store.RemediationRun, error) {
	if err := validateRemediationIdentity(namespace, id); err != nil {
		return nil, err
	}
	if err := validateRemediationFence(owner, epoch, now); err != nil {
		return nil, err
	}
	if err := validateRemediationUpdate(update, expectedRevision); err != nil {
		return nil, err
	}
	var updated *store.RemediationRun
	err := s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		run, err := getRemediationRun(ctx, tx, namespace, id)
		if err != nil {
			return err
		}
		if err := requireRemediationClaim(run, owner, epoch, now); err != nil {
			return err
		}
		if run.Revision != expectedRevision || !remediationUpdateAllowed(run, update.Phase) {
			return store.ErrConflict
		}
		next := *run
		next.Phase, next.Reason, next.ApprovalDigest = update.Phase, update.Reason, update.ApprovalDigest
		if len(update.StateJSON) != 0 {
			next.StateJSON = bytes.Clone(update.StateJSON)
		}
		if next.Phase == store.RemediationPhaseNeedsApproval {
			next.ApprovedDigest, next.ApprovedBy = "", ""
		}
		if store.IsRemediationTerminalPhase(next.Phase) || remediationPaused(next.Phase) {
			next.ClaimOwner, next.ClaimUntil = "", time.Time{}
		}
		if err := saveRemediationState(ctx, tx, run, &next, now); err != nil {
			return err
		}
		updated = &next
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func remediationUpdateAllowed(run *store.RemediationRun, phase string) bool {
	if run.CancelRequested {
		return phase == store.RemediationPhaseCancelling || phase == store.RemediationPhaseCancelled
	}
	if remediationPaused(run.Phase) {
		return phase == store.RemediationPhaseTimedOut || phase == store.RemediationPhaseCancelling
	}
	if run.Phase == store.RemediationPhaseCancelling {
		return phase == store.RemediationPhaseCancelling || store.IsRemediationTerminalPhase(phase)
	}
	return true
}

func saveRemediationState(ctx context.Context, tx *sql.Tx, previous, next *store.RemediationRun, now time.Time) error {
	if previous.Revision == math.MaxInt64 {
		return store.ErrConflict
	}
	if err := requireRemediationNamespaceCapacity(ctx, tx, previous.Namespace,
		int64(len(next.StateJSON)-len(previous.StateJSON))); err != nil {
		return err
	}
	next.Revision = previous.Revision + 1
	next.UpdatedAt = now.UTC()
	result, err := tx.ExecContext(ctx, `UPDATE remediation_runs SET
		phase = ?, reason = ?, state_json = ?, revision = ?, updated_at = ?, cancel_requested = ?,
		approval_digest = ?, approved_digest = ?, approved_by = ?, claim_owner = ?, claim_until = ?
		WHERE namespace = ? AND id = ? AND revision = ? AND claim_epoch = ? AND claim_owner = ?
		AND claim_until IS ?`,
		next.Phase, next.Reason, []byte(next.StateJSON), next.Revision, next.UpdatedAt.UnixNano(), next.CancelRequested,
		next.ApprovalDigest, next.ApprovedDigest, next.ApprovedBy, next.ClaimOwner, remediationOptionalTime(next.ClaimUntil),
		previous.Namespace, previous.ID, previous.Revision, previous.ClaimEpoch, previous.ClaimOwner,
		remediationOptionalTime(previous.ClaimUntil))
	if err != nil {
		return err
	}
	return rowsAffectedExactlyOne(result, "remediation run")
}

func (s *Store) CancelRemediationRun(ctx context.Context, namespace, id string, now time.Time) (*store.RemediationRun, error) {
	if err := validateRemediationIdentity(namespace, id); err != nil {
		return nil, err
	}
	if err := validateRemediationTime(now); err != nil {
		return nil, err
	}
	var cancelled *store.RemediationRun
	err := s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		run, err := getRemediationRun(ctx, tx, namespace, id)
		if err != nil {
			return err
		}
		if store.IsRemediationTerminalPhase(run.Phase) || run.CancelRequested {
			cancelled = run
			return nil
		}
		next := *run
		next.CancelRequested, next.Phase = true, store.RemediationPhaseCancelling
		next.ApprovalDigest = ""
		if next.Reason != store.RemediationReasonCleanupQuarantined {
			next.Reason = ""
		}
		if err := saveRemediationState(ctx, tx, run, &next, now); err != nil {
			return err
		}
		cancelled = &next
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cancelled, nil
}

func (s *Store) ApproveRemediationRun(ctx context.Context, namespace, id, planDigest, actor string, now time.Time) (*store.RemediationRun, error) {
	if err := validateRemediationIdentity(namespace, id); err != nil {
		return nil, err
	}
	if err := validateRemediationText("approval digest", planDigest, 256, true); err != nil {
		return nil, err
	}
	if err := validateRemediationText("approval actor", actor, 512, true); err != nil {
		return nil, err
	}
	if err := validateRemediationTime(now); err != nil {
		return nil, err
	}
	var approved *store.RemediationRun
	err := s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		run, err := getRemediationRun(ctx, tx, namespace, id)
		if err != nil {
			return err
		}
		if run.ApprovalDigest == "" && run.ApprovedDigest == planDigest && run.ApprovedBy == actor &&
			(run.Phase == store.RemediationPhaseQueued || run.Phase == store.RemediationPhaseRunning ||
				store.IsRemediationTerminalPhase(run.Phase)) {
			approved = run
			return nil
		}
		if run.Phase != store.RemediationPhaseNeedsApproval || run.CancelRequested ||
			run.ApprovalDigest != planDigest || remediationDeadlineExpired(run, now) {
			return store.ErrConflict
		}
		next := *run
		next.Phase, next.Reason, next.ApprovalDigest = store.RemediationPhaseQueued, "", ""
		next.ApprovedDigest, next.ApprovedBy = planDigest, actor
		next.ClaimOwner, next.ClaimUntil = "", time.Time{}
		if err := saveRemediationState(ctx, tx, run, &next, now); err != nil {
			return err
		}
		approved = &next
		return nil
	})
	if err != nil {
		return nil, err
	}
	return approved, nil
}
