package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/orka-agents/orka/internal/store"
)

var _ store.RemediationRunStore = (*Store)(nil)

const remediationRunsSchema = `CREATE TABLE IF NOT EXISTS remediation_runs (
	namespace TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 253),
	id TEXT NOT NULL CHECK (length(id) = 35),
	request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 96),
	submitted_by TEXT NOT NULL CHECK (length(CAST(submitted_by AS BLOB)) BETWEEN 1 AND 512),
	mode TEXT NOT NULL CHECK (length(mode) BETWEEN 1 AND 64),
	policy_digest TEXT NOT NULL CHECK (length(policy_digest) BETWEEN 1 AND 256),
	input_digest TEXT NOT NULL CHECK (length(input_digest) BETWEEN 1 AND 256),
	request_json BLOB NOT NULL CHECK (length(request_json) BETWEEN 1 AND 8388608),
	policy_json BLOB NOT NULL CHECK (length(policy_json) BETWEEN 1 AND 65536),
	state_json BLOB NOT NULL CHECK (length(state_json) BETWEEN 1 AND 1048576),
	phase TEXT NOT NULL CHECK (phase IN (
		'Queued', 'Running', 'NeedsInput', 'NeedsAdapter', 'NeedsApproval',
		'Cancelling', 'Succeeded', 'Failed', 'Cancelled', 'TimedOut'
	)),
	reason TEXT NOT NULL DEFAULT '' CHECK (length(CAST(reason AS BLOB)) <= 1024),
	revision INTEGER NOT NULL CHECK (typeof(revision) = 'integer' AND revision >= 1),
	claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (typeof(claim_epoch) = 'integer' AND claim_epoch >= 0),
	claim_owner TEXT NOT NULL DEFAULT '' CHECK (length(CAST(claim_owner AS BLOB)) <= 256),
	claim_until INTEGER,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	deadline INTEGER,
	cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
	approval_digest TEXT NOT NULL DEFAULT '' CHECK (length(approval_digest) <= 256),
	approved_digest TEXT NOT NULL DEFAULT '' CHECK (length(approved_digest) <= 256),
	approved_by TEXT NOT NULL DEFAULT '' CHECK (length(CAST(approved_by AS BLOB)) <= 512),
	cleanup_phase TEXT NOT NULL DEFAULT '' CHECK (length(cleanup_phase) <= 32),
	cleanup_reason TEXT NOT NULL DEFAULT '' CHECK (length(CAST(cleanup_reason AS BLOB)) <= 1024),
	cleanup_attempts INTEGER NOT NULL DEFAULT 0 CHECK (typeof(cleanup_attempts) = 'integer' AND cleanup_attempts BETWEEN 0 AND 8),
	cleanup_started_at INTEGER,
	cleanup_last_attempt_epoch INTEGER NOT NULL DEFAULT 0 CHECK (typeof(cleanup_last_attempt_epoch) = 'integer' AND cleanup_last_attempt_epoch >= 0),
	cleanup_recovery_epoch INTEGER NOT NULL DEFAULT 0 CHECK (typeof(cleanup_recovery_epoch) = 'integer' AND cleanup_recovery_epoch >= 0),
	PRIMARY KEY (namespace, id),
	UNIQUE (namespace, request_id),
	CHECK (cancel_requested = 0 OR phase IN ('Cancelling', 'Cancelled')),
	CHECK (phase <> 'NeedsApproval' OR approval_digest <> ''),
	CHECK ((claim_owner = '' AND claim_until IS NULL) OR (claim_owner <> '' AND claim_until IS NOT NULL)),
	CONSTRAINT remediation_terminal_claims_v2 CHECK (phase NOT IN (
		'NeedsInput', 'NeedsAdapter', 'Succeeded', 'Failed', 'Cancelled', 'TimedOut'
	) OR claim_owner = ''),
	CHECK (phase <> 'NeedsApproval' OR claim_owner = '' OR (deadline IS NOT NULL AND claim_until > deadline)),
	CHECK ((approved_digest = '' AND approved_by = '') OR (approved_digest <> '' AND approved_by <> ''))
)`

const remediationArtifactsSchema = `CREATE TABLE IF NOT EXISTS remediation_artifacts (
	namespace TEXT NOT NULL,
	run_id TEXT NOT NULL,
	name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
	digest TEXT NOT NULL CHECK (length(digest) = 71),
	media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 256),
	size INTEGER NOT NULL CHECK (size BETWEEN 0 AND 8388608),
	created_at INTEGER NOT NULL,
	data BLOB NOT NULL CHECK (length(data) <= 8388608 AND size = length(data)),
	PRIMARY KEY (namespace, run_id, name),
	FOREIGN KEY (namespace, run_id) REFERENCES remediation_runs(namespace, id)
)`

func (s *Store) InitializeRemediationStore(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS remediation_write_lock (
		id INTEGER PRIMARY KEY CHECK (id = 1)
	)`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO remediation_write_lock (id) VALUES (1)`); err != nil {
		return err
	}
	return s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		for _, statement := range []string{remediationRunsSchema, remediationArtifactsSchema, remediationIntakeSchema, remediationSourceClaimSchema} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		if err := migrateRemediationCleanupSchema(ctx, tx); err != nil {
			return err
		}
		if err := migrateRemediationClaimSchema(ctx, tx); err != nil {
			return err
		}
		if err := migrateRemediationSourceClaims(ctx, tx); err != nil {
			return err
		}
		statements := []string{
			`CREATE INDEX IF NOT EXISTS idx_remediation_runs_queue
				ON remediation_runs(namespace, created_at, id)`,
			`CREATE INDEX IF NOT EXISTS idx_remediation_runs_active
				ON remediation_runs(namespace, phase)`,
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		return backfillRemediationSourceClaims(ctx, tx)
	})
}

func migrateRemediationClaimSchema(ctx context.Context, tx *sql.Tx) error {
	var definition string
	err := tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_master
		WHERE type = 'table' AND name = 'remediation_runs'`).Scan(&definition)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	if strings.Contains(definition, "remediation_terminal_claims_v2") {
		return nil
	}
	// SQLite cannot alter CHECK constraints. Rebuild both related tables in the
	// same writer transaction, preserving every row and keeping foreign keys on.
	runSchema := strings.ReplaceAll(remediationRunsSchema, "remediation_runs", "remediation_runs_v2")
	artifactSchema := strings.NewReplacer(
		"remediation_artifacts", "remediation_artifacts_v2", "remediation_runs", "remediation_runs_v2",
	).Replace(remediationArtifactsSchema)
	statements := []string{
		strings.Replace(runSchema, "IF NOT EXISTS ", "", 1),
		`INSERT INTO remediation_runs_v2 (` + remediationRunColumns + `)
			SELECT ` + remediationRunColumns + ` FROM remediation_runs`,
		strings.Replace(artifactSchema, "IF NOT EXISTS ", "", 1),
		`INSERT INTO remediation_artifacts_v2
			(namespace, run_id, name, digest, media_type, size, created_at, data)
			SELECT namespace, run_id, name, digest, media_type, size, created_at, data FROM remediation_artifacts`,
		`DROP TABLE remediation_artifacts`,
		`DROP TABLE remediation_runs`,
		`ALTER TABLE remediation_runs_v2 RENAME TO remediation_runs`,
		`ALTER TABLE remediation_artifacts_v2 RENAME TO remediation_artifacts`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) withRemediationTx(ctx context.Context, operation func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Acquire the SQLite writer lock before reading. A process-local mutex (or a
	// deferred read followed by UPDATE) cannot fence independent Store instances
	// and the latter can fail with SQLITE_BUSY_SNAPSHOT rather than wait.
	result, err := tx.ExecContext(ctx, `UPDATE remediation_write_lock SET id = id WHERE id = 1`)
	if err != nil {
		return err
	}
	if err := rowsAffectedExactlyOne(result, "remediation store lock"); err != nil {
		return err
	}
	if err := operation(tx); err != nil {
		return err
	}
	return tx.Commit()
}
