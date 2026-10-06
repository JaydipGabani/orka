package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/orka-agents/orka/internal/store"
)

const remediationIntakeSchema = `CREATE TABLE IF NOT EXISTS remediation_intake_snapshots (
	namespace TEXT NOT NULL,
	run_id TEXT NOT NULL,
	digest TEXT NOT NULL,
	size INTEGER NOT NULL CHECK(size > 0 AND size <= 8388608),
	nonce BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	PRIMARY KEY(namespace,run_id)
)`

func intakeDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *Store) persistRemediationIntake(ctx context.Context, tx *sql.Tx, run *store.RemediationRun) error {
	if len(run.Intake) == 0 {
		return nil
	}
	if s.snapshotCipher == nil {
		return errSnapshotCipherRequired
	}
	if len(run.Intake) > store.RemediationMaxRequestBytes || intakeDigest(run.Intake) != run.InputDigest {
		return store.ErrValidation
	}
	nonce, ciphertext, err := s.snapshotCipher.seal("remediation-intake/"+run.Namespace+"/"+run.ID, run.InputDigest, 1, run.Intake)
	if err != nil {
		return errors.New("encrypt remediation intake snapshot")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO remediation_intake_snapshots(namespace,run_id,digest,size,nonce,ciphertext)
		VALUES(?,?,?,?,?,?)`, run.Namespace, run.ID, run.InputDigest, len(run.Intake), nonce, ciphertext)
	return err
}

// ReadRemediationIntake is an internal acquisition/reconciliation surface.
// It is deliberately absent from the ordinary run artifact HTTP contract.
func (s *Store) ReadRemediationIntake(ctx context.Context, namespace, id string) ([]byte, error) {
	if err := validateRemediationIdentity(namespace, id); err != nil {
		return nil, err
	}
	if s.snapshotCipher == nil {
		return nil, errSnapshotCipherRequired
	}
	var digest string
	var size int
	var nonce, ciphertext []byte
	err := s.db.QueryRowContext(ctx, `SELECT digest,size,nonce,ciphertext FROM remediation_intake_snapshots WHERE namespace=? AND run_id=?`, namespace, id).Scan(&digest, &size, &nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(nonce) != s.snapshotCipher.aead.NonceSize() || len(ciphertext) > store.RemediationMaxRequestBytes+s.snapshotCipher.aead.Overhead() {
		return nil, store.ErrRemediationIntegrity
	}
	raw, err := s.snapshotCipher.open("remediation-intake/"+namespace+"/"+id, digest, 1, nonce, ciphertext)
	if err != nil || size != len(raw) || intakeDigest(raw) != digest {
		return nil, store.ErrRemediationIntegrity
	}
	return raw, nil
}

func (s *Store) PruneRemediationIntake(ctx context.Context, namespace string, cutoff time.Time, limit int) (int64, error) {
	if validateRemediationNamespace(namespace) != nil || validateRemediationTime(cutoff) != nil ||
		limit < 1 || limit > store.RemediationMaxListLimit {
		return 0, store.ErrValidation
	}
	var removed int64
	err := s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		var retained bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM remediation_intake_snapshots WHERE namespace=?)`,
			namespace).Scan(&retained); err != nil {
			return err
		}
		if retained && s.snapshotCipher == nil {
			return errSnapshotCipherRequired
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM remediation_intake_snapshots
			WHERE namespace=? AND run_id IN (
				SELECT i.run_id FROM remediation_intake_snapshots i
				JOIN remediation_runs r ON r.namespace=i.namespace AND r.id=i.run_id
				WHERE i.namespace=? AND NOT (`+remediationNonterminalSQL+`)
				AND r.reason <> 'cleanup-quarantined' AND r.cleanup_started_at IS NULL
				AND r.claim_owner='' AND r.updated_at <= ?
				ORDER BY r.updated_at, r.id LIMIT ?
			)`, namespace, namespace, cutoff.UnixNano(), limit)
		if err != nil {
			return err
		}
		removed, err = result.RowsAffected()
		return err
	})
	return removed, err
}
