package sqlite

import (
	"context"
	"errors"

	"github.com/orka-agents/orka/internal/store"
)

func (s *Store) verifyRemediationIntakeCipher(cipher *AgentExecutionSnapshotCipher) error {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='remediation_intake_snapshots'`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	rows, err := s.db.QueryContext(context.Background(), `SELECT namespace,run_id,digest,size,nonce,ciphertext FROM remediation_intake_snapshots`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var namespace, id, digest string
		var size int
		var nonce, ciphertext []byte
		if err := rows.Scan(&namespace, &id, &digest, &size, &nonce, &ciphertext); err != nil {
			return err
		}
		if len(nonce) != cipher.aead.NonceSize() || len(ciphertext) > store.RemediationMaxRequestBytes+cipher.aead.Overhead() {
			return errors.New("retained remediation intake failed integrity verification")
		}
		raw, err := cipher.open("remediation-intake/"+namespace+"/"+id, digest, 1, nonce, ciphertext)
		if err != nil || len(raw) != size || intakeDigest(raw) != digest {
			return errors.New("candidate snapshot key cannot authenticate retained remediation intake; restore the previous key")
		}
	}
	return rows.Err()
}
