package sqlite

import (
	"context"
	"database/sql"

	"github.com/orka-agents/orka/internal/store"
)

func requireRemediationNamespaceCapacity(ctx context.Context, tx *sql.Tx, namespace string, additionalBytes int64) error {
	// Reductions and content-preserving cleanup remain possible at capacity.
	if additionalBytes <= 0 {
		return nil
	}
	var persistedBytes int64
	err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COALESCE(SUM(length(request_json) + length(policy_json) + length(state_json)), 0)
			FROM remediation_runs WHERE namespace = ?) +
		(SELECT COALESCE(SUM(length(data)), 0) FROM remediation_artifacts WHERE namespace = ?) +
		(SELECT COALESCE(SUM(length(ciphertext) + length(nonce)), 0) FROM remediation_intake_snapshots WHERE namespace = ?)`,
		namespace, namespace, namespace).Scan(&persistedBytes)
	if err != nil {
		return err
	}
	if additionalBytes > store.RemediationMaxNamespaceBytes ||
		persistedBytes > store.RemediationMaxNamespaceBytes-additionalBytes {
		return store.ErrCapacity
	}
	return nil
}
