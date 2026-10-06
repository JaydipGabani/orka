package sqlite

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/orka-agents/orka/internal/store"
)

const remediationSourceClaimSchema = `CREATE TABLE IF NOT EXISTS remediation_source_claims (
	namespace TEXT NOT NULL, source_key TEXT NOT NULL, run_id TEXT NOT NULL,
	PRIMARY KEY(namespace,source_key,run_id)
)`

func migrateRemediationSourceClaims(ctx context.Context, tx *sql.Tx) error {
	var definition string
	if err := tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_master
		WHERE type='table' AND name='remediation_source_claims'`).Scan(&definition); err != nil {
		return err
	}
	if !strings.Contains(strings.Join(strings.Fields(definition), ""), "PRIMARYKEY(namespace,source_key,run_id)") {
		for _, statement := range []string{
			strings.ReplaceAll(remediationSourceClaimSchema, "remediation_source_claims", "remediation_source_claims_v2"),
			`INSERT INTO remediation_source_claims_v2 SELECT namespace, source_key, run_id FROM remediation_source_claims`,
			`DROP TABLE remediation_source_claims`,
			`ALTER TABLE remediation_source_claims_v2 RENAME TO remediation_source_claims`,
		} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_remediation_source_run ON remediation_source_claims(namespace,run_id)`,
		`CREATE TABLE IF NOT EXISTS remediation_source_blockers (
			namespace TEXT NOT NULL, run_id TEXT NOT NULL, PRIMARY KEY(namespace,run_id))`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func backfillRemediationSourceClaims(ctx context.Context, tx *sql.Tx) error {
	var afterNamespace, afterID string
	for {
		var namespace, id, mode, inputDigest string
		var request []byte
		// Read one bounded frozen request at a time; neither the number of
		// namespaces nor their combined private input sizes is memory-bounded.
		err := tx.QueryRowContext(ctx, `SELECT namespace,id,mode,input_digest,request_json FROM remediation_runs r
			WHERE (namespace > ? OR (namespace = ? AND id > ?))
			AND (`+remediationNonterminalSQL+` OR reason='cleanup-quarantined')
			AND NOT EXISTS (SELECT 1 FROM remediation_source_claims s WHERE s.namespace=r.namespace AND s.run_id=r.id)
			AND NOT EXISTS (SELECT 1 FROM remediation_source_blockers b WHERE b.namespace=r.namespace AND b.run_id=r.id)
			ORDER BY namespace,id LIMIT 1`, afterNamespace, afterNamespace, afterID).Scan(&namespace, &id, &mode, &inputDigest, &request)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		afterNamespace, afterID = namespace, id
		key, err := remediationFrozenSourceKey(request, inputDigest, mode)
		if err != nil {
			// Unrecognizable legacy input cannot safely be matched to a new
			// source. Keep admission blocked in this namespace until that
			// exact run settles; never release or rewrite its external effects.
			if _, err := tx.ExecContext(ctx, `INSERT INTO remediation_source_blockers(namespace,run_id) VALUES(?,?)`, namespace, id); err != nil {
				return err
			}
			continue
		}
		// Preexisting duplicates each retain a reservation. Settling one must
		// not make a second unresolved run disappear from source admission.
		if _, err := tx.ExecContext(ctx, `INSERT INTO remediation_source_claims(namespace,source_key,run_id) VALUES(?,?,?)`, namespace, key, id); err != nil {
			return err
		}
	}
}

func remediationFrozenSourceKey(raw []byte, inputDigest, mode string) (string, error) {
	var request struct {
		Policy   string `json:"policy"`
		Mode     string `json:"mode"`
		Incident string `json:"incident"`
		Patch    string `json:"patch"`
		Report   *struct {
			SourceKind string `json:"sourceKind"`
			SourceID   string `json:"sourceID"`
		} `json:"report"`
	}
	if json.Unmarshal(raw, &request) != nil || request.Mode != mode ||
		(request.Report == nil && request.Incident == "") {
		return "", store.ErrValidation
	}
	var sourceKind, sourceID string
	if request.Report != nil {
		sourceKind, sourceID = request.Report.SourceKind, request.Report.SourceID
	}
	return store.RemediationSourceOperationKey(request.Policy, sourceKind, sourceID, inputDigest, mode, request.Patch)
}

func claimRemediationSource(ctx context.Context, tx *sql.Tx, run *store.RemediationRun) error {
	if run.SourceOperationKey == "" {
		return nil
	}
	if len(run.SourceOperationKey) != 71 || !strings.HasPrefix(run.SourceOperationKey, "sha256:") {
		return store.ErrValidation
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(run.SourceOperationKey, "sha256:")); err != nil {
		return store.ErrValidation
	}
	var blocked bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM remediation_source_blockers b
		JOIN remediation_runs r ON b.namespace=r.namespace AND b.run_id=r.id
		WHERE b.namespace=? AND (`+remediationNonterminalSQL+` OR reason='cleanup-quarantined'))`,
		run.Namespace).Scan(&blocked)
	if err != nil {
		return err
	}
	if blocked {
		return store.ErrConflict
	}
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM remediation_source_claims s
		JOIN remediation_runs r ON s.namespace=r.namespace AND s.run_id=r.id
		WHERE s.namespace=? AND s.source_key=? AND (`+remediationNonterminalSQL+` OR reason='cleanup-quarantined'))`,
		run.Namespace, run.SourceOperationKey).Scan(&blocked)
	if err != nil {
		return err
	}
	if blocked {
		return store.ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO remediation_source_claims(namespace,source_key,run_id)
		VALUES(?,?,?)`,
		run.Namespace, run.SourceOperationKey, run.ID)
	return err
}
