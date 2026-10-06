package sqlite

import (
	"context"

	"github.com/orka-agents/orka/internal/store"
)

func (s *Store) CountRemediationRuns(ctx context.Context, namespace string) (store.RemediationRunCounts, error) {
	if err := validateRemediationNamespace(namespace); err != nil {
		return store.RemediationRunCounts{}, err
	}
	var counts store.RemediationRunCounts
	err := s.db.QueryRowContext(ctx, `SELECT
		COUNT(CASE WHEN `+remediationNonterminalSQL+` THEN 1 END),
		COUNT(CASE WHEN reason = ? THEN 1 END),
		(SELECT COUNT(*) FROM remediation_intake_snapshots WHERE namespace = ?)
		FROM remediation_runs WHERE namespace = ?`,
		store.RemediationReasonCleanupQuarantined, namespace, namespace).Scan(&counts.Active, &counts.Quarantined, &counts.RetainedIntakes)
	return counts, err
}
