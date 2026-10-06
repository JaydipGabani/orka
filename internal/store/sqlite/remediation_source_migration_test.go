package sqlite

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func frozenSourceTestRun(t *testing.T, serial int, sourceID string) *store.RemediationRun {
	t.Helper()
	input := remediationTestRun("tenant", serial)
	input.RequestJSON = json.RawMessage(`{"policy":"approved","mode":"verify","patch":"synthetic patch",
		"report":{"sourceKind":"supplied-report","sourceID":"` + sourceID + `"}}`)
	key, err := store.RemediationSourceOperationKey("approved", "supplied-report", sourceID, input.InputDigest, input.Mode, "synthetic patch")
	require.NoError(t, err)
	input.SourceOperationKey = key
	return input
}

func TestRemediationSourceMigrationBackfillsAllAmbiguousActiveRuns(t *testing.T) {
	s := newRemediationTestStore(t)
	inputs := []*store.RemediationRun{
		frozenSourceTestRun(t, 1, "synthetic-source"),
		frozenSourceTestRun(t, 2, "synthetic-source"),
	}
	for _, input := range inputs {
		legacy := *input
		legacy.SourceOperationKey = ""
		_, created, err := s.CreateRemediationRun(t.Context(), &legacy)
		require.NoError(t, err)
		require.True(t, created)
	}
	_, err := s.db.ExecContext(t.Context(), `DROP TABLE remediation_source_claims`)
	require.NoError(t, err)
	_, err = s.db.ExecContext(t.Context(), `CREATE TABLE remediation_source_claims (
		namespace TEXT NOT NULL, source_key TEXT NOT NULL, run_id TEXT NOT NULL, PRIMARY KEY(namespace,source_key))`)
	require.NoError(t, err)
	now := remediationTestTime().Add(time.Hour)
	first := claimRemediationTestRun(t, s, "tenant", "worker-one", now)
	first, err = s.UpdateRemediationRun(t.Context(), first.Namespace, first.ID, first.ClaimOwner, first.ClaimEpoch,
		first.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseCancelling, Reason: store.RemediationReasonCleanupQuarantined}, now)
	require.NoError(t, err)
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	require.NoError(t, s.InitializeRemediationStore(t.Context()), "backfill must be restart-safe")
	var reservations int
	require.NoError(t, s.db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM remediation_source_claims WHERE namespace=? AND source_key=?`, "tenant", inputs[0].SourceOperationKey).Scan(&reservations))
	require.Equal(t, 2, reservations, "ambiguous duplicates must each retain their source reservation")
	for _, input := range inputs {
		replay, created, err := s.CreateRemediationRun(t.Context(), input)
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, input.ID, replay.ID)
		require.Equal(t, input.RequestJSON, replay.RequestJSON)
	}
	replacement := frozenSourceTestRun(t, 3, "synthetic-source")
	_, _, err = s.CreateRemediationRun(t.Context(), replacement)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = s.UpdateRemediationRun(t.Context(), first.Namespace, first.ID, first.ClaimOwner, first.ClaimEpoch,
		first.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseFailed}, now)
	require.NoError(t, err)
	_, _, err = s.CreateRemediationRun(t.Context(), replacement)
	require.ErrorIs(t, err, store.ErrConflict, "settling one duplicate must not release another active effect")
	second := claimRemediationTestRun(t, s, "tenant", "worker-two", now)
	_, err = s.UpdateRemediationRun(t.Context(), second.Namespace, second.ID, second.ClaimOwner, second.ClaimEpoch,
		second.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseNeedsInput}, now)
	require.NoError(t, err)
	_, created, err := s.CreateRemediationRun(t.Context(), replacement)
	require.NoError(t, err)
	require.True(t, created)
}

func TestRemediationSourceMigrationFallsBackToDigestModeAndPatch(t *testing.T) {
	s := newRemediationTestStore(t)
	input := frozenSourceTestRun(t, 1, "")
	legacy := *input
	legacy.SourceOperationKey = ""
	_, _, err := s.CreateRemediationRun(t.Context(), &legacy)
	require.NoError(t, err)
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	next := frozenSourceTestRun(t, 2, "")
	_, _, err = s.CreateRemediationRun(t.Context(), next)
	require.ErrorIs(t, err, store.ErrConflict)
	next.SourceOperationKey, err = store.RemediationSourceOperationKey("approved", "", "", next.InputDigest, next.Mode, "different synthetic patch")
	require.NoError(t, err)
	next.RequestJSON = json.RawMessage(`{"policy":"approved","mode":"verify","patch":"different synthetic patch","report":{}}`)
	_, created, err := s.CreateRemediationRun(t.Context(), next)
	require.NoError(t, err)
	require.True(t, created)
}

func TestRemediationUnknownLegacyInputConservativelyBlocksNewSources(t *testing.T) {
	s := newRemediationTestStore(t)
	unknown := remediationTestRun("tenant", 1)
	_, _, err := s.CreateRemediationRun(t.Context(), unknown)
	require.NoError(t, err)
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	next := frozenSourceTestRun(t, 2, "a-different-source")
	_, _, err = s.CreateRemediationRun(t.Context(), next)
	require.ErrorIs(t, err, store.ErrConflict)
	_, created, err := s.CreateRemediationRun(t.Context(), unknown)
	require.NoError(t, err)
	require.False(t, created)
	now := remediationTestTime().Add(time.Hour)
	claim := claimRemediationTestRun(t, s, "tenant", "worker", now)
	_, err = s.UpdateRemediationRun(t.Context(), claim.Namespace, claim.ID, claim.ClaimOwner, claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseNeedsAdapter}, now)
	require.NoError(t, err)
	_, created, err = s.CreateRemediationRun(t.Context(), next)
	require.NoError(t, err)
	require.True(t, created)
}
