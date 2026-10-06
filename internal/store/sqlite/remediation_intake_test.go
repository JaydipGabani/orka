package sqlite

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func TestRemediationIntakeIsAtomicEncryptedAndNotAnArtifact(t *testing.T) {
	storage := newRemediationTestStore(t)
	request := remediationTestRun("tenant", 30)
	request.Intake = []byte(`{"title":"private report","privateValue":"synthetic-private-snapshot-marker"}`)
	request.InputDigest = intakeDigest(request.Intake)
	request.SourceOperationKey = intakeDigest([]byte("synthetic-source-operation"))
	_, _, err := storage.CreateRemediationRun(t.Context(), request)
	require.ErrorIs(t, err, errSnapshotCipherRequired)
	_, err = storage.GetRemediationRun(t.Context(), request.Namespace, request.ID)
	require.ErrorIs(t, err, store.ErrNotFound, "missing encryption must not leave runnable work")
	var claims int
	require.NoError(t, storage.db.QueryRow(`SELECT COUNT(*) FROM remediation_source_claims`).Scan(&claims))
	require.Zero(t, claims, "failed intake encryption must not reserve the source")
	key, err := NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("x", 32)))
	require.NoError(t, err)
	require.NoError(t, storage.SetAgentExecutionSnapshotCipher(key))
	run, created, err := storage.CreateRemediationRun(t.Context(), request)
	require.NoError(t, err)
	require.True(t, created)
	require.Empty(t, run.Intake)
	raw, err := storage.ReadRemediationIntake(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, request.Intake, raw)
	var ciphertext []byte
	require.NoError(t, storage.db.QueryRow(`SELECT ciphertext FROM remediation_intake_snapshots WHERE namespace=? AND run_id=?`, run.Namespace, run.ID).Scan(&ciphertext))
	require.False(t, bytes.Contains(ciphertext, []byte("synthetic-private-snapshot-marker")))
	artifacts, err := storage.ListRemediationArtifacts(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Empty(t, artifacts)
	out, err := json.Marshal(run)
	require.NoError(t, err)
	require.NotContains(t, string(out), "synthetic-private-snapshot-marker")
	wrong, err := NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("y", 32)))
	require.NoError(t, err)
	require.Error(t, storage.SetAgentExecutionSnapshotCipher(wrong), "key changes cannot strand existing intake")
	raw, err = storage.ReadRemediationIntake(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, request.Intake, raw)
	_, err = storage.ReadRemediationIntake(t.Context(), "foreign", run.ID)
	require.ErrorIs(t, err, store.ErrNotFound)
}
