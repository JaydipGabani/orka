package sqlite

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func TestRemediationIntakeRetentionIsBoundedTerminalOnlyAndNamespaceScoped(t *testing.T) {
	s := newRemediationTestStore(t)
	cipher, err := NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("x", 32)))
	require.NoError(t, err)
	require.NoError(t, s.SetAgentExecutionSnapshotCipher(cipher))
	now := remediationTestTime().Add(60 * 24 * time.Hour)
	cutoff := now.Add(-30 * 24 * time.Hour)
	phases := []string{
		store.RemediationPhaseRunning, store.RemediationPhaseNeedsInput, store.RemediationPhaseNeedsAdapter,
		store.RemediationPhaseSucceeded, store.RemediationPhaseCancelling, store.RemediationPhaseNeedsApproval,
		store.RemediationPhaseFailed,
	}
	inputs := make([]*store.RemediationRun, 0, len(phases))
	for index, phase := range phases {
		input := remediationTestRun("tenant", index+1)
		input.Intake = []byte(`{"title":"synthetic private retention marker"}`)
		input.InputDigest = intakeDigest(input.Intake)
		_, _, err := s.CreateRemediationRun(t.Context(), input)
		require.NoError(t, err)
		reason, approval := "", ""
		if phase == store.RemediationPhaseCancelling {
			reason = store.RemediationReasonCleanupQuarantined
		}
		if phase == store.RemediationPhaseNeedsApproval {
			approval = "sha256:synthetic-approval"
		}
		updated := cutoff.Add(-time.Hour)
		if phase == store.RemediationPhaseSucceeded {
			updated = cutoff.Add(time.Nanosecond)
		}
		_, err = s.db.ExecContext(t.Context(), `UPDATE remediation_runs SET phase=?,reason=?,approval_digest=?,updated_at=?
			WHERE namespace=? AND id=?`, phase, reason, approval, updated.UnixNano(), input.Namespace, input.ID)
		require.NoError(t, err)
		inputs = append(inputs, input)
	}
	// A terminal-looking legacy row with unresolved settlement metadata is not
	// proof that its effects have gone away.
	_, err = s.db.ExecContext(t.Context(), `UPDATE remediation_runs SET cleanup_started_at=?
		WHERE namespace=? AND id=?`, cutoff.Add(-time.Hour).UnixNano(), "tenant", inputs[6].ID)
	require.NoError(t, err)
	foreign := remediationTestRun("foreign", 1)
	foreign.Intake, foreign.InputDigest = inputs[0].Intake, inputs[0].InputDigest
	_, _, err = s.CreateRemediationRun(t.Context(), foreign)
	require.NoError(t, err)
	_, err = s.db.ExecContext(t.Context(), `UPDATE remediation_runs SET phase='Failed',updated_at=? WHERE namespace=?`,
		cutoff.UnixNano(), foreign.Namespace)
	require.NoError(t, err)

	for index := range 2 {
		count, err := s.PruneRemediationIntake(t.Context(), "tenant", cutoff, 1)
		require.NoError(t, err)
		require.EqualValues(t, 1, count, "each transaction must respect its row limit")
		_, err = s.ReadRemediationIntake(t.Context(), "tenant", inputs[index+1].ID)
		require.ErrorIs(t, err, store.ErrNotFound)
	}
	count, err := s.PruneRemediationIntake(t.Context(), "tenant", cutoff, 100)
	require.NoError(t, err)
	require.Zero(t, count)
	for _, input := range []*store.RemediationRun{inputs[0], inputs[3], inputs[4], inputs[5], inputs[6], foreign} {
		raw, err := s.ReadRemediationIntake(t.Context(), input.Namespace, input.ID)
		require.NoError(t, err)
		require.Equal(t, input.Intake, raw)
	}
	counts, err := s.CountRemediationRuns(t.Context(), "tenant")
	require.NoError(t, err)
	require.EqualValues(t, 5, counts.RetainedIntakes)
	wrong, err := NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("y", 32)))
	require.NoError(t, err)
	require.Error(t, s.SetAgentExecutionSnapshotCipher(wrong), "retained active/quarantined/foreign intake still fences key rotation")
	for _, limit := range []int{0, -1, 101} {
		_, err := s.PruneRemediationIntake(t.Context(), "tenant", cutoff, limit)
		require.ErrorIs(t, err, store.ErrValidation)
	}
}

func TestRemediationIntakeKeyRotationAfterTerminalRetention(t *testing.T) {
	s := newRemediationTestStore(t)
	original, err := NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("x", 32)))
	require.NoError(t, err)
	rotated, err := NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("y", 32)))
	require.NoError(t, err)
	require.NoError(t, s.SetAgentExecutionSnapshotCipher(original))
	input := remediationTestRun("tenant", 1)
	input.Intake = []byte(`{"title":"synthetic ciphertext retention marker"}`)
	input.InputDigest = intakeDigest(input.Intake)
	_, _, err = s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	var ciphertext []byte
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT ciphertext FROM remediation_intake_snapshots
		WHERE namespace=? AND run_id=?`, input.Namespace, input.ID).Scan(&ciphertext))
	require.False(t, bytes.Contains(ciphertext, input.Intake))
	require.False(t, bytes.Contains(ciphertext, []byte("synthetic ciphertext retention marker")))
	now := remediationTestTime().Add(time.Hour)
	claim := claimRemediationTestRun(t, s, input.Namespace, "worker", now)
	_, err = s.UpdateRemediationRun(t.Context(), input.Namespace, input.ID, claim.ClaimOwner, claim.ClaimEpoch, claim.Revision,
		store.RemediationUpdate{Phase: store.RemediationPhaseFailed}, now)
	require.NoError(t, err)
	require.Error(t, s.SetAgentExecutionSnapshotCipher(rotated), "terminal status alone must not permit key replacement")
	count, err := s.PruneRemediationIntake(t.Context(), input.Namespace, now.Add(-time.Nanosecond), 100)
	require.NoError(t, err)
	require.Zero(t, count)
	count, err = s.PruneRemediationIntake(t.Context(), input.Namespace, now, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	var retained int
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM remediation_intake_snapshots`).Scan(&retained))
	require.Zero(t, retained, "verify actual SQLite ciphertext retention rather than a metadata-only result")
	require.NoError(t, s.SetAgentExecutionSnapshotCipher(rotated))
	_, err = s.ReadRemediationIntake(t.Context(), input.Namespace, input.ID)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, created, err := s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	require.False(t, created, "an exact replay must not recreate a pruned raw snapshot")
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM remediation_intake_snapshots`).Scan(&retained))
	require.Zero(t, retained)
	next := remediationTestRun("tenant", 2)
	next.Intake, next.InputDigest = input.Intake, input.InputDigest
	_, _, err = s.CreateRemediationRun(t.Context(), next)
	require.NoError(t, err)
	raw, err := s.ReadRemediationIntake(t.Context(), next.Namespace, next.ID)
	require.NoError(t, err)
	require.Equal(t, next.Intake, raw)
	require.Error(t, s.SetAgentExecutionSnapshotCipher(original), "new snapshots must use the rotated key")
}

func TestRemediationIntakeRetentionRequiresVerifiedKey(t *testing.T) {
	s := newRemediationTestStore(t)
	cipher, err := NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("x", 32)))
	require.NoError(t, err)
	require.NoError(t, s.SetAgentExecutionSnapshotCipher(cipher))
	input := remediationTestRun("tenant", 1)
	input.Intake = []byte(`{"title":"synthetic retained report"}`)
	input.InputDigest = intakeDigest(input.Intake)
	_, _, err = s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	_, err = s.db.ExecContext(t.Context(), `UPDATE remediation_runs SET phase='Failed' WHERE namespace=? AND id=?`, input.Namespace, input.ID)
	require.NoError(t, err)
	restarted := NewStore(s.db, "")
	_, err = restarted.PruneRemediationIntake(t.Context(), input.Namespace, remediationTestTime().Add(time.Hour), 100)
	require.ErrorIs(t, err, errSnapshotCipherRequired)
	var retained int
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM remediation_intake_snapshots`).Scan(&retained))
	require.Equal(t, 1, retained)
	_, err = s.db.ExecContext(t.Context(), `UPDATE remediation_intake_snapshots SET nonce=?`, []byte("bad"))
	require.NoError(t, err)
	require.NotPanics(t, func() {
		require.Error(t, restarted.SetAgentExecutionSnapshotCipher(cipher))
		_, err := s.ReadRemediationIntake(t.Context(), input.Namespace, input.ID)
		require.ErrorIs(t, err, store.ErrRemediationIntegrity)
	})
}

func TestRemediationOrphanIntakeStillFencesKeyRotation(t *testing.T) {
	s := newRemediationTestStore(t)
	cipher, err := NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("x", 32)))
	require.NoError(t, err)
	require.NoError(t, s.SetAgentExecutionSnapshotCipher(cipher))
	input := remediationTestRun("tenant", 1)
	input.Intake = []byte(`{"title":"synthetic orphan snapshot"}`)
	input.InputDigest = intakeDigest(input.Intake)
	_, _, err = s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	_, err = s.db.ExecContext(t.Context(), `DELETE FROM remediation_runs WHERE namespace=? AND id=?`, input.Namespace, input.ID)
	require.NoError(t, err)
	count, err := s.PruneRemediationIntake(t.Context(), "tenant", remediationTestTime().Add(365*24*time.Hour), 100)
	require.NoError(t, err)
	require.Zero(t, count, "an absent owning run is not proof of terminal cleanup")
	counts, err := s.CountRemediationRuns(t.Context(), "tenant")
	require.NoError(t, err)
	require.Zero(t, counts.Active)
	require.EqualValues(t, 1, counts.RetainedIntakes)
	require.NoError(t, s.SetAgentExecutionSnapshotCipher(cipher))
	wrong, err := NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("y", 32)))
	require.NoError(t, err)
	require.Error(t, s.SetAgentExecutionSnapshotCipher(wrong))
}
