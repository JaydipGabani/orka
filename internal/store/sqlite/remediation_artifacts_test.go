package sqlite

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orka-agents/orka/internal/store"
)

func TestRemediationArtifactReceiptReplayAndIsolation(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	data := []byte("synthetic evidence")
	artifact, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"report.txt", "text/plain; charset=utf-8", data, now)
	require.NoError(t, err)
	digest := sha256.Sum256(data)
	require.Equal(t, "sha256:"+hex.EncodeToString(digest[:]), artifact.Digest)
	require.EqualValues(t, len(data), artifact.Size)
	require.Equal(t, now, artifact.CreatedAt)
	replayed, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		artifact.Name, artifact.MediaType, data, now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, artifact, replayed)
	_, err = s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		artifact.Name, "application/octet-stream", data, now)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		artifact.Name, artifact.MediaType, []byte("different synthetic evidence"), now)
	require.ErrorIs(t, err, store.ErrConflict)

	metadata, stored, err := s.GetRemediationArtifact(t.Context(), run.Namespace, run.ID, artifact.Name)
	require.NoError(t, err)
	require.Equal(t, artifact, metadata)
	require.Equal(t, data, stored)
	stored[0] = 'X'
	_, again, err := s.GetRemediationArtifact(t.Context(), run.Namespace, run.ID, artifact.Name)
	require.NoError(t, err)
	require.Equal(t, data, again)
	artifacts, err := s.ListRemediationArtifacts(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, []store.RemediationArtifact{*artifact}, artifacts)
	_, _, err = s.GetRemediationArtifact(t.Context(), "tenant-b", run.ID, artifact.Name)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.ListRemediationArtifacts(t.Context(), "tenant-b", run.ID)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.PutRemediationArtifact(t.Context(), "tenant-b", run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		artifact.Name, artifact.MediaType, data, now)
	require.ErrorIs(t, err, store.ErrNotFound)

	empty, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"empty.txt", "text/plain", nil, now)
	require.NoError(t, err)
	require.Zero(t, empty.Size)
	emptyReplay, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		empty.Name, empty.MediaType, []byte{}, now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, empty, emptyReplay)
}

func TestRemediationArtifactRequiresActiveClaim(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	_, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, "worker", 1,
		"report.txt", "text/plain", []byte("synthetic"), now)
	require.ErrorIs(t, err, store.ErrConflict)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	_, err = s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, "other", claim.ClaimEpoch,
		"report.txt", "text/plain", []byte("synthetic"), now)
	require.ErrorIs(t, err, store.ErrConflict)
	_, err = s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch+1,
		"report.txt", "text/plain", []byte("synthetic"), now)
	require.ErrorIs(t, err, store.ErrConflict)
	artifacts, err := s.ListRemediationArtifacts(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Empty(t, artifacts)
}

func TestRemediationArtifactTamperingFailsClosed(t *testing.T) {
	for _, tamper := range []string{"data", "digest"} {
		t.Run(tamper, func(t *testing.T) {
			s := newRemediationTestStore(t)
			run := createRemediationTestRun(t, s, "tenant-a", 1)
			now := remediationTestTime().Add(time.Minute)
			claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
			data := []byte("synthetic evidence")
			artifact, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				"report.txt", "text/plain", data, now)
			require.NoError(t, err)
			if tamper == "data" {
				_, err = s.db.ExecContext(t.Context(), `UPDATE remediation_artifacts SET data = ?
					WHERE namespace = ? AND run_id = ? AND name = ?`,
					bytes.Repeat([]byte("x"), len(data)), run.Namespace, run.ID, artifact.Name)
			} else {
				_, err = s.db.ExecContext(t.Context(), `UPDATE remediation_artifacts SET digest = ?
					WHERE namespace = ? AND run_id = ? AND name = ?`,
					remediationArtifactDigest([]byte("other synthetic data")), run.Namespace, run.ID, artifact.Name)
			}
			require.NoError(t, err)
			got, content, err := s.GetRemediationArtifact(t.Context(), run.Namespace, run.ID, artifact.Name)
			require.ErrorIs(t, err, store.ErrRemediationIntegrity)
			require.Nil(t, got)
			require.Nil(t, content)
			_, err = s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				artifact.Name, artifact.MediaType, data, now)
			require.ErrorIs(t, err, store.ErrRemediationIntegrity)
		})
	}
}

func TestRemediationArtifactCountQuotaAndReplay(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	for index := range store.RemediationMaxArtifacts {
		_, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
			fmt.Sprintf("report-%03d.txt", index), "text/plain", []byte("synthetic"), now)
		require.NoError(t, err)
	}
	_, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"over-quota.txt", "text/plain", nil, now)
	require.ErrorIs(t, err, store.ErrCapacity)
	_, err = s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"report-000.txt", "text/plain", []byte("synthetic"), now.Add(time.Second))
	require.NoError(t, err)
	artifacts, err := s.ListRemediationArtifacts(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Len(t, artifacts, store.RemediationMaxArtifacts)
	require.Equal(t, "report-000.txt", artifacts[0].Name)
	require.Equal(t, "report-127.txt", artifacts[127].Name)

	otherRun := createRemediationTestRun(t, s, "tenant-a", 2)
	otherClaim := claimRemediationTestRun(t, s, otherRun.Namespace, "other-worker", now)
	require.Equal(t, otherRun.ID, otherClaim.ID)
	_, err = s.PutRemediationArtifact(t.Context(), otherRun.Namespace, otherRun.ID, otherClaim.ClaimOwner, otherClaim.ClaimEpoch,
		"independent.txt", "text/plain", []byte("synthetic"), now)
	require.NoError(t, err)
}

func TestRemediationArtifactByteQuota(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	data := bytes.Repeat([]byte("x"), store.RemediationMaxArtifactBytes)
	for index := range store.RemediationMaxArtifactTotalBytes / store.RemediationMaxArtifactBytes {
		_, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
			fmt.Sprintf("report-%d.bin", index), "application/octet-stream", data, now)
		require.NoError(t, err)
	}
	_, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"over-quota.bin", "application/octet-stream", []byte("x"), now)
	require.ErrorIs(t, err, store.ErrCapacity)
	_, err = s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"report-0.bin", "application/octet-stream", data, now.Add(time.Second))
	require.NoError(t, err)
	_, err = s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"empty.bin", "application/octet-stream", nil, now)
	require.NoError(t, err)
	var stored int64
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT SUM(length(data)) FROM remediation_artifacts
		WHERE namespace = ? AND run_id = ?`, run.Namespace, run.ID).Scan(&stored))
	require.EqualValues(t, store.RemediationMaxArtifactTotalBytes, stored)
}

func TestRemediationConcurrentArtifactQuota(t *testing.T) {
	first, second := newRemediationTestStores(t)
	run := createRemediationTestRun(t, first, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, first, run.Namespace, "worker", now)
	for index := range store.RemediationMaxArtifacts - 1 {
		_, err := first.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
			fmt.Sprintf("report-%03d.txt", index), "text/plain", []byte("synthetic"), now)
		require.NoError(t, err)
	}
	results := make(chan error, 2)
	start := make(chan struct{})
	var writers sync.WaitGroup
	for index, s := range []*Store{first, second} {
		writers.Go(func() {
			<-start
			_, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				fmt.Sprintf("last-%d.txt", index), "text/plain", []byte("synthetic"), now)
			results <- err
		})
	}
	close(start)
	writers.Wait()
	close(results)
	successes, full := 0, 0
	for err := range results {
		if errors.Is(err, store.ErrCapacity) {
			full++
			continue
		}
		require.NoError(t, err)
		successes++
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, full)
	artifacts, err := second.ListRemediationArtifacts(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Len(t, artifacts, store.RemediationMaxArtifacts)
}
