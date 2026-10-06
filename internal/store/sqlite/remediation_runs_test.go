package sqlite

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orka-agents/orka/internal/store"
)

func newRemediationTestStore(t *testing.T) *Store {
	t.Helper()
	s := setupTestStore(t)
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	return s
}

func openRemediationTestStore(t *testing.T, path string) *Store {
	t.Helper()
	db, err := NewDB(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	s := NewStore(db, path)
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	return s
}

func newRemediationTestStores(t *testing.T) (*Store, *Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "remediation.db")
	return openRemediationTestStore(t, path), openRemediationTestStore(t, path)
}

func remediationTestTime() time.Time {
	return time.Date(2026, time.September, 28, 12, 0, 0, 123, time.UTC)
}

func remediationTestRun(namespace string, serial int) *store.RemediationRun {
	return &store.RemediationRun{
		Namespace:    namespace,
		ID:           fmt.Sprintf("rm-%032x", serial),
		RequestID:    fmt.Sprintf("request-%d", serial),
		SubmittedBy:  "test-user",
		Mode:         "verify",
		InputDigest:  "sha256:synthetic-input",
		PolicyDigest: "sha256:synthetic-policy",
		RequestJSON:  json.RawMessage(`{"report":"synthetic fixture"}`),
		PolicyJSON:   json.RawMessage(`{"publication":"disabled"}`),
		CreatedAt:    remediationTestTime().Add(time.Duration(serial) * time.Second),
	}
}

func createRemediationTestRun(t *testing.T, s *Store, namespace string, serial int) *store.RemediationRun {
	t.Helper()
	run, created, err := s.CreateRemediationRun(t.Context(), remediationTestRun(namespace, serial))
	require.NoError(t, err)
	require.True(t, created)
	return run
}

func claimRemediationTestRun(t *testing.T, s *Store, namespace, owner string, now time.Time) *store.RemediationRun {
	t.Helper()
	run, err := s.ClaimNextRemediationRun(t.Context(), namespace, owner, now, time.Minute)
	require.NoError(t, err)
	return run
}

func TestRemediationInitializationIsExplicitAndIdempotent(t *testing.T) {
	s := setupTestStore(t)
	var count int
	require.NoError(t, s.db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'remediation_runs'`).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	require.NoError(t, s.InitializeRemediationStore(t.Context()))
	got, err := s.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, run, got)
	require.Equal(t, 1, s.db.Stats().MaxOpenConnections)
}

func TestRemediationRequestLookupIsNamespaceScoped(t *testing.T) {
	s := newRemediationTestStore(t)
	first := createRemediationTestRun(t, s, "tenant-a", 1)
	second := createRemediationTestRun(t, s, "tenant-b", 1)
	for _, expected := range []*store.RemediationRun{first, second} {
		run, err := s.GetRemediationRunByRequestID(t.Context(), expected.Namespace, expected.RequestID)
		require.NoError(t, err)
		require.Equal(t, expected, run)
	}
	_, err := s.GetRemediationRunByRequestID(t.Context(), "foreign", first.RequestID)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.GetRemediationRunByRequestID(t.Context(), first.Namespace, "missing-request")
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.GetRemediationRunByRequestID(t.Context(), "", first.RequestID)
	require.ErrorIs(t, err, store.ErrValidation)
	_, err = s.GetRemediationRunByRequestID(t.Context(), first.Namespace, "")
	require.ErrorIs(t, err, store.ErrValidation)
}

func TestRemediationRunJSONUsesLowerCamelNames(t *testing.T) {
	content, err := json.Marshal(remediationTestRun("tenant-a", 1))
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(content, &fields))
	for _, name := range []string{"id", "namespace", "requestId", "submittedBy", "policyDigest", "inputDigest",
		"requestJson", "policyJson", "stateJson", "claimEpoch", "claimUntil", "cancelRequested"} {
		require.Contains(t, fields, name)
	}
	for _, name := range []string{"requestID", "requestJSON", "policyJSON", "stateJSON"} {
		require.NotContains(t, fields, name)
	}
}

func TestRemediationNamespaceIsolation(t *testing.T) {
	s := newRemediationTestStore(t)
	now := remediationTestTime().Add(time.Hour)
	first := createRemediationTestRun(t, s, "tenant-a", 1)
	second := createRemediationTestRun(t, s, "tenant-b", 1)
	require.Equal(t, first.ID, second.ID)
	require.Equal(t, first.RequestID, second.RequestID)

	for _, namespace := range []string{first.Namespace, second.Namespace} {
		runs, err := s.ListRemediationRuns(t.Context(), namespace, 100)
		require.NoError(t, err)
		require.Len(t, runs, 1)
		require.Equal(t, namespace, runs[0].Namespace)
	}
	_, err := s.GetRemediationRun(t.Context(), "tenant-c", first.ID)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.ClaimNextRemediationRun(t.Context(), "tenant-c", "worker", now, time.Minute)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.CancelRemediationRun(t.Context(), "tenant-c", first.ID, now)
	require.ErrorIs(t, err, store.ErrNotFound)

	first = claimRemediationTestRun(t, s, first.Namespace, "worker", now)
	_, err = s.PutRemediationArtifact(t.Context(), first.Namespace, first.ID, first.ClaimOwner, first.ClaimEpoch,
		"report.json", "application/json", []byte(`{"fixture":true}`), now)
	require.NoError(t, err)
	_, _, err = s.GetRemediationArtifact(t.Context(), second.Namespace, first.ID, "report.json")
	require.ErrorIs(t, err, store.ErrNotFound)
	artifacts, err := s.ListRemediationArtifacts(t.Context(), second.Namespace, second.ID)
	require.NoError(t, err)
	require.Empty(t, artifacts)

	_, err = s.CancelRemediationRun(t.Context(), first.Namespace, first.ID, now)
	require.NoError(t, err)
	got, err := s.GetRemediationRun(t.Context(), second.Namespace, second.ID)
	require.NoError(t, err)
	require.Equal(t, second, got)

	got.RequestJSON[0] = '['
	again, err := s.GetRemediationRun(t.Context(), second.Namespace, second.ID)
	require.NoError(t, err)
	require.Equal(t, second.RequestJSON, again.RequestJSON)
}

func TestRemediationSubmissionDefaultsAndExactReplay(t *testing.T) {
	s := newRemediationTestStore(t)
	input := remediationTestRun("tenant-a", 1)
	input.Deadline = remediationTestTime().Add(time.Hour)
	run, created, err := s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, store.RemediationPhaseQueued, run.Phase)
	require.EqualValues(t, 1, run.Revision)
	require.Zero(t, run.ClaimEpoch)
	require.Empty(t, run.ClaimOwner)
	require.True(t, run.ClaimUntil.IsZero())
	require.Equal(t, json.RawMessage(`{}`), run.StateJSON)
	require.Equal(t, run.CreatedAt, run.UpdatedAt)
	require.Zero(t, input.Revision)
	require.Nil(t, input.StateJSON)
	require.Empty(t, input.Phase)

	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, input.Namespace, "worker", now)
	updated, err := s.UpdateRemediationRun(t.Context(), input.Namespace, input.ID, "worker", claim.ClaimEpoch,
		claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning, StateJSON: json.RawMessage(`{"step":1}`)}, now)
	require.NoError(t, err)
	retry := *input
	retry.ID = fmt.Sprintf("rm-%032x", 99)
	retry.CreatedAt = retry.CreatedAt.Add(time.Hour)
	retry.Deadline = retry.Deadline.Add(time.Hour)
	retry.StateJSON = json.RawMessage(`{"ignored":"retry state"}`)
	replayed, created, err := s.CreateRemediationRun(t.Context(), &retry)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, updated, replayed)
	replayed, created, err = s.CreateRemediationRun(t.Context(), updated)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, updated, replayed, "execution state is not part of submission idempotency")

	run.RequestJSON[0] = '['
	stored, err := s.GetRemediationRun(t.Context(), input.Namespace, input.ID)
	require.NoError(t, err)
	require.Equal(t, input.RequestJSON, stored.RequestJSON)
}

func TestRemediationSubmissionMismatch(t *testing.T) {
	s := newRemediationTestStore(t)
	input := remediationTestRun("tenant-a", 1)
	_, created, err := s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	require.True(t, created)
	cases := []struct {
		name   string
		mutate func(*store.RemediationRun)
	}{
		{"submitter", func(run *store.RemediationRun) { run.SubmittedBy = "another-user" }},
		{"mode", func(run *store.RemediationRun) { run.Mode = "patch" }},
		{"input digest", func(run *store.RemediationRun) { run.InputDigest = "different-input" }},
		{"request bytes", func(run *store.RemediationRun) { run.RequestJSON = json.RawMessage(`{"report": "synthetic fixture"}`) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			retry := *input
			test.mutate(&retry)
			got, created, err := s.CreateRemediationRun(t.Context(), &retry)
			require.ErrorIs(t, err, store.ErrDuplicateMismatch)
			require.False(t, created)
			require.Nil(t, got)
		})
	}
	collision := *input
	collision.RequestID = "other-request"
	_, created, err = s.CreateRemediationRun(t.Context(), &collision)
	require.ErrorIs(t, err, store.ErrConflict)
	require.False(t, created)
}

func TestRemediationReplayPreservesFrozenPolicyAfterReload(t *testing.T) {
	s := newRemediationTestStore(t)
	input := remediationTestRun("tenant-a", 1)
	original, created, err := s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	require.True(t, created)
	for _, policy := range []json.RawMessage{json.RawMessage(`{"publication":"changed"}`), nil} {
		retry := *input
		retry.PolicyDigest = "sha256:reloaded-policy"
		retry.PolicyJSON = policy
		replayed, created, err := s.CreateRemediationRun(t.Context(), &retry)
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, original, replayed)
		require.Equal(t, input.PolicyDigest, replayed.PolicyDigest)
		require.Equal(t, input.PolicyJSON, replayed.PolicyJSON)
		retry.RequestJSON = json.RawMessage(`{"report":"changed fixture"}`)
		_, _, err = s.CreateRemediationRun(t.Context(), &retry)
		require.ErrorIs(t, err, store.ErrDuplicateMismatch)
	}
}

func TestRemediationConcurrentSubmissionIdempotency(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("mismatch=%t", mismatch), func(t *testing.T) {
			first, second := newRemediationTestStores(t)
			type result struct {
				run     *store.RemediationRun
				created bool
				err     error
			}
			results := make(chan result, 2)
			start := make(chan struct{})
			var submitters sync.WaitGroup
			for index, s := range []*Store{first, second} {
				submitters.Go(func() {
					<-start
					input := remediationTestRun("tenant-a", index+1)
					input.RequestID = "stable-request"
					if mismatch && index == 1 {
						input.SubmittedBy = "other-user"
					}
					run, created, err := s.CreateRemediationRun(t.Context(), input)
					results <- result{run, created, err}
				})
			}
			close(start)
			submitters.Wait()
			close(results)
			createdCount, rejectedCount := 0, 0
			var returnedID string
			for result := range results {
				if result.err != nil {
					require.ErrorIs(t, result.err, store.ErrDuplicateMismatch)
					require.Nil(t, result.run)
					require.False(t, result.created)
					rejectedCount++
					continue
				}
				if result.created {
					createdCount++
				}
				if returnedID != "" {
					require.Equal(t, returnedID, result.run.ID)
				}
				returnedID = result.run.ID
			}
			require.Equal(t, 1, createdCount)
			if mismatch {
				require.Equal(t, 1, rejectedCount)
			} else {
				require.Zero(t, rejectedCount)
			}
			runs, err := second.ListRemediationRuns(t.Context(), "tenant-a", 100)
			require.NoError(t, err)
			require.Len(t, runs, 1)
		})
	}
}

func TestRemediationListingIsBoundedAndOrdered(t *testing.T) {
	s := newRemediationTestStore(t)
	for serial := 1; serial <= 3; serial++ {
		createRemediationTestRun(t, s, "tenant-a", serial)
	}
	runs, err := s.ListRemediationRuns(t.Context(), "tenant-a", 2)
	require.NoError(t, err)
	require.Len(t, runs, 2)
	require.Equal(t, "request-3", runs[0].RequestID)
	require.Equal(t, "request-2", runs[1].RequestID)
	for _, run := range runs {
		require.Nil(t, run.RequestJSON)
		require.Nil(t, run.PolicyJSON)
		require.Nil(t, run.StateJSON)
	}
	runs, err = s.ListRemediationRuns(t.Context(), "unknown", 100)
	require.NoError(t, err)
	require.NotNil(t, runs)
	require.Empty(t, runs)
	for _, limit := range []int{-1, 0, 101} {
		_, err := s.ListRemediationRuns(t.Context(), "tenant-a", limit)
		require.ErrorIs(t, err, store.ErrValidation)
	}
}

func TestRemediationMetadataReadDoesNotReturnBlobs(t *testing.T) {
	s := newRemediationTestStore(t)
	input := remediationTestRun("tenant-a", 1)
	input.RequestJSON = remediationTestJSON(store.RemediationMaxRequestBytes)
	input.StateJSON = remediationTestJSON(store.RemediationMaxStateBytes)
	run, _, err := s.CreateRemediationRun(t.Context(), input)
	require.NoError(t, err)
	metadata, err := s.GetRemediationRunMetadata(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	expected := *run
	expected.RequestJSON, expected.PolicyJSON, expected.StateJSON = nil, nil, nil
	require.Equal(t, &expected, metadata)
	runs, err := s.ListRemediationRuns(t.Context(), run.Namespace, 1)
	require.NoError(t, err)
	require.Equal(t, []store.RemediationRun{expected}, runs)
	_, err = s.GetRemediationRunMetadata(t.Context(), "tenant-b", run.ID)
	require.ErrorIs(t, err, store.ErrNotFound)
	full, err := s.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, run, full)
}

func remediationCapacityInput(serial int) *store.RemediationRun {
	run := remediationTestRun("tenant-a", serial)
	run.SubmittedBy = fmt.Sprintf("submitter-%d", (serial-1)/store.RemediationMaxSubmitterActiveRuns)
	return run
}

func TestRemediationActiveSubmissionCapacity(t *testing.T) {
	s, other := newRemediationTestStores(t)
	for serial := 1; serial < store.RemediationMaxActiveRuns; serial++ {
		_, created, err := s.CreateRemediationRun(t.Context(), remediationCapacityInput(serial))
		require.NoError(t, err)
		require.True(t, created)
	}
	type admission struct {
		created bool
		err     error
	}
	results := make(chan admission, 2)
	start := make(chan struct{})
	var submitters sync.WaitGroup
	for index, candidate := range []*Store{s, other} {
		submitters.Go(func() {
			<-start
			_, created, err := candidate.CreateRemediationRun(t.Context(), remediationCapacityInput(1000+index))
			results <- admission{created, err}
		})
	}
	close(start)
	submitters.Wait()
	close(results)
	newRuns, full := 0, 0
	for result := range results {
		if result.created {
			require.NoError(t, result.err)
			newRuns++
		} else {
			require.ErrorIs(t, result.err, store.ErrCapacity)
			full++
		}
	}
	require.Equal(t, 1, newRuns)
	require.Equal(t, 1, full)
	now := remediationTestTime().Add(time.Hour)
	claimed := claimRemediationTestRun(t, s, "tenant-a", "worker", now)
	_, err := s.UpdateRemediationRun(t.Context(), claimed.Namespace, claimed.ID, claimed.ClaimOwner, claimed.ClaimEpoch,
		claimed.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseNeedsApproval, ApprovalDigest: "sha256:plan"}, now)
	require.NoError(t, err)
	_, created, err := s.CreateRemediationRun(t.Context(), remediationCapacityInput(1002))
	require.ErrorIs(t, err, store.ErrCapacity)
	require.False(t, created)

	replay, created, err := s.CreateRemediationRun(t.Context(), remediationCapacityInput(1))
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, store.RemediationPhaseNeedsApproval, replay.Phase)
	mismatch := remediationCapacityInput(1)
	mismatch.Mode = "different"
	_, _, err = s.CreateRemediationRun(t.Context(), mismatch)
	require.ErrorIs(t, err, store.ErrDuplicateMismatch)
	createRemediationTestRun(t, s, "tenant-b", 1002)

	claimed = claimRemediationTestRun(t, s, "tenant-a", "worker", now)
	_, err = s.UpdateRemediationRun(t.Context(), claimed.Namespace, claimed.ID, claimed.ClaimOwner, claimed.ClaimEpoch,
		claimed.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseSucceeded}, now)
	require.NoError(t, err)
	_, created, err = s.CreateRemediationRun(t.Context(), remediationCapacityInput(1002))
	require.NoError(t, err)
	require.True(t, created)
}

func TestRemediationPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remediation.db")
	s := openRemediationTestStore(t, path)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	artifact, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"report.txt", "text/plain", []byte("synthetic report"), now)
	require.NoError(t, err)
	cancelled, err := s.CancelRemediationRun(t.Context(), run.Namespace, run.ID, now)
	require.NoError(t, err)
	require.NoError(t, s.db.Close())

	reopened := openRemediationTestStore(t, path)
	got, err := reopened.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, cancelled, got)
	metadata, data, err := reopened.GetRemediationArtifact(t.Context(), run.Namespace, run.ID, artifact.Name)
	require.NoError(t, err)
	require.Equal(t, artifact, metadata)
	require.Equal(t, []byte("synthetic report"), data)
	next := claimRemediationTestRun(t, reopened, run.Namespace, "successor", claim.ClaimUntil)
	require.Equal(t, claim.ClaimEpoch+1, next.ClaimEpoch)
	require.True(t, next.CancelRequested)
	require.Equal(t, store.RemediationPhaseCancelling, next.Phase)
}
