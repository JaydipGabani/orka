package sqlite

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orka-agents/orka/internal/store"
)

func TestRemediationSubmissionInputBounds(t *testing.T) {
	s := newRemediationTestStore(t)
	cases := []struct {
		name   string
		mutate func(*store.RemediationRun)
	}{
		{"empty namespace", func(run *store.RemediationRun) { run.Namespace = "" }},
		{"whitespace namespace", func(run *store.RemediationRun) { run.Namespace = " tenant-a " }},
		{"oversized namespace", func(run *store.RemediationRun) { run.Namespace = strings.Repeat("n", 254) }},
		{"invalid run ID", func(run *store.RemediationRun) { run.ID = "rm-short" }},
		{"empty request ID", func(run *store.RemediationRun) { run.RequestID = "" }},
		{"oversized request ID", func(run *store.RemediationRun) { run.RequestID = strings.Repeat("r", 97) }},
		{"invalid request ID", func(run *store.RemediationRun) { run.RequestID = "REQUEST_ID" }},
		{"empty request label", func(run *store.RemediationRun) { run.RequestID = "a..b" }},
		{"invalid request label", func(run *store.RemediationRun) { run.RequestID = "a.-b" }},
		{"empty submitter", func(run *store.RemediationRun) { run.SubmittedBy = "" }},
		{"empty mode", func(run *store.RemediationRun) { run.Mode = "" }},
		{"empty policy digest", func(run *store.RemediationRun) { run.PolicyDigest = "" }},
		{"empty input digest", func(run *store.RemediationRun) { run.InputDigest = "" }},
		{"bad request JSON", func(run *store.RemediationRun) { run.RequestJSON = json.RawMessage(`{"invalid":`) }},
		{"bad policy JSON", func(run *store.RemediationRun) { run.PolicyJSON = json.RawMessage(`{`) }},
		{"bad state JSON", func(run *store.RemediationRun) { run.StateJSON = json.RawMessage(`{`) }},
		{"oversized request", func(run *store.RemediationRun) {
			run.RequestJSON = remediationTestJSON(store.RemediationMaxRequestBytes + 1)
		}},
		{"oversized policy", func(run *store.RemediationRun) {
			run.PolicyJSON = remediationTestJSON(store.RemediationMaxPolicyBytes + 1)
		}},
		{"oversized state", func(run *store.RemediationRun) {
			run.StateJSON = remediationTestJSON(store.RemediationMaxStateBytes + 1)
		}},
		{"oversized reason", func(run *store.RemediationRun) { run.Reason = strings.Repeat("r", store.RemediationMaxReasonBytes+1) }},
		{"terminal phase", func(run *store.RemediationRun) { run.Phase = store.RemediationPhaseSucceeded }},
		{"revision", func(run *store.RemediationRun) { run.Revision = 2 }},
		{"claim epoch", func(run *store.RemediationRun) { run.ClaimEpoch = 1 }},
		{"claim owner", func(run *store.RemediationRun) { run.ClaimOwner = "worker" }},
		{"claim until", func(run *store.RemediationRun) { run.ClaimUntil = remediationTestTime() }},
		{"cancellation flag", func(run *store.RemediationRun) { run.CancelRequested = true }},
		{"approval digest", func(run *store.RemediationRun) { run.ApprovalDigest = "sha256:plan" }},
		{"approved digest", func(run *store.RemediationRun) { run.ApprovedDigest = "sha256:plan" }},
		{"approved actor", func(run *store.RemediationRun) { run.ApprovedBy = "approver" }},
		{"out of range timestamp", func(run *store.RemediationRun) { run.Deadline = time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := remediationTestRun("tenant-a", 1)
			test.mutate(input)
			run, created, err := s.CreateRemediationRun(t.Context(), input)
			require.ErrorIs(t, err, store.ErrValidation)
			require.Less(t, len(err.Error()), 256)
			require.False(t, created)
			require.Nil(t, run)
		})
	}
	_, _, err := s.CreateRemediationRun(t.Context(), nil)
	require.ErrorIs(t, err, store.ErrValidation)
	runs, err := s.ListRemediationRuns(t.Context(), "tenant-a", 100)
	require.NoError(t, err)
	require.Empty(t, runs)

	atBounds := remediationTestRun("tenant-a", 1)
	atBounds.RequestID = strings.Repeat("r", store.RemediationMaxRequestIDBytes)
	atBounds.RequestJSON = remediationTestJSON(store.RemediationMaxRequestBytes)
	atBounds.PolicyJSON = remediationTestJSON(store.RemediationMaxPolicyBytes)
	atBounds.StateJSON = remediationTestJSON(store.RemediationMaxStateBytes)
	atBounds.Reason = strings.Repeat("r", store.RemediationMaxReasonBytes)
	stored, created, err := s.CreateRemediationRun(t.Context(), atBounds)
	require.NoError(t, err)
	require.True(t, created)
	require.Len(t, stored.RequestJSON, store.RemediationMaxRequestBytes)
	require.Len(t, stored.PolicyJSON, store.RemediationMaxPolicyBytes)
	require.Len(t, stored.StateJSON, store.RemediationMaxStateBytes)
}

func remediationTestJSON(size int) json.RawMessage {
	data := bytes.Repeat([]byte("x"), size)
	data[0], data[len(data)-1] = '"', '"'
	return data
}

func TestRemediationEveryOperationRejectsEmptyNamespace(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	operations := []struct {
		name string
		call func() error
	}{
		{"get", func() error { _, err := s.GetRemediationRun(t.Context(), "", run.ID); return err }},
		{"get metadata", func() error { _, err := s.GetRemediationRunMetadata(t.Context(), "", run.ID); return err }},
		{"list", func() error { _, err := s.ListRemediationRuns(t.Context(), "", 100); return err }},
		{"claim", func() error {
			_, err := s.ClaimNextRemediationRun(t.Context(), "", "worker", now, time.Minute)
			return err
		}},
		{"renew", func() error {
			return s.RenewRemediationClaim(t.Context(), "", run.ID, claim.ClaimOwner, claim.ClaimEpoch, now, time.Minute)
		}},
		{"update", func() error {
			_, err := s.UpdateRemediationRun(t.Context(), "", run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				claim.Revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning}, now)
			return err
		}},
		{"cancel", func() error { _, err := s.CancelRemediationRun(t.Context(), "", run.ID, now); return err }},
		{"approve", func() error {
			_, err := s.ApproveRemediationRun(t.Context(), "", run.ID, "sha256:plan", "approver", now)
			return err
		}},
		{"put artifact", func() error {
			_, err := s.PutRemediationArtifact(t.Context(), "", run.ID, claim.ClaimOwner, claim.ClaimEpoch,
				"report.txt", "text/plain", nil, now)
			return err
		}},
		{"get artifact", func() error {
			_, _, err := s.GetRemediationArtifact(t.Context(), "", run.ID, "report.txt")
			return err
		}},
		{"list artifacts", func() error { _, err := s.ListRemediationArtifacts(t.Context(), "", run.ID); return err }},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) { require.ErrorIs(t, operation.call(), store.ErrValidation) })
	}
}

func TestRemediationClaimAndUpdateValidation(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	for _, lease := range []time.Duration{-time.Second, 0, store.RemediationMaxClaimLease + time.Nanosecond} {
		_, err := s.ClaimNextRemediationRun(t.Context(), run.Namespace, "worker", now, lease)
		require.ErrorIs(t, err, store.ErrValidation)
	}
	for _, owner := range []string{"", " ", strings.Repeat("w", 257), "worker\ninjection"} {
		_, err := s.ClaimNextRemediationRun(t.Context(), run.Namespace, owner, now, time.Minute)
		require.ErrorIs(t, err, store.ErrValidation)
		require.NotContains(t, err.Error(), owner+"injection")
	}
	_, err := s.ClaimNextRemediationRun(t.Context(), run.Namespace, "worker", time.Time{}, time.Minute)
	require.ErrorIs(t, err, store.ErrValidation)
	claim, err := s.ClaimNextRemediationRun(t.Context(), run.Namespace, "worker", now, store.RemediationMaxClaimLease)
	require.NoError(t, err)
	for _, lease := range []time.Duration{-time.Second, 0, store.RemediationMaxClaimLease + time.Nanosecond} {
		err := s.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch, now, lease)
		require.ErrorIs(t, err, store.ErrValidation)
	}
	for _, epoch := range []uint64{0, math.MaxUint64} {
		err := s.RenewRemediationClaim(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, epoch, now, time.Minute)
		require.ErrorIs(t, err, store.ErrValidation)
	}
	updates := []store.RemediationUpdate{
		{Phase: "unrecognized"},
		{Phase: store.RemediationPhaseRunning, StateJSON: json.RawMessage(`{`)},
		{Phase: store.RemediationPhaseRunning, StateJSON: remediationTestJSON(store.RemediationMaxStateBytes + 1)},
		{Phase: store.RemediationPhaseRunning, ApprovalDigest: "sha256:unexpected"},
		{Phase: store.RemediationPhaseNeedsApproval},
		{Phase: store.RemediationPhaseRunning, Reason: strings.Repeat("r", store.RemediationMaxReasonBytes+1)},
	}
	for _, update := range updates {
		_, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch, claim.Revision, update, now)
		require.ErrorIs(t, err, store.ErrValidation)
	}
	for _, revision := range []uint64{0, math.MaxUint64} {
		_, err := s.UpdateRemediationRun(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
			revision, store.RemediationUpdate{Phase: store.RemediationPhaseRunning}, now)
		require.ErrorIs(t, err, store.ErrValidation)
	}
	got, err := s.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, claim, got)
}

func TestRemediationArtifactBoundsAndSafeErrors(t *testing.T) {
	s := newRemediationTestStore(t)
	run := createRemediationTestRun(t, s, "tenant-a", 1)
	now := remediationTestTime().Add(time.Minute)
	claim := claimRemediationTestRun(t, s, run.Namespace, "worker", now)
	for _, name := range []string{"", "../report", "a/b", "report\ninjection", strings.Repeat("r", 257)} {
		_, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
			name, "text/plain", nil, now)
		require.ErrorIs(t, err, store.ErrValidation)
		require.Less(t, len(err.Error()), 256)
	}
	for _, mediaType := range []string{"", "text/plain\r\nX-Fixture: marker", strings.Repeat("m", 257)} {
		_, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
			"report.txt", mediaType, nil, now)
		require.ErrorIs(t, err, store.ErrValidation)
		require.NotContains(t, err.Error(), "X-Fixture")
	}
	_, err := s.PutRemediationArtifact(t.Context(), run.Namespace, run.ID, claim.ClaimOwner, claim.ClaimEpoch,
		"report.txt", "text/plain", bytes.Repeat([]byte("x"), store.RemediationMaxArtifactBytes+1), now)
	require.ErrorIs(t, err, store.ErrValidation)
	artifacts, err := s.ListRemediationArtifacts(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Empty(t, artifacts)
}
