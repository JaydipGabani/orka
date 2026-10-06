package environment

import (
	"testing"

	"github.com/orka-agents/orka/internal/remediation/disclosure"
	"github.com/stretchr/testify/require"
)

func TestBuildCandidateUsesTheSameDisclosureBoundaryAsReview(t *testing.T) {
	patch := []byte("diff --git a/source.go b/source.go\n--- a/source.go\n+++ b/source.go\n@@ -1 +1 @@\n-old\n+// The secret namespace is not implicitly authorized.\n")
	require.True(t, secretPattern.Match(patch), "the old configuration-oriented regex reproduced the false rejection")
	require.NoError(t, disclosure.Check(disclosure.Candidate, patch))
	request := BuildRequest{RunID: "synthetic-run", OperationID: "candidate-0", Role: Candidate,
		Patch: patch, PatchDigest: digest(patch)}
	require.NoError(t, validateBuildRequest(request))
}

func TestBuildCandidateStillRejectsCredentialBearingBytes(t *testing.T) {
	for _, patch := range [][]byte{
		[]byte("+url=https://user:fixture-only@example.invalid\n"),
		[]byte("+password: fixture-only-value\n"),
		[]byte("+-----BEGIN PRIVATE KEY-----\n"),
	} {
		require.Error(t, disclosure.Check(disclosure.Candidate, patch))
		request := BuildRequest{RunID: "synthetic-run", OperationID: "candidate-0", Role: Candidate,
			Patch: patch, PatchDigest: digest(patch)}
		require.Error(t, validateBuildRequest(request))
	}
}
