//go:build linux

package environment

import (
	"testing"

	"github.com/orka-agents/orka/internal/remediation/disclosure"
	"github.com/stretchr/testify/require"
)

func TestCandidateRecipePreservesBaselineRestrictionsWithoutReclassifyingSafeCode(t *testing.T) {
	for _, line := range []string{"\tSecret: secretName,", "\ttoken = strings.TrimSpace(value)"} {
		fixture := newJobFixture(t, false)
		plan := fixture.plans[0]
		baseline, err := fixture.adapter.recipeSnapshot(BuildRequest{Plan: plan, Role: RebuiltControl})
		require.NoError(t, err)
		patch := []byte("diff --git a/source.go b/source.go\n--- a/source.go\n+++ b/source.go\n@@ -1 +1 @@\n-old\n+" + line + "\n")
		require.NoError(t, disclosure.Check(disclosure.Candidate, patch))
		request := BuildRequest{RunID: "safe-code", OperationID: "candidate-0", Plan: plan, Role: Candidate,
			Patch: patch, PatchDigest: digest(patch)}
		require.NoError(t, validateBuildRequest(request))
		snapshot, err := fixture.adapter.recipeSnapshot(request)
		require.NoError(t, err)
		require.Equal(t, baseline.buildOnly, snapshot.buildOnly)
		require.Len(t, snapshot.built.OrderedPatches, len(baseline.built.OrderedPatches)+1)
		require.Equal(t, digest(patch), snapshot.built.OrderedPatches[len(snapshot.built.OrderedPatches)-1].Digest)
	}
}

func TestCandidateRecipeRejectsCredentialBearingAdditions(t *testing.T) {
	fixture := newJobFixture(t, false)
	for _, content := range []string{
		"+password: fixture-only\n", "+url=https://user:fixture-only@example.invalid\n", "+-----BEGIN PRIVATE KEY-----\n",
	} {
		patch := []byte(content)
		_, err := fixture.adapter.recipeSnapshot(BuildRequest{Plan: fixture.plans[0], Role: Candidate,
			Patch: patch, PatchDigest: digest(patch)})
		require.Error(t, err)
	}
}
