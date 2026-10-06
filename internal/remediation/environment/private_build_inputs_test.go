//go:build linux

package environment

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/buildjob"
	"github.com/stretchr/testify/require"
)

func TestBuildOnlyInputAuthorityComesFromImmutableCatalog(t *testing.T) {
	f := newJobFixture(t, true)
	f.config.BuildJobs.RegistrySecretName = "approved-registry"
	repo := &f.config.Repositories[0]
	recipe := &repo.Recipes[0]
	var patchName string
	for name := range recipe.Files {
		if name != recipe.Path {
			patchName = name
			break
		}
	}
	require.NotEmpty(t, patchName)
	raw := []byte("--- a/example.conf\n+++ b/example.conf\n@@ -1 +1 @@\n-old\n+endpoint=https://fixture:nonsecret@example.invalid\n")
	require.NoError(t, os.WriteFile(filepath.Join(repo.RecipeRoot, patchName), raw, 0600))
	recipe.Files = maps.Clone(recipe.Files)
	recipe.Files[patchName] = digest(raw)
	adapter, err := newAdapter(f.config)
	require.NoError(t, err)
	adapter.kube = f.kube
	request := f.request()
	snapshot, err := adapter.recipeSnapshot(request)
	require.NoError(t, err)
	require.Len(t, snapshot.buildOnly, 1)
	input := adapter.jobInput(request, digest([]byte("synthetic-build-identity")), snapshot.files)
	require.Equal(t, map[string]string{patchName: digest(raw)}, input.BuildOnlyInputs)
	backend, err := adapter.jobBackend(input, nil)
	require.NoError(t, err)
	require.NoError(t, backend.ValidateInput(input))

	safeCandidate := request
	safeCandidate.Role = Candidate
	safeCandidate.Patch = []byte("diff --git a/source.go b/source.go\n--- a/source.go\n+++ b/source.go\n@@ -1 +1 @@\n-old\n+\tSecret: secretName,\n")
	safeCandidate.PatchDigest = digest(safeCandidate.Patch)
	withCandidate, err := adapter.recipeSnapshot(safeCandidate)
	require.NoError(t, err)
	require.Equal(t, snapshot.buildOnly, withCandidate.buildOnly, "safe candidate code cannot change private baseline authority")

	tampered := input
	tampered.BuildOnlyInputs = maps.Clone(input.BuildOnlyInputs)
	tampered.BuildOnlyInputs["candidate.patch"] = digest(raw)
	_, err = adapter.jobBackend(tampered, nil)
	require.Error(t, err)
	tampered = input
	tampered.Files = maps.Clone(input.Files)
	tampered.Files[patchName] = append(bytes.Clone(raw), '\n')
	require.Error(t, backend.ValidateInput(tampered))
	_, err = buildjob.CanonicalInputDigest(tampered)
	require.Error(t, err)

	request.Role, request.Patch = Candidate, raw
	request.PatchDigest = digest(raw)
	_, err = adapter.recipeSnapshot(request)
	require.Error(t, err, "candidate screening cannot inherit private baseline permission")
}
