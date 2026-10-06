//go:build linux

package environment

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/provenance"
	"github.com/stretchr/testify/require"
)

func platformJobFixture(t *testing.T, platform string) *jobFixture {
	t.Helper()
	f := newJobFixture(t, true)
	repository := &f.config.Repositories[0]
	recipe := &repository.Recipes[0]
	raw, err := os.ReadFile(filepath.Join(repository.RecipeRoot, recipe.Path))
	require.NoError(t, err)
	raw = bytes.Replace(raw, []byte("build:\n"), []byte("args: {TARGETARCH: null, TARGETOS: null, TARGETPLATFORM: null}\nbuild:\n"), 1)
	raw = bytes.Replace(raw, []byte("    BUILD_LANGUAGE: go"), []byte("    BUILD_LANGUAGE: go\n    GOARCH: \"${TARGETARCH}\"\n    GOOS: \"${TARGETOS}\""), 1)
	raw = bytes.Replace(raw, []byte("dependencies:\n  build:\n"), []byte("dependencies:\n  build:\n    git: null\n    bash: null\n    protobuf-devel: null\n"), 1)
	raw = bytes.Replace(raw, []byte("platforms: [linux/amd64]"), []byte("platforms: [linux/amd64, linux/arm64]"), 1)
	require.NoError(t, os.WriteFile(filepath.Join(repository.RecipeRoot, recipe.Path), raw, 0600))
	recipe.Platform, recipe.Files[recipe.Path] = platform, digest(raw)
	f.adapter, err = newAdapter(f.config)
	require.NoError(t, err)
	f.adapter.kube = f.kube
	binding, err := f.adapter.BindRecipe(f.plans[0].Bind.SourceTarget, recipe.ID)
	require.NoError(t, err)
	f.plans[0].Bind = binding
	f.plans[0], err = f.adapter.FreezePlan(f.plans[0])
	require.NoError(t, err)
	return f
}

func TestPlatformArgumentsPreserveCandidateRecipeAndDurableBuild(t *testing.T) {
	t.Parallel()
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		t.Run(platform, func(t *testing.T) {
			f := platformJobFixture(t, platform)
			request := f.request()
			control, err := f.adapter.Build(t.Context(), request)
			require.NoError(t, err)
			original := bytes.Clone(f.lastFiles[request.Plan.Bind.Recipe.Path])
			require.Contains(t, string(original), "TARGETARCH: null")
			require.Contains(t, string(original), "git: null")
			require.Equal(t, platform, control.Baseline.Arguments["TARGETPLATFORM"])
			patch := []byte("diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+fixed\n")
			request.OperationID, request.Role = "candidate", Candidate
			request.Patch, request.PatchDigest = patch, digest(patch)
			candidate, err := f.adapter.Build(t.Context(), request)
			require.NoError(t, err)
			require.NoError(t, provenance.CompareWithAdditionalPatch(control.Baseline, candidate.Built, request.PatchDigest))
			require.Equal(t, control.Baseline.BaseInputsDigest, candidate.Built.BaseInputsDigest)
			require.Equal(t, control.Baseline.Arguments, candidate.Built.Arguments)
			require.Equal(t, "linux", candidate.Built.BuildEnvironment["GOOS"])
			updated := f.lastFiles[request.Plan.Bind.Recipe.Path]
			position := 0
			for _, line := range bytes.SplitAfter(original, []byte("\n")) {
				offset := bytes.Index(updated[position:], line)
				require.NotEqual(t, -1, offset, "the candidate overlay rewrote an existing recipe line")
				position += offset + len(line)
			}
			require.Equal(t, patch, f.lastFiles["orka-candidate-"+request.PatchDigest[len("sha256:"):]+".patch"])
			require.Equal(t, int64(2), f.buildCount.Load())
		})
	}
}

func TestPlatformArgumentConflictFailsBeforeBuildSubmission(t *testing.T) {
	t.Parallel()
	f := platformJobFixture(t, "linux/arm64")
	repository := f.config.Repositories[0]
	recipe := repository.Recipes[0]
	path := filepath.Join(repository.RecipeRoot, recipe.Path)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	raw = bytes.Replace(raw, []byte("TARGETARCH: null"), []byte("TARGETARCH: amd64"), 1)
	require.NoError(t, os.WriteFile(path, raw, 0600))
	recipe.Files[recipe.Path] = digest(raw)
	_, err = readRecipe(repository, recipe)
	require.Error(t, err)
	require.Zero(t, f.buildCount.Load())
}
