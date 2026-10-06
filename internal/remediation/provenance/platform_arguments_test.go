package provenance

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func platformFixture(t *testing.T, platform string) syntheticFixture {
	t.Helper()
	input := fixture(t)
	input.metadata.Platform = platform
	input.replace(t, "args:\n", "args:\n  TARGETARCH: null\n  TARGETOS: ~\n  TARGETPLATFORM:\n")
	input.replace(t, "    CGO_ENABLED: \"0\"", "    CGO_ENABLED: \"0\"\n    GOARCH: \"${TARGETARCH}\"\n    BUILD_OS: \"${TARGETOS}\"\n    TARGET: \"${TARGETPLATFORM}\"")
	input.replace(t, "make -C engine VERSION=${VERSION}", "make -C engine VERSION=${VERSION} ARCH=${TARGETARCH}")
	input.replace(t, "dependencies:\n  build:\n", "dependencies:\n  build:\n    git: null\n    bash: ~\n    protobuf-devel:\n    g++: null\n")
	input.replace(t, "ca-certificates: {}", "ca-certificates: null")
	return input
}

func TestDalecPlatformDeclarationsAndUnconstrainedDependencies(t *testing.T) {
	t.Parallel()
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		t.Run(platform, func(t *testing.T) {
			input := platformFixture(t, platform)
			original := bytes.Clone(input.spec)
			files := maps.Clone(input.files)
			recipe, err := ParseDalec(input.spec, input.files, input.metadata)
			require.NoError(t, err)
			_, arch, _ := strings.Cut(platform, "/")
			require.Equal(t, arch, recipe.Arguments["TARGETARCH"])
			require.Equal(t, "linux", recipe.Arguments["TARGETOS"])
			require.Equal(t, platform, recipe.Arguments["TARGETPLATFORM"])
			require.Equal(t, arch, recipe.BuildEnvironment["GOARCH"])
			require.Equal(t, platform, recipe.BuildEnvironment["TARGET"])
			require.Contains(t, recipe.Missing, MissingDependencyIdentity)
			require.Equal(t, expectedDigest(original), recipe.ContentDigest)
			require.Equal(t, original, input.spec)
			require.Equal(t, files, input.files)
			require.NoError(t, Compare(recipe, recipe))

			root, effective, err := readSpec(input.spec, platform)
			require.NoError(t, err)
			require.Equal(t, arch, effective["TARGETARCH"])
			declaration := mappingValue(mappingValue(root, "args"), "TARGETARCH")
			require.Equal(t, yamlNullTag, declaration.Tag)
			require.Equal(t, "null", declaration.Value)
			packages := mappingValue(mappingValue(root, "dependencies"), "build")
			require.Equal(t, yamlNullTag, mappingValue(packages, "git").Tag)
			require.Equal(t, "null", mappingValue(packages, "git").Value)
			command := mappingValue(mappingValue(root, "build"), "steps").Content[0]
			require.Contains(t, mappingValue(command, "command").Value, "ARCH=${TARGETARCH}")
			var decoded dalecSpec
			require.NoError(t, decodeStrict(root, &decoded))
			for _, name := range []string{"git", "bash", "protobuf-devel", "g++"} {
				require.Contains(t, decoded.Dependencies.Build, name)
				require.Equal(t, dalecConstraint{}, decoded.Dependencies.Build[name])
			}
			require.NoError(t, ValidateDalecBuildArguments(input.spec, platform))
		})
	}
}

func TestDalecPlatformArgumentDefaultsAndOptIn(t *testing.T) {
	t.Parallel()
	for _, value := range []string{`null`, `~`, `""`, `"amd64"`} {
		input := platformFixture(t, "linux/amd64")
		input.replace(t, "TARGETARCH: null", "TARGETARCH: "+value)
		recipe, err := ParseDalec(input.spec, input.files, input.metadata)
		require.NoError(t, err)
		require.Equal(t, "amd64", recipe.Arguments["TARGETARCH"])
	}
	input := fixture(t)
	input.replace(t, "CGO_ENABLED: \"0\"", "GOARCH: \"${TARGETARCH}\"")
	_, err := ParseDalec(input.spec, input.files, input.metadata)
	require.Error(t, err, "frontend platform arguments require explicit declaration")
}

func TestDalecPlatformArgumentsRejectUnknownOrConflictingBindings(t *testing.T) {
	t.Parallel()
	for _, change := range []struct{ name, old, replacement string }{
		{"wrong-arch", "TARGETARCH: null", `TARGETARCH: "arm64"`},
		{"wrong-os", "TARGETOS: ~", `TARGETOS: "windows"`},
		{"wrong-platform", "TARGETPLATFORM:", `TARGETPLATFORM: "linux/arm64"`},
		{"arbitrary-unresolved", "TARGETARCH: null", "UNRESOLVED: null"},
		{"builder-platform", "TARGETARCH: null", "BUILDARCH: amd64"},
		{"variant", "TARGETARCH: null", "TARGETVARIANT: v8"},
		{"recursive", "TARGETARCH: null", `TARGETARCH: "${VERSION}"`},
		{"boolean", "TARGETARCH: null", "TARGETARCH: true"},
	} {
		t.Run(change.name, func(t *testing.T) {
			input := platformFixture(t, "linux/amd64")
			input.replace(t, change.old, change.replacement)
			_, err := ParseDalec(input.spec, input.files, input.metadata)
			require.Error(t, err)
			_, err = InspectPrivateBuildInputs(input.spec, input.files, input.metadata)
			require.Error(t, err)
			require.Error(t, ValidateDalecBuildArguments(input.spec, input.metadata.Platform))
		})
	}
	for _, platform := range []string{"", "linux/x86_64", "linux/arm64/v8", "linux/arm/v7", "unknown"} {
		input := platformFixture(t, platform)
		_, err := ParseDalec(input.spec, input.files, input.metadata)
		require.Error(t, err)
	}
}

func TestDalecNullExceptionsDoNotAdmitCriticalNullsOrUnsafeYAML(t *testing.T) {
	t.Parallel()
	for _, change := range []struct{ name, old, replacement string }{
		{"version", `version: "${VERSION}"`, "version: null"},
		{"revision", `revision: "${REVISION}"`, "revision: null"},
		{"source-url", "url: https://example.invalid/project/engine", "url: null"},
		{"source-commit", `commit: "${COMMIT}"`, "commit: null"},
		{"source-object", "    git:\n", "    git: null\n    rejected:\n"},
		{"build-env", `CGO_ENABLED: "0"`, "CGO_ENABLED: null"},
		{"command", "command: make -C engine VERSION=${VERSION} ARCH=${TARGETARCH}", "command: null"},
		{"step-env", "GOTOOLCHAIN: local", "GOTOOLCHAIN: null"},
		{"constraint-version", `version: ["=1.25.1"]`, "version: null"},
		{"opaque-null", "description: Synthetic downstream component", "description: Synthetic downstream component\nimage: null"},
		{"null-dependency-map", "  build:\n    git: null", "  build: null\n  invalid:\n    git: null"},
		{"credential-env", `CGO_ENABLED: "0"`, `password: "synthetic-value"`},
		{"credential-url", "https://example.invalid/project/engine", "https://user:synthetic@example.invalid/project/engine"},
		{"unsafe-tag", "TARGETARCH: null", "TARGETARCH: !untrusted null"},
		{"invalid-null-value", "TARGETARCH: null", "TARGETARCH: !!null arbitrary"},
		{"duplicate", "TARGETARCH: null", "TARGETARCH: null\n  TARGETARCH: amd64"},
		{"case-duplicate", "TARGETARCH: null", "TARGETARCH: null\n  targetarch: amd64"},
		{"anchor", "TARGETARCH: null", "TARGETARCH: &arch null"},
		{"alias", "TARGETARCH: null", "TARGETARCH: &arch null\n  ALIAS: *arch"},
		{"merge", "args:\n", "args:\n  <<: {TARGETARCH: null}\n"},
	} {
		t.Run(change.name, func(t *testing.T) {
			input := platformFixture(t, "linux/amd64")
			input.replace(t, change.old, change.replacement)
			_, err := ParseDalec(input.spec, input.files, input.metadata)
			require.Error(t, err)
			_, err = InspectPrivateBuildInputs(input.spec, input.files, input.metadata)
			require.Error(t, err)
			require.Error(t, ValidateDalecBuildArguments(input.spec, input.metadata.Platform))
		})
	}
}

func TestDalecNullTagsRemainPartOfCandidateBaseIdentity(t *testing.T) {
	t.Parallel()
	baselineInput := platformFixture(t, "linux/amd64")
	baseline := baselineInput.parse(t)
	candidateInput := platformFixture(t, "linux/amd64")
	patch := []byte("--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-vendor-two\n+fixed\n")
	candidateInput.appendPatch(t, "0003-candidate.patch", patch)
	candidate := candidateInput.parse(t)
	require.Equal(t, baseline.BaseInputsDigest, candidate.BaseInputsDigest)
	require.NotEqual(t, baseline.ContentDigest, candidate.ContentDigest)
	require.True(t, slices.Equal(baseline.OrderedPatches, candidate.OrderedPatches[:len(baseline.OrderedPatches)]))
	require.NoError(t, CompareWithAdditionalPatch(baseline, candidate, expectedDigest(patch)))
	for _, change := range []struct{ old, replacement string }{
		{"TARGETARCH: null", `TARGETARCH: ""`},
		{"git: null", "git: {}"},
	} {
		changed := platformFixture(t, "linux/amd64")
		changed.appendPatch(t, "0003-candidate.patch", patch)
		changed.replace(t, change.old, change.replacement)
		recipe := changed.parse(t)
		require.NotEqual(t, baseline.BaseInputsDigest, recipe.BaseInputsDigest)
		require.Error(t, CompareWithAdditionalPatch(baseline, recipe, expectedDigest(patch)))
	}
	var roundTrip Recipe
	raw, err := json.Marshal(candidate)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &roundTrip))
	require.NoError(t, CompareWithAdditionalPatch(baseline, roundTrip, expectedDigest(patch)))
}

func TestPrivateDalecPlatformInputsRemainBuildOnly(t *testing.T) {
	t.Parallel()
	input := platformFixture(t, "linux/arm64")
	input.files["patches/0001-vendor.patch"] = []byte("--- a/test.go\n+++ b/test.go\n@@ -1 +1 @@\n-old\n+password=synthetic-value\n")
	input.metadata.ExpectedDigests = make(map[string]string)
	for name, raw := range input.files {
		input.metadata.ExpectedDigests[name] = expectedDigest(raw)
	}
	_, err := ParseDalec(input.spec, input.files, input.metadata)
	require.Error(t, err)
	private, err := InspectPrivateBuildInputs(input.spec, input.files, input.metadata)
	require.NoError(t, err)
	require.Len(t, private.BuildOnly, 1)
	require.Equal(t, "arm64", private.Recipe.Arguments["TARGETARCH"])
	require.Equal(t, input.metadata.ExpectedDigests["patches/0001-vendor.patch"], private.BuildOnly[0].Digest)
}
