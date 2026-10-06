package provenance

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDalecBuildCommandsPreserveRuntimeVariables(t *testing.T) {
	for _, target := range []bool{false, true} {
		t.Run(fmt.Sprintf("target=%t", target), func(t *testing.T) {
			input := platformFixture(t, "linux/amd64")
			command := `flags="$GOFLAGS"; printf '%s' "${VERSION} $flags $TARGETARCH"`
			if target {
				input.replace(t, "    build:\n      env:", "    build:\n      steps:\n        - command: "+fmt.Sprintf("%q", command)+"\n      env:")
			} else {
				input.replace(t, "make -C engine VERSION=${VERSION} ARCH=${TARGETARCH}", fmt.Sprintf("%q", command))
			}
			before := bytes.Clone(input.spec)
			recipe := input.parse(t)
			root, _, err := readSpec(input.spec, input.metadata.Platform)
			require.NoError(t, err)
			build := mappingValue(root, "build")
			if target {
				build = mappingValue(mappingValue(mappingValue(root, "targets"), "distro"), "build")
			}
			step := mappingValue(build, "steps").Content[0]
			require.Equal(t, command, mappingValue(step, "command").Value)
			require.Equal(t, before, input.spec)
			require.Equal(t, "amd64", recipe.BuildEnvironment["GOARCH"])
			require.NoError(t, ValidateDalecBuildArguments(input.spec, input.metadata.Platform))
			input.metadata.ExpectedDigests = make(map[string]string)
			for path, content := range input.files {
				input.metadata.ExpectedDigests[path] = expectedDigest(content)
			}
			classified, err := InspectPrivateBuildInputs(input.spec, input.files, input.metadata)
			require.NoError(t, err)
			require.Equal(t, recipe.BaseInputsDigest, classified.Recipe.BaseInputsDigest)

			input.metadata.ExpectedDigests = nil
			patch := []byte("--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+new\n")
			input.appendPatch(t, "0003-candidate.patch", patch)
			candidate := input.parse(t)
			require.NoError(t, CompareWithAdditionalPatch(recipe, candidate, expectedDigest(patch)))
		})
	}
}

func TestDalecCommandIdentityDoesNotConflateLiteralAndShellExpansion(t *testing.T) {
	input := fixture(t)
	baseline := input.parse(t)
	input.replace(t, "VERSION=${VERSION}", "VERSION=1.2.3")
	literal := input.parse(t)
	require.NotEqual(t, baseline.BaseInputsDigest, literal.BaseInputsDigest)
	require.Error(t, Compare(baseline, literal))
}

func TestDalecBuildCommandExceptionsRemainLocationBounded(t *testing.T) {
	for _, change := range []struct{ old, replacement string }{
		{"commit: \"${COMMIT}\"", "commit: \"$COMMIT\""},
		{`GOFLAGS: "-trimpath"`, `GOFLAGS: "$HOME"`},
		{"GOTOOLCHAIN: local", `GOTOOLCHAIN: "$HOME"`},
		{"description: Synthetic downstream component", "description: Synthetic downstream component\nimage:\n  command: \"printf $HOME\""},
	} {
		input := fixture(t)
		input.replace(t, change.old, change.replacement)
		requireParseError(t, input)
	}
	for _, command := range []string{
		"echo $(unsupported)", "echo `unsupported`", "echo ${ARG:-fallback}",
		"echo ${ARG@P}", "echo ${!ARG}", "eval $ARG",
		"echo $BUILDARCH", "echo ${BUILDPLATFORM}", "echo $TARGETVARIANT",
	} {
		input := fixture(t)
		input.replace(t, "make -C engine VERSION=${VERSION}", command)
		requireParseError(t, input)
		require.Error(t, ValidateDalecBuildArguments(input.spec, input.metadata.Platform))
	}
}

func TestDalecNullDependencySpellingsAreEquivalentConstraints(t *testing.T) {
	for _, name := range []string{"golang", "libsecret-1-dev", "docker-credential-helpers"} {
		for _, spelling := range []string{"", "null", "~"} {
			input := platformFixture(t, "linux/amd64")
			input.replace(t, "    git: null", "    "+name+": "+spelling)
			recipe := input.parse(t)
			require.Contains(t, recipe.Missing, MissingDependencyIdentity)
			require.NoError(t, ValidateDalecBuildArguments(input.spec, input.metadata.Platform))
		}
	}
	input := fixture(t)
	input.replace(t, `CGO_ENABLED: "0"`, `PASSWORD: null`)
	requireParseError(t, input)
}

func TestDalecRuntimeVariableParsingDoesNotExecuteCommands(t *testing.T) {
	input := fixture(t)
	marker := filepath.Join(t.TempDir(), "not-created")
	input.replace(t, "make -C engine VERSION=${VERSION}", `value="$HOME"; touch `+marker)
	input.parse(t)
	require.NoFileExists(t, marker)
	require.True(t, strings.Contains(string(input.spec), "$HOME"))
}
