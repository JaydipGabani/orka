package buildjob

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func platformRecipe() []byte {
	return []byte(`name: synthetic
args: {TARGETARCH: null, TARGETOS: null, TARGETPLATFORM: null}
dependencies:
  build: {git: null, bash: null, protobuf-devel: null}
build:
  network_mode: none
  env: {GOARCH: "${TARGETARCH}", GOOS: "${TARGETOS}"}
  steps:
    - command: make build
`)
}

func TestBuildJobPlatformDeclarationsRoundTripWithoutRewriting(t *testing.T) {
	t.Parallel()
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		t.Run(platform, func(t *testing.T) {
			f := newFixture(t, func(config *Config) { config.Policies[0].Platform = platform })
			input := f.input
			input.Platform = platform
			input.Files[input.RecipePath] = platformRecipe()
			original := bytes.Clone(input.Files[input.RecipePath])
			require.NoError(t, f.backend.ValidateInput(input))
			frozen, policy, err := f.backend.admit(input)
			require.NoError(t, err)
			data, err := f.backend.bundle(frozen, policy)
			require.NoError(t, err)
			manifest, received, err := unpackBundle(data)
			require.NoError(t, err)
			require.Equal(t, original, received.Files[input.RecipePath])
			require.Equal(t, original, input.Files[input.RecipePath])
			require.Equal(t, platform, received.Platform)
			require.Empty(t, received.Args, "built-in platform values must not become arbitrary build-arg overrides")
			arguments := buildArguments(manifest, received, "/synthetic-worker")
			require.Contains(t, arguments, "platform="+platform)
			for _, argument := range arguments {
				require.False(t, strings.HasPrefix(argument, "build-arg:TARGET"))
			}
		})
	}
}

func TestBuildJobRejectsUnresolvedOrConflictingPlatformDeclarations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, old, replacement string }{
		{"wrong-arch", "TARGETARCH: null", "TARGETARCH: arm64"},
		{"wrong-os", "TARGETOS: null", "TARGETOS: windows"},
		{"wrong-platform", "TARGETPLATFORM: null", "TARGETPLATFORM: linux/arm64"},
		{"arbitrary-null", "TARGETARCH: null", "ARBITRARY: null"},
		{"build-platform", "TARGETARCH: null", "BUILDARCH: amd64"},
		{"null-env", `GOARCH: "${TARGETARCH}"`, "GOARCH: null"},
		{"null-command", "command: make build", "command: null"},
		{"unknown-tag", "TARGETARCH: null", "TARGETARCH: !custom null"},
		{"duplicate", "TARGETARCH: null", "TARGETARCH: null, TARGETARCH: amd64"},
		{"case-duplicate", "TARGETARCH: null", "TARGETARCH: null, targetarch: amd64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.input.Files[f.input.RecipePath] = bytes.Replace(platformRecipe(), []byte(tc.old), []byte(tc.replacement), 1)
			require.Error(t, f.backend.ValidateInput(f.input))
			_, err := CanonicalInputDigest(f.input)
			require.Error(t, err)
			require.Empty(t, f.kube.Actions(), "invalid input must not allocate Kubernetes resources")
		})
	}
	f := newFixture(t)
	f.input.Files[f.input.RecipePath] = platformRecipe()
	f.input.Args = map[string]string{"TARGETARCH": "arm64"}
	require.Error(t, f.backend.ValidateInput(f.input))
}
