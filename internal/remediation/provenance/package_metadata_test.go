package provenance

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDalecPreservesPackageMetadataAndLiteralContextIncludes(t *testing.T) {
	input := fixture(t)
	input.replace(t, "    path: patches", "    path: patches\n    includes: [0001-vendor.patch, 0002-vendor.patch]")
	input.replace(t, "x-build-extensions:\n", "changelog:\n  - date: \"2026-09-01\"\n    author: Synthetic maintainer\n    changes: [Preserve downstream build inputs]\ntests:\n  - name: binary-layout\n    files:\n      /usr/bin/engine:\n        permissions: 0755\nx-build-extensions:\n  strip-tag-prefix: v\n")
	input.replace(t, "example.invalid/module=example.invalid/module@v1.9.1", "example.invalid/module => example.invalid/module@v1.9.1")
	original := bytes.Clone(input.spec)
	baseline := input.parse(t)
	require.Equal(t, original, input.spec)
	require.Contains(t, baseline.ModuleReplacements, "example.invalid/module => example.invalid/module@v1.9.1")
	require.NoError(t, Compare(baseline, baseline))

	// A separate literal include directory can admit an additional patch while
	// preserving the complete approved filter definition.
	candidate := input
	candidate.spec = bytes.Clone(input.spec)
	candidate.files = make(map[string][]byte)
	for name, raw := range input.files {
		candidate.files[name] = bytes.Clone(raw)
	}
	candidate.replace(t, "includes: [0001-vendor.patch, 0002-vendor.patch]", "includes: [0001-vendor.patch]")
	_, err := ParseDalec(candidate.spec, candidate.files, candidate.metadata)
	require.Error(t, err, "a filter may not silently exclude an approved patch")
	for _, change := range []struct{ from, to string }{
		{"permissions: 0755", "permissions: 0700"},
		{"strip-tag-prefix: v", "strip-tag-prefix: release"},
		{"Synthetic maintainer", "Another maintainer"},
		{"includes: [0001-vendor.patch, 0002-vendor.patch]", "includes: [0002-vendor.patch, 0001-vendor.patch]"},
	} {
		variant := fixture(t)
		variant.spec = bytes.Clone(input.spec)
		variant.files = make(map[string][]byte)
		for name, raw := range input.files {
			variant.files[name] = bytes.Clone(raw)
		}
		variant.replace(t, change.from, change.to)
		changed := variant.parse(t)
		require.Error(t, Compare(baseline, changed), "package metadata and context filters are frozen inputs")
	}
}

func TestDalecRejectsUnsupportedPackageMetadataAndFilters(t *testing.T) {
	for _, declaration := range []string{
		"tests:\n  - name: execution\n    steps:\n      - command: true\n",
		"tests:\n  - name: bad-path\n    files:\n      /tmp/../outside:\n        permissions: 0755\n",
		"tests:\n  - name: bad-mode\n    files:\n      /usr/bin/engine:\n        permissions: 017777\n",
		"changelog:\n  - date: not-a-date\n    author: Synthetic\n    changes: [change]\n",
	} {
		input := fixture(t)
		input.replace(t, "x-build-extensions:\n", declaration+"x-build-extensions:\n")
		requireParseError(t, input)
	}
	for _, filter := range []string{"../escape", "*", "patches/**", "/absolute", ".git"} {
		input := fixture(t)
		input.replace(t, "    path: patches", "    path: patches\n    includes: [\""+filter+"\"]")
		requireParseError(t, input)
	}
	input := fixture(t)
	input.replace(t, "  engine:\n    git:", "  engine:\n    includes: [cmd]\n    git:")
	requireParseError(t, input)
}

func TestDalecModuleReplaceArrowSyntaxRemainsVersionPinned(t *testing.T) {
	for _, value := range []string{
		"example.invalid/module => example.invalid/fork@v1.2.3",
		"example.invalid/module@v1.0.0 => example.invalid/fork@v2.0.0+incompatible",
		" example.invalid/module  =>  example.invalid/fork@v1.2.3 ",
	} {
		require.True(t, validModuleReplacement(value))
	}
	for _, value := range []string{
		"example.invalid/module=>example.invalid/fork@v1.2.3",
		"example.invalid/module => ../local",
		"example.invalid/module => example.invalid/fork",
		"example.invalid/module => example.invalid/fork@latest",
		"example.invalid/module => example.invalid/fork@v1.2.3 extra",
		"example.invalid/module => example.invalid/fork@v1.2.3 => extra",
	} {
		require.False(t, validModuleReplacement(value), "unsupported replacement shape")
	}
	require.False(t, validModuleReplacement(strings.Repeat("x", maxValueSize+1)))
}
