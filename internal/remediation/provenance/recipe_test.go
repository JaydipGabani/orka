package provenance

import (
	"bytes"
	"maps"
	"slices"
	"strings"
	"testing"
)

func candidateFixture(t *testing.T) (syntheticFixture, string) {
	t.Helper()
	candidate := fixture(t)
	additional := []byte("--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-vendor-two\n+candidate-fix\n")
	candidate.appendPatch(t, "0003-candidate.patch", additional)
	return candidate, expectedDigest(additional)
}

func TestCompareOnlyExplicitlyAuthorizedAppend(t *testing.T) {
	t.Parallel()
	baseline := fixture(t).parse(t)
	input, authorized := candidateFixture(t)
	candidate := input.parse(t)
	if err := Compare(baseline, baseline); err != nil {
		t.Fatal(err)
	}
	if err := Compare(baseline, candidate); err == nil {
		t.Fatal("plain comparison authorized an additional patch")
	}
	if err := CompareWithAdditionalPatch(baseline, candidate, authorized); err != nil {
		t.Fatalf("an explicit appended patch was rejected: %v", err)
	}
	if baseline.BaseInputsDigest != candidate.BaseInputsDigest ||
		baseline.ContentDigest == candidate.ContentDigest ||
		!slices.Equal(baseline.ModuleReplacements, candidate.ModuleReplacements) ||
		!maps.Equal(baseline.BuildEnvironment, candidate.BuildEnvironment) {
		t.Fatal("appending a patch changed the base-input contract")
	}
	input.replace(t, "    distro/container:\n      platforms: [linux/amd64, linux/arm64]\n    distro/package:\n      platforms: [linux/amd64]",
		"    distro/package:\n      platforms: [linux/amd64]\n    distro/container:\n      platforms: [linux/amd64, linux/arm64]")
	if err := CompareWithAdditionalPatch(baseline, input.parse(t), authorized); err != nil {
		t.Fatal("unordered target mapping keys changed the canonical inputs")
	}
	for _, wrong := range []string{"", "v1.2.3", "sha256:abc", "sha256:" + strings.Repeat("0", 64)} {
		if err := CompareWithAdditionalPatch(baseline, candidate, wrong); err == nil {
			t.Fatal("missing, abbreviated or incorrect patch authorization was accepted")
		}
	}
	if err := CompareWithAdditionalPatch(baseline, baseline, authorized); err == nil {
		t.Fatal("explicit append comparison accepted no appended patch")
	}
}

func TestComparePreservesEveryVendorPatch(t *testing.T) {
	t.Parallel()
	baseline := fixture(t).parse(t)
	tests := map[string]func(*syntheticFixture){
		"reordered": func(input *syntheticFixture) {
			first := "    - source: vendor-patches\n      path: 0001-vendor.patch\n      strip: 1\n"
			second := "    - source: vendor-patches\n      path: 0002-vendor.patch\n      strip: 0\n"
			input.replace(t, first+second, second+first)
		},
		"modified-bytes": func(input *syntheticFixture) {
			input.files["patches/0001-vendor.patch"] = []byte("changed vendor patch\n")
		},
		"changed-strip": func(input *syntheticFixture) {
			input.replace(t, "path: 0001-vendor.patch\n      strip: 1", "path: 0001-vendor.patch\n      strip: 0")
		},
		"renamed-vendor-file": func(input *syntheticFixture) {
			input.replace(t, "0001-vendor.patch", "renamed-vendor.patch")
			input.files["patches/renamed-vendor.patch"] = input.files["patches/0001-vendor.patch"]
			delete(input.files, "patches/0001-vendor.patch")
		},
		"renamed-vendor-source": func(input *syntheticFixture) {
			input.replace(t, "vendor-patches", "renamed-patches")
		},
		"remapped-context-root": func(input *syntheticFixture) {
			input.replace(t, "    path: patches", "    path: .")
			for _, name := range []string{"0001-vendor.patch", "0002-vendor.patch", "0003-candidate.patch"} {
				input.replace(t, "path: "+name, "path: patches/"+name)
			}
		},
		"removed-vendor-patch": func(input *syntheticFixture) {
			input.replace(t, "    - source: vendor-patches\n      path: 0001-vendor.patch\n      strip: 1\n", "")
			delete(input.files, "patches/0001-vendor.patch")
		},
		"extra-declared-patch": func(input *syntheticFixture) {
			input.appendPatch(t, "0004-unapproved.patch", []byte("unapproved patch\n"))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input, authorized := candidateFixture(t)
			mutate(&input)
			candidate := input.parse(t)
			if err := CompareWithAdditionalPatch(baseline, candidate, authorized); err == nil {
				t.Fatal("comparison accepted a modified vendor series or extra patch")
			}
		})
	}
}

func TestCompareLocksAllBaseInputs(t *testing.T) {
	t.Parallel()
	baseline := fixture(t).parse(t)
	tests := []struct{ name, old, replacement string }{
		{"module", "module@v1.9.1", "module@v2.0.0"},
		{"module-order", "              - example.invalid/module=example.invalid/module@v1.9.1\n              - example.invalid/other@v1.0.0=example.invalid/fork@v2.0.1",
			"              - example.invalid/other@v1.0.0=example.invalid/fork@v2.0.1\n              - example.invalid/module=example.invalid/module@v1.9.1"},
		{"environment", `CGO_ENABLED: "0"`, `CGO_ENABLED: "1"`},
		{"target-environment", "GOOS: linux", "GOOS: freebsd"},
		{"step-environment", "GOTOOLCHAIN: local", "GOTOOLCHAIN: auto"},
		{"dependency", `version: ["=1.25.1"]`, `version: ["=1.26.0"]`},
		{"target-dependency", "ca-certificates: {}", "tzdata: {}"},
		{"command", "make -C engine VERSION=${VERSION}", "make -C engine other"},
		{"frontend", strings.Repeat("f", 64), strings.Repeat("e", 64)},
		{"upstream-repository", "https://example.invalid/project/engine", "https://example.invalid/other/engine"},
		{"upstream-commit", strings.Repeat("a", 40), strings.Repeat("c", 40)},
		{"version", `VERSION: "1.2.3"`, `VERSION: "1.2.4"`},
		{"revision", `REVISION: "2"`, `REVISION: "3"`},
		{"unused-argument", `REVISION: "2"`, "REVISION: \"2\"\n  UNUSED: literal"},
		{"output-configuration", "description: Synthetic downstream component",
			"description: Synthetic downstream component\nimage:\n  labels:\n    component: engine"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, authorized := candidateFixture(t)
			input.replace(t, test.old, test.replacement)
			candidate := input.parse(t)
			if err := CompareWithAdditionalPatch(baseline, candidate, authorized); err == nil {
				t.Fatal("comparison permitted changed base inputs")
			}
		})
	}
}

func TestCompareRejectsChangedMetadataAndInvalidRecords(t *testing.T) {
	t.Parallel()
	baseline := fixture(t).parse(t)
	for name, mutate := range map[string]func(*Recipe){
		"schema-version":      func(recipe *Recipe) { recipe.SchemaVersion = 2 },
		"recipe-commit":       func(recipe *Recipe) { recipe.RecipeCommit = strings.Repeat("c", 64) },
		"recipe-repository":   func(recipe *Recipe) { recipe.RecipeRepository = "private:other/recipes" },
		"recipe-path":         func(recipe *Recipe) { recipe.Path = "different/recipe.yml" },
		"target":              func(recipe *Recipe) { recipe.Target = "distro/package" },
		"platform":            func(recipe *Recipe) { recipe.Platform = "linux/arm64" },
		"missing-base-digest": func(recipe *Recipe) { recipe.BaseInputsDigest = "" },
		"invalid-content":     func(recipe *Recipe) { recipe.ContentDigest = "not-a-digest" },
		"false-verified":      func(recipe *Recipe) { recipe.EvidenceStatus = EvidenceVerified },
		"invalid-evidence":    func(recipe *Recipe) { recipe.EvidenceStatus = "success" },
		"missing-git-input":   func(recipe *Recipe) { recipe.Missing = append(recipe.Missing, MissingUpstreamCommit) },
		"observed-image": func(recipe *Recipe) {
			recipe.ObservedOriginalImage = ImageIdentity{
				Reference: "sha256:" + strings.Repeat("9", 64), Digest: "sha256:" + strings.Repeat("9", 64),
			}
		},
		"control-image": func(recipe *Recipe) {
			recipe.RebuiltControlImage = ImageIdentity{
				Reference: "sha256:" + strings.Repeat("8", 64), Digest: "sha256:" + strings.Repeat("8", 64),
			}
		},
		"forged-image-digest": func(recipe *Recipe) { recipe.Frontend.Digest = "sha256:" + strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			input, authorized := candidateFixture(t)
			candidate := input.parse(t)
			mutate(&candidate)
			if err := CompareWithAdditionalPatch(baseline, candidate, authorized); err == nil {
				t.Fatal("comparison accepted changed identity, unsupported schema or incomplete evidence")
			}
		})
	}
}

func TestCanonicalDigestsTrackBytesNotSemver(t *testing.T) {
	t.Parallel()
	first := fixture(t)
	versionOne := first.parse(t)
	second := fixture(t)
	second.files["patches/0001-vendor.patch"] = bytes.ReplaceAll(
		second.files["patches/0001-vendor.patch"], []byte("vendor-one"), []byte("different-vendor-one"),
	)
	versionTwo := second.parse(t)
	if versionOne.Version != versionTwo.Version || versionOne.UpstreamCommit != versionTwo.UpstreamCommit ||
		versionOne.BaseInputsDigest != versionTwo.BaseInputsDigest ||
		versionOne.OrderedPatches[0].Digest == versionTwo.OrderedPatches[0].Digest {
		t.Fatal("patch byte identity must not be collapsed into version or upstream commit")
	}
	if err := Compare(versionOne, versionTwo); err == nil {
		t.Fatal("comparison treated two different downstream builds as equivalent")
	}
	third := fixture(t)
	third.replace(t, "description: Synthetic downstream component", "description: Synthetic downstream component # inert comment")
	third.replace(t, "    CGO_ENABLED: \"0\"\n    GOFLAGS: \"-trimpath\"", "    GOFLAGS: \"-trimpath\"\n    CGO_ENABLED: \"0\"")
	canonical := third.parse(t)
	if canonical.BaseInputsDigest != versionOne.BaseInputsDigest || canonical.ContentDigest == versionOne.ContentDigest {
		t.Fatal("canonical base hash must ignore comments/map order while content hash preserves raw bytes")
	}
}

func TestCanonicalDigestV1Encoding(t *testing.T) {
	t.Parallel()
	spec := fixtureForFuzz()
	recipe, err := ParseDalec(spec, map[string][]byte{"recipe.yml": spec}, Metadata{Path: "recipe.yml"})
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"domain":"orka.build-provenance.base.v2","spec":{"name":["!!str","synthetic"],` +
		`"revision":["!!str","1"],"sources":{"component":{"git":{"commit":["!!str","` + strings.Repeat("a", 40) +
		`"],"url":["!!str","https://example.invalid/component/repo"]}}},"version":["!!str","1.0.0"]}}`
	if recipe.BaseInputsDigest != expectedDigest([]byte(canonical)) {
		t.Fatal("the public v1 base-input digest encoding changed")
	}
}

func TestParseDalecRequiresAllGitSourcesToBeImmutable(t *testing.T) {
	t.Parallel()
	input := fixture(t)
	input.replace(t, "  vendor-patches:\n",
		"  helper:\n    git:\n      url: https://example.invalid/project/helper\n      commit: \""+
			strings.Repeat("d", 40)+"\"\n  vendor-patches:\n")
	requireParseError(t, input)
	input.metadata.UpstreamSource = "engine"
	complete := input.parse(t)
	if err := Compare(complete, complete); err != nil {
		t.Fatal(err)
	}
	input.replace(t, strings.Repeat("d", 40), "")
	partial := input.parse(t)
	if !slices.Contains(partial.Missing, MissingUpstreamCommit) || partial.EvidenceStatus != EvidencePartial {
		t.Fatal("an unresolved dependency Git source was hidden")
	}
	if err := Compare(partial, partial); err == nil {
		t.Fatal("comparison accepted an unresolved dependency Git source")
	}
}
