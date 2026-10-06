package provenance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type syntheticFixture struct {
	spec     []byte
	files    map[string][]byte
	metadata Metadata
}

func fixture(t *testing.T) syntheticFixture {
	t.Helper()
	spec := fmt.Sprintf(`# syntax=registry.example.invalid/build/frontend:1@sha256:%s
name: engine
description: Synthetic downstream component
version: "${VERSION}"
revision: "${REVISION}"
args:
  COMMIT: "%s"
  VERSION: "1.2.3"
  REVISION: "2"
sources:
  engine:
    git:
      url: https://example.invalid/project/engine
      commit: "${COMMIT}"
    generate:
      - gomod:
          paths: ["."]
          edits:
            replace:
              - example.invalid/module=example.invalid/module@v1.9.1
              - example.invalid/other@v1.0.0=example.invalid/fork@v2.0.1
  vendor-patches:
    context: {name: context}
    path: patches
patches:
  engine:
    - source: vendor-patches
      path: 0001-vendor.patch
      strip: 1
    - source: vendor-patches
      path: 0002-vendor.patch
      strip: 0
build:
  env:
    CGO_ENABLED: "0"
    GOFLAGS: "-trimpath"
  steps:
    - command: make -C engine VERSION=${VERSION}
      env:
        GOTOOLCHAIN: local
dependencies:
  build:
    go-toolchain:
      version: ["=1.25.1"]
targets:
  distro:
    build:
      env:
        GOOS: linux
    dependencies:
      runtime:
        ca-certificates: {}
x-build-extensions:
  build-targets:
    distro/container:
      platforms: [linux/amd64, linux/arm64]
    distro/package:
      platforms: [linux/amd64]
`, strings.Repeat("f", 64), strings.Repeat("a", 40))
	metadata := Metadata{
		RecipeRepository: "private:synthetic/recipes", RecipeCommit: strings.Repeat("b", 64),
		Path: "packaging/engine.yml", Target: "distro/container", Platform: "linux/amd64",
		ObservedOriginalImage: "registry.example.invalid/engine:1.2.3@sha256:" + strings.Repeat("1", 64),
		RebuiltControlImage:   "registry.example.invalid/control@sha256:" + strings.Repeat("2", 64),
	}
	return syntheticFixture{
		spec: []byte(spec), metadata: metadata,
		files: map[string][]byte{
			metadata.Path:               []byte(spec),
			"patches/0001-vendor.patch": []byte("--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-original\n+vendor-one\n"),
			"patches/0002-vendor.patch": []byte("--- main.go\n+++ main.go\n@@ -1 +1 @@\n-vendor-one\n+vendor-two\n"),
		},
	}
}

func (fixture *syntheticFixture) replace(t *testing.T, old, replacement string) {
	t.Helper()
	if !bytes.Contains(fixture.spec, []byte(old)) {
		t.Fatal("synthetic fixture replacement did not match")
	}
	fixture.spec = bytes.ReplaceAll(fixture.spec, []byte(old), []byte(replacement))
	fixture.files[fixture.metadata.Path] = bytes.Clone(fixture.spec)
}

func (fixture *syntheticFixture) appendPatch(t *testing.T, name string, content []byte) {
	t.Helper()
	fixture.replace(t, "\nbuild:\n", "\n    - source: vendor-patches\n      path: "+name+"\n      strip: 1\nbuild:\n")
	fixture.files["patches/"+name] = bytes.Clone(content)
}

func (fixture syntheticFixture) parse(t *testing.T) Recipe {
	t.Helper()
	recipe, err := ParseDalec(fixture.spec, fixture.files, fixture.metadata)
	if err != nil {
		t.Fatalf("synthetic recipe parse failed: %v", err)
	}
	return recipe
}

func expectedDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestParseDalecPreservesDownstreamInputs(t *testing.T) {
	t.Parallel()
	input := fixture(t)
	recipe := input.parse(t)
	if recipe.SchemaVersion != SchemaVersion || recipe.RecipeRepository != input.metadata.RecipeRepository ||
		recipe.RecipeCommit != input.metadata.RecipeCommit || recipe.Path != input.metadata.Path ||
		recipe.ContentDigest != expectedDigest(input.spec) || recipe.BaseInputsDigest == recipe.ContentDigest {
		t.Fatal("recipe acquisition identity or byte digest changed")
	}
	if recipe.UpstreamSource != "engine" || recipe.UpstreamRepoURL != "https://example.invalid/project/engine" ||
		recipe.UpstreamCommit != strings.Repeat("a", 40) || recipe.Version != "1.2.3" || recipe.Revision != "2" ||
		recipe.Arguments["COMMIT"] != recipe.UpstreamCommit || recipe.Arguments["VERSION"] != recipe.Version ||
		recipe.Arguments["REVISION"] != recipe.Revision {
		t.Fatal("upstream identity and version/revision arguments were not preserved")
	}
	wantPatches := []Patch{
		{
			Path: "patches/0001-vendor.patch", Digest: expectedDigest(input.files["patches/0001-vendor.patch"]),
			InputDigest: expectedDigest([]byte(`{"domain":"orka.build-provenance.patch-input.v1","sourceName":"vendor-patches","kind":"context","contextName":"context","sourcePath":"patches","patchPath":"0001-vendor.patch"}`)),
			Source:      "engine", Strip: 1,
		},
		{
			Path: "patches/0002-vendor.patch", Digest: expectedDigest(input.files["patches/0002-vendor.patch"]),
			InputDigest: expectedDigest([]byte(`{"domain":"orka.build-provenance.patch-input.v1","sourceName":"vendor-patches","kind":"context","contextName":"context","sourcePath":"patches","patchPath":"0002-vendor.patch"}`)),
			Source:      "engine", Strip: 0,
		},
	}
	if !slices.Equal(recipe.OrderedPatches, wantPatches) {
		t.Fatal("vendor patch ordering, digests, paths or application options changed")
	}
	if !slices.Equal(recipe.ModuleReplacements, []string{
		"example.invalid/module=example.invalid/module@v1.9.1",
		"example.invalid/other@v1.0.0=example.invalid/fork@v2.0.1",
	}) || !maps.Equal(recipe.BuildEnvironment, map[string]string{
		"CGO_ENABLED": "0", "GOFLAGS": "-trimpath", "GOOS": "linux",
	}) {
		t.Fatal("downstream module replacements or selected build environment were lost")
	}
	if recipe.Target != "distro/container" || recipe.Platform != "linux/amd64" ||
		len(recipe.BuildTargets) != 2 || recipe.Frontend.Digest != "sha256:"+strings.Repeat("f", 64) {
		t.Fatal("explicit target/platform or immutable frontend was lost")
	}
	if recipe.EvidenceStatus != EvidencePartial || !slices.Equal(recipe.Missing, []string{
		MissingRecipeMapping, MissingOriginalBinding, MissingControlBinding, MissingAcquisition,
		MissingDependencyIdentity, MissingSourceAttestation, MissingWorkerDigest,
	}) {
		t.Fatal("parsing must retain external evidence gaps")
	}
}

func TestParseDalecGenericComponentNamesAndGitObjectIDs(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"renderer", "http_component", "utility.v2"} {
		t.Run(name, func(t *testing.T) {
			input := fixture(t)
			input.replace(t, "engine", name)
			input.replace(t, strings.Repeat("a", 40), strings.Repeat("C", 64))
			input.metadata.RecipeCommit = strings.Repeat("D", 40)
			recipe := input.parse(t)
			if recipe.UpstreamSource != name || recipe.UpstreamCommit != strings.Repeat("c", 64) ||
				recipe.RecipeCommit != strings.Repeat("d", 40) || recipe.OrderedPatches[0].Source != name {
				t.Fatal("component names or canonical full Git object IDs were not preserved")
			}
		})
	}
}

func TestParseDalecRecipeRepositoryIsAnOpaqueIdentifier(t *testing.T) {
	t.Parallel()
	for _, identifier := range []string{"", "private:synthetic/recipes", "private-fixture://recipes/component"} {
		input := fixture(t)
		input.metadata.RecipeRepository = identifier
		recipe := input.parse(t)
		if recipe.RecipeRepository != identifier || !slices.Contains(recipe.Missing, MissingAcquisition) {
			t.Fatal("a recipe identifier was resolved or treated as verified acquisition")
		}
	}
}

func TestParseDalecNoImageEquivalenceFromTagsOrVersions(t *testing.T) {
	t.Parallel()
	for _, observation := range []string{"", "registry.example.invalid/engine:1.2.3", "registry.example.invalid/engine:latest"} {
		t.Run(observation, func(t *testing.T) {
			input := fixture(t)
			input.metadata.ObservedOriginalImage = observation
			recipe := input.parse(t)
			if recipe.ObservedOriginalImage.Reference != observation || recipe.ObservedOriginalImage.Digest != "" ||
				recipe.RebuiltControlImage.Digest != "sha256:"+strings.Repeat("2", 64) ||
				!slices.Contains(recipe.Missing, MissingOriginalDigest) || recipe.EvidenceStatus != EvidencePartial {
				t.Fatal("a tag or rebuilt image was misrepresented as published image evidence")
			}
			if err := Compare(recipe, recipe); err == nil {
				t.Fatal("comparison accepted an unresolved published image identity")
			}
		})
	}
	input := fixture(t)
	input.metadata.RebuiltControlImage = ""
	recipe := input.parse(t)
	if recipe.RebuiltControlImage != (ImageIdentity{}) || !slices.Contains(recipe.Missing, MissingControlDigest) ||
		recipe.ObservedOriginalImage.Digest != "sha256:"+strings.Repeat("1", 64) {
		t.Fatal("published image evidence must not populate a missing control observation")
	}
}

func TestParseDalecUnpinnedFrontendIsMissingEvidence(t *testing.T) {
	t.Parallel()
	for _, header := range []string{"", "# syntax=registry.example.invalid/build/frontend:1\n", "# syntax=registry.example.invalid/build/frontend\n"} {
		t.Run(header, func(t *testing.T) {
			input := fixture(t)
			input.replace(t, strings.SplitAfterN(string(input.spec), "\n", 2)[0], header)
			recipe := input.parse(t)
			if recipe.Frontend.Digest != "" || !slices.Contains(recipe.Missing, MissingFrontendDigest) ||
				recipe.EvidenceStatus != EvidencePartial {
				t.Fatal("an unpinned frontend was silently pinned or verified")
			}
			if err := Compare(recipe, recipe); err == nil {
				t.Fatal("comparison accepted an unpinned frontend")
			}
		})
	}
}

func TestParseDalecFrontendDirectiveScope(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"\n", "# ordinary comment\n"} {
		input := fixture(t)
		input.spec = append([]byte(prefix), input.spec...)
		input.files[input.metadata.Path] = bytes.Clone(input.spec)
		recipe := input.parse(t)
		if recipe.Frontend.Digest != "" || !slices.Contains(recipe.Missing, MissingFrontendDigest) {
			t.Fatal("a later comment was treated as an active frontend directive")
		}
	}
	for _, header := range []string{
		"# syntax=\n",
		"# syntax=registry.example.invalid/frontend@sha256:not-hex\n",
		"# syntax=sha256:" + strings.Repeat("f", 64) + "\n",
		"# syntax=registry.example.invalid/frontend:1\n# syntax=registry.example.invalid/frontend:2\n",
	} {
		input := fixture(t)
		input.replace(t, strings.SplitAfterN(string(input.spec), "\n", 2)[0], header)
		requireParseError(t, input)
	}
}

func TestParseDalecNeverChoosesTargetOrPlatform(t *testing.T) {
	t.Parallel()
	for _, omitted := range []string{"target", "platform", "both"} {
		t.Run(omitted, func(t *testing.T) {
			input := fixture(t)
			if omitted != "platform" {
				input.metadata.Target = ""
			}
			if omitted != "target" {
				input.metadata.Platform = ""
			}
			recipe := input.parse(t)
			if recipe.Target != input.metadata.Target || recipe.Platform != input.metadata.Platform ||
				(omitted != "platform" && !slices.Contains(recipe.Missing, MissingTarget)) ||
				(omitted != "target" && !slices.Contains(recipe.Missing, MissingPlatform)) {
				t.Fatal("a build selection was guessed")
			}
		})
	}
	input := fixture(t)
	input.replace(t, "    distro/container:\n      platforms: [linux/amd64, linux/arm64]\n    distro/package:\n      platforms: [linux/amd64]",
		"    - distro/container\n    - distro/package")
	if got := input.parse(t).BuildTargets; len(got) != 2 || got[0].Name != "distro/container" {
		t.Fatal("build-target name sequence was not extracted")
	}
}

func TestParseDalecInlinePatchByteIdentity(t *testing.T) {
	t.Parallel()
	input := fixture(t)
	content := input.files["patches/0001-vendor.patch"]
	var inline strings.Builder
	inline.WriteString("  first.patch:\n    inline:\n      file:\n        contents: |\n")
	for line := range strings.SplitSeq(strings.TrimSuffix(string(content), "\n"), "\n") {
		inline.WriteString("          " + line + "\n")
	}
	input.replace(t, "  vendor-patches:\n", inline.String()+"  vendor-patches:\n")
	input.replace(t, "source: vendor-patches\n      path: 0001-vendor.patch", "source: first.patch")
	delete(input.files, "patches/0001-vendor.patch")
	input.files["first.patch"] = content
	recipe := input.parse(t)
	if recipe.OrderedPatches[0].Path != "first.patch" || recipe.OrderedPatches[0].Digest != expectedDigest(content) {
		t.Fatal("inline patch identity changed")
	}
	input.files["first.patch"] = bytes.ReplaceAll(content, []byte("\n"), []byte("\r\n"))
	requireParseError(t, input)
}

func TestParseDalecExpectedDigestsAndNoMutation(t *testing.T) {
	t.Parallel()
	input := fixture(t)
	input.metadata.ExpectedDigests = map[string]string{}
	for name, content := range input.files {
		input.metadata.ExpectedDigests[name] = "sha256:" + strings.ToUpper(strings.TrimPrefix(expectedDigest(content), "sha256:"))
	}
	originalSpec := bytes.Clone(input.spec)
	originalFiles := make(map[string][]byte, len(input.files))
	for name, content := range input.files {
		originalFiles[name] = bytes.Clone(content)
	}
	first, second := input.parse(t), input.parse(t)
	if !reflect.DeepEqual(first, second) || !bytes.Equal(originalSpec, input.spec) ||
		!reflect.DeepEqual(originalFiles, input.files) {
		t.Fatal("parsing is not deterministic or mutated caller bytes")
	}
	input.files["patches/0001-vendor.patch"][0] = 'X'
	requireParseError(t, input)
}

func TestParseDalecCommandsAreInert(t *testing.T) {
	t.Parallel()
	input := fixture(t)
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	input.replace(t, "make -C engine VERSION=${VERSION}", "touch "+marker)
	input.parse(t)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("parsing must not execute a build command")
	}
}

func requireParseError(t *testing.T, input syntheticFixture) {
	t.Helper()
	recipe, err := ParseDalec(input.spec, input.files, input.metadata)
	if err == nil {
		t.Fatal("unsafe or unsupported provenance was accepted")
	}
	if !reflect.DeepEqual(recipe, Recipe{}) {
		t.Fatal("parse error returned partially populated untrusted provenance")
	}
	for _, private := range []string{
		"PRIVATE_FIXTURE_MARKER", input.metadata.RecipeRepository, input.metadata.Path,
		"https://example.invalid", "0001-vendor.patch",
	} {
		if private != "" && strings.Contains(err.Error(), private) {
			t.Fatal("parse error disclosed input content")
		}
	}
}

func TestParseDalecRejectsUnsafeAndUnsupportedYAML(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, old, replacement string
	}{
		{"duplicate-root", "name: engine", "name: engine\nname: PRIVATE_FIXTURE_MARKER"},
		{"case-collision", "name: engine", "name: engine\nName: PRIVATE_FIXTURE_MARKER"},
		{"duplicate-nested", `CGO_ENABLED: "0"`, "CGO_ENABLED: \"0\"\n    CGO_ENABLED: PRIVATE_FIXTURE_MARKER"},
		{"unknown-root", "name: engine", "name: engine\nPRIVATE_FIXTURE_MARKER: value"},
		{"unknown-git", "    git:\n", "    git:\n      PRIVATE_FIXTURE_MARKER: value\n"},
		{"unknown-build", "build:\n  env:", "build:\n  PRIVATE_FIXTURE_MARKER: value\n  env:"},
		{"unknown-gomod", "          edits:\n", "          PRIVATE_FIXTURE_MARKER: value\n          edits:\n"},
		{"unsupported-http", "    git:\n      url:", "    http:\n      url:"},
		{"unsupported-revision", `REVISION: "2"`, `REVISION: "2.vendor"`},
		{"conflicting-revision", `revision: "${REVISION}"`, `revision: "3"`},
		{"conflicting-version", `version: "${VERSION}"`, `version: "9.0.0"`},
		{"unsupported-schema", "name: engine", "schemaVersion: 2\nname: engine"},
		{"short-upstream-commit", strings.Repeat("a", 40), "deadbeef"},
		{"semver-upstream-commit", strings.Repeat("a", 40), "v1.2.3"},
		{"unknown-substitution", `commit: "${COMMIT}"`, `commit: "${PRIVATE_FIXTURE_MARKER}"`},
		{"operator-substitution", `commit: "${COMMIT}"`, `commit: "${COMMIT:-main}"`},
		{"recursive-args", `VERSION: "1.2.3"`, `VERSION: "${REVISION}"`},
		{"shell-command-substitution", "make -C engine VERSION=${VERSION}", "make $(PRIVATE_FIXTURE_MARKER)"},
		{"shell-backticks", "make -C engine VERSION=${VERSION}", "make `PRIVATE_FIXTURE_MARKER`"},
		{"float-version", `VERSION: "1.2.3"`, "VERSION: 1.2"},
		{"bool-arg", `REVISION: "2"`, "REVISION: true"},
		{"null-build", "  env:\n    CGO_ENABLED: \"0\"\n    GOFLAGS: \"-trimpath\"", "  env: null"},
		{"alias", "name: engine", "name: &component engine\nvendor: *component"},
		{"merge", "name: engine", "name: engine\n<<: {vendor: PRIVATE_FIXTURE_MARKER}"},
		{"custom-tag", "name: engine", "name: !PRIVATE_FIXTURE_MARKER engine"},
		{"typed-key", "name: engine", "123: PRIVATE_FIXTURE_MARKER\nname: engine"},
		{"trailing-document", "name: engine", "---\nPRIVATE_FIXTURE_MARKER: true\n---\nname: engine"},
		{"malformed", "name: engine", "name: [PRIVATE_FIXTURE_MARKER"},
		{"source-traversal", "path: patches", "path: ../PRIVATE_FIXTURE_MARKER"},
		{"patch-traversal", "path: 0001-vendor.patch", "path: ../PRIVATE_FIXTURE_MARKER"},
		{"patch-absolute", "path: 0001-vendor.patch", "path: /PRIVATE_FIXTURE_MARKER"},
		{"patch-backslash", "path: 0001-vendor.patch", "path: 'dir\\PRIVATE_FIXTURE_MARKER'"},
		{"patch-git-directory", "path: 0001-vendor.patch", "path: .git/PRIVATE_FIXTURE_MARKER"},
		{"patch-url-encoding", "path: 0001-vendor.patch", "path: '%2e%2e/PRIVATE_FIXTURE_MARKER'"},
		{"patch-negative-strip", "strip: 1", "strip: -1"},
		{"patch-excessive-strip", "strip: 1", "strip: 17"},
		{"patch-unknown-source", "source: vendor-patches", "source: PRIVATE_FIXTURE_MARKER"},
		{"patch-other-context", "{name: context}", "{name: PRIVATE_FIXTURE_MARKER}"},
		{"module-local-replacement", "example.invalid/module@v1.9.1", "../PRIVATE_FIXTURE_MARKER"},
		{"module-unversioned-replacement", "example.invalid/module@v1.9.1", "example.invalid/module"},
		{"unknown-extension", "  build-targets:", "  PRIVATE_FIXTURE_MARKER: value\n  build-targets:"},
		{"empty-platform-constraint", "platforms: [linux/amd64, linux/arm64]", "platforms: []"},
		{"unsafe-target-name", "    distro/package:", "    ../PRIVATE_FIXTURE_MARKER:"},
		{"duplicate-platform", "platforms: [linux/amd64, linux/arm64]", "platforms: [linux/amd64, linux/amd64]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := fixture(t)
			input.replace(t, test.old, test.replacement)
			requireParseError(t, input)
		})
	}
}

func TestParseDalecRejectsCredentialCarriers(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ old, replacement string }{
		{"https://example.invalid/project/engine", "https://user:PRIVATE_FIXTURE_MARKER@example.invalid/project/engine"},
		{"https://example.invalid/project/engine", "https://example.invalid/project/engine?token=PRIVATE_FIXTURE_MARKER"},
		{`GOFLAGS: "-trimpath"`, `API_TOKEN: "PRIVATE_FIXTURE_MARKER"`},
		{`GOFLAGS: "-trimpath"`, `PASSWORD: "PRIVATE_FIXTURE_MARKER"`},
		{`GOFLAGS: "-trimpath"`, `AWS_ACCESS_KEY_ID: "PRIVATE_FIXTURE_MARKER"`},
		{`GOFLAGS: "-trimpath"`, `GOPROXY: "https://user:PRIVATE_FIXTURE_MARKER@example.invalid"`},
		{`VERSION: "1.2.3"`, "VERSION: \"1.2.3\"\n  AUTHORIZATION: PRIVATE_FIXTURE_MARKER"},
		{"make -C engine VERSION=${VERSION}", "make TOKEN=PRIVATE_FIXTURE_MARKER"},
		{"Synthetic downstream component", "-----BEGIN PRIVATE KEY-----"},
		{"description: Synthetic downstream component", "description: Synthetic downstream component\nimage:\n  labels:\n    apiToken: PRIVATE_FIXTURE_MARKER"},
	} {
		input := fixture(t)
		input.replace(t, test.old, test.replacement)
		requireParseError(t, input)
	}
	input := fixture(t)
	input.metadata.RecipeRepository = "https://user:PRIVATE_FIXTURE_MARKER@example.invalid/recipes"
	requireParseError(t, input)
}

func TestParseDalecMissingIdentityIsPartial(t *testing.T) {
	t.Parallel()
	input := fixture(t)
	input.metadata.RecipeCommit = ""
	input.metadata.RecipeRepository = ""
	input.replace(t, "  COMMIT: \""+strings.Repeat("a", 40)+"\"\n", "")
	input.replace(t, `commit: "${COMMIT}"`, `commit: ""`)
	input.replace(t, "  VERSION: \"1.2.3\"\n  REVISION: \"2\"\n", "")
	input.replace(t, "args:\n", "args: {}\n")
	input.replace(t, "version: \"${VERSION}\"\nrevision: \"${REVISION}\"\n", "")
	input.replace(t, "make -C engine VERSION=${VERSION}", "make -C engine")
	recipe := input.parse(t)
	for _, missing := range []string{MissingRecipeCommit, MissingUpstreamCommit, MissingVersion, MissingRevision} {
		if !slices.Contains(recipe.Missing, missing) || recipe.EvidenceStatus != EvidencePartial {
			t.Fatal("incomplete identity was not reported")
		}
	}
	if err := Compare(recipe, recipe); err == nil {
		t.Fatal("comparison accepted incomplete recipe identity")
	}
}

func TestParseDalecRejectsAcquisitionAndSelectionErrors(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*syntheticFixture){
		"missing-recipe": func(input *syntheticFixture) { delete(input.files, input.metadata.Path) },
		"changed-recipe-bytes": func(input *syntheticFixture) {
			input.files[input.metadata.Path] = append(bytes.Clone(input.spec), '\n')
		},
		"missing-patch": func(input *syntheticFixture) { delete(input.files, "patches/0001-vendor.patch") },
		"empty-patch":   func(input *syntheticFixture) { input.files["patches/0001-vendor.patch"] = nil },
		"unclaimed-patch": func(input *syntheticFixture) {
			input.files["patches/PRIVATE_FIXTURE_MARKER.patch"] = []byte("unclaimed")
		},
		"unsafe-file-key": func(input *syntheticFixture) { input.files["../PRIVATE_FIXTURE_MARKER"] = []byte("unsafe") },
		"unsafe-recipe-path": func(input *syntheticFixture) {
			input.metadata.Path = "/PRIVATE_FIXTURE_MARKER"
		},
		"short-recipe-commit": func(input *syntheticFixture) { input.metadata.RecipeCommit = "deadbeef" },
		"message-recipe-commit": func(input *syntheticFixture) {
			input.metadata.RecipeCommit = "release PRIVATE_FIXTURE_MARKER"
		},
		"incorrect-expected-digest": func(input *syntheticFixture) {
			input.metadata.ExpectedDigests = map[string]string{"patches/0001-vendor.patch": "sha256:" + strings.Repeat("0", 64)}
		},
		"missing-expected-file": func(input *syntheticFixture) {
			input.metadata.ExpectedDigests = map[string]string{"PRIVATE_FIXTURE_MARKER.patch": "sha256:" + strings.Repeat("0", 64)}
		},
		"unknown-target":   func(input *syntheticFixture) { input.metadata.Target = "PRIVATE_FIXTURE_MARKER/container" },
		"wrong-platform":   func(input *syntheticFixture) { input.metadata.Platform = "windows/amd64" },
		"unsafe-platform":  func(input *syntheticFixture) { input.metadata.Platform = "linux/../../PRIVATE_FIXTURE_MARKER" },
		"unknown-upstream": func(input *syntheticFixture) { input.metadata.UpstreamSource = "PRIVATE_FIXTURE_MARKER" },
		"invalid-image-digest": func(input *syntheticFixture) {
			input.metadata.ObservedOriginalImage = "example.invalid/engine@sha256:PRIVATE_FIXTURE_MARKER"
		},
		"credential-image": func(input *syntheticFixture) {
			input.metadata.ObservedOriginalImage = "https://user:PRIVATE_FIXTURE_MARKER@example.invalid/engine"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := fixture(t)
			mutate(&input)
			requireParseError(t, input)
		})
	}
}

func TestRecipeJSONSeparatesEvidence(t *testing.T) {
	t.Parallel()
	recipe := fixture(t).parse(t)
	data, err := json.Marshal(recipe)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Recipe
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recipe, decoded) || decoded.ObservedOriginalImage.Digest == decoded.RebuiltControlImage.Digest {
		t.Fatal("serialized provenance lost distinct observations")
	}
	if err := Compare(recipe, decoded); err != nil {
		t.Fatalf("serialized provenance cannot be compared: %v", err)
	}
}
