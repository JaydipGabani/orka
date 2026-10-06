package provenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func downstreamFixture(t *testing.T) syntheticFixture {
	t.Helper()
	input := fixture(t)
	input.replace(t, `VERSION: "1.2.3"`, `VERSION: "2.17.3"`)
	input.replace(t, `REVISION: "2"`, `REVISION: "16"`)
	input.replace(t, "distro", "azlinux3")
	input.replace(t, `GOFLAGS: "-trimpath"`, "GOFLAGS: \"-trimpath\"\n    GOEXPERIMENT: systemcrypto")
	input.replace(t, strings.SplitAfterN(string(input.spec), "\n", 2)[0],
		"# syntax=registry.example.invalid/build/frontend:0.21\n")
	input.metadata.Target = "azlinux3/container"
	input.metadata.ExpectedVersion, input.metadata.ExpectedRevision = "2.17.3", "16"
	input.metadata.ObservedOriginalImage = "registry.example.invalid/engine:2.17.3-16@sha256:" + strings.Repeat("1", 64)
	input.metadata.AttestedInputs = &AttestedBuildInputs{
		StatementDigest: "sha256:" + strings.Repeat("3", 64), SubjectImageDigest: "sha256:" + strings.Repeat("1", 64),
		UpstreamRepoURL: "https://example.invalid/project/engine", UpstreamCommit: strings.Repeat("a", 40),
		Frontend: ImageIdentity{Reference: "registry.example.invalid/build/frontend:0.21", Digest: "sha256:" + strings.Repeat("4", 64)},
		Worker:   ImageIdentity{Reference: "registry.example.invalid/build/worker:0.21", Digest: "sha256:" + strings.Repeat("5", 64)},
		ConfigSource: ConfigSource{
			URI: "input:context", Path: input.metadata.Path,
		},
	}
	return input
}

func TestCallerAttestedBuildInputs(t *testing.T) {
	t.Parallel()
	input := downstreamFixture(t)
	original := *input.metadata.AttestedInputs
	recipe := input.parse(t)
	if recipe.Version != "2.17.3" || recipe.Revision != "16" || recipe.Target != "azlinux3/container" ||
		recipe.Platform != "linux/amd64" || recipe.BuildEnvironment["GOEXPERIMENT"] != "systemcrypto" {
		t.Fatal("actual recipe identity, selected target/platform or build environment changed")
	}
	if len(recipe.OrderedPatches) != 2 || recipe.OrderedPatches[0].Path != "patches/0001-vendor.patch" ||
		recipe.OrderedPatches[1].Path != "patches/0002-vendor.patch" ||
		!slices.Equal(recipe.ModuleReplacements, []string{
			"example.invalid/module=example.invalid/module@v1.9.1",
			"example.invalid/other@v1.0.0=example.invalid/fork@v2.0.1",
		}) {
		t.Fatal("vendor patches or module overrides were lost")
	}
	if recipe.FrontendSyntax.Reference != original.Frontend.Reference || recipe.FrontendSyntax.Digest != "" ||
		recipe.Frontend.Reference != original.Frontend.Reference+"@"+original.Frontend.Digest ||
		recipe.Frontend.Digest != original.Frontend.Digest || recipe.Worker.Digest != original.Worker.Digest {
		t.Fatal("syntax tag, attested frontend and worker identities were conflated")
	}
	if recipe.AttestedInputs == nil || recipe.AttestedInputs.ConfigSource != original.ConfigSource ||
		recipe.AttestedInputs.StatementDigest != original.StatementDigest ||
		recipe.AttestedInputs.SubjectImageDigest != recipe.ObservedOriginalImage.Digest ||
		recipe.RebuiltControlImage.Digest == recipe.AttestedInputs.SubjectImageDigest ||
		recipe.RecipeCommit != input.metadata.RecipeCommit || recipe.RecipeCommit == recipe.UpstreamCommit {
		t.Fatal("source/context evidence was conflated with Git recipe or control image identity")
	}
	if recipe.UpstreamCommitStatus != SourceAttested || recipe.RecipeMappingStatus != MappingInferred ||
		recipe.EvidenceStatus != EvidencePartial || !slices.Contains(recipe.Missing, MissingRecipeMapping) {
		t.Fatal("attested upstream source incorrectly verified the Git recipe mapping or the whole recipe")
	}
	for _, resolved := range []string{MissingFrontendDigest, MissingWorkerDigest, MissingSourceAttestation} {
		if slices.Contains(recipe.Missing, resolved) {
			t.Fatal("a supplied attested input was reported missing")
		}
	}
	if original != *input.metadata.AttestedInputs {
		t.Fatal("parser mutated caller attestation inputs")
	}
}

func TestAttestedRecipeJSONRoundTrip(t *testing.T) {
	t.Parallel()
	recipe := downstreamFixture(t).parse(t)
	if err := Compare(recipe, recipe); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(recipe)
	if err != nil {
		t.Fatal(err)
	}
	var restored Recipe
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recipe, restored) {
		t.Fatal("serialized provenance lost independently scoped evidence")
	}
	if err := Compare(recipe, restored); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataMatchesActualSpecRevisionNotMessages(t *testing.T) {
	t.Parallel()
	for _, revision := range []string{"17", "21"} {
		t.Run(revision, func(t *testing.T) {
			input := downstreamFixture(t)
			input.replace(t, `REVISION: "16"`, `REVISION: "`+revision+`"`)
			input.replace(t, "description: Synthetic downstream component", "description: Synthetic downstream component # commit message bump16")
			recipe, err := ParseDalec(input.spec, input.files, input.metadata)
			if !errors.Is(err, ErrRevisionMismatch) || !reflect.DeepEqual(recipe, Recipe{}) {
				t.Fatal("a reported revision was matched using a message rather than actual spec bytes")
			}
			requireParseError(t, input)
		})
	}
	input := downstreamFixture(t)
	input.replace(t, `VERSION: "2.17.3"`, `VERSION: "2.17.4"`)
	if _, err := ParseDalec(input.spec, input.files, input.metadata); !errors.Is(err, ErrVersionMismatch) {
		t.Fatal("a different actual version was accepted")
	}
}

func TestNoVersionOrRevisionInferenceFromTagsAndMessages(t *testing.T) {
	t.Parallel()
	input := downstreamFixture(t)
	input.metadata.AttestedInputs = nil
	input.metadata.ExpectedVersion, input.metadata.ExpectedRevision = "", ""
	input.replace(t, `REVISION: "16"`, `REVISION: "21"`)
	input.replace(t, "description: Synthetic downstream component", "description: Synthetic downstream component # commit message bump16")
	recipe := input.parse(t)
	if recipe.Revision != "21" || recipe.Version != "2.17.3" ||
		recipe.RecipeMappingStatus != MappingInferred || recipe.UpstreamCommitStatus != SourceUnverified ||
		recipe.Frontend.Digest != "" || !slices.Contains(recipe.Missing, MissingFrontendDigest) {
		t.Fatal("a tag, comment or recipe commit silently supplied missing build evidence")
	}
}

func TestExpectedIdentityCannotSupplyMissingSpecValues(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		field, argument string
		want            error
	}{
		{"version", "VERSION", ErrVersionMismatch},
		{"revision", "REVISION", ErrRevisionMismatch},
	} {
		t.Run(test.field, func(t *testing.T) {
			input := downstreamFixture(t)
			value := "2.17.3"
			if test.field == "revision" {
				value = "16"
			}
			input.replace(t, test.field+": \"${"+test.argument+"}\"\n", "")
			input.replace(t, "  "+test.argument+": \""+value+"\"\n", "")
			input.replace(t, "make -C engine VERSION=${VERSION}", "make -C engine")
			if _, err := ParseDalec(input.spec, input.files, input.metadata); !errors.Is(err, test.want) {
				t.Fatal("metadata supplied a version or revision absent from actual spec bytes")
			}
		})
	}
}

func TestContextSourceNeverAttestsAGitRecipeCommit(t *testing.T) {
	t.Parallel()
	input := downstreamFixture(t)
	input.metadata.RecipeCommit = ""
	input.metadata.RecipeRepository = ""
	recipe := input.parse(t)
	if recipe.RecipeCommit != "" || recipe.RecipeRepository != "" || recipe.RecipeMappingStatus != MappingUnknown ||
		recipe.UpstreamCommitStatus != SourceAttested || !slices.Contains(recipe.Missing, MissingRecipeCommit) ||
		recipe.AttestedInputs.ConfigSource.URI != "input:context" {
		t.Fatal("attested context/source identity was converted into a Git recipe mapping")
	}
	if err := Compare(recipe, recipe); err == nil {
		t.Fatal("comparison accepted a missing base Git recipe identity")
	}
}

func TestGitRecipeMappingRequiresIndependentEvidence(t *testing.T) {
	t.Parallel()
	input := downstreamFixture(t)
	input.metadata.RecipeMappingStatus = MappingVerified
	requireParseError(t, input)
	input.metadata.RecipeMappingEvidenceDigest = input.metadata.AttestedInputs.StatementDigest
	requireParseError(t, input)
	input.metadata.RecipeMappingEvidenceDigest = "sha256:" + strings.Repeat("6", 64)
	recipe := input.parse(t)
	if recipe.RecipeMappingStatus != MappingVerified || recipe.UpstreamCommitStatus != SourceAttested ||
		recipe.EvidenceStatus != EvidencePartial || slices.Contains(recipe.Missing, MissingRecipeMapping) {
		t.Fatal("independent mapping/source labels were not retained separately")
	}
	input.metadata.AttestedInputs = nil
	recipe = input.parse(t)
	if recipe.RecipeMappingStatus != MappingVerified || recipe.UpstreamCommitStatus != SourceUnverified ||
		!slices.Contains(recipe.Missing, MissingSourceAttestation) {
		t.Fatal("a Git recipe mapping was promoted to a source commit attestation")
	}
}

func TestIncompleteOrMismatchedAttestedInputsFailClosed(t *testing.T) {
	t.Parallel()
	mutations := map[string]func(*syntheticFixture){
		"missing-expected-version":  func(input *syntheticFixture) { input.metadata.ExpectedVersion = "" },
		"missing-expected-revision": func(input *syntheticFixture) { input.metadata.ExpectedRevision = "" },
		"invalid-expected-revision": func(input *syntheticFixture) { input.metadata.ExpectedRevision = "16.vendor" },
		"missing-statement": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.StatementDigest = ""
		},
		"wrong-subject": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.SubjectImageDigest = "sha256:" + strings.Repeat("2", 64)
		},
		"tag-only-published-image": func(input *syntheticFixture) {
			input.metadata.ObservedOriginalImage = "registry.example.invalid/engine:2.17.3-16"
		},
		"wrong-source-repository": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.UpstreamRepoURL = "https://example.invalid/another/component"
		},
		"wrong-source-commit": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.UpstreamCommit = strings.Repeat("f", 40)
		},
		"abbreviated-source-commit": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.UpstreamCommit = "deadbeef"
		},
		"frontend-tag-only": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.Frontend.Digest = ""
		},
		"worker-tag-only": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.Worker.Digest = ""
		},
		"wrong-frontend-repository": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.Frontend.Reference = "registry.example.invalid/another/frontend:0.21"
		},
		"wrong-frontend-tag": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.Frontend.Reference = "registry.example.invalid/build/frontend:0.22"
		},
		"conflicting-frontend-digests": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.Frontend.Reference += "@sha256:" + strings.Repeat("9", 64)
		},
		"missing-worker-reference": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.Worker.Reference = ""
		},
		"missing-config-source": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.ConfigSource.URI = ""
		},
		"different-spec-path": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.ConfigSource.Path = "another/recipe.yml"
		},
		"unsafe-spec-path": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.ConfigSource.Path = "../PRIVATE_FIXTURE_MARKER"
		},
		"source-credentials": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.UpstreamRepoURL = "https://user:PRIVATE_FIXTURE_MARKER@example.invalid/project/engine"
		},
		"frontend-credentials": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.Frontend.Reference = "https://user:PRIVATE_FIXTURE_MARKER@registry.example.invalid/build/frontend"
		},
		"config-source-credentials": func(input *syntheticFixture) {
			input.metadata.AttestedInputs.ConfigSource.URI = "https://user:PRIVATE_FIXTURE_MARKER@example.invalid/context"
		},
		"invalid-mapping-status": func(input *syntheticFixture) {
			input.metadata.RecipeMappingStatus = "attested"
		},
		"inferred-mapping-without-commit": func(input *syntheticFixture) {
			input.metadata.RecipeMappingStatus = MappingInferred
			input.metadata.RecipeCommit = ""
		},
		"invalid-mapping-evidence": func(input *syntheticFixture) {
			input.metadata.RecipeMappingEvidenceDigest = "PRIVATE_FIXTURE_MARKER"
		},
		"verified-mapping-without-repository": func(input *syntheticFixture) {
			input.metadata.RecipeMappingStatus = MappingVerified
			input.metadata.RecipeMappingEvidenceDigest = "sha256:" + strings.Repeat("6", 64)
			input.metadata.RecipeRepository = ""
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			input := downstreamFixture(t)
			mutate(&input)
			requireParseError(t, input)
		})
	}
}

func TestAttestedFrontendCannotReplaceConflictingSyntaxPin(t *testing.T) {
	t.Parallel()
	input := downstreamFixture(t)
	input.replace(t, "frontend:0.21\n", "frontend:0.21@sha256:"+strings.Repeat("9", 64)+"\n")
	if _, err := ParseDalec(input.spec, input.files, input.metadata); !errors.Is(err, ErrAttestedInputsMismatch) {
		t.Fatal("a conflicting attested digest overrode a syntax pin")
	}
	input.replace(t, strings.Repeat("9", 64), strings.Repeat("4", 64))
	recipe := input.parse(t)
	if recipe.Frontend != recipe.FrontendSyntax {
		t.Fatal("matching pinned syntax was not preserved")
	}
}

func TestAttestedImageNormalizationAndOwnership(t *testing.T) {
	t.Parallel()
	input := downstreamFixture(t)
	input.metadata.AttestedInputs.UpstreamCommit = strings.ToUpper(input.metadata.AttestedInputs.UpstreamCommit)
	input.metadata.AttestedInputs.StatementDigest = "sha256:" + strings.Repeat("A", 64)
	input.metadata.AttestedInputs.Frontend.Reference += "@" + input.metadata.AttestedInputs.Frontend.Digest
	input.metadata.AttestedInputs.Frontend.Digest = ""
	recipe := input.parse(t)
	if recipe.AttestedInputs.StatementDigest != "sha256:"+strings.Repeat("a", 64) ||
		recipe.UpstreamCommit != recipe.AttestedInputs.UpstreamCommit || recipe.Frontend.Digest == "" {
		t.Fatal("attested digests or source object IDs were not canonicalized")
	}
	worker := recipe.AttestedInputs.Worker
	input.metadata.AttestedInputs.Worker.Digest = "sha256:" + strings.Repeat("9", 64)
	if recipe.AttestedInputs.Worker != worker {
		t.Fatal("recipe retained a mutable pointer to caller metadata")
	}
}

func TestAttestedContextIdentifierBounds(t *testing.T) {
	t.Parallel()
	for _, size := range []int{maxValueSize - 1, maxValueSize, maxValueSize + 1} {
		input := downstreamFixture(t)
		input.metadata.AttestedInputs.ConfigSource.URI = "urn:" + strings.Repeat("x", size-len("urn:"))
		if size > maxValueSize {
			requireParseError(t, input)
		} else {
			input.parse(t)
		}
	}
}

func TestAttestedFrontendWithoutSyntaxIsExplicitMetadata(t *testing.T) {
	t.Parallel()
	input := downstreamFixture(t)
	input.replace(t, "# syntax=registry.example.invalid/build/frontend:0.21\n", "")
	recipe := input.parse(t)
	if recipe.FrontendSyntax != (ImageIdentity{}) || recipe.Frontend.Digest != input.metadata.AttestedInputs.Frontend.Digest {
		t.Fatal("explicit attested metadata was not distinguished from absent syntax")
	}
	input.metadata.AttestedInputs = nil
	recipe = input.parse(t)
	if recipe.Frontend != (ImageIdentity{}) || !slices.Contains(recipe.Missing, MissingFrontendDigest) {
		t.Fatal("removing attested metadata retained an invented frontend pin")
	}
}

func TestComparisonPreservesAttestedAndDownstreamInputs(t *testing.T) {
	t.Parallel()
	baseline := downstreamFixture(t).parse(t)
	input := downstreamFixture(t)
	additional := []byte("--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-vendor-two\n+candidate-fix\n")
	input.appendPatch(t, "0003-candidate.patch", additional)
	candidate := input.parse(t)
	if err := CompareWithAdditionalPatch(baseline, candidate, expectedDigest(additional)); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct{ old, replacement string }{
		{"GOEXPERIMENT: systemcrypto", "GOEXPERIMENT: boringcrypto"},
		{"module@v1.9.1", "module@v1.9.2"},
	} {
		changed := downstreamFixture(t)
		changed.appendPatch(t, "0003-candidate.patch", additional)
		changed.replace(t, test.old, test.replacement)
		if err := CompareWithAdditionalPatch(baseline, changed.parse(t), expectedDigest(additional)); err == nil {
			t.Fatal("attested upstream commit concealed changed downstream inputs")
		}
	}
	input.metadata.AttestedInputs.Worker.Digest = "sha256:" + strings.Repeat("9", 64)
	if err := CompareWithAdditionalPatch(baseline, input.parse(t), expectedDigest(additional)); err == nil {
		t.Fatal("comparison accepted a changed worker image")
	}
	for _, mutate := range []func(*Recipe){
		func(recipe *Recipe) { recipe.UpstreamCommitStatus = SourceUnverified },
		func(recipe *Recipe) { recipe.AttestedInputs = nil },
		func(recipe *Recipe) { recipe.Worker = ImageIdentity{} },
		func(recipe *Recipe) {
			recipe.FrontendSyntax = ImageIdentity{Reference: "registry.example.invalid/wrong:0.21"}
		},
		func(recipe *Recipe) { recipe.RecipeMappingStatus = MappingVerified },
	} {
		changed := downstreamFixture(t)
		changed.appendPatch(t, "0003-candidate.patch", bytes.Clone(additional))
		recipe := changed.parse(t)
		mutate(&recipe)
		if err := CompareWithAdditionalPatch(baseline, recipe, expectedDigest(additional)); err == nil {
			t.Fatal("comparison accepted inconsistent evidence labels or image identities")
		}
	}
}

func FuzzAttestedBuildInputs(f *testing.F) {
	f.Add(byte(0), "registry.example.invalid/build/frontend:0.21")
	f.Add(byte(1), "sha256:"+strings.Repeat("4", 64))
	f.Add(byte(2), "input:context")
	f.Add(byte(3), strings.Repeat("a", 40))
	f.Add(byte(4), "sha256:"+strings.Repeat("1", 64))
	f.Fuzz(func(t *testing.T, field byte, value string) {
		if len(value) > maxValueSize+1 {
			return
		}
		input := downstreamFixture(t)
		switch field % 5 {
		case 0:
			input.metadata.AttestedInputs.Frontend.Reference = value
		case 1:
			input.metadata.AttestedInputs.Frontend.Digest = value
		case 2:
			input.metadata.AttestedInputs.ConfigSource.URI = value
		case 3:
			input.metadata.AttestedInputs.UpstreamCommit = value
		case 4:
			input.metadata.AttestedInputs.SubjectImageDigest = value
		}
		recipe, err := ParseDalec(input.spec, input.files, input.metadata)
		if err != nil {
			if !reflect.DeepEqual(recipe, Recipe{}) {
				t.Fatal("invalid attested inputs returned partially populated evidence")
			}
			return
		}
		if recipe.EvidenceStatus != EvidencePartial || recipe.UpstreamCommitStatus != SourceAttested ||
			recipe.RecipeMappingStatus != MappingInferred {
			t.Fatal("normalized caller inputs promoted unrelated evidence")
		}
		if err := Compare(recipe, recipe); err != nil {
			t.Fatal("successful parse returned inconsistent comparison inputs")
		}
	})
}
