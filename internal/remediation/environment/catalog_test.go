package environment

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCatalogChoicesAndExactTargetBindingNeedNoSourceCheckout(t *testing.T) {
	f := testFixture(t)
	for i := range f.config.Repositories {
		if err := os.RemoveAll(f.config.Repositories[i].SourceRoot); err != nil {
			t.Fatal(err)
		}
		f.config.Repositories[i].SourceRoot = ""
	}
	a, err := newAdapter(f.config)
	if err != nil {
		t.Fatal(err)
	}
	choices := a.RecipeChoices()
	if len(choices) != 2 {
		t.Fatal("catalog did not surface both approved repositories")
	}
	data, err := json.Marshal(choices)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{f.root, `"sourceRoot"`, `"recipeRoot"`, `"path"`, `"files"`, `"command"`, `"ready"`} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatal("model-facing discovery leaked executor configuration or claimed readiness")
		}
	}
	for i, plan := range f.plans {
		choice, err := a.MatchTarget(plan.Bind.SourceTarget.Repository, plan.Bind.SourceTarget.Commit)
		if err != nil || choice.ID != plan.Bind.Recipe.ID || choice.Version != "1.0.0" ||
			len(choice.OrderedPatchDigests) != 2 || choice.OriginalImage != f.config.Repositories[i].Recipes[0].OriginalImage {
			t.Fatal("catalog did not derive the exact approved commit, version, image and patch series")
		}
		if !slices.Equal(choice.SupportedChecks, []string{HTTPExact}) ||
			!slices.Equal(choice.NeedsAdapterChecks, []string{EventSink}) {
			t.Fatal("catalog treated an unknown primitive as supported")
		}
		binding, err := a.BindRecipe(choice.SourceTarget, choice.ID)
		want := plan.Bind
		want.ChecksDigest = ""
		if err != nil || binding != want {
			t.Fatal("recipe ID did not restore the trusted binding")
		}
	}
	choices[0].SupportedChecks[0] = "forged-capability"
	choices[0].HTTPPorts[0] = 1
	choices[0].OrderedPatchDigests[0] = "forged"
	again := a.RecipeChoices()
	if again[0].SupportedChecks[0] != HTTPExact || again[0].HTTPPorts[0] != 8080 ||
		again[0].OrderedPatchDigests[0] == "forged" {
		t.Fatal("model-facing discovery records were not detached from executor policy")
	}
	for _, commit := range []string{"main", strings.Repeat("c", 40)} {
		_, err := a.MatchTarget(f.plans[0].Bind.SourceTarget.Repository, commit)
		assertKind(t, err, NeedsAdapter)
	}
	plan := f.plans[0]
	plan.Bind.SourceTarget.Commit = strings.Repeat("c", 40)
	plan.Bind.ChecksDigest = ""
	_, err = a.FreezePlan(plan)
	assertKind(t, err, NeedsAdapter)
}

func TestCatalogRequiresExplicitSelectionForAmbiguousTargets(t *testing.T) {
	f := testFixture(t)
	alternative := f.config.Repositories[0].Recipes[0]
	alternative.ID = "go-alternative"
	f.config.Repositories[0].Recipes = append(f.config.Repositories[0].Recipes, alternative)
	a, err := newAdapter(f.config)
	if err != nil {
		t.Fatal(err)
	}
	target := f.plans[0].Bind.SourceTarget
	_, err = a.MatchTarget(target.Repository, target.Commit)
	assertKind(t, err, NeedsAdapter)
	binding, err := a.BindRecipe(target, alternative.ID)
	if err != nil || binding.Recipe.ID != alternative.ID {
		t.Fatal("explicit approved ID could not resolve an ambiguous target")
	}
	_, err = a.BindRecipe(target, "../recipe.yml")
	assertKind(t, err, NeedsAdapter)
	slices.Reverse(f.config.Repositories[0].Recipes)
	reordered, err := newAdapter(f.config)
	if err != nil || !sameJSON(a.RecipeChoices(), reordered.RecipeChoices()) {
		t.Fatal("catalog ordering depends on operator map/slice iteration")
	}
}

func TestCatalogCannotOverlapWritableRunStorage(t *testing.T) {
	f := testFixture(t)
	destination := filepath.Join(f.config.Repositories[0].RecipeRoot, "run-storage")
	f.config.OutputRoot = destination
	_, err := newAdapter(f.config)
	assertKind(t, err, NeedsAdapter)
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("invalid configuration wrote into the read-only catalog")
	}
}

func TestCatalogVersionContextsPreserveOriginalRecipeAndVendorPatchPaths(t *testing.T) {
	f := testFixture(t)
	repo := &f.config.Repositories[0]
	base := repo.Recipes[0]
	versions := []RecipePolicy{base, base}
	for i := range versions {
		version := &versions[i]
		version.ID = []string{"go-original", "go-next"}[i]
		version.CatalogDirectory = "versions/" + version.ID
		version.Files = maps.Clone(base.Files)
		for name := range base.Files {
			data, err := os.ReadFile(filepath.Join(repo.RecipeRoot, name))
			if err != nil {
				t.Fatal(err)
			}
			if i == 1 && name == base.Path {
				data = bytes.ReplaceAll(data, []byte(strings.Repeat("a", 40)), []byte(strings.Repeat("c", 40)))
				data = bytes.ReplaceAll(data, []byte(`version: "1.0.0"`), []byte(`version: "1.1.0"`))
				data = bytes.ReplaceAll(data, []byte("\nbuild:\n"),
					[]byte("\n    - source: vendor\n      path: third.patch\n      strip: 1\nbuild:\n"))
			}
			writeCatalogFixture(t, repo.RecipeRoot, version.CatalogDirectory, name, data)
			version.Files[name] = digest(data)
		}
		if i == 1 {
			extra := []byte("--- a/NOTICE\n+++ b/NOTICE\n@@ -1 +1 @@\n-old\n+vendor-notice\n")
			writeCatalogFixture(t, repo.RecipeRoot, version.CatalogDirectory, "patches/third.patch", extra)
			version.Files["patches/third.patch"] = digest(extra)
			version.Commit = strings.Repeat("d", 40)
			version.OriginalImage = "registry.example.invalid/original@sha256:" + strings.Repeat("4", 64)
		}
	}
	repo.Recipes, repo.SourceRoot = versions, ""
	f.config.ImageBindings = nil
	a, err := newAdapter(f.config)
	if err != nil {
		t.Fatal(err)
	}
	target := SourceTarget{Repository: repo.URL, Commit: strings.Repeat("c", 40)}
	choice, err := a.MatchTarget(target.Repository, target.Commit)
	if err != nil || choice.Version != "1.1.0" || choice.ID != versions[1].ID ||
		len(choice.OrderedPatchDigests) != 3 || choice.OriginalImage != versions[1].OriginalImage {
		t.Fatal("operator catalog version selection lost exact source/image/three-vendor-patch mapping")
	}
	binding, err := a.BindRecipe(target, choice.ID)
	if err != nil {
		t.Fatal(err)
	}
	plan := f.plans[0]
	plan.Bind = binding
	plan, err = a.FreezePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.recipeSnapshot(BuildRequest{
		Plan: plan, Role: Candidate, Patch: candidatePatch(), PatchDigest: digest(candidatePatch()),
	})
	if err != nil || snapshot.baseline.Version != "1.1.0" || snapshot.baseline.Path != base.Path ||
		len(snapshot.baseline.OrderedPatches) != 3 || len(snapshot.built.OrderedPatches) != 4 {
		t.Fatalf("versioned recipe was not acquired into the original build context: %v", err)
	}
	for name := range snapshot.files {
		if strings.Contains(name, "versions/") {
			t.Fatal("operator catalog layout leaked into original build input paths")
		}
	}
	if snapshot.baseline.OrderedPatches[2].Path != "patches/third.patch" {
		t.Fatal("vendor patch path changed during acquisition")
	}
}

func writeCatalogFixture(t *testing.T, root, directory, name string, data []byte) {
	t.Helper()
	destination := filepath.Join(root, directory, name)
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0600); err != nil {
		t.Fatal(err)
	}
}
