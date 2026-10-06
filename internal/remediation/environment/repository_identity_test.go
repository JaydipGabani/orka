package environment

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRecipeGitHubCloneSuffixMatchesApprovedRepository(t *testing.T) {
	f := testFixture(t)
	repo := &f.config.Repositories[0]
	recipe := &repo.Recipes[0]
	filename := filepath.Join(repo.RecipeRoot, recipe.Path)
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	before := repo.URL
	repo.URL = "https://github.com/example/component"
	raw = bytes.ReplaceAll(raw, []byte(before), []byte(repo.URL+".git"))
	if err := os.WriteFile(filename, raw, 0600); err != nil {
		t.Fatal(err)
	}
	recipe.Files[recipe.Path] = digest(raw)
	snapshot, err := readRecipe(*repo, *recipe)
	if err != nil {
		t.Fatal("equivalent canonical GitHub source identity was rejected", err)
	}
	if snapshot.baseline.UpstreamRepoURL != repo.URL+".git" {
		t.Fatal("canonical matching changed the original provenance identity")
	}
	repo.URL = "https://github.com/example/different"
	_, err = readRecipe(*repo, *recipe)
	assertKind(t, err, NeedsAdapter)
}
