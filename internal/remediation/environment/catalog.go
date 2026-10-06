package environment

import (
	"cmp"
	"slices"
)

const (
	maxCatalogRecipes = 128
	maxCatalogBytes   = 64 << 20
)

type catalogEntry struct {
	choice    RecipeChoice
	bind      Bind
	buildOnly map[string]string
}

func loadCatalog(config Config) ([]catalogEntry, error) {
	entries := make([]catalogEntry, 0)
	total := 0
	for _, repo := range config.Repositories {
		for _, policy := range repo.Recipes {
			if len(entries) >= maxCatalogRecipes {
				return nil, failure(NeedsAdapter, "approved-recipe-catalog-limit")
			}
			snapshot, err := readRecipe(repo, policy)
			if err != nil {
				return nil, err
			}
			for _, content := range snapshot.files {
				total += len(content)
			}
			if total > maxCatalogBytes {
				return nil, failure(NeedsAdapter, "approved-recipe-catalog-limit")
			}
			entries = append(entries, catalogSelection(repo, policy, snapshot))
		}
	}
	slices.SortFunc(entries, func(a, b catalogEntry) int {
		return cmp.Or(cmp.Compare(a.choice.SourceTarget.Repository, b.choice.SourceTarget.Repository),
			cmp.Compare(a.choice.SourceTarget.Commit, b.choice.SourceTarget.Commit), cmp.Compare(a.choice.ID, b.choice.ID))
	})
	return entries, nil
}

func catalogSelection(repo RepositoryPolicy, policy RecipePolicy, snapshot recipeSnapshot) catalogEntry {
	baseline := snapshot.baseline
	choice := RecipeChoice{
		ID: policy.ID, SourceTarget: SourceTarget{Repository: repo.URL, Commit: baseline.UpstreamCommit},
		Version: baseline.Version, Revision: baseline.Revision, Target: policy.Target, Platform: policy.Platform,
		RecipeDigest: baseline.ContentDigest, OriginalImage: policy.OriginalImage,
		OrderedPatchDigests: []string{}, HTTPPorts: slices.Clone(repo.HTTPPorts),
		SupportedChecks: []string{}, NeedsAdapterChecks: []string{},
	}
	for _, patch := range baseline.OrderedPatches {
		choice.OrderedPatchDigests = append(choice.OrderedPatchDigests, patch.Digest)
	}
	for _, capability := range repo.CheckCapabilities {
		if capability == HTTPExact {
			choice.SupportedChecks = append(choice.SupportedChecks, capability)
		} else {
			choice.NeedsAdapterChecks = append(choice.NeedsAdapterChecks, capability)
		}
	}
	slices.Sort(choice.HTTPPorts)
	slices.Sort(choice.SupportedChecks)
	slices.Sort(choice.NeedsAdapterChecks)
	choice.HTTPPorts = slices.Compact(choice.HTTPPorts)
	choice.SupportedChecks = slices.Compact(choice.SupportedChecks)
	choice.NeedsAdapterChecks = slices.Compact(choice.NeedsAdapterChecks)
	privateInputs := make(map[string]string, len(snapshot.buildOnly))
	for _, input := range snapshot.buildOnly {
		privateInputs[input.Path] = input.Digest
	}
	if len(privateInputs) == 0 {
		privateInputs = nil
	}
	return catalogEntry{
		choice:    choice,
		buildOnly: privateInputs,
		bind: Bind{
			SourceTarget: choice.SourceTarget,
			Recipe: RecipeIdentity{
				ID: policy.ID, Repository: repo.RecipeRepository, Commit: policy.Commit, Path: policy.Path,
				ContentDigest: baseline.ContentDigest, Target: policy.Target, Platform: policy.Platform,
				FrontendImage: policy.FrontendImage, WorkerImage: policy.WorkerImage,
			},
		},
	}
}

// RecipeChoices returns deterministic, detached discovery records. No host
// roots, context paths, file contents, executable arguments, or credentials are
// exposed. SupportedChecks names implemented primitives, not live readiness.
func (a *Adapter) RecipeChoices() []RecipeChoice {
	choices := make([]RecipeChoice, 0, len(a.catalog))
	for _, entry := range a.catalog {
		choices = append(choices, cloneChoice(entry.choice))
	}
	return choices
}

// MatchTarget resolves an exact approved upstream commit, never a version guess
// or a tag. Multiple target/platform recipes require explicit ID selection through
// BindRecipe rather than a first-match fallback.
func (a *Adapter) MatchTarget(repository, commit string) (RecipeChoice, error) {
	if !repositoryURL(repository) || !commitPattern.MatchString(commit) {
		return RecipeChoice{}, failure(NeedsAdapter, "exact-catalog-source-target-required")
	}
	var selected *RecipeChoice
	for _, entry := range a.catalog {
		if entry.choice.SourceTarget != (SourceTarget{Repository: repository, Commit: commit}) {
			continue
		}
		if selected != nil {
			return RecipeChoice{}, failure(NeedsAdapter, "ambiguous-approved-recipe")
		}
		choice := entry.choice
		selected = &choice
	}
	if selected == nil {
		return RecipeChoice{}, failure(NeedsAdapter, "approved-recipe-not-found")
	}
	return cloneChoice(*selected), nil
}

// BindRecipe fills the trusted portion of Plan.Bind from a catalog ID plus the
// already-resolved source target. FreezePlan subsequently fills ChecksDigest.
func (a *Adapter) BindRecipe(target SourceTarget, recipeID string) (Bind, error) {
	if !repositoryURL(target.Repository) || !commitPattern.MatchString(target.Commit) || !idPattern.MatchString(recipeID) {
		return Bind{}, failure(NeedsAdapter, "invalid-recipe-selection")
	}
	for _, entry := range a.catalog {
		if entry.choice.ID == recipeID && entry.choice.SourceTarget == target {
			return entry.bind, nil
		}
	}
	return Bind{}, failure(NeedsAdapter, "approved-recipe-not-found")
}

func cloneChoice(choice RecipeChoice) RecipeChoice {
	choice.OrderedPatchDigests = slices.Clone(choice.OrderedPatchDigests)
	choice.HTTPPorts = slices.Clone(choice.HTTPPorts)
	choice.SupportedChecks = slices.Clone(choice.SupportedChecks)
	choice.NeedsAdapterChecks = slices.Clone(choice.NeedsAdapterChecks)
	return choice
}
