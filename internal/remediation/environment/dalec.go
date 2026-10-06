package environment

import (
	"bytes"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/orka-agents/orka/internal/remediation/disclosure"
	"github.com/orka-agents/orka/internal/remediation/provenance"
	"github.com/orka-agents/orka/internal/security"
	"go.yaml.in/yaml/v3"
)

type recipeSnapshot struct {
	files     map[string][]byte
	metadata  provenance.Metadata
	baseline  provenance.Recipe
	built     provenance.Recipe
	buildOnly []provenance.InputDisposition
}

func (a *Adapter) recipeSnapshot(request BuildRequest) (recipeSnapshot, error) {
	repo, policy, err := a.policy(request.Plan.Bind)
	if err != nil {
		return recipeSnapshot{}, err
	}
	result, err := readRecipe(*repo, *policy)
	if err != nil {
		return recipeSnapshot{}, err
	}
	if len(result.buildOnly) != 0 && !a.HasPrivateBuildBoundary() {
		return recipeSnapshot{}, failure(NeedsAdapter, "private-build-input-isolation-required")
	}
	if result.baseline.UpstreamCommit != request.Plan.Bind.SourceTarget.Commit {
		return recipeSnapshot{}, failure(NeedsAdapter, "recipe-source-commit-mismatch")
	}
	if request.Role == RebuiltControl {
		return result, nil
	}
	if disclosure.Check(disclosure.Candidate, request.Patch) != nil {
		return recipeSnapshot{}, failure(NeedsAdapter, "candidate-disclosure-policy-blocked")
	}
	files, metadata, baseline := result.files, result.metadata, result.baseline
	updated, patchName, err := appendDalecPatch(files[policy.Path], baseline.UpstreamSource, request.PatchDigest)
	if err != nil {
		return recipeSnapshot{}, err
	}
	if _, exists := files[patchName]; exists {
		return recipeSnapshot{}, failure(NeedsAdapter, "candidate-patch-path-collision")
	}
	files[policy.Path], files[patchName] = updated, bytes.Clone(request.Patch)
	metadata.ExpectedDigests[policy.Path], metadata.ExpectedDigests[patchName] = digest(updated), request.PatchDigest
	classified, err := provenance.InspectPrivateBuildInputs(updated, files, metadata)
	candidate := classified.Recipe
	if err != nil {
		return recipeSnapshot{}, failure(NeedsAdapter, "candidate-recipe-provenance-mismatch")
	}
	// The candidate passed the shared disclosure gate above. Opaque baseline
	// classification must not reinterpret code references as new credentials.
	baselineOnly := slices.DeleteFunc(classified.BuildOnly, func(input provenance.InputDisposition) bool {
		return input.Path == patchName && input.Digest == request.PatchDigest
	})
	if !slices.Equal(baselineOnly, result.buildOnly) ||
		provenance.CompareWithAdditionalPatch(baseline, candidate, request.PatchDigest) != nil {
		return recipeSnapshot{}, failure(NeedsAdapter, "candidate-recipe-provenance-mismatch")
	}
	result.built, result.metadata = candidate, metadata
	return result, nil
}

func readRecipe(repo RepositoryPolicy, policy RecipePolicy) (recipeSnapshot, error) {
	files := make(map[string][]byte, len(policy.Files)+1)
	total := 0
	for name, expected := range policy.Files {
		content, err := readApprovedFile(repo.RecipeRoot, path.Join(policy.CatalogDirectory, name), provenance.MaxFileBytes)
		if err != nil || digest(content) != expected {
			return recipeSnapshot{}, failure(NeedsAdapter, "approved-recipe-file-mismatch")
		}
		total += len(content)
		if total > provenance.MaxTotalBytes {
			return recipeSnapshot{}, failure(NeedsAdapter, "recipe-input-limit")
		}
		files[name] = content
	}
	metadata := provenance.Metadata{
		RecipeRepository: repo.RecipeRepository, RecipeCommit: policy.Commit, Path: policy.Path,
		UpstreamSource: policy.UpstreamSource, Target: policy.Target, Platform: policy.Platform,
		ObservedOriginalImage: policy.OriginalImage, ExpectedDigests: maps.Clone(policy.Files),
		ExpectedVersion: policy.ExpectedVersion, ExpectedRevision: policy.ExpectedRevision, AttestedInputs: policy.AttestedInputs,
	}
	if err := offlineRecipe(files[policy.Path]); err != nil {
		return recipeSnapshot{}, err
	}
	classified, err := provenance.InspectPrivateBuildInputs(files[policy.Path], files, metadata)
	baseline := classified.Recipe
	if err != nil {
		return recipeSnapshot{}, failure(NeedsAdapter, "unsupported-approved-dalec-recipe")
	}
	if security.CanonicalRepositoryCloneURL(baseline.UpstreamRepoURL) != security.CanonicalRepositoryCloneURL(repo.URL) ||
		baseline.Frontend.Reference != policy.FrontendImage ||
		(baseline.BuildNetworkMode != "" && baseline.BuildNetworkMode != "none") ||
		provenance.Compare(baseline, baseline) != nil {
		return recipeSnapshot{}, failure(NeedsAdapter, "recipe-source-or-frontend-mismatch")
	}
	return recipeSnapshot{files: files, metadata: metadata, baseline: baseline, built: baseline, buildOnly: classified.BuildOnly}, nil
}

func offlineRecipe(raw []byte) error {
	var document yaml.Node
	if yaml.Unmarshal(raw, &document) != nil || len(document.Content) != 1 {
		return failure(NeedsAdapter, "invalid-build-network-policy")
	}
	build := yamlValue(document.Content[0], "build")
	if build == nil {
		return failure(NeedsAdapter, "build-policy-required")
	}
	if network := yamlValue(build, "network_mode"); network != nil && network.Value != "" && network.Value != "none" {
		return failure(NeedsAdapter, "candidate-build-must-be-network-isolated")
	}
	if caches := yamlValue(build, "caches"); caches != nil && len(caches.Content) != 0 {
		return failure(NeedsAdapter, "shared-build-cache-mounts-unsupported")
	}
	return nil
}

type insertion struct {
	offset int
	text   string
	order  int
}

// Only insert at parsed block boundaries. Re-encoding the YAML would silently
// replace the original bytes; textual search for "build:" could hit a script or
// a comment. Unsupported flow collections fail closed instead.
func appendDalecPatch(original []byte, source, patchDigest string) ([]byte, string, error) {
	var document yaml.Node
	if !digestPattern.MatchString(patchDigest) || yaml.Unmarshal(original, &document) != nil ||
		len(document.Content) != 1 {
		return nil, "", failure(NeedsAdapter, "dalec-safe-insertion-anchor-required")
	}
	root := document.Content[0]
	sources := yamlValue(root, "sources")
	if sources == nil || sources.Kind != yaml.MappingNode || sources.Style&yaml.FlowStyle != 0 ||
		len(sources.Content) == 0 {
		return nil, "", failure(NeedsAdapter, "dalec-safe-insertion-anchor-required")
	}
	lines := bytes.SplitAfter(original, []byte("\n"))
	offsets := make([]int, len(lines)+1)
	for i, line := range lines {
		if strings.TrimSpace(string(line)) == "..." {
			return nil, "", failure(NeedsAdapter, "dalec-safe-insertion-anchor-required")
		}
		offsets[i+1] = offsets[i] + len(line)
	}
	blockEnd := func(key string) int {
		for i := 0; i < len(root.Content); i += 2 {
			if root.Content[i].Value == key {
				if i+2 < len(root.Content) {
					return offsets[root.Content[i+2].Line-1]
				}
				return len(original)
			}
		}
		return len(original)
	}
	name := "orka-candidate-" + strings.TrimPrefix(patchDigest, "sha256:")
	patchName := name + ".patch"
	if yamlValue(sources, name) != nil {
		return nil, "", failure(NeedsAdapter, "candidate-patch-path-collision")
	}
	indent := strings.Repeat(" ", sources.Content[0].Column-1)
	additions := []insertion{{
		offset: blockEnd("sources"),
		text:   indent + name + ":\n" + indent + "  context: {name: context}\n" + indent + "  includes: [" + patchName + "]\n",
	}}
	patches := yamlValue(root, "patches")
	if patches == nil {
		additions = append(additions, insertion{
			offset: len(original), order: 1,
			text: "patches:\n  " + source + ":\n    - source: " + name + "\n      path: " + patchName + "\n      strip: 1\n",
		})
	} else {
		series := yamlValue(patches, source)
		if patches.Kind != yaml.MappingNode || patches.Style&yaml.FlowStyle != 0 ||
			series == nil || series.Kind != yaml.SequenceNode || series.Style&yaml.FlowStyle != 0 ||
			len(series.Content) == 0 {
			return nil, "", failure(NeedsAdapter, "dalec-safe-insertion-anchor-required")
		}
		indent := strings.Repeat(" ", series.Column-1)
		additions = append(additions, insertion{
			offset: blockEnd("patches"), order: 1,
			text: indent + "- source: " + name + "\n" + indent + "  path: " + patchName + "\n" + indent + "  strip: 1\n",
		})
	}
	slices.SortStableFunc(additions, func(a, b insertion) int {
		if a.offset != b.offset {
			return a.offset - b.offset
		}
		return a.order - b.order
	})
	newline := "\n"
	if bytes.Contains(original, []byte("\r\n")) {
		newline = "\r\n"
	}
	var result bytes.Buffer
	offset := 0
	for _, add := range additions {
		if add.offset < offset || add.offset > len(original) {
			return nil, "", failure(NeedsAdapter, "dalec-safe-insertion-anchor-required")
		}
		result.Write(original[offset:add.offset])
		if result.Len() != 0 && result.Bytes()[result.Len()-1] != '\n' {
			result.WriteString(newline)
		}
		result.WriteString(strings.ReplaceAll(add.text, "\n", newline))
		offset = add.offset
	}
	result.Write(original[offset:])
	if result.Len() > provenance.MaxSpecBytes {
		return nil, "", failure(NeedsAdapter, "candidate-recipe-size-limit")
	}
	return result.Bytes(), patchName, nil
}

func yamlValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func buildArguments(b BuildKitConfig, recipe RecipeIdentity, contextRoot, metadataPath, output string) []string {
	args := append([]string{}, b.Command[1:]...)
	return append(args,
		"--addr", b.Address, "build",
		"--frontend", "gateway.v0",
		"--opt", "source="+recipe.FrontendImage,
		"--opt", "filename="+recipe.Path,
		"--opt", "target="+recipe.Target,
		"--opt", "platform="+recipe.Platform,
		"--opt", "build-arg:"+b.WorkerImageArgument+"="+recipe.WorkerImage,
		"--local", "context="+contextRoot,
		"--local", "dockerfile="+contextRoot,
		"--output", fmt.Sprintf("type=image,name=%s,push=true", output),
		"--metadata-file", metadataPath,
		"--progress", "plain",
	)
}
