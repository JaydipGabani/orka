package provenance

import (
	"bytes"
	"errors"
	"maps"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

type dalecSpec struct {
	Name         string                  `yaml:"name"`
	Description  string                  `yaml:"description"`
	Website      string                  `yaml:"website"`
	Version      string                  `yaml:"version"`
	Revision     string                  `yaml:"revision"`
	License      string                  `yaml:"license"`
	Vendor       string                  `yaml:"vendor"`
	Packager     string                  `yaml:"packager"`
	Changelog    []dalecChangelog        `yaml:"changelog"`
	Tests        []dalecFileTest         `yaml:"tests"`
	Args         map[string]string       `yaml:"args"`
	Sources      map[string]dalecSource  `yaml:"sources"`
	Patches      map[string][]dalecPatch `yaml:"patches"`
	Build        dalecBuild              `yaml:"build"`
	Dependencies dalecDependencies       `yaml:"dependencies"`
	Targets      map[string]dalecTarget  `yaml:"targets"`
	Extensions   dalecExtensions         `yaml:"x-build-extensions"`
	Artifacts    yaml.Node               `yaml:"artifacts"`
	Image        yaml.Node               `yaml:"image"`
}

type dalecBuild struct {
	Env         map[string]string `yaml:"env"`
	Steps       []dalecStep       `yaml:"steps"`
	NetworkMode string            `yaml:"network_mode"`
}

type dalecStep struct {
	Command string            `yaml:"command"`
	Env     map[string]string `yaml:"env"`
}

type dalecDependencies struct {
	Build   map[string]dalecConstraint `yaml:"build"`
	Runtime map[string]dalecConstraint `yaml:"runtime"`
	Test    map[string]dalecConstraint `yaml:"test"`
}

type dalecConstraint struct {
	Version []string `yaml:"version"`
	Arch    []string `yaml:"arch"`
}

type dalecTarget struct {
	Build        dalecBuild        `yaml:"build"`
	Dependencies dalecDependencies `yaml:"dependencies"`
	Artifacts    yaml.Node         `yaml:"artifacts"`
	Image        yaml.Node         `yaml:"image"`
}

type dalecExtensions struct {
	BuildTargets   yaml.Node `yaml:"build-targets"`
	StripTagPrefix string    `yaml:"strip-tag-prefix"`
}

// ParseDalec parses a bounded, offline Dalec subset. It never opens a file,
// fetches a repository/image, executes a command, or verifies an attestation.
// Every error is deliberately independent of untrusted values and private names.
func ParseDalec(spec []byte, files map[string][]byte, metadata Metadata) (Recipe, error) {
	if err := validateInputs(spec, files, metadata); err != nil {
		return Recipe{}, err
	}
	return parseDalec(spec, files, metadata)
}

func parseDalec(spec []byte, files map[string][]byte, metadata Metadata) (Recipe, error) {
	included, exists := files[metadata.Path]
	if !exists || !bytes.Equal(spec, included) {
		return Recipe{}, errors.New("provenance requires the exact recipe bytes in the supplied files")
	}
	root, args, err := readSpec(spec, metadata.Platform)
	if err != nil {
		return Recipe{}, err
	}
	var parsed dalecSpec
	if err := decodeStrict(root, &parsed); err != nil {
		return Recipe{}, err
	}
	recipe := Recipe{
		SchemaVersion: SchemaVersion, RecipeRepository: metadata.RecipeRepository,
		RecipeCommit: strings.ToLower(metadata.RecipeCommit), Path: metadata.Path,
		ContentDigest: digestBytes(spec), Arguments: args, Target: metadata.Target, Platform: metadata.Platform,
		OrderedPatches: []Patch{}, ModuleReplacements: []string{}, BuildEnvironment: map[string]string{},
		EvidenceStatus: EvidencePartial,
		Missing:        []string{MissingAcquisition, MissingOriginalBinding, MissingControlBinding},
	}
	if err := recipe.readMetadata(spec, metadata); err != nil {
		return Recipe{}, err
	}
	if err := recipe.readVersions(parsed); err != nil {
		return Recipe{}, err
	}
	if err := recipe.matchExpectedIdentity(metadata); err != nil {
		return Recipe{}, err
	}
	if err := recipe.readBuild(parsed); err != nil {
		return Recipe{}, err
	}
	if err := validatePackageMetadata(parsed); err != nil {
		return Recipe{}, err
	}
	patchSources, err := recipe.readSources(parsed, files, metadata.UpstreamSource)
	if err != nil {
		return Recipe{}, err
	}
	if err := recipe.readEvidence(metadata); err != nil {
		return Recipe{}, err
	}
	recipe.BaseInputsDigest, err = baseDigest(root, patchSources)
	if err != nil {
		return Recipe{}, err
	}
	slices.Sort(recipe.Missing)
	recipe.Missing = slices.Compact(recipe.Missing)
	return recipe, nil
}

func (recipe *Recipe) readMetadata(spec []byte, metadata Metadata) error {
	if metadata.RecipeCommit == "" {
		recipe.Missing = append(recipe.Missing, MissingRecipeCommit)
	}
	frontend, err := syntaxFrontend(spec)
	if err != nil {
		return err
	}
	recipe.FrontendSyntax, err = parseImage(frontend, true)
	if err != nil {
		return err
	}
	recipe.Frontend = recipe.FrontendSyntax
	recipe.ObservedOriginalImage, err = parseImage(metadata.ObservedOriginalImage, false)
	if err != nil {
		return err
	}
	recipe.RebuiltControlImage, err = parseImage(metadata.RebuiltControlImage, false)
	if err != nil {
		return err
	}
	for _, missing := range []struct {
		value string
		code  string
	}{
		{recipe.ObservedOriginalImage.Digest, MissingOriginalDigest},
		{recipe.RebuiltControlImage.Digest, MissingControlDigest},
		{recipe.Target, MissingTarget},
		{recipe.Platform, MissingPlatform},
	} {
		if missing.value == "" {
			recipe.Missing = append(recipe.Missing, missing.code)
		}
	}
	if (recipe.Target != "" && !safePath(recipe.Target)) ||
		(recipe.Platform != "" && !validPlatform(recipe.Platform)) {
		return errors.New("provenance requires a safe explicit target and platform")
	}
	return nil
}

func syntaxFrontend(spec []byte) (string, error) {
	var frontend string
	for line := range strings.SplitSeq(string(spec), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		comment, isComment := strings.CutPrefix(line, "#")
		if !isComment {
			break
		}
		key, value, assignment := strings.Cut(strings.TrimSpace(comment), "=")
		if strings.TrimSpace(key) != "syntax" || !assignment {
			break
		}
		if frontend != "" || strings.TrimSpace(value) == "" {
			return "", errors.New("provenance requires at most one nonempty frontend syntax directive")
		}
		frontend = strings.TrimSpace(value)
	}
	return frontend, nil
}

func (recipe *Recipe) readVersions(parsed dalecSpec) error {
	recipe.Version, recipe.Revision = parsed.Version, parsed.Revision
	for _, field := range []struct {
		value   *string
		arg     string
		missing string
		valid   func(string) bool
	}{
		{&recipe.Version, "VERSION", MissingVersion, safeVersion},
		{&recipe.Revision, "REVISION", MissingRevision, validRevision},
	} {
		argument, found := recipe.Arguments[field.arg]
		if *field.value == "" {
			*field.value = argument
		} else if found && *field.value != argument {
			return errors.New("provenance recipe version or revision conflicts with its arguments")
		}
		if *field.value == "" {
			recipe.Missing = append(recipe.Missing, field.missing)
		} else if !field.valid(*field.value) {
			return errors.New("provenance contains an unsupported version or revision")
		}
	}
	return nil
}

func (recipe *Recipe) readBuild(parsed dalecSpec) error {
	targets, err := readBuildTargets(&parsed.Extensions.BuildTargets)
	if err != nil {
		return err
	}
	recipe.BuildTargets = targets
	if err := checkSelection(recipe.Target, recipe.Platform, targets); err != nil {
		return err
	}
	if err := validateBuild(parsed.Build); err != nil {
		return err
	}
	maps.Copy(recipe.BuildEnvironment, parsed.Build.Env)
	recipe.BuildNetworkMode = parsed.Build.NetworkMode
	for name, target := range parsed.Targets {
		if !safePath(name) {
			return errors.New("provenance contains an unsafe target name")
		}
		if err := validateBuild(target.Build); err != nil {
			return err
		}
		if hasDependencies(target.Dependencies) || target.Image.Kind != 0 {
			recipe.Missing = append(recipe.Missing, MissingDependencyIdentity)
		}
	}
	// Dalec targets commonly select a frontend namespace and output, e.g.
	// distro/container. Do not combine ambiguous exact and namespace overrides.
	namespace, _, _ := strings.Cut(recipe.Target, "/")
	exact, exactExists := parsed.Targets[recipe.Target]
	scope, scopeExists := parsed.Targets[namespace]
	if exactExists && scopeExists && namespace != recipe.Target {
		return errors.New("provenance target has ambiguous build overrides")
	}
	if exactExists {
		maps.Copy(recipe.BuildEnvironment, exact.Build.Env)
		if exact.Build.NetworkMode != "" {
			recipe.BuildNetworkMode = exact.Build.NetworkMode
		}
	} else if scopeExists {
		maps.Copy(recipe.BuildEnvironment, scope.Build.Env)
		if scope.Build.NetworkMode != "" {
			recipe.BuildNetworkMode = scope.Build.NetworkMode
		}
	}
	if hasDependencies(parsed.Dependencies) || parsed.Image.Kind != 0 {
		recipe.Missing = append(recipe.Missing, MissingDependencyIdentity)
	}
	return nil
}

func validateBuild(build dalecBuild) error {
	if build.NetworkMode != "" && build.NetworkMode != "none" && build.NetworkMode != "sandbox" {
		return errors.New("provenance build network mode is unsupported")
	}
	if err := safeVariables(build.Env); err != nil {
		return err
	}
	for _, step := range build.Steps {
		if step.Command == "" {
			return errors.New("provenance build steps require a command")
		}
		if err := safeVariables(step.Env); err != nil {
			return err
		}
	}
	return nil
}

func hasDependencies(dependencies dalecDependencies) bool {
	return len(dependencies.Build)+len(dependencies.Runtime)+len(dependencies.Test) > 0
}

func readBuildTargets(node *yaml.Node) ([]BuildTarget, error) {
	targets := []BuildTarget{}
	switch node.Kind {
	case 0:
		return targets, nil
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode || item.Tag != yamlStringTag {
				return nil, errors.New("provenance build targets must be named strings")
			}
			targets = append(targets, BuildTarget{Name: item.Value, Platforms: []string{}})
		}
	case yaml.MappingNode:
		for index := 0; index < len(node.Content); index += 2 {
			var target struct {
				Platforms []string `yaml:"platforms"`
			}
			if err := decodeStrict(node.Content[index+1], &target); err != nil {
				return nil, err
			}
			if len(target.Platforms) == 0 {
				return nil, errors.New("provenance platform-constrained build targets require platforms")
			}
			targets = append(targets, BuildTarget{Name: node.Content[index].Value, Platforms: target.Platforms})
		}
		slices.SortFunc(targets, func(left, right BuildTarget) int {
			return strings.Compare(left.Name, right.Name)
		})
	default:
		return nil, errors.New("provenance build targets have an unsupported shape")
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		if !safePath(target.Name) || seen[target.Name] {
			return nil, errors.New("provenance contains duplicate or unsafe build targets")
		}
		seen[target.Name] = true
		platforms := make(map[string]bool, len(target.Platforms))
		for _, platform := range target.Platforms {
			if !validPlatform(platform) || platforms[platform] {
				return nil, errors.New("provenance contains duplicate or unsupported platforms")
			}
			platforms[platform] = true
		}
	}
	return targets, nil
}

func checkSelection(target, platform string, targets []BuildTarget) error {
	if target == "" || len(targets) == 0 {
		return nil
	}
	for _, declared := range targets {
		if declared.Name == target {
			if platform != "" && len(declared.Platforms) > 0 && !slices.Contains(declared.Platforms, platform) {
				return errors.New("provenance selected platform is not declared by the build target")
			}
			return nil
		}
	}
	return errors.New("provenance selected build target is not declared")
}
