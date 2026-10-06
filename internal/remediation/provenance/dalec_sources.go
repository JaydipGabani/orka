package provenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"path"
	"slices"
	"strings"
)

type dalecSource struct {
	Git      *dalecGit        `yaml:"git"`
	Context  *dalecContext    `yaml:"context"`
	Inline   *dalecInline     `yaml:"inline"`
	Path     string           `yaml:"path"`
	Includes []string         `yaml:"includes"`
	Generate []dalecGenerator `yaml:"generate"`
}

type dalecGit struct {
	URL        string `yaml:"url"`
	Commit     string `yaml:"commit"`
	KeepGitDir bool   `yaml:"keepGitDir"`
}

type dalecContext struct {
	Name string `yaml:"name"`
}

type dalecInline struct {
	File *dalecInlineFile `yaml:"file"`
}

type dalecInlineFile struct {
	Contents string `yaml:"contents"`
}

type dalecGenerator struct {
	Gomod *dalecGomod `yaml:"gomod"`
}

type dalecGomod struct {
	Paths []string `yaml:"paths"`
	Edits struct {
		Replace []string `yaml:"replace"`
	} `yaml:"edits"`
}

type dalecPatch struct {
	Source string `yaml:"source"`
	Path   string `yaml:"path"`
	Strip  *int   `yaml:"strip"`
}

func (recipe *Recipe) readSources(parsed dalecSpec, files map[string][]byte, selected string) (map[string]bool, error) {
	gitNames := []string{}
	for _, name := range slices.Sorted(maps.Keys(parsed.Sources)) {
		source := parsed.Sources[name]
		if !safeName(name) || (source.Path != "" && source.Path != "." && !safePath(source.Path)) {
			return nil, errors.New("provenance contains an unsafe source name or path")
		}
		if err := validateContextIncludes(source); err != nil {
			return nil, err
		}
		if source.Git == nil {
			continue
		}
		if source.Context != nil || source.Inline != nil || !safeRepository(source.Git.URL) {
			return nil, errors.New("provenance requires credential-free Git sources")
		}
		if source.Git.Commit != "" && !exactCommit(source.Git.Commit) {
			return nil, errors.New("provenance Git sources require exact object IDs")
		}
		if source.Git.Commit == "" {
			recipe.Missing = append(recipe.Missing, MissingUpstreamCommit)
		}
		gitNames = append(gitNames, name)
		if err := recipe.readModules(source.Generate); err != nil {
			return nil, err
		}
	}
	if selected == "" && len(gitNames) == 1 {
		selected = gitNames[0]
	}
	if !safeName(selected) || !slices.Contains(gitNames, selected) {
		return nil, errors.New("provenance requires an unambiguous selected Git source")
	}
	recipe.UpstreamSource = selected
	upstream := parsed.Sources[selected].Git
	recipe.UpstreamRepoURL, recipe.UpstreamCommit = upstream.URL, strings.ToLower(upstream.Commit)
	if commit, found := recipe.Arguments["COMMIT"]; found &&
		(!exactCommit(commit) || strings.ToLower(commit) != recipe.UpstreamCommit) {
		return nil, errors.New("provenance upstream commit conflicts with its argument")
	}
	patchSources, err := recipe.readPatches(parsed, files)
	if err != nil {
		return nil, err
	}
	for name, source := range parsed.Sources {
		if source.Git == nil && !patchSources[name] {
			return nil, errors.New("provenance contains an unsupported or unclaimed non-Git source")
		}
	}
	return patchSources, nil
}

func (recipe *Recipe) readModules(generators []dalecGenerator) error {
	for _, generator := range generators {
		if generator.Gomod == nil {
			return errors.New("provenance contains an unsupported source generator")
		}
		recipe.Missing = append(recipe.Missing, MissingDependencyIdentity)
		for _, directory := range generator.Gomod.Paths {
			if directory != "." && !safePath(directory) {
				return errors.New("provenance contains an unsafe module directory")
			}
		}
		for _, replacement := range generator.Gomod.Edits.Replace {
			if !validModuleReplacement(replacement) {
				return errors.New("provenance contains an unsupported module replacement")
			}
			recipe.ModuleReplacements = append(recipe.ModuleReplacements, replacement)
		}
	}
	return nil
}

func validModuleReplacement(value string) bool {
	if !safeText(value, maxValueSize) || strings.ContainsAny(value, "\r\n$`\\") {
		return false
	}
	old, replacement, found := strings.Cut(value, " => ")
	if found {
		old, replacement = strings.TrimSpace(old), strings.TrimSpace(replacement)
	} else {
		old, replacement, found = strings.Cut(value, "=")
	}
	if !found || strings.Contains(replacement, "=") {
		return false
	}
	if strings.ContainsAny(old+replacement, " \t") {
		return false
	}
	oldPath, oldVersion, versioned := strings.Cut(old, "@")
	newPath, newVersion, pinned := strings.Cut(replacement, "@")
	return validModulePath(oldPath) && (!versioned || moduleVersion.MatchString(oldVersion)) &&
		validModulePath(newPath) && pinned && moduleVersion.MatchString(newVersion)
}

func validModulePath(value string) bool {
	domain, _, found := strings.Cut(value, "/")
	return found && strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".") && safePath(value)
}

func (recipe *Recipe) readPatches(parsed dalecSpec, files map[string][]byte) (map[string]bool, error) {
	for name := range parsed.Patches {
		if name != recipe.UpstreamSource {
			return nil, errors.New("provenance supports a patch series for the selected Git source only")
		}
	}
	patchSources := make(map[string]bool)
	usedFiles := map[string]bool{recipe.Path: true}
	for _, entry := range parsed.Patches[recipe.UpstreamSource] {
		source, exists := parsed.Sources[entry.Source]
		if !exists || !safeName(entry.Source) {
			return nil, errors.New("provenance patch references a missing source")
		}
		file, err := patchFile(entry, source)
		if err != nil {
			return nil, err
		}
		content, exists := files[file]
		if !exists || len(content) == 0 || usedFiles[file] {
			return nil, errors.New("provenance patch file is missing, empty, or repeated")
		}
		if source.Inline != nil && !bytes.Equal(content, []byte(source.Inline.File.Contents)) {
			return nil, errors.New("provenance inline patch bytes do not match the supplied file")
		}
		strip := 1
		if entry.Strip != nil {
			strip = *entry.Strip
		}
		if strip < 0 || strip > maxPatchStrip {
			return nil, errors.New("provenance patch strip count is unsupported")
		}
		inputDigest, err := patchInputDigest(entry, source)
		if err != nil {
			return nil, err
		}
		recipe.OrderedPatches = append(recipe.OrderedPatches, Patch{
			Path: file, Digest: digestBytes(content), InputDigest: inputDigest, Source: recipe.UpstreamSource, Strip: strip,
		})
		patchSources[entry.Source], usedFiles[file] = true, true
	}
	for file := range files {
		if !usedFiles[file] {
			return nil, errors.New("provenance contains an unclaimed supplied file")
		}
	}
	return patchSources, nil
}

func patchFile(entry dalecPatch, source dalecSource) (string, error) {
	if source.Git != nil || len(source.Generate) != 0 ||
		(entry.Path != "" && !safePath(entry.Path)) {
		return "", errors.New("provenance patches require inert local file sources")
	}
	var file string
	switch {
	case source.Context != nil && source.Inline == nil:
		if (source.Context.Name != "" && source.Context.Name != "context") || entry.Path == "" {
			return "", errors.New("provenance does not support alternate patch build contexts")
		}
		file = path.Join(source.Path, entry.Path)
		if len(source.Includes) != 0 && !slices.ContainsFunc(source.Includes, func(include string) bool {
			return entry.Path == include || strings.HasPrefix(entry.Path, include+"/")
		}) {
			return "", errors.New("provenance patch is excluded by its context source")
		}
	case source.Inline != nil && source.Context == nil:
		if source.Inline.File == nil || source.Path != "" || entry.Path != "" {
			return "", errors.New("provenance only supports whole inline patch files")
		}
		file = entry.Source
	default:
		return "", errors.New("provenance patches require an unambiguous local source")
	}
	if !safePath(file) {
		return "", errors.New("provenance contains an unsafe patch file path")
	}
	return file, nil
}

// Keep the source name and the two path selections distinct: changing them can
// change the build's source layout despite resolving to the same patch bytes.
func patchInputDigest(entry dalecPatch, source dalecSource) (string, error) {
	identity := struct {
		Domain      string   `json:"domain"`
		SourceName  string   `json:"sourceName"`
		Kind        string   `json:"kind"`
		ContextName string   `json:"contextName"`
		SourcePath  string   `json:"sourcePath"`
		PatchPath   string   `json:"patchPath"`
		Includes    []string `json:"includes,omitempty"`
	}{
		Domain: "orka.build-provenance.patch-input.v1", SourceName: entry.Source,
		Kind: "inline", SourcePath: source.Path, PatchPath: entry.Path,
		Includes: source.Includes,
	}
	if len(source.Includes) != 0 {
		identity.Domain = "orka.build-provenance.patch-input.v2"
	}
	if source.Context != nil {
		identity.Kind, identity.ContextName = "context", source.Context.Name
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return "", errors.New("provenance patch inputs could not be digested")
	}
	return digestBytes(data), nil
}

func validateContextIncludes(source dalecSource) error {
	if len(source.Includes) == 0 {
		return nil
	}
	if source.Context == nil || source.Git != nil || source.Inline != nil || len(source.Includes) > 64 {
		return errors.New("provenance include paths require a local patch context")
	}
	seen := make(map[string]bool)
	for _, include := range source.Includes {
		if !safePath(include) || seen[include] {
			return errors.New("provenance context includes require unique literal relative paths")
		}
		seen[include] = true
	}
	return nil
}
