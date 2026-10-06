package investigate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/remediation/source"
)

const (
	maxPromptBytes = 256 << 10
	maxPacketBytes = 256 << 10
	maxStateBytes  = 8 << 20
)

var (
	ErrConfig          = errors.New("investigation configuration is invalid or exceeds its bounds")
	ErrState           = errors.New("investigation state or accepted identity does not match the frozen request")
	ErrReport          = errors.New("investigation requires a bounded normalized report")
	ErrModelOperation  = errors.New("investigation model operation did not complete")
	ErrSourceOperation = errors.New("investigation source operation did not complete")

	repositoryOwner       = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repositoryName        = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	requirementName       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	catalogVersion        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$`)
	affectedVersionClause = regexp.MustCompile(`(?i)\b(?:affected|vulnerable|impacted)\s+(?:versions?|releases?)\b[^\n]{0,256}`)
	versionClaim          = regexp.MustCompile(`(?i)\bv?[0-9]+\.[0-9]+(?:\.[0-9]+){0,2}(?:-[0-9a-z]+(?:[.-][0-9a-z]+)*)?`)
	versionRangeClaim     = regexp.MustCompile(`(?i)[<>]|\.[x*]|\b(?:all|before|through|until|older|earlier|range)\b|[0-9]\s*[-–]\s*v?[0-9]+\.`)
)

func normalizeConfig(config Config) (Config, string, error) {
	config.AllowedRepositoryRoots = slices.Clone(config.AllowedRepositoryRoots)
	if len(config.AllowedRepositoryRoots) == 0 || len(config.AllowedRepositoryRoots) > 64 {
		return Config{}, "", ErrConfig
	}
	for index, root := range config.AllowedRepositoryRoots {
		canonical := canonicalRepository(root)
		if canonical == "" {
			return Config{}, "", ErrConfig
		}
		config.AllowedRepositoryRoots[index] = strings.ToLower(canonical)
	}
	slices.Sort(config.AllowedRepositoryRoots)
	config.AllowedRepositoryRoots = slices.Compact(config.AllowedRepositoryRoots)
	var err error
	config.SourceCatalog, err = catalogHints(config)
	if err != nil {
		return Config{}, "", err
	}
	for _, limit := range []struct {
		value *int
		max   int
	}{
		{&config.MaxCandidates, 4}, {&config.MaxFiles, 32},
		{&config.MaxDiscoveryRounds, 3}, {&config.MaxSelectionRounds, 3},
		{&config.MaxPlanJSONBytes, maxStateBytes},
	} {
		if *limit.value == 0 {
			*limit.value = limit.max
		}
		if *limit.value < 1 || *limit.value > limit.max {
			return Config{}, "", ErrConfig
		}
	}
	if config.RepositoryHint != "" {
		config.RepositoryHint = canonicalRepository(config.RepositoryHint)
		if config.RepositoryHint == "" || !allowedRepository(config, config.RepositoryHint) {
			return Config{}, "", ErrConfig
		}
	}
	if config.RefHint != "" && (config.RepositoryHint == "" || !validRef(config.RefHint)) {
		return Config{}, "", ErrConfig
	}
	if config.MaxTurns != 0 {
		return Config{}, "", ErrConfig
	}

	policy := config
	policy.RequestTaskName, policy.ExpectedTaskUID = "", ""
	data, err := json.Marshal(policy)
	if err != nil || (pv.CredentialMatcher{}).Match(data) {
		return Config{}, "", ErrConfig
	}
	return config, digest(data), nil
}

func catalogHints(config Config) ([]SourceCatalogEntry, error) {
	if len(config.SourceCatalog) > 128 {
		return nil, ErrConfig
	}
	hints := slices.Clone(config.SourceCatalog)
	for index, hint := range hints {
		if !allowedRepository(config, hint.Repository) || !validObjectID(hint.Commit) ||
			!catalogVersion.MatchString(hint.Version) || (hint.Revision != "" && !requirementName.MatchString(hint.Revision)) ||
			!text(hint.VerificationContract, 4096, false) {
			return nil, ErrConfig
		}
		hints[index].Repository = strings.ToLower(canonicalRepository(hint.Repository))
	}
	slices.SortFunc(hints, func(first, second SourceCatalogEntry) int {
		for _, fields := range [][2]string{
			{first.Repository, second.Repository}, {first.Commit, second.Commit},
			{first.Version, second.Version}, {first.Revision, second.Revision},
			{first.VerificationContract, second.VerificationContract},
		} {
			if comparison := strings.Compare(fields[0], fields[1]); comparison != 0 {
				return comparison
			}
		}
		return 0
	})
	return slices.Compact(hints), nil
}

func reportData(report intake.Report) ([]byte, error) {
	if report.Version != intake.SchemaVersion || !validDigest(report.SourceDigest) ||
		!text(report.SourceKind, 64, true) || !text(report.SourceID, 256, false) ||
		!text(report.Title, 4096, false) || (len(report.Sections) == 0 && !missingReport(report)) || len(report.Sections) > 128 ||
		!stringList(report.Repositories, 32, 512) || !stringList(report.Versions, 64, 256) ||
		!stringList(report.Warnings, 128, 256) {
		return nil, ErrReport
	}
	for _, section := range report.Sections {
		if !text(section.Kind, 256, true) || !text(section.Text, 64<<10, true) ||
			!text(section.SourcePointer, 1024, false) {
			return nil, ErrReport
		}
	}
	data, err := json.Marshal(report)
	if err != nil || len(data) > maxPromptBytes || (pv.CredentialMatcher{}).Match(data) {
		return nil, ErrReport
	}
	return data, nil
}

func canonicalRepository(raw string) string {
	const prefix = "https://github.com/"
	if !strings.HasPrefix(raw, prefix) {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(raw, prefix), "/")
	if len(parts) != 2 || !repositoryOwner.MatchString(parts[0]) {
		return ""
	}
	name := strings.TrimSuffix(parts[1], ".git")
	if !repositoryName.MatchString(name) || name == "." || name == ".." || strings.HasSuffix(name, ".git") {
		return ""
	}
	return prefix + parts[0] + "/" + name
}

func allowedRepository(config Config, repository string) bool {
	root := canonicalRepository(repository)
	return root != "" && slices.Contains(config.AllowedRepositoryRoots, strings.ToLower(root))
}

func validRef(ref string) bool {
	if !text(ref, 255, true) || ref == "@" || strings.HasPrefix(ref, "-") ||
		strings.ContainsAny(ref, `~^:?*[\`) || strings.Contains(ref, "..") || strings.Contains(ref, "@{") ||
		strings.HasSuffix(ref, ".") || strings.ContainsFunc(ref, unicode.IsSpace) {
		return false
	}
	for part := range strings.SplitSeq(ref, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

func text(value string, limit int, required bool) bool {
	if len(value) > limit || !utf8.ValidString(value) || (required && strings.TrimSpace(value) == "") {
		return false
	}
	for _, char := range value {
		if (unicode.IsControl(char) && char != '\n' && char != '\r' && char != '\t') || unicode.Is(unicode.Cf, char) {
			return false
		}
	}
	return true
}

func stringList(values []string, count, size int) bool {
	if len(values) > count {
		return false
	}
	for _, value := range values {
		if !text(value, size, true) {
			return false
		}
	}
	return true
}

func validRequirements(requirements []pv.EnvironmentRequirement) bool {
	if len(requirements) > 32 {
		return false
	}
	seen := make(map[string]bool)
	for _, requirement := range requirements {
		switch requirement.Kind {
		case "process", "local-services", "cluster", "controller", "external-service", "test-identity":
		default:
			return false
		}
		key := requirement.Kind + ":" + requirement.Name
		if !requirementName.MatchString(requirement.Name) || seen[key] || !text(requirement.Description, 4096, false) {
			return false
		}
		seen[key] = true
	}
	return true
}

func validPath(name string) bool {
	if name == "" || len(name) > 1024 || path.IsAbs(name) || path.Clean(name) != name ||
		strings.ContainsAny(name, `\:*?"<>|`) || strings.Count(name, "/") >= 32 {
		return false
	}
	for _, char := range name {
		if char < 32 || char > 126 {
			return false
		}
	}
	for part := range strings.SplitSeq(name, "/") {
		if part == "" || part == "." || part == ".." || len(part) > 255 || strings.TrimSpace(part) != part ||
			strings.HasSuffix(part, ".") || strings.EqualFold(part, ".git") {
			return false
		}
		base, _, _ := strings.Cut(strings.ToUpper(part), ".")
		switch base {
		case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
			"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
			return false
		}
	}
	return !(pv.CredentialMatcher{}).MatchString(name)
}

func validPaths(paths []string) bool {
	seen := make(map[string]string)
	files := make(map[string]bool)
	for _, name := range paths {
		if !validPath(name) {
			return false
		}
		parts := strings.Split(name, "/")
		for index := range parts {
			prefix := strings.Join(parts[:index+1], "/")
			key := strings.ToLower(prefix)
			if previous, found := seen[key]; found && (previous != prefix || files[key] || index == len(parts)-1) {
				return false
			}
			seen[key] = prefix
			files[key] = index == len(parts)-1
		}
	}
	return true
}

func validObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	nonzero := false
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
		nonzero = nonzero || char != '0'
	}
	return nonzero
}

func validDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == 71 && validObjectID(value[7:])
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validTarget(target source.Target, suggestion TargetSuggestion) bool {
	return strings.EqualFold(target.Repository.URL, canonicalRepository(suggestion.Repository)) &&
		target.Repository.URL == "https://github.com/"+target.Repository.Owner+"/"+target.Repository.Name &&
		canonicalRepository(target.Repository.URL) == target.Repository.URL &&
		validRef(target.Repository.DefaultBranch) && target.Ref == suggestion.Ref &&
		validObjectID(target.Commit) && validObjectID(target.Tree) && len(target.Commit) == len(target.Tree) &&
		(!validObjectID(target.Ref) || target.Ref == target.Commit)
}

func validateInventory(entries []source.Entry, target source.Target) error {
	if len(entries) == 0 || len(entries) > source.MaxInventoryEntries {
		return ErrState
	}
	size := 2
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !validObjectID(entry.BlobSHA) || len(entry.BlobSHA) != len(target.Commit) || entry.Size < 0 ||
			(entry.Mode != "100644" && entry.Mode != "100755" && entry.Mode != "040000") ||
			(entry.Mode == "040000" && entry.Size != 0) {
			return ErrState
		}
		data, err := json.Marshal(entry)
		if err != nil || len(data)+1 > source.MaxInventoryBytes-size {
			return ErrState
		}
		size += len(data) + 1
		paths = append(paths, entry.Path)
	}
	if !validPaths(paths) {
		return ErrState
	}
	return nil
}
