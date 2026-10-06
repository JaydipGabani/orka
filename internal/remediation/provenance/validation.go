package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/distribution/reference"
)

const (
	MaxSpecBytes  = 1 << 20
	MaxFileBytes  = 4 << 20
	MaxTotalBytes = 16 << 20
	MaxFiles      = 256

	maxYAMLDepth  = 32
	maxYAMLNodes  = 32768
	maxScalarSize = 64 << 10
	maxValueSize  = 4096
	maxPathSize   = 512
	maxPatchStrip = 16
)

var (
	commitPattern   = regexp.MustCompile(`^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$`)
	namePattern     = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)
	argPattern      = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	pathPattern     = regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`)
	platformPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*(?:/[a-z0-9][a-z0-9_.-]*)?$`)
	revisionPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,9})$`)
	versionPattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+_~-]{0,127}$`)
	moduleVersion   = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?(?:\+[a-zA-Z0-9.-]+)?$`)
	urlCredentials  = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s/?#"'<>]*@`)
	urlParameters   = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s"'<>]*[?#]`)
	secretLiteral   = regexp.MustCompile(`(?i)(?:\b(?:password|passwd|secret|token|credential|api[_-]?key|authorization)\b)["']?\s*[:=]\s*["']?[a-zA-Z0-9+/_.-]+`)
	privateKey      = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)
)

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func canonicalDigest(value string) (string, error) {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return "", errors.New("provenance requires a sha256 digest")
	}
	if _, err := hex.DecodeString(value[len("sha256:"):]); err != nil {
		return "", errors.New("provenance requires a sha256 digest")
	}
	return strings.ToLower(value), nil
}

func exactCommit(value string) bool {
	return commitPattern.MatchString(value)
}

func safePath(value string) bool {
	if value == "" || len(value) > maxPathSize || !pathPattern.MatchString(value) ||
		path.IsAbs(value) || path.Clean(value) != value || value == "." {
		return false
	}
	for segment := range strings.SplitSeq(value, "/") {
		if segment == ".." || strings.EqualFold(segment, ".git") {
			return false
		}
	}
	return true
}

func safeName(value string) bool {
	return len(value) <= maxPathSize && namePattern.MatchString(value) && value != "." && value != ".."
}

func validPlatform(value string) bool {
	return len(value) <= 128 && platformPattern.MatchString(value) &&
		!strings.Contains(value, "..") && !strings.Contains(value, "/.")
}

func safeVersion(value string) bool {
	return versionPattern.MatchString(value)
}

func validRevision(value string) bool {
	return revisionPattern.MatchString(value)
}

func credentialText(value string) bool {
	return urlCredentials.MatchString(value) || urlParameters.MatchString(value) ||
		secretLiteral.MatchString(value) || privateKey.MatchString(value)
}

func safeText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsFunc(value, unsafeControl) &&
		!credentialText(value)
}

func unsafeControl(value rune) bool {
	return unicode.IsControl(value) && value != '\n' && value != '\r' && value != '\t'
}

func safeIdentifier(value string) bool {
	if value == "" {
		return true
	}
	if !safeText(value, maxValueSize) || strings.ContainsAny(value, "$`\\?#") ||
		strings.ContainsFunc(value, unicode.IsSpace) || strings.Contains(value, "@") {
		return false
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		return err == nil && parsed.Scheme != "" && parsed.User == nil &&
			!strings.ContainsFunc(parsed.Path, unicode.IsControl)
	}
	return true
}

func safeRepository(value string) bool {
	if !safeText(value, maxValueSize) || strings.ContainsAny(value, "$`\\") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" &&
		parsed.User == nil && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" &&
		parsed.Path != "" && parsed.Path != "/" && parsed.Opaque == "" &&
		!strings.ContainsFunc(value, unicode.IsSpace) && !strings.ContainsFunc(parsed.Path, unicode.IsControl)
}

func parseImage(value string, frontend bool) (ImageIdentity, error) {
	if value == "" {
		return ImageIdentity{}, nil
	}
	if !safeText(value, maxValueSize) || strings.ContainsAny(value, "$`\\?#") {
		return ImageIdentity{}, errors.New("provenance contains an unsafe image identity")
	}
	if strings.HasPrefix(value, "sha256:") {
		digest, err := canonicalDigest(value)
		if err != nil || frontend {
			return ImageIdentity{}, errors.New("provenance contains an invalid image identity")
		}
		return ImageIdentity{Reference: digest, Digest: digest}, nil
	}
	image := ImageIdentity{Reference: value}
	if name, digest, pinned := strings.Cut(value, "@"); pinned {
		canonical, err := canonicalDigest(digest)
		if err != nil {
			return ImageIdentity{}, errors.New("provenance contains an invalid image digest")
		}
		image = ImageIdentity{Reference: name + "@" + canonical, Digest: canonical}
	}
	if _, err := reference.ParseNormalizedNamed(image.Reference); err != nil {
		return ImageIdentity{}, errors.New("provenance contains an invalid image reference")
	}
	return image, nil
}

func sensitiveName(value string) bool {
	canonical := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(value))
	for _, part := range []string{
		"password", "passwd", "secret", "token", "credential", "privatekey", "apikey",
		"accesskey", "signingkey", "authorization", "bearer", "cookie",
	} {
		if strings.Contains(canonical, part) {
			return true
		}
	}
	return canonical == "auth" || strings.HasSuffix(canonical, "key")
}

func safeVariables(variables map[string]string) error {
	for key, value := range variables {
		if len(key) > 128 || !argPattern.MatchString(key) || sensitiveName(key) ||
			!safeText(value, maxValueSize) || strings.ContainsAny(value, "\r\n") {
			return errors.New("provenance contains an unsafe argument or build environment")
		}
	}
	return nil
}

// Expansion is single-pass. Argument values cannot themselves be templates, and
// shell parameter operators, command substitution and bare dollars are rejected.
func resolve(value string, args map[string]string) (string, error) {
	if strings.ContainsRune(value, '`') {
		return "", errors.New("provenance does not support shell substitution")
	}
	var result strings.Builder
	for {
		prefix, rest, found := strings.Cut(value, "$")
		result.WriteString(prefix)
		if !found {
			break
		}
		if !strings.HasPrefix(rest, "{") {
			return "", errors.New("provenance supports only simple argument substitution")
		}
		key, remaining, closed := strings.Cut(rest[1:], "}")
		replacement, exists := args[key]
		if !closed || !argPattern.MatchString(key) || !exists {
			return "", errors.New("provenance contains an unknown or unsupported substitution")
		}
		result.WriteString(replacement)
		if result.Len() > maxScalarSize {
			return "", errors.New("provenance substitution exceeds the scalar limit")
		}
		value = remaining
	}
	if result.Len() > maxScalarSize {
		return "", errors.New("provenance substitution exceeds the scalar limit")
	}
	return result.String(), nil
}

func validateInputs(spec []byte, files map[string][]byte, metadata Metadata) error {
	if err := validateInputStructure(spec, files, metadata); err != nil {
		return err
	}
	for _, content := range files {
		if credentialText(string(content)) {
			return errors.New("provenance contains credential-shaped supplied content")
		}
	}
	return nil
}

func validateInputStructure(spec []byte, files map[string][]byte, metadata Metadata) error {
	if len(spec) == 0 || len(spec) > MaxSpecBytes || !utf8.Valid(spec) || credentialText(string(spec)) {
		return errors.New("provenance recipe is empty, oversized, unsafe, or not UTF-8")
	}
	if len(files) > MaxFiles || len(metadata.ExpectedDigests) > MaxFiles ||
		!safePath(metadata.Path) || !safeIdentifier(metadata.RecipeRepository) ||
		(metadata.RecipeCommit != "" && !exactCommit(metadata.RecipeCommit)) {
		return errors.New("provenance contains invalid acquisition metadata or too many files")
	}
	total := len(spec)
	for name, content := range files {
		if !safePath(name) || len(content) > MaxFileBytes || !utf8.Valid(content) {
			return errors.New("provenance contains an unsafe or oversized supplied file")
		}
		total += len(content)
		if total > MaxTotalBytes {
			return errors.New("provenance exceeds the aggregate input limit")
		}
	}
	for name, expected := range metadata.ExpectedDigests {
		content, exists := files[name]
		digest, err := canonicalDigest(expected)
		if !safePath(name) || !exists || err != nil || digestBytes(content) != digest {
			return errors.New("provenance supplied bytes do not match an expected file digest")
		}
	}
	return nil
}
