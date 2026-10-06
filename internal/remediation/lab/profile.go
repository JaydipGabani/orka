package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	commitPattern   = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
	namePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	checkIDPattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$`)
	platformPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*(?:/[a-z0-9][a-z0-9_-]*)?$`)
	credentialText  = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]*://[^\s/?#]*@|(?:password|secret|token|credential|api[_-]?key)\s*[:=]|-----BEGIN .*PRIVATE KEY-----)`)
)

// ParseProfile accepts one bounded JSON object, rejecting duplicate/colliding
// keys, nulls and unknown fields. Files are inspected only by New and execution.
func ParseProfile(data []byte) (Profile, error) {
	var profile Profile
	if err := decodeStrict(data, MaxProfileBytes, &profile); err != nil {
		return Profile{}, err
	}
	if err := validateProfile(profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

// DigestProfile hashes the canonical v1 JSON struct encoding, including every
// approved file/image identity, scope and gap. Array order is significant.
func DigestProfile(profile Profile) (string, error) {
	if err := validateProfile(profile); err != nil {
		return "", err
	}
	data, err := encode(profile, MaxProfileBytes)
	if err != nil {
		return "", err
	}
	return digest(data), nil
}

// DigestChecks commits to the exact expected ID/class manifest, sorted by ID.
// The separately pinned driver/configuration commits to the check implementation.
func DigestChecks(checks []Check) (string, error) {
	if len(checks) < 2 || len(checks) > MaxChecks {
		return "", ErrInvalidInput
	}
	ordered := slices.Clone(checks)
	slices.SortFunc(ordered, func(left, right Check) int { return strings.Compare(left.ID, right.ID) })
	var reproduction, normal bool
	for index, check := range ordered {
		if !checkIDPattern.MatchString(check.ID) || (index > 0 && ordered[index-1].ID == check.ID) {
			return "", ErrInvalidInput
		}
		switch check.Class {
		case Reproduction:
			reproduction = true
		case Normal:
			normal = true
		default:
			return "", ErrInvalidInput
		}
	}
	if !reproduction || !normal {
		return "", ErrInvalidInput
	}
	data, err := encode(ordered, MaxResultBytes)
	if err != nil {
		return "", err
	}
	return digest(data), nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateProfile(profile Profile) error {
	if profile.Version != Version || !publicRepositoryURL(profile.Repository) ||
		!commitPattern.MatchString(profile.Commit) || !digestPattern.MatchString(profile.OriginalImage) ||
		(profile.ControlImage != "" && !digestPattern.MatchString(profile.ControlImage)) ||
		len(profile.Platform) > 96 || !platformPattern.MatchString(profile.Platform) ||
		!validFileIdentity(profile.Driver) || !validFileIdentity(profile.Configuration) ||
		profile.Driver.Path == profile.Configuration.Path || !digestPattern.MatchString(profile.ChecksDigest) ||
		len(profile.Scope) == 0 || !validDescriptions(profile.Scope) || !validDescriptions(profile.Gaps) ||
		profile.Gaps == nil {
		return ErrInvalidProfile
	}
	return nil
}

func publicRepositoryURL(value string) bool {
	if !safeText(value, 2048) || strings.ContainsAny(value, "\\?#") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.User == nil && parsed.Hostname() != "" &&
		strings.Contains(parsed.Hostname(), ".") && net.ParseIP(parsed.Hostname()) == nil &&
		(parsed.Port() == "" || parsed.Port() == "443") &&
		parsed.Path != "" && parsed.Path != "/" && parsed.RawQuery == "" && parsed.Fragment == "" &&
		!strings.ContainsAny(parsed.Path, "\x00\r\n\t")
}

func validFileIdentity(file FileIdentity) bool {
	return safeAbsolutePath(file.Path) && digestPattern.MatchString(file.Digest)
}

func validExpectedImage(image, original, control string) bool {
	return image == "" || (digestPattern.MatchString(image) && image != original && image != control)
}

func safeAbsolutePath(value string) bool {
	return value != "/" && safeText(value, 4096) && filepath.IsAbs(value) &&
		filepath.Clean(value) == value && !strings.ContainsRune(value, '\\')
}

func safeText(value string, limit int) bool {
	if len(value) > limit || credentialText.MatchString(value) {
		return false
	}
	for _, char := range value {
		if char < 32 || char > 126 {
			return false
		}
	}
	return true
}

func validDescriptions(values []string) bool {
	if len(values) > 64 {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" || !safeText(value, 512) {
			return false
		}
	}
	return true
}
