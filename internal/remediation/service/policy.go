package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/orka-agents/orka/internal/remediationpolicy"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
)

func LoadPolicies(filename string) ([]Policy, error) {
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		return nil, ErrPolicy
	}
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > MaxPolicyBytes {
		return nil, ErrPolicy
	}
	resolved, err := filepath.EvalSymlinks(filename)
	if err != nil || resolved != filename {
		return nil, ErrPolicy
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, ErrPolicy
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, MaxPolicyBytes+1))
	if err != nil {
		return nil, ErrPolicy
	}
	var document struct {
		Policies []Policy `json:"policies"`
	}
	if decodeObject(raw, MaxPolicyBytes, &document) != nil || len(document.Policies) == 0 || len(document.Policies) > 16 {
		return nil, ErrPolicy
	}
	seen := make(map[string]bool)
	for _, policy := range document.Policies {
		key := policy.Namespace + "/" + policy.Name
		if validatePolicy(policy) != nil || seen[key] {
			return nil, ErrPolicy
		}
		seen[key] = true
	}
	return document.Policies, nil
}

func validatePolicy(policy Policy) error {
	if err := validateProposalBackend(policy); err != nil {
		return err
	}
	if policy.Version != Version || len(kubevalidation.IsDNS1123Label(policy.Name)) != 0 ||
		len(kubevalidation.IsDNS1123Label(policy.Namespace)) != 0 ||
		len(kubevalidation.IsDNS1123Subdomain(policy.AgentName)) != 0 ||
		len(policy.Repositories) == 0 || len(policy.Repositories) > 32 ||
		len(policy.Adapters) == 0 || len(policy.Adapters) > 16 ||
		policy.MaxDurationSeconds < 30 || policy.MaxDurationSeconds > 7200 ||
		policy.MaxCandidates < 1 || policy.MaxCandidates > 5 ||
		policy.MaxModelCalls < 1 || policy.MaxModelCalls > 32 {
		return ErrPolicy
	}
	repositories := make(map[string]bool)
	for _, repository := range policy.Repositories {
		if !validRepository(repository) || repositories[repository] {
			return ErrPolicy
		}
		repositories[repository] = true
	}
	names := make(map[string]bool)
	for _, adapter := range policy.Adapters {
		if len(kubevalidation.IsDNS1123Label(adapter.Name)) != 0 || names[adapter.Name] ||
			len(kubevalidation.IsDNS1123Label(adapter.Kind)) != 0 ||
			len(adapter.Repositories) == 0 || len(adapter.Configuration) == 0 || !json.Valid(adapter.Configuration) {
			return ErrPolicy
		}
		names[adapter.Name] = true
		for _, repository := range adapter.Repositories {
			if !repositories[repository] {
				return ErrPolicy
			}
		}
	}
	return nil
}

func validateProposalBackend(policy Policy) error {
	switch policy.ProposalBackend {
	case "", remediationpolicy.NativeBackend:
		if policy.Copilot != nil {
			return ErrPolicy
		}
	case "copilot-acp-v1":
		if policy.Copilot == nil || policy.Copilot.Validate(policy.Namespace) != nil {
			return ErrPolicy
		}
	default:
		return ErrPolicy
	}
	return nil
}

func validRepository(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.HasSuffix(u.Path, ".git") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != "" &&
		parts[0] != "." && parts[1] != "." && parts[0] != ".." && parts[1] != ".."
}

func Digest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	raw, ok := strings.CutPrefix(value, "sha256:")
	if !ok || len(raw) != 64 || strings.ToLower(raw) != raw {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

func decodeObject(raw []byte, limit int, value any) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	budget := 1 << 20
	if err := uniqueKeys(decoder, 0, &budget); err != nil {
		return ErrInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrInvalid
	}
	return nil
}

func uniqueKeys(decoder *json.Decoder, depth int, budget *int) error {
	*budget--
	if depth > 64 || *budget < 0 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, container := token.(json.Delim)
	if depth == 0 && (!container || delimiter != '{') {
		return ErrInvalid
	}
	if !container {
		return nil
	}
	keys := make(map[string]bool)
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return ErrInvalid
			}
			name, ok := key.(string)
			if !ok || keys[strings.ToLower(name)] {
				return ErrInvalid
			}
			keys[strings.ToLower(name)] = true
		}
		if err := uniqueKeys(decoder, depth+1, budget); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
