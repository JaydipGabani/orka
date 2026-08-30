package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

const (
	DefaultPolicyConfigMapKey   = "policy"
	PolicyConfigMapAllowedLabel = "orka.ai/security-policy"
	MaxCustomPolicyBytes        = 32 * 1024
)

type PolicySource struct {
	Name   string `json:"name,omitempty"`
	Key    string `json:"key,omitempty"`
	Digest string `json:"digest,omitempty"`
}

type ScannerPolicy struct {
	CustomScanInstructions string
	FalsePositivePolicy    string
	CustomScanSource       PolicySource
	FalsePositiveSource    PolicySource
	Digest                 string
}

func PolicyRefKey(ref *corev1alpha1.PolicyConfigMapKeyRef) string {
	if ref == nil || strings.TrimSpace(ref.Key) == "" {
		return DefaultPolicyConfigMapKey
	}
	return strings.TrimSpace(ref.Key)
}

func ValidateCustomPolicyText(text string) error {
	if len([]byte(text)) > MaxCustomPolicyBytes {
		return fmt.Errorf("policy exceeds %d bytes", MaxCustomPolicyBytes)
	}
	if LooksLikeSecret(text) {
		return fmt.Errorf("policy appears to contain a secret or token")
	}
	return nil
}

var (
	policySensitivePrefixPattern     = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9])(?:(?:github` + `_pat_|` + `g` + `hp_|xo` + `xb-|s` + `k-)[A-Za-z0-9_./+=:-]{8,}|(?:A` + `KIA|A` + `SIA)[A-Z0-9]{16})`)
	policySensitiveAssignmentPattern = regexp.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?` + `token|refresh[_-]?` + `token|id[_-]?` + `token|auth[_-]?` + `token|to` + `ken|pass` + `word|clien` + `t[_-]?secret|priv` + `ate[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_./+=:-]{16,})`)
	policyJWTPattern                 = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_-])ey` + `J[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}([^A-Za-z0-9_-]|$)`)
	// Header-carried credentials are flagged only when a credential-shaped
	// value follows: "Authorization: Bearer $TOKEN" in documentation is not
	// a secret, "Authorization: Bearer eyJ…" or a 16+ character opaque token
	// is.
	policyBearerHeaderPattern = regexp.MustCompile(`(?i)auth` + `orization\s*:\s*be` + `arer\s+([A-Za-z0-9_./+=:-]{16,})`)
	policyTxnTokenPattern     = regexp.MustCompile(`(?i)\btxn?-to` + `ken\s*:\s*([A-Za-z0-9_./+=:-]{16,})`)
)

// secretValuePlaceholder reports whether a credential-position value is an
// obvious placeholder (a shell or template variable reference, or a
// bracketed/braced example) rather than a literal secret.
func secretValuePlaceholder(value string) bool {
	if value == "" {
		return true
	}
	switch value[0] {
	case '$', '<', '{', '%', '[':
		return true
	}
	return false
}

// codeReferencePattern matches a qualified identifier such as
// strings.TrimSpace or cfg.Provider.APIKey: source code that reads a secret
// from configuration, not the secret itself.
var codeReferencePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)

// secretValueIsCode reports whether a credential-position value is source
// code rather than a literal: a call such as strings.TrimSpace(cfg.APIKey)
// (the value is immediately followed by "(") or a qualified identifier.
// Go/TS/Python that assigns apiKey from configuration would otherwise make
// any file that touches credential plumbing unpublishable.
func secretValueIsCode(text string, value string, end int) bool {
	if end < len(text) && text[end] == '(' {
		return true
	}
	return codeReferencePattern.MatchString(value)
}

func sensitiveValueMatch(pattern *regexp.Regexp, text string) bool {
	for _, match := range pattern.FindAllStringSubmatchIndex(text, -1) {
		if len(match) < 4 || match[2] < 0 {
			continue
		}
		value := text[match[2]:match[3]]
		if secretValuePlaceholder(value) || secretValueIsCode(text, value, match[3]) {
			continue
		}
		return true
	}
	return false
}

// LooksLikeSecret reports whether text carries a credential-shaped value:
// known token prefixes, JWTs, PEM blocks, or an assignment/header whose value
// is long enough to be a real secret. Bare keywords such as
// "OPENAI_API_KEY=dummy" or "Authorization: Bearer $TOKEN" are not secrets
// and must not block documentation or code that merely mentions them.
func LooksLikeSecret(text string) bool {
	if policySensitivePrefixPattern.MatchString(text) {
		return true
	}
	if sensitiveValueMatch(policySensitiveAssignmentPattern, text) {
		return true
	}
	if policyJWTPattern.MatchString(text) {
		return true
	}
	if sensitiveValueMatch(policyBearerHeaderPattern, text) || sensitiveValueMatch(policyTxnTokenPattern, text) {
		return true
	}
	return strings.Contains(strings.ToLower(text), "-----"+"begin ")
}

func PolicyTextDigest(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ScannerPolicyDigest(policy ScannerPolicy) string {
	parts := []string{ScannerPolicyVersion}
	if policy.CustomScanSource.Name != "" || policy.CustomScanInstructions != "" {
		parts = append(parts,
			"custom-scan", policy.CustomScanSource.Name, policy.CustomScanSource.Key,
			PolicyTextDigest(policy.CustomScanInstructions),
		)
	}
	if policy.FalsePositiveSource.Name != "" || policy.FalsePositivePolicy != "" {
		parts = append(parts,
			"false-positive", policy.FalsePositiveSource.Name, policy.FalsePositiveSource.Key,
			PolicyTextDigest(policy.FalsePositivePolicy),
		)
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (p ScannerPolicy) PromptPolicy() PromptPolicy {
	return PromptPolicy{
		CustomScanInstructions: p.CustomScanInstructions,
		FalsePositivePolicy:    p.FalsePositivePolicy,
		PolicyDigest:           p.Digest,
		CustomScanSource:       p.CustomScanSource.String(),
		FalsePositiveSource:    p.FalsePositiveSource.String(),
	}
}

func (s PolicySource) String() string {
	if s.Name == "" {
		return ""
	}
	key := s.Key
	if key == "" {
		key = DefaultPolicyConfigMapKey
	}
	if s.Digest == "" {
		return s.Name + "/" + key
	}
	return s.Name + "/" + key + " (" + s.Digest + ")"
}

func PolicyProvenanceEnv(policy ScannerPolicy) string {
	items := []string{}
	if value := policy.CustomScanSource.String(); value != "" {
		items = append(items, "customScan="+value)
	}
	if value := policy.FalsePositiveSource.String(); value != "" {
		items = append(items, "falsePositive="+value)
	}
	sort.Strings(items)
	return strings.Join(items, ";")
}

func LoadScannerPolicy(ctx context.Context, reader client.Reader, namespace string, spec corev1alpha1.RepositoryScanSpec) (ScannerPolicy, error) {
	policy := ScannerPolicy{}
	if reader == nil {
		policy.Digest = ScannerPolicyDigest(policy)
		return policy, nil
	}
	if spec.CustomScanInstructionsRef != nil {
		text, source, err := loadPolicyConfigMapKey(ctx, reader, namespace, spec.CustomScanInstructionsRef)
		if err != nil {
			return ScannerPolicy{}, fmt.Errorf("customScanInstructionsRef: %w", err)
		}
		policy.CustomScanInstructions = text
		policy.CustomScanSource = source
	}
	if spec.FalsePositivePolicyRef != nil {
		text, source, err := loadPolicyConfigMapKey(ctx, reader, namespace, spec.FalsePositivePolicyRef)
		if err != nil {
			return ScannerPolicy{}, fmt.Errorf("falsePositivePolicyRef: %w", err)
		}
		policy.FalsePositivePolicy = text
		policy.FalsePositiveSource = source
	}
	policy.Digest = ScannerPolicyDigest(policy)
	return policy, nil
}

func policyConfigMapAllowed(cm corev1.ConfigMap) bool {
	return strings.EqualFold(strings.TrimSpace(cm.Labels[PolicyConfigMapAllowedLabel]), "true") ||
		strings.EqualFold(strings.TrimSpace(cm.Annotations[PolicyConfigMapAllowedLabel]), "true")
}

func loadPolicyConfigMapKey(
	ctx context.Context,
	reader client.Reader,
	namespace string,
	ref *corev1alpha1.PolicyConfigMapKeyRef,
) (string, PolicySource, error) {
	name := strings.TrimSpace(ref.Name)
	if name == "" {
		return "", PolicySource{}, fmt.Errorf("name is required")
	}
	key := PolicyRefKey(ref)
	var cm corev1.ConfigMap
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &cm); err != nil {
		return "", PolicySource{}, err
	}
	if !policyConfigMapAllowed(cm) {
		return "", PolicySource{}, fmt.Errorf("ConfigMap %q must be labeled or annotated %s=true to be used as scanner policy", name, PolicyConfigMapAllowedLabel)
	}
	value, ok := cm.Data[key]
	if !ok {
		return "", PolicySource{}, fmt.Errorf("key %q is missing in ConfigMap %q", key, name)
	}
	if err := ValidateCustomPolicyText(value); err != nil {
		return "", PolicySource{}, err
	}
	source := PolicySource{Name: name, Key: key, Digest: PolicyTextDigest(value)}
	return strings.TrimSpace(value), source, nil
}

func ScanRunIdempotencyKey(namespace, repositoryScan, mode, baseSHA, headSHA, subPath, policyDigest string) string {
	parts := []string{
		strings.TrimSpace(namespace),
		strings.TrimSpace(repositoryScan),
		strings.TrimSpace(mode),
		strings.TrimSpace(baseSHA),
		strings.TrimSpace(headSHA),
		strings.Trim(strings.TrimSpace(subPath), "/"),
		strings.TrimSpace(policyDigest),
		ScannerPolicyVersion,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "scanidem:" + hex.EncodeToString(sum[:])
}
