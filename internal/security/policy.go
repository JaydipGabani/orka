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
	policySensitivePrefixPattern = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9])(?:(?:github` + `_pat_|` + `g` + `hp_|xo` + `xb-|s` + `k-)[A-Za-z0-9_./+=:-]{8,}|(?:A` + `KIA|A` + `SIA)[A-Z0-9]{16})`)
	// The credential keyword may carry a conventional identifier prefix
	// ("OPENAI_API_KEY", "SLACK_BOT_TOKEN"): "\b" alone cannot see past the
	// "_" word character, so the prefix is matched explicitly. Quoted values
	// additionally admit spaces and any symbol ("correct horse battery
	// staple"); the unquoted alternative admits common password symbols
	// (@#$%^&*!?|,;\\`) so a dotenv or YAML literal like p@ssword-… is still
	// measured as one value. Structural characters stay excluded deliberately:
	// quotes delimit, and ()<>[]{} feed the placeholder and
	// call-syntax exemptions — swallowing them would break the code-plumbing
	// negatives (apiKey = strings.TrimSpace(cfg.APIKey)). Placeholder ($VAR, <example>, {{ .Token }}) and
	// code-reference exemptions run on the captured value either way.
	policySensitiveAssignmentPattern = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[_-]){0,3}(?:api[_-]?key|access[_-]?` + `token|refresh[_-]?` + `token|id[_-]?` + `token|auth[_-]?` + `token|to` + `ken|pass` + `word|clien` + `t[_-]?secret|secr` + `et|cred` + `entials?|priv` + `ate[_-]?key)\s*[:=]\s*(?:"([^"\r\n]{16,})"|'([^'\r\n]{16,})'|([A-Za-z0-9_./+=~:@#$%^&*!?|,;\\` + "`" + `-]{16,}))`)
	// YAML plain scalars may contain spaces without quoting. Scan the complete
	// line value so a short first word cannot hide a long credential value.
	// Requiring whitespace after ':' excludes Go's ':=' assignments; the
	// token-part filter below keeps call expressions and other source syntax
	// out of this YAML-specific fallback.
	policySensitiveYAMLAssignmentPattern = regexp.MustCompile(`(?im)^[\t ]*(?:-\s*)?(?:[A-Za-z0-9]+[_-]){0,3}(?:api[_-]?key|access[_-]?` + `token|refresh[_-]?` + `token|id[_-]?` + `token|auth[_-]?` + `token|to` + `ken|pass` + `word|clien` + `t[_-]?secret|secr` + `et|cred` + `entials?|priv` + `ate[_-]?key)\s*:\s+([^\r\n]+)$`)
	// YAML block scalars put their value on following indented lines. Match
	// the credential-bearing header here; yamlBlockScalarAssignmentsLookLikeSecret
	// reconstructs all content lines before evaluating the value.
	policySensitiveYAMLBlockHeaderPattern = regexp.MustCompile(`(?i)^[\t ]*(?:-\s*)?(?:[A-Za-z0-9]+[_-]){0,3}(?:api[_-]?key|access[_-]?` + `token|refresh[_-]?` + `token|id[_-]?` + `token|auth[_-]?` + `token|to` + `ken|pass` + `word|clien` + `t[_-]?secret|secr` + `et|cred` + `entials?|priv` + `ate[_-]?key)\s*:\s*[|>](?:[+-][1-9]?|[1-9][+-]?)?[ \t]*(?:#[^\r\n]*)?$`)
	policyYAMLPlainScalarPartPattern      = regexp.MustCompile("^[A-Za-z0-9_./+=~:@#$%^&*!?|,;\\\\`-]+$")
	policyJWTPattern                      = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_-])ey` + `J[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}([^A-Za-z0-9_-]|$)`)
	// Header-carried credentials are flagged only when a credential-shaped
	// value follows: "Authorization: Bearer $TOKEN" in documentation is not
	// a secret, "Authorization: Bearer eyJ…" or a 16+ character opaque token
	// is. The value alphabet is the RFC 6750 token68 grammar, which includes
	// "~".
	policyBearerHeaderPattern = regexp.MustCompile(`(?i)auth` + `orization\s*:\s*be` + `arer\s+([A-Za-z0-9_./+=~:-]{16,})`)
	// Signed-URL query credentials (S3/GCS presigned URLs, SAS tokens) use
	// the same parameter set internal/redact scrubs; a published URL with a
	// live signature grants access just like a bearer token.
	policySignedURLPattern   = regexp.MustCompile(`(?i)[?&](?:sig|sign` + `ature|sas|x-amz-sign` + `ature|x-amz-sec` + `urity-token|x-amz-cred` + `ential|x-goog-sign` + `ature|x-goog-cred` + `ential)=([^&#\s"'<>,;()\[\]]{16,})`)
	policyTxnTokenPattern    = regexp.MustCompile(`(?i)\btxn?-to` + `ken\s*:\s*([A-Za-z0-9_./+=~:-]{16,})`)
	policyCookiePattern      = regexp.MustCompile(`(?i)\b(set-cookie|cookie)\s*:\s*([^\r\n]+)`)
	policyCookieValuePattern = regexp.MustCompile("^[A-Za-z0-9_./+=~:@#$%^&*!?|,'\\\\`-]{16,}$")
)

// placeholderFormPattern matches complete variable/template forms: a shell
// or template variable reference, or a fully bracketed/braced example. A
// prefix alone is not enough — "$tr0ng-password!" is a literal that merely
// starts with '$', not a placeholder.
var placeholderFormPattern = regexp.MustCompile(
	`^(?:` +
		`\$[A-Za-z_][A-Za-z0-9_]*` + // $VAR
		`|\$\{[A-Za-z_][A-Za-z0-9_]*\}` + // ${VAR} — variable-only; ${VAR:-fallback} can embed a literal secret and stays flagged
		`|\{\{.*\}\}` + // {{ .Token }}, {{ secret }}
		`|\{[^{}]*\}` + // {placeholder}
		`|<[^<>]*>` + // <your-token>
		`|\[[^\[\]]*\]` + // [REDACTED], [token]
		`|%[^%]*%` + // %VAR% (Windows)
		`|%\([^()]*\)[A-Za-z]` + // %(name)s (Python)
		`)$`)

// secretValuePlaceholder reports whether a credential-position value is an
// obvious placeholder rather than a literal secret. Only complete recognized
// forms are exempt; a value that merely begins with a placeholder character
// stays flagged.
func secretValuePlaceholder(value string) bool {
	if value == "" {
		return true
	}
	return placeholderFormPattern.MatchString(value)
}

// codeReferencePattern matches a qualified identifier such as
// strings.TrimSpace or cfg.Provider.APIKey: source code that reads a secret
// from configuration, not the secret itself.
var codeReferencePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)

// codeReferenceCredentialTail matches the final dotted segment of a code
// reference that names a credential field. Code that reads a secret refers to
// it by name (cfg.Provider.APIKey, settings.auth_token); a literal dotted
// secret ("correct.horse.battery.staple") does not end in the credential
// keyword it is assigned to, so only credential-named references are exempt.
var codeReferenceCredentialTail = regexp.MustCompile(`(?i)^(?:api[_-]?key|access[_-]?` + `token|refresh[_-]?` + `token|id[_-]?` + `token|auth[_-]?` + `token|to` + `ken|pass` + `word|passwd|clien` + `t[_-]?secret|secr` + `et|credentials?|priv` + `ate[_-]?key|key)$`)

// secretValueIsCode reports whether a credential-position value is source
// code rather than a literal: a call such as strings.TrimSpace(cfg.APIKey)
// (the value is immediately followed by "(") or a qualified identifier whose
// final segment names a credential field. Go/TS/Python that assigns apiKey
// from configuration would otherwise make any file that touches credential
// plumbing unpublishable, while arbitrary dotted literals stay flagged.
// callableReferencePattern matches an identifier that can legally precede a
// call and is either qualified (os.Getenv) or an unqualified credential
// reader (readPasswordFromKeychain). Requiring a complete call suffix and a
// reader-shaped unqualified name prevents arbitrary mixed-case or underscored
// credentials from buying the exemption by appending call punctuation.
var callableReferencePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$`)
var unqualifiedCredentialReaderPattern = regexp.MustCompile(`(?i)^(?:fetch|get|load|lookup|read|resolve)[A-Za-z0-9_]*(?:api[_-]?key|token|password|passwd|secret|credential|private[_-]?key)[A-Za-z0-9_]*$`)

func callableReferenceShape(value string) bool {
	if !callableReferencePattern.MatchString(value) {
		return false
	}
	if strings.Contains(value, ".") {
		return true
	}
	return unqualifiedCredentialReaderPattern.MatchString(value)
}

func hasCompleteCallSuffix(text string, start int) bool {
	if start >= len(text) || text[start] != '(' {
		return false
	}
	depth := 0
	var quote byte
	escaped := false
	for i := start; i < len(text); i++ {
		ch := text[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"', '`':
			quote = ch
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return true
			}
		case '\r', '\n':
			return false
		}
	}
	return false
}

func secretValueIsCode(text string, value string, end int) bool {
	if callableReferenceShape(value) && hasCompleteCallSuffix(text, end) {
		return true
	}
	if !codeReferencePattern.MatchString(value) {
		return false
	}
	tail := value[strings.LastIndexByte(value, '.')+1:]
	return codeReferenceCredentialTail.MatchString(tail)
}

func sensitiveValueMatch(pattern *regexp.Regexp, text string) bool {
	for _, match := range pattern.FindAllStringSubmatchIndex(text, -1) {
		// Exactly one value alternative captures per match; find it.
		for group := 1; 2*group+1 < len(match); group++ {
			start, end := match[2*group], match[2*group+1]
			if start < 0 {
				continue
			}
			value := text[start:end]
			if !secretValuePlaceholder(value) && !secretValueIsCode(text, value, end) {
				return true
			}
			break
		}
	}
	return false
}

func trimYAMLPlainScalarComment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value[0] == '#' {
		return ""
	}
	for i := 1; i < len(value); i++ {
		if value[i] == '#' && (value[i-1] == ' ' || value[i-1] == '\t') {
			value = value[:i]
			break
		}
	}
	return strings.TrimSpace(value)
}

func yamlPlainScalarAssignmentsLookLikeSecret(text string) bool {
	for _, match := range policySensitiveYAMLAssignmentPattern.FindAllStringSubmatch(text, -1) {
		value := trimYAMLPlainScalarComment(match[1])
		if len(value) < 16 {
			continue
		}
		parts := strings.Fields(value)
		if len(parts) < 2 {
			continue
		}
		credentialShaped := true
		for _, part := range parts {
			if !policyYAMLPlainScalarPartPattern.MatchString(part) {
				credentialShaped = false
				break
			}
		}
		if credentialShaped && !secretValuePlaceholder(value) {
			return true
		}
	}
	return false
}

func yamlBlockScalarAssignmentsLookLikeSecret(text string) bool {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, line := range lines {
		if !policySensitiveYAMLBlockHeaderPattern.MatchString(line) {
			continue
		}
		baseIndent := len(line) - len(strings.TrimLeft(line, " \t"))
		var value strings.Builder
		for _, contentLine := range lines[i+1:] {
			if strings.TrimSpace(contentLine) == "" {
				continue
			}
			indent := len(contentLine) - len(strings.TrimLeft(contentLine, " \t"))
			if indent <= baseIndent {
				break
			}
			value.WriteString(strings.TrimLeft(contentLine, " \t"))
		}
		candidate := strings.TrimSpace(value.String())
		if len(candidate) < 16 || secretValuePlaceholder(candidate) || secretValueIsCode(candidate, candidate, len(candidate)) {
			continue
		}
		credentialShaped := true
		for part := range strings.FieldsSeq(candidate) {
			if !policyYAMLPlainScalarPartPattern.MatchString(part) {
				credentialShaped = false
				break
			}
		}
		if credentialShaped {
			return true
		}
	}
	return false
}

func cookieHeadersLookLikeSecret(text string) bool {
	for _, match := range policyCookiePattern.FindAllStringSubmatch(text, -1) {
		parts := strings.Split(match[2], ";")
		if strings.EqualFold(match[1], "set-cookie") && len(parts) > 1 {
			parts = parts[:1]
		}
		for _, part := range parts {
			_, value, ok := strings.Cut(part, "=")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}
			if !secretValuePlaceholder(value) && policyCookieValuePattern.MatchString(value) {
				return true
			}
		}
	}
	return false
}

// LooksLikeSecret reports whether text carries a credential-shaped value:
// known token prefixes, JWTs, PEM blocks, or an assignment/header whose value
// is long enough to be a real secret. Bare keywords such as
// "OPENAI_API_KEY=dummy" or "Authorization: Bearer $TOKEN" are not secrets
// and must not block documentation or code that merely mentions them.
func LooksLikeSecret(text string) bool {
	text = stripUnsafeTextRunes(text)
	if policySensitivePrefixPattern.MatchString(text) {
		return true
	}
	if sensitiveValueMatch(policySensitiveAssignmentPattern, text) {
		return true
	}
	if yamlPlainScalarAssignmentsLookLikeSecret(text) {
		return true
	}
	if policyJWTPattern.MatchString(text) {
		return true
	}
	if sensitiveValueMatch(policyBearerHeaderPattern, text) || sensitiveValueMatch(policyTxnTokenPattern, text) {
		return true
	}
	if cookieHeadersLookLikeSecret(text) {
		return true
	}
	if sensitiveValueMatch(policySignedURLPattern, text) {
		return true
	}
	if yamlBlockScalarAssignmentsLookLikeSecret(text) {
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
