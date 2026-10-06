package buildjob

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/distribution/reference"
	"github.com/orka-agents/orka/internal/remediation/provenance"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

var (
	digestPattern    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	idPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	pathPattern      = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_./+-]{0,239}$`)
	workerArgPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,55}WORKER(?:_IMAGE)?$`)
	targetPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_./-]{0,95}$`)
	secretPattern    = regexp.MustCompile(`(?i)(-----BEGIN[ A-Z]*PRIVATE KEY-----|github_pat_[a-z0-9_]{20,}|gh[pousr]_[a-z0-9]{20,}|(?:bearer|authorization)[ :=]+[a-z0-9_./+-]{20,}|[a-z]+://[^ /@\n]+:[^ /@\n]+@)`)
)

type Backend struct {
	config Config
	digest string
}

func New(config Config) (*Backend, error) {
	if config.Kube == nil {
		return nil, failure(ErrInvalid, "build-kubernetes-client-required")
	}
	if config.APIReader == nil {
		config.APIReader = config.Kube
	}
	if len(validation.IsDNS1123Label(config.Namespace)) != 0 || config.Namespace == corev1.NamespaceDefault ||
		strings.HasPrefix(config.Namespace, "kube-") || !immutableImage(config.WorkerImage) {
		return nil, failure(ErrInvalid, "dedicated-namespace-and-pinned-worker-required")
	}
	if err := validateEndpoint(config.Namespace, config.BuildKitAddress, config.TLS); err != nil {
		return nil, err
	}
	if config.RegistrySecretName != "" && (len(validation.IsDNS1123Subdomain(config.RegistrySecretName)) != 0 ||
		config.RegistrySecretName == config.TLS.CASecretName || config.RegistrySecretName == config.TLS.ClientSecretName) {
		return nil, failure(ErrInvalid, "invalid-operator-registry-secret-reference")
	}
	if config.TLS != nil {
		tls := *config.TLS
		config.TLS = &tls
	}
	defaultLimits(&config.Limits)
	if err := validateLimits(config.Limits); err != nil {
		return nil, err
	}
	if len(config.Policies) == 0 || len(config.Policies) > 64 {
		return nil, failure(ErrInvalid, "operator-build-policies-required")
	}
	config.Policies = slices.Clone(config.Policies)
	for i, policy := range config.Policies {
		if err := validatePolicy(policy); err != nil {
			return nil, err
		}
		if len(policy.BuildOnlyInputs) != 0 && config.RegistrySecretName == "" {
			return nil, failure(ErrInvalid, "private-baseline-inputs-require-authenticated-registry")
		}
		policy.Args = maps.Clone(policy.Args)
		policy.BuildOnlyInputs = maps.Clone(policy.BuildOnlyInputs)
		policy.SourcePaths = slices.Clone(policy.SourcePaths)
		slices.Sort(policy.SourcePaths)
		config.Policies[i] = policy
	}
	frozen := struct {
		Version            int
		Namespace          string
		WorkerImage        string
		BuildKitAddress    string
		TLS                *TLS
		Policies           []Policy
		Limits             Limits
		RegistrySecretName string `json:",omitempty"`
	}{Version, config.Namespace, config.WorkerImage, config.BuildKitAddress, config.TLS, config.Policies, config.Limits,
		config.RegistrySecretName}
	return &Backend{config: config, digest: jsonDigest(frozen)}, nil
}

// ConfigurationDigest identifies the normalized operator execution policy.
func (b *Backend) ConfigurationDigest() string { return b.digest }

// ValidateInput performs the same admission and encoded-size checks as Start
// without reserving an operation or contacting Kubernetes.
func (b *Backend) ValidateInput(input Input) error {
	frozen, policy, err := b.admit(input)
	if err != nil {
		return err
	}
	_, err = b.bundle(frozen, policy)
	return err
}

func defaultLimits(l *Limits) {
	if l.MaxInputBytes == 0 {
		l.MaxInputBytes = MaxInputBytes
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = 384 << 10
	}
	if l.MaxFiles == 0 {
		l.MaxFiles = 128
	}
	if l.MaxOperations == 0 {
		l.MaxOperations = 16
	}
	if l.MaxLogBytes == 0 {
		l.MaxLogBytes = 64 << 10
	}
	if l.BuildTimeout == 0 {
		l.BuildTimeout = 20 * time.Minute
	}
	if l.SettlementTimeout == 0 {
		l.SettlementTimeout = 10 * time.Second
	}
	if l.APITimeout == 0 {
		l.APITimeout = 15 * time.Second
	}
	if l.CleanupTimeout == 0 {
		l.CleanupTimeout = 2 * time.Minute
	}
	if l.PollInterval == 0 {
		l.PollInterval = 250 * time.Millisecond
	}
	if l.CPU == "" {
		l.CPU = "250m"
	}
	if l.Memory == "" {
		l.Memory = "256Mi"
	}
}

func validateLimits(l Limits) error {
	if l.MaxInputBytes < 1024 || l.MaxInputBytes > MaxInputBytes ||
		l.MaxFileBytes < 1 || l.MaxFileBytes > l.MaxInputBytes ||
		l.MaxFiles < 1 || l.MaxFiles > 512 || l.MaxOperations < 1 || l.MaxOperations > 64 ||
		l.MaxLogBytes < 1024 || l.MaxLogBytes > 256<<10 ||
		l.BuildTimeout < time.Second || l.BuildTimeout > time.Hour ||
		l.SettlementTimeout < time.Millisecond || l.SettlementTimeout > 20*time.Second ||
		l.APITimeout < time.Millisecond || l.APITimeout > time.Minute ||
		l.CleanupTimeout < time.Millisecond || l.CleanupTimeout > 10*time.Minute ||
		l.PollInterval < time.Millisecond || l.PollInterval > 5*time.Second {
		return failure(ErrInvalid, "build-limits-out-of-bounds")
	}
	for _, bound := range []struct{ value, maximum string }{{l.CPU, "4"}, {l.Memory, "8Gi"}} {
		value, err := resource.ParseQuantity(bound.value)
		if err != nil || value.Sign() <= 0 || value.Cmp(resource.MustParse(bound.maximum)) > 0 {
			return failure(ErrInvalid, "build-worker-resources-out-of-bounds")
		}
	}
	return nil
}

func validateEndpoint(namespace, address string, tls *TLS) error {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "tcp" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return failure(ErrInvalid, "approved-tcp-buildkit-service-required")
	}
	host, port, err := net.SplitHostPort(u.Host)
	number, parseErr := strconv.Atoi(port)
	if err != nil || parseErr != nil || number < 1 || number > 65535 {
		return failure(ErrInvalid, "approved-tcp-buildkit-service-required")
	}
	service := strings.TrimSuffix(strings.TrimSuffix(host, ".cluster.local"), "."+namespace+".svc")
	if host != service+"."+namespace+".svc" && host != service+"."+namespace+".svc.cluster.local" {
		return failure(ErrInvalid, "buildkit-service-must-share-dedicated-namespace")
	}
	if len(validation.IsDNS1123Label(service)) != 0 {
		return failure(ErrInvalid, "buildkit-service-must-share-dedicated-namespace")
	}
	if tls == nil || len(validation.IsDNS1123Subdomain(tls.CASecretName)) != 0 ||
		len(validation.IsDNS1123Subdomain(tls.ClientSecretName)) != 0 ||
		tls.CASecretName == tls.ClientSecretName || tls.ServerName != host {
		return failure(ErrInvalid, "buildkit-mutual-tls-and-exact-server-identity-required")
	}
	return nil
}

func validatePolicy(p Policy) error {
	if SourcePath(p.RecipePath) != nil || !immutableImage(p.Frontend) || !immutableImage(p.Worker) ||
		!validWorkerSelector(p.WorkerArg, p.WorkerContext) || !targetPattern.MatchString(p.Target) ||
		strings.Contains(p.Target, "..") || (p.Platform != "linux/amd64" && p.Platform != "linux/arm64") ||
		!outputRepository(p.OutputRepository) || len(p.SourcePaths) > 512 || len(p.Args) > 2 {
		return failure(ErrInvalid, "invalid-operator-build-policy")
	}
	for key, value := range p.Args {
		switch key {
		case "SOURCE_DATE_EPOCH":
			if n, err := strconv.ParseInt(value, 10, 64); err != nil || n < 0 || len(value) > 12 {
				return failure(ErrInvalid, "invalid-reproducible-build-argument")
			}
		case "BUILDKIT_MULTI_PLATFORM":
			if value != "1" {
				return failure(ErrInvalid, "invalid-multiplatform-build-argument")
			}
		default:
			return failure(ErrInvalid, "unsupported-build-argument")
		}
	}
	for _, name := range p.SourcePaths {
		if SourcePath(name) != nil {
			return failure(ErrInvalid, "invalid-approved-diagnostic-path")
		}
	}
	if len(p.BuildOnlyInputs) > 128 {
		return failure(ErrInvalid, "private-baseline-input-limit")
	}
	for name, digest := range p.BuildOnlyInputs {
		if name == p.RecipePath || SourcePath(name) != nil || !strings.HasSuffix(name, ".patch") || !digestPattern.MatchString(digest) {
			return failure(ErrInvalid, "private-baseline-input-binding-invalid")
		}
	}
	return nil
}

func validWorkerSelector(argument, contextName string) bool {
	if (argument == "") == (contextName == "") {
		return false
	}
	if argument != "" {
		return workerArgPattern.MatchString(argument)
	}
	return len(validation.IsDNS1123Label(contextName)) == 0 &&
		contextName != "context" && contextName != "dockerfile" && contextName != "source"
}

// SourcePath accepts only canonical relative source paths. Credential/config
// locations and hidden files are deliberately unsupported in the first lane.
func SourcePath(name string) error {
	if !pathPattern.MatchString(name) || path.Clean(name) != name {
		return failure(ErrInvalid, "noncanonical-source-path")
	}
	for part := range strings.SplitSeq(name, "/") {
		lower := strings.ToLower(part)
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") ||
			lower == "credentials" || lower == "kubeconfig" || lower == "config.json" ||
			lower == "id_rsa" || lower == "id_ed25519" || lower == "token" ||
			strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") {
			return failure(ErrInvalid, "credential-or-hidden-source-path-forbidden")
		}
	}
	return nil
}

func immutableImage(value string) bool {
	parsed, err := reference.ParseNormalizedNamed(value)
	if err != nil || parsed.String() != value || len(value) > 256 {
		return false
	}
	digested, ok := parsed.(reference.Digested)
	return ok && digestPattern.MatchString(digested.Digest().String())
}

func outputRepository(value string) bool {
	parsed, err := reference.ParseNormalizedNamed(value)
	return err == nil && len(value) <= 200 && parsed.String() == value &&
		reference.IsNameOnly(parsed) && !strings.ContainsAny(value, ",@")
}

func inputPolicy(input Input) Policy {
	return Policy{
		RecipePath: input.RecipePath, Frontend: input.Frontend, Worker: input.Worker,
		WorkerArg: input.WorkerArg, Target: input.Target, Platform: input.Platform,
		WorkerContext:    input.WorkerContext,
		OutputRepository: input.OutputRepository, Args: input.Args, BuildOnlyInputs: input.BuildOnlyInputs,
	}
}

func (b *Backend) admit(input Input) (Input, Policy, error) {
	if err := validateInput(input, b.config.Limits); err != nil {
		return Input{}, Policy{}, err
	}
	for _, approved := range b.config.Policies {
		compare := approved
		compare.SourcePaths = nil
		if jsonDigest(compare) != jsonDigest(inputPolicy(input)) {
			continue
		}
		input.Files = maps.Clone(input.Files)
		for name, body := range input.Files {
			input.Files[name] = bytes.Clone(body)
		}
		input.Args = maps.Clone(input.Args)
		input.BuildOnlyInputs = maps.Clone(input.BuildOnlyInputs)
		input.InputDigest = canonicalDigest(input)
		return input, approved, nil
	}
	return Input{}, Policy{}, failure(ErrInvalid, "build-options-not-operator-approved")
}

func validateInput(input Input, limits Limits) error {
	if !idPattern.MatchString(input.RunID) || !idPattern.MatchString(input.OperationID) ||
		len(input.Files) == 0 || len(input.Files) > limits.MaxFiles {
		return failure(ErrInvalid, "invalid-build-input")
	}
	if err := validatePolicy(inputPolicy(input)); err != nil {
		return err
	}
	for name, expected := range input.BuildOnlyInputs {
		content, exists := input.Files[name]
		if !exists || digest(content) != expected {
			return failure(ErrInvalid, "private-baseline-input-bytes-changed")
		}
	}
	total := 0
	for name, body := range input.Files {
		if SourcePath(name) != nil || len(body) > limits.MaxFileBytes || !utf8.Valid(body) ||
			bytes.IndexByte(body, 0) >= 0 ||
			(secretPattern.Match(body) && input.BuildOnlyInputs[name] != digest(body)) {
			return failure(ErrInvalid, "unsupported-source-file")
		}
		total += len(name) + len(body)
		if total > limits.MaxInputBytes {
			return failure(ErrLimit, "build-input-size-limit")
		}
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if _, exists := input.Files[parent]; exists {
				return failure(ErrInvalid, "source-file-directory-collision")
			}
		}
	}
	if _, ok := input.Files[input.RecipePath]; !ok {
		return failure(ErrInvalid, "recipe-file-missing")
	}
	if err := provenance.ValidateDalecBuildArguments(input.Files[input.RecipePath], input.Platform); err != nil {
		return failure(ErrInvalid, "unsupported-dalec-argument-or-yaml")
	}
	if err := offlineRecipe(input.Files[input.RecipePath]); err != nil {
		return err
	}
	if input.InputDigest != "" && input.InputDigest != canonicalDigest(input) {
		return failure(ErrInvalid, "canonical-input-digest-mismatch")
	}
	return nil
}

// CanonicalInputDigest is a versioned wire contract. It binds operation identity,
// all source bytes, and exact approved options, but excludes recovery hints and
// the supplied digest. Map order is normalized by encoding/json.
func CanonicalInputDigest(input Input) (string, error) {
	limits := Limits{}
	defaultLimits(&limits)
	limits.MaxFileBytes = MaxInputBytes
	limits.MaxFiles = 512
	if err := validateInput(input, limits); err != nil {
		return "", err
	}
	return canonicalDigest(input), nil
}

func canonicalDigest(input Input) string {
	input.InputDigest, input.ExpectedJobUID, input.RequireExisting = "", "", false
	return jsonDigest(struct {
		Domain string
		Input  Input
	}{"orka.remediation.buildjob.input.v1", input})
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func jsonDigest(value any) string {
	raw, _ := json.Marshal(value)
	return digest(raw)
}

func operationName(run, operation string) string {
	key := jsonDigest(struct{ Run, Operation string }{run, operation})
	return "rem-build-" + strings.TrimPrefix(key, "sha256:")[:40]
}
