// Package remediationpolicy defines the restrictive native proposal policy
// shared by admission to the adapter and the controller's Job render boundary.
// Metadata markers only restrict execution; they are not authorization proof.
package remediationpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/workerenv"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	NativeBackend           = "native-ai"
	CreatedBy               = "remediation-proposal"
	RunLabel                = "orka.ai/remediation-run"
	RunAnnotation           = "orka.ai/remediation-run-id"
	RequestDigestAnnotation = "orka.ai/remediation-request-digest"
	IdentityAnnotation      = "orka.ai/remediation-plan-identity"
	TaskTimeout             = 15 * time.Minute
	MaxPromptBytes          = 256 << 10

	requestVersion  = "orka.remediation.native/v1"
	identityVersion = "orka.remediation.native-plan/v2"
)

var (
	// ErrIdentityChanged requires a new explicit policy decision; it never
	// authorizes transparently switching to another Agent or Provider.
	ErrIdentityChanged = errors.New("proposal Agent or Provider identity changed")
	// ErrCredentialRotated distinguishes a changed Secret UID/resourceVersion
	// when all other frozen identities match. Retrying requires caller policy.
	ErrCredentialRotated = errors.New("proposal Provider credential identity changed")
	proposalNamePattern  = regexp.MustCompile(`^rm-[a-f0-9]{32}-(?:discovery|checks|patch)(?:-|$)`)
)

// PlanIdentity contains only public object identities, never Secret data.
// Its digest is versioned and JSON-framed; changing that framing requires a new
// identityVersion. Generation attests a Kubernetes object's immutable spec
// revision; status and unrelated Agent/Provider metadata are deliberately absent.
type PlanIdentity struct {
	Backend               string `json:"backend,omitempty"`
	CopilotConfigDigest   string `json:"copilotConfigDigest,omitempty"`
	RuntimeImage          string `json:"runtimeImage,omitempty"`
	RuntimeNamespace      string `json:"runtimeNamespace,omitempty"`
	RuntimeNamespaceUID   string `json:"runtimeNamespaceUID,omitempty"`
	RuntimeProfileDigest  string `json:"runtimeProfileDigest,omitempty"`
	ProxyEndpoint         string `json:"proxyEndpoint,omitempty"`
	ProxyNamespace        string `json:"proxyNamespace,omitempty"`
	ProxyNamespaceUID     string `json:"proxyNamespaceUID,omitempty"`
	ProxyIdentityDigest   string `json:"proxyIdentityDigest,omitempty"`
	Namespace             string `json:"namespace"`
	AgentName             string `json:"agentName"`
	AgentUID              string `json:"agentUID"`
	AgentGeneration       int64  `json:"agentGeneration"`
	ProviderName          string `json:"providerName"`
	ProviderUID           string `json:"providerUID"`
	ProviderGeneration    int64  `json:"providerGeneration"`
	SecretRefName         string `json:"secretRefName"`
	SecretUID             string `json:"secretUID"`
	SecretResourceVersion string `json:"secretResourceVersion"`
	Digest                string `json:"digest"`
}

// IsNativeProposal selects either marker independently. A malformed or empty
// identity annotation must not bypass the controller's fail-closed guard.
func IsNativeProposal(task *corev1alpha1.Task) bool {
	if task == nil {
		return false
	}
	for _, name := range []string{IdentityAnnotation, RunAnnotation, RequestDigestAnnotation} {
		if _, pinned := task.Annotations[name]; pinned {
			return true
		}
	}
	_, labeled := task.Labels[RunLabel]
	return task.Labels[labels.LabelCreatedBy] == CreatedBy || labeled || proposalNamePattern.MatchString(task.Name)
}

// ValidateAgent rejects extensions instead of silently stripping configuration.
func ValidateAgent(registered *corev1alpha1.Agent) error {
	if registered == nil || len(validation.IsDNS1123Subdomain(registered.Name)) != 0 ||
		len(validation.IsDNS1123Label(registered.Namespace)) != 0 || registered.UID == "" ||
		registered.Generation < 1 || registered.DeletionTimestamp != nil {
		return errors.New("proposal Agent has no stable identity")
	}
	spec := &registered.Spec
	if spec.ProviderRef == nil || len(validation.IsDNS1123Subdomain(spec.ProviderRef.Name)) != 0 ||
		(spec.ProviderRef.Namespace != "" && spec.ProviderRef.Namespace != registered.Namespace) {
		return errors.New("native proposal Agent requires a same-namespace Provider reference")
	}
	if spec.Runtime != nil || spec.Coordination != nil || len(spec.Skills) != 0 ||
		spec.SecretRef != nil || spec.Execution != nil {
		return errors.New("native proposal Agent contains runtime, coordination, skill, credential, or execution extensions")
	}
	if spec.Model != nil && len(spec.Model.Fallbacks) != 0 {
		return errors.New("native proposal Agent must not configure fallback providers")
	}
	if spec.SystemPrompt != nil && spec.SystemPrompt.ConfigMapRef != nil {
		return errors.New("native proposal Agent system prompt must not reference mutable external content")
	}
	for _, tool := range spec.Tools {
		if tool.Enabled == nil || *tool.Enabled {
			return errors.New("native proposal Agent must explicitly disable every configured tool")
		}
	}
	return nil
}

// MetadataIdentity derives the pin from these exact Agent/Provider objects.
// It never fetches replacement Agent/Provider objects. Reader must be uncached
// and is used only for Secret metadata, not credential data. Readiness is not
// identity: an in-flight operation may observe a transient readiness flap.
func MetadataIdentity(
	ctx context.Context, reader client.Reader, registered *corev1alpha1.Agent, provider *corev1alpha1.Provider,
) (PlanIdentity, error) {
	var identity PlanIdentity
	if ctx == nil || reader == nil {
		return identity, errors.New("proposal context and uncached Kubernetes reader are required")
	}
	if err := ctx.Err(); err != nil {
		return identity, err
	}
	if err := ValidateAgent(registered); err != nil {
		return identity, err
	}
	if provider == nil || provider.Name != registered.Spec.ProviderRef.Name ||
		provider.Namespace != registered.Namespace || provider.UID == "" ||
		provider.Generation < 1 || provider.DeletionTimestamp != nil {
		return identity, errors.New("proposal Provider has no matching stable identity")
	}
	if len(validation.IsDNS1123Subdomain(provider.Spec.SecretRef.Name)) != 0 {
		return identity, errors.New("proposal Provider requires an explicit credential Secret reference")
	}
	secret := &metav1.PartialObjectMetadata{}
	secret.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Secret"})
	key := client.ObjectKey{Namespace: registered.Namespace, Name: provider.Spec.SecretRef.Name}
	if err := reader.Get(ctx, key, secret); err != nil {
		if ctx.Err() != nil {
			return identity, ctx.Err()
		}
		return identity, errors.New("proposal Provider credential identity is unavailable")
	}
	if secret.Name != key.Name || secret.Namespace != key.Namespace || secret.UID == "" ||
		secret.ResourceVersion == "" || secret.DeletionTimestamp != nil {
		return identity, errors.New("proposal Provider credential has no stable identity")
	}
	identity = PlanIdentity{
		Namespace: registered.Namespace, AgentName: registered.Name, AgentUID: string(registered.UID),
		AgentGeneration: registered.Generation, ProviderName: provider.Name, ProviderUID: string(provider.UID),
		ProviderGeneration: provider.Generation, SecretRefName: secret.Name, SecretUID: string(secret.UID),
		SecretResourceVersion: secret.ResourceVersion,
	}
	digest, err := MetadataDigest(identity)
	if err != nil {
		return PlanIdentity{}, err
	}
	identity.Digest = digest
	return identity, nil
}

// MetadataDigest validates and hashes a metadata-only identity. Digest itself is
// excluded from the input so persisted identities can be independently checked.
func MetadataDigest(identity PlanIdentity) (string, error) {
	if identity.Backend == CopilotBackend {
		return copilotIdentityDigest(identity)
	}
	if identity.Backend != "" {
		return "", ErrIdentityChanged
	}
	if len(validation.IsDNS1123Label(identity.Namespace)) != 0 ||
		len(validation.IsDNS1123Subdomain(identity.AgentName)) != 0 ||
		len(validation.IsDNS1123Subdomain(identity.ProviderName)) != 0 ||
		len(validation.IsDNS1123Subdomain(identity.SecretRefName)) != 0 ||
		identity.AgentUID == "" || identity.ProviderUID == "" || identity.SecretUID == "" ||
		identity.AgentGeneration < 1 || identity.ProviderGeneration < 1 || identity.SecretResourceVersion == "" {
		return "", errors.New("proposal metadata identity is incomplete")
	}
	identity.Digest = ""
	return framedDigest(identityVersion, identity)
}

// CompareIdentity classifies drift without authorizing a new attempt or endpoint.
func CompareIdentity(expected, current PlanIdentity) error {
	for _, identity := range []PlanIdentity{expected, current} {
		digest, err := MetadataDigest(identity)
		if err != nil || identity.Digest != digest {
			return errors.New("proposal metadata identity digest is invalid")
		}
	}
	if expected == current {
		return nil
	}
	expected.Digest, current.Digest = "", ""
	expected.SecretUID, current.SecretUID = "", ""
	expected.SecretResourceVersion, current.SecretResourceVersion = "", ""
	if expected == current {
		return ErrCredentialRotated
	}
	return ErrIdentityChanged
}

// ValidateNativeDispatch is the last restrictive check before Job rendering.
// Pass the exact in-memory Agent/Provider that will be rendered, not independently
// refetched replacements. The annotation grants no authorization. Secret refs
// resolve again at Pod start, so callers must retain completion-time pin checks
// to discard results after a post-render credential rotation.
func ValidateNativeDispatch(
	ctx context.Context, reader client.Reader, task *corev1alpha1.Task,
	registered *corev1alpha1.Agent, provider *corev1alpha1.Provider,
) error {
	if err := ValidateTask(task); err != nil {
		return err
	}
	if registered == nil || registered.Name != task.Spec.AgentRef.Name || registered.Namespace != task.Namespace {
		return errors.New("proposal render Agent does not match the Task")
	}
	if provider == nil || !provider.Status.Ready {
		return errors.New("proposal Provider is not ready for dispatch")
	}
	identity, err := MetadataIdentity(ctx, reader, registered, provider)
	if err != nil {
		return err
	}
	if identity.Digest != task.Annotations[IdentityAnnotation] {
		return ErrIdentityChanged
	}
	return nil
}

// TaskSpec is the single native no-tools render policy. Ordinary AI Tasks do
// not use it and therefore retain their existing worker memory defaults.
func TaskSpec(prompt, agentName string) corev1alpha1.TaskSpec {
	return corev1alpha1.TaskSpec{
		Type: corev1alpha1.TaskTypeAI, Prompt: prompt,
		AgentRef:    &corev1alpha1.AgentReference{Name: agentName},
		Timeout:     &metav1.Duration{Duration: TaskTimeout},
		RetryPolicy: &corev1alpha1.RetryPolicy{MaxRetries: 0, BackoffMultiplier: 2},
		Env: []corev1.EnvVar{
			{Name: workerenv.MemoryToolsAutoEnable, Value: "false"},
			{Name: workerenv.MemoryContextEnabled, Value: "false"},
			{Name: workerenv.ResultStdout, Value: "true"},
		},
	}
}

// RequestDigest preserves the adapter's deterministic request framing. Only
// inert Kubernetes defaults are normalized, never execution policy overrides.
func RequestDigest(namespace, name, runID, identity string, spec corev1alpha1.TaskSpec) (string, error) {
	return framedDigest(requestVersion, struct {
		Namespace string                `json:"namespace"`
		Name      string                `json:"name"`
		RunID     string                `json:"runID"`
		Identity  string                `json:"identity"`
		Spec      corev1alpha1.TaskSpec `json:"spec"`
	}{namespace, name, runID, identity, *NormalizeTaskSpec(spec)})
}

// ValidateTask enforces the native Task shape and both restrictive metadata
// bindings. A trusted operation store must separately bind this Task UID.
func ValidateTask(task *corev1alpha1.Task) error {
	if task == nil || len(validation.IsDNS1123Subdomain(task.Name)) != 0 ||
		len(validation.IsDNS1123Label(task.Namespace)) != 0 || task.UID == "" || task.Generation < 1 ||
		task.DeletionTimestamp != nil || len(task.OwnerReferences) != 0 {
		return errors.New("proposal Task has no stable native identity")
	}
	if (task.Kind != "" && task.Kind != "Task") ||
		(task.APIVersion != "" && task.APIVersion != corev1alpha1.GroupVersion.String()) {
		return errors.New("proposal Task has a different resource type")
	}
	if task.Spec.AgentRef == nil || len(validation.IsDNS1123Subdomain(task.Spec.AgentRef.Name)) != 0 ||
		len(task.Spec.Prompt) > MaxPromptBytes || !utf8.ValidString(task.Spec.Prompt) ||
		strings.TrimSpace(task.Spec.Prompt) == "" {
		return errors.New("proposal Task requires a configured Agent and bounded UTF-8 prompt")
	}
	if !reflect.DeepEqual(NormalizeTaskSpec(task.Spec), NormalizeTaskSpec(TaskSpec(task.Spec.Prompt, task.Spec.AgentRef.Name))) {
		return errors.New("proposal Task contains unapproved execution settings")
	}
	runID, identity := task.Annotations[RunAnnotation], task.Annotations[IdentityAnnotation]
	if len(validation.IsDNS1123Subdomain(runID)) != 0 || !ValidDigest(identity) {
		return errors.New("proposal Task has no valid run or plan identity")
	}
	digest, err := RequestDigest(task.Namespace, task.Name, runID, identity, task.Spec)
	if err != nil {
		return err
	}
	expectedLabels := map[string]string{labels.LabelCreatedBy: CreatedBy, RunLabel: labels.SelectorValue(runID)}
	expectedAnnotations := map[string]string{
		RunAnnotation: runID, IdentityAnnotation: identity, RequestDigestAnnotation: digest,
	}
	if !reflect.DeepEqual(task.Labels, expectedLabels) || !reflect.DeepEqual(task.Annotations, expectedAnnotations) {
		return errors.New("proposal Task metadata does not match its native request")
	}
	return nil
}

// NormalizeTaskSpec permits only the CRD's inert nonscheduling defaults.
func NormalizeTaskSpec(spec corev1alpha1.TaskSpec) *corev1alpha1.TaskSpec {
	normalized := spec.DeepCopy()
	if normalized.Priority != nil && *normalized.Priority == 500 {
		normalized.Priority = nil
	}
	if normalized.ConcurrencyPolicy == corev1alpha1.ForbidConcurrent {
		normalized.ConcurrencyPolicy = ""
	}
	if normalized.StartingDeadlineSeconds != nil && *normalized.StartingDeadlineSeconds == 100 {
		normalized.StartingDeadlineSeconds = nil
	}
	if normalized.SuccessfulRunsHistoryLimit != nil && *normalized.SuccessfulRunsHistoryLimit == 3 {
		normalized.SuccessfulRunsHistoryLimit = nil
	}
	if normalized.FailedRunsHistoryLimit != nil && *normalized.FailedRunsHistoryLimit == 1 {
		normalized.FailedRunsHistoryLimit = nil
	}
	return normalized
}

// ValidDigest accepts only the canonical SHA-256 representation.
func ValidDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func framedDigest(version string, value any) (string, error) {
	data, err := json.Marshal(struct {
		Version string `json:"version"`
		Value   any    `json:"value"`
	}{version, value})
	if err != nil {
		return "", errors.New("proposal identity could not be encoded")
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
