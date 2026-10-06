package remediationpolicy

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/orka-agents/orka/internal/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	CopilotBackend             = "copilot-acp-v1"
	CopilotResourceClass       = "remediation-source-free-v1"
	CopilotMaxTurns      int32 = 8
)

func ValidateCopilotAgent(agent *corev1alpha1.Agent) error {
	if agent == nil || agent.UID == "" || agent.Generation < 1 || agent.DeletionTimestamp != nil ||
		len(validation.IsDNS1123Label(agent.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(agent.Name)) != 0 {
		return ErrIdentityChanged
	}
	spec := agent.Spec
	if spec.Runtime == nil || spec.Runtime.Type != corev1alpha1.AgentRuntimeCopilot ||
		spec.Runtime.RuntimeRef != nil || agent.BuiltInContractVersion() != corev1alpha1.AgentRuntimeContractHarnessV2 ||
		spec.ProviderRef != nil || spec.SecretRef != nil || spec.Execution != nil || spec.Coordination != nil || len(spec.Skills) != 0 ||
		spec.Model == nil || strings.TrimSpace(spec.Model.Name) == "" || len(spec.Model.Fallbacks) != 0 ||
		(spec.SystemPrompt != nil && spec.SystemPrompt.ConfigMapRef != nil) {
		return errors.New("copilot remediation requires an immutable built-in source-free Agent without credential or tool extensions")
	}
	for _, tool := range spec.Tools {
		if tool.Enabled == nil || *tool.Enabled {
			return errors.New("copilot remediation does not permit Agent tools")
		}
	}
	return nil
}

func CopilotTaskSpec(prompt, agent string) corev1alpha1.TaskSpec {
	return corev1alpha1.TaskSpec{
		Type: corev1alpha1.TaskTypeAgent, AgentRef: &corev1alpha1.AgentReference{Name: agent}, Prompt: prompt,
		Timeout:     &metav1.Duration{Duration: 15 * time.Minute},
		RetryPolicy: &corev1alpha1.RetryPolicy{MaxRetries: 0, BackoffMultiplier: 2},
		AgentRuntime: &corev1alpha1.AgentRuntimeSpec{
			AllowedTools: []string{}, AllowBash: new(false), MaxTurns: new(CopilotMaxTurns),
		},
	}
}

func ValidateCopilotTask(task *corev1alpha1.Task) error {
	if task == nil || task.UID == "" || task.Generation < 1 || task.DeletionTimestamp != nil || task.Spec.AgentRef == nil ||
		task.Spec.Type != corev1alpha1.TaskTypeAgent || task.Spec.Prompt == "" || len(task.Spec.Prompt) > MaxPromptBytes {
		return errors.New("copilot proposal Task identity is unavailable")
	}
	if !reflect.DeepEqual(NormalizeTaskSpec(task.Spec), NormalizeTaskSpec(CopilotTaskSpec(task.Spec.Prompt, task.Spec.AgentRef.Name))) {
		return errors.New("copilot proposal Task contains unsupported execution settings")
	}
	run := task.Annotations[RunAnnotation]
	identity := task.Annotations[IdentityAnnotation]
	if len(validation.IsDNS1123Subdomain(run)) != 0 || !ValidDigest(identity) ||
		task.Labels[labels.LabelCreatedBy] != CreatedBy || task.Labels[RunLabel] != labels.SelectorValue(run) {
		return errors.New("copilot proposal Task lacks the exact remediation binding")
	}
	if task.Annotations[labels.AnnotationAgentReadOnly] != "true" {
		return errors.New("copilot remediation requires its restrictive read-only declaration")
	}
	expected, err := RequestDigest(task.Namespace, task.Name, run, identity, task.Spec)
	if err != nil || task.Annotations[RequestDigestAnnotation] != expected {
		return ErrIdentityChanged
	}
	return nil
}

func ValidateCopilotProfile(profile harnessv2.RuntimeProfile) error {
	tools, err := harnessv2.CanonicalRuntimeToolPolicyDigest([]string{}, nil, false)
	if err != nil {
		return err
	}
	mcp, err := harnessv2.CanonicalMCPConfigurationDigest([]string{})
	if err != nil {
		return err
	}
	if profile.ProviderKind != "copilot" || profile.WorkspaceIntent != harnessv2.WorkspaceIntentRead ||
		profile.ResourceClass != CopilotResourceClass || profile.ToolPolicyDigest != tools || profile.MCPConfigurationDigest != mcp {
		return errors.New("copilot remediation runtime must have no tool or MCP authority")
	}
	return nil
}

func copilotIdentityDigest(identity PlanIdentity) (string, error) {
	if len(validation.IsDNS1123Label(identity.Namespace)) != 0 || len(validation.IsDNS1123Label(identity.RuntimeNamespace)) != 0 ||
		len(validation.IsDNS1123Label(identity.ProxyNamespace)) != 0 ||
		identity.RuntimeNamespaceUID == "" || identity.ProxyNamespaceUID == "" ||
		identity.RuntimeNamespace == identity.ProxyNamespace || !ValidCopilotProxyEndpoint(identity.ProxyEndpoint) ||
		identity.Namespace == identity.RuntimeNamespace || len(validation.IsDNS1123Subdomain(identity.AgentName)) != 0 ||
		identity.AgentUID == "" || identity.AgentGeneration < 1 || !ValidDigest(identity.RuntimeProfileDigest) ||
		!ValidDigest(identity.ProxyIdentityDigest) || !ValidDigest(identity.CopilotConfigDigest) ||
		!strings.Contains(identity.RuntimeImage, "@sha256:") ||
		identity.ProviderName != "" || identity.ProviderUID != "" || identity.SecretRefName != "" {
		return "", ErrIdentityChanged
	}
	identity.Digest = ""
	return framedDigest("orka.remediation.copilot-plan/v3", identity)
}

func ValidCopilotProxyEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && len(endpoint) <= 2048 && endpoint == strings.TrimSpace(endpoint) &&
		(u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" &&
		u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == ""
}
