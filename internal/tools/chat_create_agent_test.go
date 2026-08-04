/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

const testProviderOpenAI = "openai"

func TestChatCreateAgentTool_Execute_OmittedProviderRefLeavesNil(t *testing.T) {
	fc := newFakeClient()
	ctx := WithToolContext(context.Background(), &ToolContext{
		Client:    fc,
		Namespace: defaultNamespace,
	})

	tool := &ChatCreateAgentTool{}
	result, err := tool.Execute(ctx, json.RawMessage(`{"name":"agent-no-provider","model":{"provider":"openai","name":"gpt-4.1-mini"}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var r ChatToolResult
	if err := json.Unmarshal([]byte(result), &r); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}
	if !r.Success {
		t.Fatalf("expected success, got error: %s", r.Error)
	}

	var created corev1alpha1.Agent
	if err := fc.Get(context.Background(), client.ObjectKey{
		Name:      "agent-no-provider",
		Namespace: defaultNamespace,
	}, &created); err != nil {
		t.Fatalf("failed to get created agent: %v", err)
	}

	if created.Spec.ProviderRef != nil {
		t.Fatalf("providerRef = %#v, want nil when providerRef argument is omitted", created.Spec.ProviderRef)
	}
	if created.Spec.Model == nil {
		t.Fatal("model is nil")
	}
	if created.Spec.Model.Provider != testProviderOpenAI {
		t.Fatalf("model.provider = %q, want openai when no providerRef is set", created.Spec.Model.Provider)
	}
}
func TestChatCreateAgentTool_Execute_RejectsUnsupportedRuntime(t *testing.T) {
	fc := newFakeClient()
	ctx := WithToolContext(context.Background(), &ToolContext{Client: fc, Namespace: defaultNamespace})
	result, err := (&ChatCreateAgentTool{}).Execute(ctx, json.RawMessage(`{
		"name": "legacy-runtime-agent",
		"runtime": {"type": "opencode", "secretRef": "legacy-runtime"}
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var response ChatToolResult
	if err := json.Unmarshal([]byte(result), &response); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}
	if response.Success || response.ErrorType != errTypeInvalidArgs || !strings.Contains(response.Error, "unsupported runtime type") {
		t.Fatalf("response = %#v, want unsupported runtime rejection", response)
	}
	var created corev1alpha1.Agent
	if err := fc.Get(context.Background(), client.ObjectKey{Name: "legacy-runtime-agent", Namespace: defaultNamespace}, &created); !apierrors.IsNotFound(err) {
		t.Fatalf("unsupported runtime Agent should not be created, get err=%v", err)
	}
}

func TestChatCreateAgentTool_Execute_RollsBackAgentWhenInitialTaskAuthorizationFails(t *testing.T) {
	fc := newFakeClient()
	ctx := WithToolContext(context.Background(), &ToolContext{
		Client:     fc,
		Namespace:  defaultNamespace,
		TaskLabels: func() map[string]string { return map[string]string{} },
		CheckTaskLimit: func() *ChatToolError {
			return nil
		},
		GenerateTaskName: func() string { return "blocked-task" },
		AuthorizeTaskCreate: func(context.Context, *corev1alpha1.Task) *ChatToolError {
			return &ChatToolError{Type: "permission_denied", Message: "task blocked by context token"}
		},
	})

	tool := &ChatCreateAgentTool{}
	result, err := tool.Execute(ctx, json.RawMessage(`{"name":"agent-rollback","initialPrompt":"run this"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var r ChatToolResult
	if err := json.Unmarshal([]byte(result), &r); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}
	if r.Success {
		t.Fatalf("expected authorization failure, got success: %#v", r)
	}
	if r.ErrorType != "permission_denied" {
		t.Fatalf("errorType = %q, want permission_denied", r.ErrorType)
	}

	var created corev1alpha1.Agent
	err = fc.Get(context.Background(), client.ObjectKey{Name: "agent-rollback", Namespace: defaultNamespace}, &created)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("agent should have been rolled back, get err=%v", err)
	}
}

func TestChatCreateAgentTool_Execute_AuthorizesAgentBeforeCreate(t *testing.T) {
	fc := newFakeClient()
	ctx := WithToolContext(context.Background(), &ToolContext{
		Client:    fc,
		Namespace: defaultNamespace,
		AuthorizeAgentCreate: func(context.Context, *corev1alpha1.Agent) *ChatToolError {
			return &ChatToolError{Type: "authorization_failed", Message: "agent blocked by context token"}
		},
	})

	tool := &ChatCreateAgentTool{}
	result, err := tool.Execute(ctx, json.RawMessage(`{"name":"agent-blocked"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var r ChatToolResult
	if err := json.Unmarshal([]byte(result), &r); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}
	if r.Success {
		t.Fatalf("expected authorization failure, got success: %#v", r)
	}

	var created corev1alpha1.Agent
	err = fc.Get(context.Background(), client.ObjectKey{Name: "agent-blocked", Namespace: defaultNamespace}, &created)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("agent should not have been created, get err=%v", err)
	}
}
func TestParseRuntimeConfig_BuiltInRuntimesAreCredentialFree(t *testing.T) {
	for _, runtimeType := range []corev1alpha1.AgentRuntimeType{
		corev1alpha1.AgentRuntimeCopilot,
		corev1alpha1.AgentRuntimeClaude,
		corev1alpha1.AgentRuntimeCodex,
	} {
		t.Run(string(runtimeType), func(t *testing.T) {
			agent := &corev1alpha1.Agent{Spec: corev1alpha1.AgentSpec{
				ProviderRef: &corev1alpha1.ProviderReference{Name: testProviderOpenAI},
				SecretRef:   &corev1.LocalObjectReference{Name: "legacy-runtime"},
			}}
			args := map[string]any{runtimeField: map[string]any{
				jsonSchemaTypeField: string(runtimeType),
				secretRefField:      "missing-legacy-runtime",
			}}
			if errResult, ok := parseRuntimeConfig(args, agent); !ok {
				t.Fatalf("parseRuntimeConfig returned error: %s", errResult)
			}
			if agent.Spec.Runtime == nil || agent.Spec.Runtime.Type != runtimeType {
				t.Fatalf("runtime = %#v, want %q", agent.Spec.Runtime, runtimeType)
			}
			if agent.Spec.ProviderRef != nil || agent.Spec.SecretRef != nil {
				t.Fatalf("providerRef=%#v secretRef=%#v, want credential-free runtime", agent.Spec.ProviderRef, agent.Spec.SecretRef)
			}
		})
	}
	t.Run("normalizes runtime type", func(t *testing.T) {
		agent := &corev1alpha1.Agent{}
		args := map[string]any{runtimeField: map[string]any{jsonSchemaTypeField: "  claude  "}}
		if errResult, ok := parseRuntimeConfig(args, agent); !ok {
			t.Fatalf("parseRuntimeConfig returned error: %s", errResult)
		}
		if agent.Spec.Runtime == nil || agent.Spec.Runtime.Type != corev1alpha1.AgentRuntimeClaude {
			t.Fatalf("runtime = %#v, want normalized claude", agent.Spec.Runtime)
		}
	})
}

func TestParseRuntimeConfig_RejectsUnsupportedRuntime(t *testing.T) {
	for _, runtimeType := range []string{"opencode", "", "   "} {
		t.Run(runtimeType, func(t *testing.T) {
			agent := &corev1alpha1.Agent{}
			args := map[string]any{runtimeField: map[string]any{jsonSchemaTypeField: runtimeType}}
			errResult, ok := parseRuntimeConfig(args, agent)
			if ok {
				t.Fatal("parseRuntimeConfig accepted invalid runtime")
			}
			var response ChatToolResult
			if err := json.Unmarshal([]byte(errResult), &response); err != nil {
				t.Fatalf("unmarshal error result: %v", err)
			}
			if response.ErrorType != errTypeInvalidArgs || (!strings.Contains(response.Error, "unsupported runtime type") && !strings.Contains(response.Error, "runtime.type is required")) {
				t.Fatalf("response = %#v, want invalid runtime rejection", response)
			}
		})
	}
}

func TestParseRuntimeConfig_AppliesRuntimeDefaults(t *testing.T) {
	agent := &corev1alpha1.Agent{
		Spec: corev1alpha1.AgentSpec{
			ProviderRef: &corev1alpha1.ProviderReference{Name: testProviderOpenAI},
		},
	}

	args := map[string]any{runtimeField: map[string]any{jsonSchemaTypeField: runtimeTypeClaude, "defaultMaxTurns": float64(15),
		"defaultAllowedTools": []any{"Read", "Write", "Bash"},
		"defaultAllowBash":    false,
	},
	}

	if errResult, ok := parseRuntimeConfig(args, agent); !ok {
		t.Fatalf("parseRuntimeConfig returned error: %s", errResult)
	}

	if agent.Spec.Runtime == nil {
		t.Fatal("agent.Spec.Runtime is nil")
	}
	if agent.Spec.Runtime.DefaultMaxTurns == nil || *agent.Spec.Runtime.DefaultMaxTurns != 15 {
		t.Fatalf("defaultMaxTurns = %v, want 15", agent.Spec.Runtime.DefaultMaxTurns)
	}
	if got := agent.Spec.Runtime.DefaultAllowedTools; len(got) != 3 || got[0] != "Read" || got[1] != "Write" || got[2] != "Bash" {
		t.Fatalf("defaultAllowedTools = %#v, want Read/Write/Bash", got)
	}
	if agent.Spec.Runtime.DefaultAllowBash == nil || *agent.Spec.Runtime.DefaultAllowBash {
		t.Fatalf("defaultAllowBash = %v, want false", agent.Spec.Runtime.DefaultAllowBash)
	}
}
func TestParseCoordinationConfig_EnabledClearsRuntimeAndSecretRef(t *testing.T) {
	agent := &corev1alpha1.Agent{
		Spec: corev1alpha1.AgentSpec{
			Runtime:   &corev1alpha1.AgentCLIRuntime{Type: runtimeTypeClaude},
			SecretRef: &corev1.LocalObjectReference{Name: testRuntimeCredsSecretName},
		},
	}

	args := map[string]any{
		"coordination": map[string]any{
			enabledString: true,
		},
	}

	parseCoordinationConfig(args, agent)

	if agent.Spec.Coordination == nil {
		t.Fatal("agent.Spec.Coordination is nil")
	}
	if !agent.Spec.Coordination.Enabled {
		t.Fatal("coordination.enabled = false, want true")
	}
	if agent.Spec.Runtime != nil {
		t.Errorf("runtime = %v, want nil", agent.Spec.Runtime)
	}
	if agent.Spec.SecretRef != nil {
		t.Errorf("secretRef = %v, want nil", agent.Spec.SecretRef)
	}
}
