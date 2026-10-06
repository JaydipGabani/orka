package agent

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/acp"
	"github.com/orka-agents/orka/internal/cli/client"
	"github.com/orka-agents/orka/internal/controller"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func assertOpenCodeReadOnlyPolicy(t *testing.T, task *corev1alpha1.Task, plan controller.ACPRuntimePlan, withSource bool) string {
	t.Helper()
	wantAllowed := []string{}
	if withSource {
		wantAllowed = []string{"glob", "read"}
	}
	wantDenied := []string{"apply_patch", "bash", "edit", "grep", "write"}
	wantPolicyDigest, err := harnessv2.CanonicalRuntimeToolPolicyDigest(wantAllowed, wantDenied, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Profile.ToolPolicyDigest != wantPolicyDigest {
		t.Fatal("production OpenCode profile did not enforce the exact expected read-only or deny-all policy")
	}
	wantMCPDigest, err := harnessv2.CanonicalMCPConfigurationDigest(wantAllowed)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Profile.MCPConfigurationDigest != wantMCPDigest {
		t.Fatal("production profile admitted unrequested MCP tools")
	}
	allowed, denied, bash := acp.NormalizeOpenCodeToolPolicy(
		true, slices.Clone(task.Spec.AgentRuntime.AllowedTools), nil, false,
	)
	if !reflect.DeepEqual(allowed, wantAllowed) || !reflect.DeepEqual(denied, wantDenied) || bash {
		t.Fatal("shared OpenCode normalization differs from the expected production profile")
	}
	if effective := acp.OpenCodeEffectiveAllowedTools(allowed, denied, bash); !reflect.DeepEqual(effective, wantAllowed) {
		t.Fatal("effective OpenCode permissions differ from the admitted tool surface")
	}
	return wantPolicyDigest
}

func TestOpenCodeProductionAdmissionAndReadOnlyPolicy(t *testing.T) {
	for _, model := range []string{"openai/synthetic-gpt", "anthropic/synthetic-claude"} {
		for _, withSource := range []bool{true, false} {
			name := model + "/source-free"
			if withSource {
				name = model + "/repository"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				c := Client{
					API:       client.NewWithNamespace("http://127.0.0.1", "", "remediation-tests"),
					AgentName: "proposal-agent",
				}
				request := syntheticRequest()
				if !withSource {
					request.Repository, request.Commit = "", ""
				}
				_, payload, err := c.prepare(request)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(payload)
				if err != nil {
					t.Fatal("cannot marshal synthetic proposal request")
				}
				task := &corev1alpha1.Task{
					ObjectMeta: metav1.ObjectMeta{Name: request.TaskName, Namespace: c.API.Namespace},
				}
				// Decode the adapter's actual flat request into the API's TaskSpec,
				// rather than supplying a separately authored tool-policy fixture.
				if err := json.Unmarshal(encoded, &task.Spec); err != nil {
					t.Fatal("proposal request does not decode into the production Task spec")
				}
				if task.Spec.AgentRuntime == nil || task.Spec.AgentRuntime.AllowedTools == nil ||
					task.Spec.AgentRuntime.AllowBash == nil || *task.Spec.AgentRuntime.AllowBash {
					t.Fatal("proposal request must explicitly override tools and disable Bash")
				}
				contextWindow, outputTokens := int32(32768), int32(4096)
				defaultAllowBash := true
				contract := corev1alpha1.AgentRuntimeContractHarnessV2
				registered := &corev1alpha1.Agent{
					ObjectMeta: metav1.ObjectMeta{
						Name: c.AgentName, Namespace: c.API.Namespace, UID: "synthetic-opencode-agent", Generation: 1,
					},
					Spec: corev1alpha1.AgentSpec{
						Model: &corev1alpha1.ModelConfig{
							Name: model, ContextWindow: &contextWindow, MaxTokens: &outputTokens,
						},
						Runtime: &corev1alpha1.AgentCLIRuntime{
							Type:                corev1alpha1.AgentRuntimeOpencode,
							ContractVersion:     &contract,
							DefaultAllowedTools: []string{"read", "write", "edit", "bash", "glob", "grep"},
							DefaultAllowBash:    &defaultAllowBash,
						},
					},
				}
				configuration := harnessv2.AgentSessionConfiguration{
					AgentUID: string(registered.UID), AgentGeneration: registered.Generation,
					ProviderKind: "opencode", Model: model, MaxTurns: request.MaxTurns,
				}
				image := "example.invalid/opencode@sha256:" + strings.Repeat("a", 64)
				images := controller.ACPRuntimeImages{Opencode: image}
				plan, err := controller.PlanACPRuntimeWithConfiguration(task, registered, images, configuration)
				if err != nil {
					t.Fatalf("production OpenCode planning rejected the proposal Task: %v", err)
				}
				if plan.Image != image || plan.Profile.ProviderKind != "opencode" || plan.Profile.Model != model ||
					plan.Profile.WorkspaceIntent != harnessv2.WorkspaceIntentRead || !strings.HasPrefix(plan.PoolName, "acp-opencode-") {
					t.Fatal("production planning did not preserve the registered model and read-only OpenCode profile")
				}
				if err := configuration.ValidateProfile(plan.Profile); err != nil {
					t.Fatalf("runtime admission rejected the planned Agent configuration: %v", err)
				}

				wantPolicyDigest := assertOpenCodeReadOnlyPolicy(t, task, plan, withSource)
				authorizationTools := acp.NormalizeOpenCodeAuthorizationTools(registered.Spec.Runtime.DefaultAllowedTools)
				for _, permission := range acp.NormalizeOpenCodeAuthorizationTools(task.Spec.AgentRuntime.AllowedTools) {
					if !slices.Contains(authorizationTools, permission) {
						t.Fatal("case-normalized proposal tools exceed the registered Agent's authorization surface")
					}
				}

				lowercase := task.DeepCopy()
				for i, tool := range lowercase.Spec.AgentRuntime.AllowedTools {
					lowercase.Spec.AgentRuntime.AllowedTools[i] = strings.ToLower(tool)
				}
				lowercasePlan, err := controller.PlanACPRuntimeWithConfiguration(lowercase, registered, images, configuration)
				if err != nil {
					t.Fatal(err)
				}
				if lowercasePlan.Digest != plan.Digest || lowercasePlan.PoolName != plan.PoolName {
					t.Fatal("tool-name casing changed the admitted OpenCode profile")
				}
				poolProfile := controller.RuntimePoolProfileFromPlan(plan)
				if poolProfile.ToolPolicyDigest != wantPolicyDigest || poolProfile.Model != model {
					t.Fatal("RuntimePool projection changed the admitted model or tool policy")
				}
			})
		}
	}
}
