package supervisor

import (
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/acp"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
)

// The fixture chunks below are the exact agent_message_chunk texts GitHub
// Copilot CLI 1.0.77 emitted in --acp mode under the supervisor's flags when
// --excluded-tools carried the pre-fix exclusion list (issue #460).
var copilotObservedDiagnostics = []string{
	"Info: Disabled tools: list_agents, read_agent, skill, sql, task, write_agent",
	`Info: Unknown tool name in the tool excludedlist: "ask_user"`,
	`Info: Unknown tool name in the tool excludedlist: "code_review"`,
	`Info: Unknown tool name in the tool excludedlist: "github-mcp-server"`,
	`Info: Unknown tool name in the tool excludedlist: "report_intent"`,
	"Info: Response was interrupted due to a server error. Retrying...",
}

func TestCopilotAgentDiagnosticFilterWithholdsPinnedCLIDiagnostics(t *testing.T) {
	filter := copilotAgentDiagnosticFilter([]string{
		"ask_user", "code_review", "github-mcp-server", "list_agents", "read_agent", "report_intent",
		"skill", "sql", "task", "write_agent", "bash", "list_bash",
	})
	for _, text := range copilotObservedDiagnostics {
		if !filter(text) {
			t.Fatalf("observed CLI diagnostic was not recognized: %q", text)
		}
	}
	withheld := []string{
		// A restricted session's line names policy exclusions and tools the
		// CLI disabled on its own (web_search under a BYOK provider).
		"Info: Disabled tools: bash, list_bash, skill, web_search",
		"Info: Disabled tools: github-mcp-server-search_code, sql",
	}
	for _, text := range withheld {
		if !filter(text) {
			t.Fatalf("diagnostic naming a session exclusion was not recognized: %q", text)
		}
	}
	forwarded := []string{
		"PONG",
		"",
		"Info:",
		"Info: Disabled tools: ",
		"Info: Disabled tools: web_search",
		"Info: Disabled tools: skill; PONG",
		"Info: Disabled tools: skill\nPONG",
		"Info: Disabled tools: skill, ",
		`Info: Unknown tool name in the tool excludedlist: "view"`,
		`Info: Unknown tool name in the tool excludedlist: skill`,
		`Info: Unknown tool name in the tool excludedlist: "skill" PONG`,
		"Info: Response was interrupted due to a server error. Retrying... PONG",
		"Error: Could not connect to local model provider at http://127.0.0.1:1/v1.",
		"The disabled tools are: skill",
	}
	for _, text := range forwarded {
		if filter(text) {
			t.Fatalf("assistant text was withheld as a CLI diagnostic: %q", text)
		}
	}
}

func TestWithholdAgentDiagnosticKeepsModelTextIntact(t *testing.T) {
	filter := copilotAgentDiagnosticFilter(copilotAlwaysExcludedToolIDs)
	compactor := newAssistantMessageCompactor()
	compactor.flushInterval = time.Hour
	t.Cleanup(compactor.close)
	now := time.Now().UTC()
	state := &sessionState{agentDiagnosticFilter: filter}

	var texts []string
	sequence := int64(0)
	push := func(text string) {
		sequence++
		event := testAssistantMessagePromptEvent(t, sequence, now, text)
		if withholdAgentDiagnostic(state, "prompt-1", event) {
			return
		}
		for _, ready := range compactor.push(event, now) {
			ready, _ := assistantMessageText(ready)
			texts = append(texts, ready)
		}
	}
	push("Info: Disabled tools: list_agents, read_agent, skill, sql, task, write_agent")
	push("PO")
	push("NG")
	push("Info: Response was interrupted due to a server error. Retrying...")
	push(" Done.")
	for _, ready := range compactor.flushPending() {
		text, _ := assistantMessageText(ready)
		texts = append(texts, text)
	}
	if got := strings.Join(texts, "|"); got != "PONG Done." {
		t.Fatalf("assistant text after withholding = %q, want %q", got, "PONG Done.")
	}

	// Sessions without a projection filter forward every chunk.
	if withholdAgentDiagnostic(&sessionState{}, "prompt-1", testAssistantMessagePromptEvent(t, 1, now, copilotObservedDiagnostics[0])) {
		t.Fatal("session without a diagnostic filter withheld a chunk")
	}
	// Non-text updates are never withheld even when they carry a matching string.
	toolCall := acp.PromptEvent{Type: acp.PromptEventUpdate, Sequence: 2, Timestamp: now, Update: &acp.SessionNotification{
		SessionID: "s",
		Update:    []byte(`{"sessionUpdate":"tool_call","toolCallId":"t","title":"` + copilotObservedDiagnostics[0] + `"}`),
	}}
	if withholdAgentDiagnostic(state, "prompt-1", toolCall) {
		t.Fatal("tool_call update was withheld as a diagnostic")
	}
}

func TestCopilotProjectionDeclaresDiagnosticFilterForSessionExclusions(t *testing.T) {
	paths := acp.SessionPaths{Home: t.TempDir(), Config: t.TempDir()}
	proxy := ProviderProxyBinding{BaseURL: "http://127.0.0.1:1/v1", Credential: strings.Repeat("c", 32)}
	copilot, err := providerProfile(providerKindCopilot, "copilot-test", harnessv2.WorkspaceIntentRead)
	if err != nil {
		t.Fatal(err)
	}
	unrestricted, err := copilot.ProjectSession(testProviderProjectionRequest(t, providerKindCopilot, "copilot-test", "", "", nil, nil, true), paths, proxy)
	if err != nil {
		t.Fatal(err)
	}
	if unrestricted.AgentDiagnosticFilter == nil {
		t.Fatal("unrestricted Copilot projection declared no diagnostic filter")
	}
	for _, text := range copilotObservedDiagnostics[:1] {
		if !unrestricted.AgentDiagnosticFilter(text) {
			t.Fatalf("unrestricted projection did not recognize %q", text)
		}
	}
	if unrestricted.AgentDiagnosticFilter("Info: Disabled tools: bash, list_bash") {
		t.Fatal("unrestricted projection withheld a diagnostic about tools it did not exclude")
	}

	restricted, err := copilot.ProjectSession(
		testProviderProjectionRequest(t, providerKindCopilot, "copilot-test", "", "", []string{providerToolRead, providerToolGrep}, nil, false), paths, proxy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !restricted.AgentDiagnosticFilter("Info: Disabled tools: bash, list_bash, read_bash, stop_bash, write_bash, skill") {
		t.Fatal("restricted projection did not recognize the policy exclusion diagnostic")
	}
	if restricted.AgentDiagnosticFilter("Info: Disabled tools: view, grep") {
		t.Fatal("restricted projection withheld a diagnostic about authorized tools")
	}
}

// The pinned Copilot CLI registers exactly these built-in tool names from the
// permanent exclusion set; any other name makes it print an "Unknown tool
// name" diagnostic for every prompt. Re-verify against the CLI in --acp mode
// when the runtime image pin moves.
func TestCopilotAlwaysExcludedToolIDsMatchPinnedCLICatalog(t *testing.T) {
	want := "list_agents,read_agent,skill,sql,task,write_agent"
	if got := strings.Join(copilotAlwaysExcludedToolIDs, ","); got != want {
		t.Fatalf("copilotAlwaysExcludedToolIDs = %s, want %s (verified against Copilot CLI 1.0.77)", got, want)
	}
}
