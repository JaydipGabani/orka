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
var copilotObservedStartupDiagnostics = []string{
	"Info: Disabled tools: list_agents, read_agent, skill, sql, task, write_agent",
	`Info: Unknown tool name in the tool excludedlist: "ask_user"`,
	`Info: Unknown tool name in the tool excludedlist: "code_review"`,
	`Info: Unknown tool name in the tool excludedlist: "github-mcp-server"`,
	`Info: Unknown tool name in the tool excludedlist: "report_intent"`,
}

const copilotObservedRetryNotice = "Info: Response was interrupted due to a server error. Retrying..."

func TestCopilotStartupDiagnosticRecognizesPinnedCLIDiagnostics(t *testing.T) {
	recognize := copilotStartupDiagnostic([]string{
		"ask_user", "code_review", "github-mcp-server", "list_agents", "read_agent", "report_intent",
		"skill", "sql", "task", "write_agent", "bash", "list_bash",
	})
	for _, text := range copilotObservedStartupDiagnostics {
		if !recognize(text) {
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
		if !recognize(text) {
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
		copilotObservedRetryNotice,
		"Error: Could not connect to local model provider at http://127.0.0.1:1/v1.",
		"The disabled tools are: skill",
	}
	for _, text := range forwarded {
		if recognize(text) {
			t.Fatalf("assistant text was recognized as a startup diagnostic: %q", text)
		}
	}
	if !copilotInferenceRetryNotice(copilotObservedRetryNotice) || copilotInferenceRetryNotice(copilotObservedRetryNotice+" PONG") {
		t.Fatal("inference retry notice recognition is not exact")
	}
}

func TestWithholdAgentDiagnosticKeepsModelTextIntact(t *testing.T) {
	filter := &AgentDiagnosticFilter{
		Startup:        copilotStartupDiagnostic(copilotAlwaysExcludedToolIDs),
		InferenceRetry: copilotInferenceRetryNotice,
	}
	compactor := newAssistantMessageCompactor()
	compactor.flushInterval = time.Hour
	t.Cleanup(compactor.close)
	now := time.Now().UTC()
	proxy := &providerProxySession{turnPromptID: "prompt-1"}
	state := &sessionState{agentDiagnosticFilter: filter, providerProxy: proxy}
	prompt := testDiagnosticPromptState()

	var texts []string
	sequence := int64(0)
	push := func(text string) {
		sequence++
		event := testAssistantMessagePromptEvent(t, sequence, now, text)
		if withholdAgentDiagnostic(state, prompt, event) {
			return
		}
		for _, ready := range compactor.push(event, now) {
			ready, _ := assistantMessageText(ready)
			texts = append(texts, ready)
		}
	}
	// The CLI reports exclusions before its first inference request; that
	// request fails in-stream and is retried; the retried response then
	// streams a model answer that repeats both diagnostic sentences
	// verbatim, the first of them as the very first delta.
	push(copilotObservedStartupDiagnostics[0])
	proxy.inferenceResponsesStarted = 1
	proxy.inferenceFailures = 1
	push(copilotObservedRetryNotice)
	proxy.inferenceResponsesStarted = 2
	push(copilotObservedStartupDiagnostics[0])
	push("PO")
	push("NG")
	push(copilotObservedRetryNotice)
	for _, ready := range compactor.flushPending() {
		text, _ := assistantMessageText(ready)
		texts = append(texts, text)
	}
	want := copilotObservedStartupDiagnostics[0] + "PONG" + copilotObservedRetryNotice
	if got := strings.Join(texts, ""); got != want {
		t.Fatalf("assistant text after withholding = %q, want %q", got, want)
	}
	if prompt.withheldRetryNotices != 1 {
		t.Fatalf("withheld retry notices = %d, want 1", prompt.withheldRetryNotices)
	}
}

func TestWithholdAgentDiagnosticAnchorsOnProviderProxyState(t *testing.T) {
	now := time.Now().UTC()
	filter := &AgentDiagnosticFilter{
		Startup:        copilotStartupDiagnostic(copilotAlwaysExcludedToolIDs),
		InferenceRetry: copilotInferenceRetryNotice,
	}
	startup := testAssistantMessagePromptEvent(t, 1, now, copilotObservedStartupDiagnostics[0])
	retry := testAssistantMessagePromptEvent(t, 2, now, copilotObservedRetryNotice)
	toolCall := acp.PromptEvent{Type: acp.PromptEventUpdate, Sequence: 3, Timestamp: now, Update: &acp.SessionNotification{
		SessionID: "s",
		Update:    []byte(`{"sessionUpdate":"tool_call","toolCallId":"t","title":"` + copilotObservedStartupDiagnostics[0] + `"}`),
	}}

	// Sessions without a projection filter forward every chunk.
	if withholdAgentDiagnostic(&sessionState{}, testDiagnosticPromptState(), startup) {
		t.Fatal("session without a diagnostic filter withheld a chunk")
	}

	// A startup diagnostic is withheld until the prompt's first non-error
	// inference response begins relaying; after that an identical chunk is
	// model output. Non-text updates are never withheld.
	state := &sessionState{agentDiagnosticFilter: filter, providerProxy: &providerProxySession{turnPromptID: "prompt-1"}}
	if !withholdAgentDiagnostic(state, testDiagnosticPromptState(), startup) {
		t.Fatal("startup diagnostic was forwarded before any inference response")
	}
	if withholdAgentDiagnostic(state, testDiagnosticPromptState(), toolCall) {
		t.Fatal("tool_call update was withheld as a diagnostic")
	}
	state.providerProxy = &providerProxySession{turnPromptID: "prompt-1", inferenceResponsesStarted: 1}
	if withholdAgentDiagnostic(state, testDiagnosticPromptState(), startup) {
		t.Fatal("startup diagnostic text was withheld after an inference response started")
	}
	state.providerProxy = &providerProxySession{turnPromptID: "other-prompt", inferenceResponsesStarted: 1}
	if !withholdAgentDiagnostic(state, testDiagnosticPromptState(), startup) {
		t.Fatal("another prompt's inference response unblocked a startup diagnostic")
	}

	// A retry notice is withheld only while the proxy recorded more failures
	// than notices already withheld.
	state.providerProxy = &providerProxySession{turnPromptID: "prompt-1"}
	if withholdAgentDiagnostic(state, testDiagnosticPromptState(), retry) {
		t.Fatal("retry notice withheld without a recorded failure")
	}
	state.providerProxy = &providerProxySession{turnPromptID: "prompt-1", inferenceFailures: 2}
	prompt := testDiagnosticPromptState()
	for i := range 2 {
		if !withholdAgentDiagnostic(state, prompt, retry) {
			t.Fatalf("retry notice %d was not withheld with two recorded failures", i+1)
		}
	}
	if withholdAgentDiagnostic(state, prompt, retry) {
		t.Fatal("third retry notice withheld with only two recorded failures")
	}
	state.providerProxy = &providerProxySession{turnPromptID: "other-prompt", inferenceFailures: 5}
	if withholdAgentDiagnostic(state, testDiagnosticPromptState(), retry) {
		t.Fatal("retry notice withheld against another prompt's failures")
	}
}

func testDiagnosticPromptState() *promptState {
	prompt := &promptState{}
	prompt.request.Metadata.PromptID = "prompt-1"
	return prompt
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
	if unrestricted.AgentDiagnosticFilter == nil || unrestricted.AgentDiagnosticFilter.Startup == nil || unrestricted.AgentDiagnosticFilter.InferenceRetry == nil {
		t.Fatal("unrestricted Copilot projection declared no diagnostic filter")
	}
	if !unrestricted.AgentDiagnosticFilter.Startup(copilotObservedStartupDiagnostics[0]) {
		t.Fatalf("unrestricted projection did not recognize %q", copilotObservedStartupDiagnostics[0])
	}
	if unrestricted.AgentDiagnosticFilter.Startup("Info: Disabled tools: bash, list_bash") {
		t.Fatal("unrestricted projection recognized a diagnostic about tools it did not exclude")
	}
	if !unrestricted.AgentDiagnosticFilter.InferenceRetry(copilotObservedRetryNotice) {
		t.Fatal("unrestricted projection did not recognize the inference retry notice")
	}

	restricted, err := copilot.ProjectSession(
		testProviderProjectionRequest(t, providerKindCopilot, "copilot-test", "", "", []string{providerToolRead, providerToolGrep}, nil, false), paths, proxy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !restricted.AgentDiagnosticFilter.Startup("Info: Disabled tools: bash, list_bash, read_bash, stop_bash, write_bash, skill") {
		t.Fatal("restricted projection did not recognize the policy exclusion diagnostic")
	}
	if restricted.AgentDiagnosticFilter.Startup("Info: Disabled tools: view, grep") {
		t.Fatal("restricted projection recognized a diagnostic about authorized tools")
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
