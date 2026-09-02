package supervisor

import (
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/orka-agents/orka/internal/acp"
)

// Built-in provider CLIs occasionally write operator-facing diagnostics into
// the ACP agent message stream instead of their own log. Left alone, those
// chunks are compacted together with the model's text and reach Task results,
// chat, and monitor reviews as if the model had said them. A provider
// projection declares recognizers for the exact chunks its CLI emits
// (AgentDiagnosticFilter); the prompt stream withholds them before compaction,
// anchored on prompt state the supervisor can prove, and logs them so the
// CLI's report still reaches operators.

const (
	copilotDisabledToolsDiagnosticPrefix       = "Info: Disabled tools: "
	copilotUnknownExcludedToolDiagnosticPrefix = "Info: Unknown tool name in the tool excludedlist: "
	copilotInferenceRetryDiagnostic            = "Info: Response was interrupted due to a server error. Retrying..."
)

// copilotStartupDiagnostic recognizes the tool-exclusion report GitHub Copilot
// CLI 1.0.77 emits as agent_message_chunk updates at the start of a prompt in
// --acp mode; --log-level none does not silence it. Each line arrives as its
// own chunk, ahead of the CLI's first inference request, so a chunk is
// recognized only when its entire text is one of:
//
//   - "Info: Disabled tools: a, b". The CLI lists every tool it removed from
//     the model's catalog, folding tools it disabled for its own reasons into
//     the same line, so the line is recognized when it is a comma-separated
//     list of tool identifiers that names at least one tool this session
//     excluded.
//   - "Info: Unknown tool name in the tool excludedlist: \"a\"" for exactly a
//     name this session passed in --excluded-tools that the CLI's catalog does
//     not contain.
//
// Anchoring on the session's own exclusion list means a chunk about some
// other tool is never recognized. The CLI forwards model deltas verbatim and
// without a messageId, so the supervisor additionally withholds startup
// diagnostics only when they were received before the provider proxy began
// relaying the prompt's first inference response.
func copilotStartupDiagnostic(excludedTools []string) func(string) bool {
	excluded := make(map[string]struct{}, len(excludedTools))
	for _, name := range excludedTools {
		excluded[name] = struct{}{}
	}
	return func(text string) bool {
		if list, ok := strings.CutPrefix(text, copilotDisabledToolsDiagnosticPrefix); ok {
			return copilotDisabledToolsListNamesExcluded(list, excluded)
		}
		if quoted, ok := strings.CutPrefix(text, copilotUnknownExcludedToolDiagnosticPrefix); ok {
			name, err := strconv.Unquote(quoted)
			if err != nil {
				return false
			}
			_, excludedName := excluded[name]
			return excludedName
		}
		return false
	}
}

// copilotInferenceRetryNotice recognizes the notice the CLI writes into the
// agent message stream after an inference request fails and before it
// retries; the provider proxy already accounts for the failed request.
func copilotInferenceRetryNotice(text string) bool {
	return text == copilotInferenceRetryDiagnostic
}

func copilotDisabledToolsListNamesExcluded(list string, excluded map[string]struct{}) bool {
	namesExcluded := false
	for entry := range strings.SplitSeq(list, ",") {
		name := strings.TrimSpace(entry)
		if !copilotToolIdentifier(name) {
			return false
		}
		if _, ok := excluded[name]; ok {
			namesExcluded = true
		}
	}
	return namesExcluded
}

// copilotToolIdentifier reports whether name is shaped like a Copilot tool
// identifier (built-in names such as list_bash, MCP names such as
// github-mcp-server-search_code).
func copilotToolIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

// withholdAgentDiagnostic reports whether event is an assistant text chunk the
// session's provider projection recognizes as a CLI diagnostic under the
// anchoring rules documented on AgentDiagnosticFilter. A withheld chunk is
// logged and never reaches compaction, the harness event stream, or the
// terminal assistant text. The logged text is bounded by construction: each
// recognized shape is a fixed CLI sentence whose only variable parts are tool
// identifiers. Only the prompt stream goroutine touches the prompt counters.
func withholdAgentDiagnostic(state *sessionState, prompt *promptState, event acp.PromptEvent) bool {
	filter := state.agentDiagnosticFilter
	if filter == nil {
		return false
	}
	text, ok := assistantMessageText(event)
	if !ok || text == "" {
		return false
	}
	promptID := prompt.request.Metadata.PromptID
	switch {
	// The receipt time is stamped when the session received the chunk from
	// the child, before any buffering, so a startup diagnostic queued behind
	// prompt acceptance or a slow consumer keeps the phase it was emitted in.
	case filter.Startup != nil && filter.Startup(text) &&
		!state.providerProxy.modelOutputPossibleAt(string(promptID), promptEventReceivedAt(event)):
		slog.Info(
			"ACP provider CLI startup diagnostic withheld from the agent message stream",
			"runtimeSession", state.id, "promptID", promptID, "sequence", event.Sequence, "diagnostic", text,
		)
		return true
	case filter.InferenceRetry != nil && filter.InferenceRetry(text) &&
		prompt.withheldRetryNotices < state.providerProxy.inferenceFailureCount(string(promptID)):
		prompt.withheldRetryNotices++
		slog.Info(
			"ACP provider CLI inference retry notice withheld from the agent message stream",
			"runtimeSession", state.id, "promptID", promptID, "sequence", event.Sequence, "diagnostic", text,
		)
		return true
	}
	return false
}

// promptEventReceivedAt is the instant the session received event from the
// child; the enqueue timestamp stands in for events that carry no receipt
// time.
func promptEventReceivedAt(event acp.PromptEvent) time.Time {
	if !event.ReceivedAt.IsZero() {
		return event.ReceivedAt
	}
	return event.Timestamp
}
