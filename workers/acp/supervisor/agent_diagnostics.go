package supervisor

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/orka-agents/orka/internal/acp"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
)

// Built-in provider CLIs occasionally write operator-facing diagnostics into
// the ACP agent message stream instead of their own log. Left alone, those
// chunks are compacted together with the model's text and reach Task results,
// chat, and monitor reviews as if the model had said them. A provider
// projection declares which exact chunks are CLI diagnostics
// (ProviderSessionProjection.AgentDiagnosticFilter); the prompt stream
// withholds them before compaction and logs them so the CLI's report still
// reaches operators.

const (
	copilotDisabledToolsDiagnosticPrefix       = "Info: Disabled tools: "
	copilotUnknownExcludedToolDiagnosticPrefix = "Info: Unknown tool name in the tool excludedlist: "
	copilotInferenceRetryDiagnostic            = "Info: Response was interrupted due to a server error. Retrying..."
)

// copilotAgentDiagnosticFilter recognizes the diagnostics GitHub Copilot CLI
// 1.0.77 emits as agent_message_chunk updates in --acp mode; --log-level none
// does not silence them. Each arrives as its own chunk without a messageId, so
// a chunk is withheld only when its entire text is one of:
//
//   - "Info: Disabled tools: a, b" at the start of the first prompt. The CLI
//     lists every tool it removed from the model's catalog, folding tools it
//     disabled for its own reasons into the same line, so the line is
//     recognized when it is a comma-separated list of tool identifiers that
//     names at least one tool this session excluded.
//   - "Info: Unknown tool name in the tool excludedlist: \"a\"" for exactly a
//     name this session passed in --excluded-tools that the CLI's catalog does
//     not contain.
//   - The retry notice the CLI prints when an inference request fails and is
//     retried; the provider proxy already accounts for that request.
//
// Anchoring on the session's own exclusion list means a model chunk can never
// be withheld for merely resembling a diagnostic about some other tool.
func copilotAgentDiagnosticFilter(excludedTools []string) func(string) bool {
	excluded := make(map[string]struct{}, len(excludedTools))
	for _, name := range excludedTools {
		excluded[name] = struct{}{}
	}
	return func(text string) bool {
		if text == copilotInferenceRetryDiagnostic {
			return true
		}
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
// session's provider projection recognizes as a CLI diagnostic. A withheld
// chunk is logged and never reaches compaction, the harness event stream, or
// the terminal assistant text. The logged text is bounded by construction:
// every recognized shape is a fixed CLI sentence whose only variable parts are
// tool identifiers.
func withholdAgentDiagnostic(state *sessionState, promptID harnessv2.PromptID, event acp.PromptEvent) bool {
	filter := state.agentDiagnosticFilter
	if filter == nil {
		return false
	}
	text, ok := assistantMessageText(event)
	if !ok || !filter(text) {
		return false
	}
	slog.Info(
		"ACP provider CLI diagnostic withheld from the agent message stream",
		"promptID", promptID,
		"sequence", event.Sequence,
		"diagnostic", text,
	)
	return true
}
