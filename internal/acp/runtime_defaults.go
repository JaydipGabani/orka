package acp

import (
	"sort"
	"strings"
)

const openCodeToolRead = "read"

var openCodeDefaultAllowedTools = [...]string{"Read", "Write", "Edit", "Bash", "Glob", "Grep"}

// OpenCodeDefaultAllowedTools returns the governed provider-native tool defaults
// used when an OpenCode Agent omits runtime.defaultAllowedTools.
func OpenCodeDefaultAllowedTools() []string {
	return append([]string(nil), openCodeDefaultAllowedTools[:]...)
}

// NormalizeOpenCodeToolPolicy canonicalizes OpenCode-native tool names and
// applies the fail-closed read-intent restrictions used by the runtime.
func NormalizeOpenCodeToolPolicy(
	readIntent bool,
	allowed, disallowed []string,
	allowBash bool,
) ([]string, []string, bool) {
	allowed = normalizeOpenCodeToolNames(allowed)
	disallowed = normalizeOpenCodeToolNames(disallowed)
	if !readIntent {
		return allowed, disallowed, allowBash
	}
	// OpenCode's Grep permission cannot carry the path-specific secret-file
	// exclusions applied to Read, so read-intent sessions disable it entirely.
	blocked := map[string]struct{}{
		"apply_patch": {}, "bash": {}, "edit": {}, "grep": {}, "write": {},
	}
	filtered := allowed[:0]
	for _, name := range allowed {
		if _, denied := blocked[name]; !denied {
			filtered = append(filtered, name)
		}
	}
	disallowed = append(disallowed, "apply_patch", "bash", "edit", "grep", "write")
	return sortedUniqueToolNames(filtered), sortedUniqueToolNames(disallowed), false
}

// OpenCodeEffectiveAllowedTools returns the tools that the normalized policy
// can actually execute after disallowed names and the Bash gate are applied.
func OpenCodeEffectiveAllowedTools(allowed, disallowed []string, allowBash bool) []string {
	denied := make(map[string]struct{}, len(disallowed))
	for _, name := range disallowed {
		denied[name] = struct{}{}
	}
	result := make([]string, 0, len(allowed))
	for _, name := range allowed {
		if _, blocked := denied[name]; blocked || (name == "bash" && !allowBash) {
			continue
		}
		result = append(result, name)
	}
	return sortedUniqueToolNames(result)
}

// NormalizeOpenCodeAuthorizationTools canonicalizes user-facing OpenCode tool
// grants so token and transaction allowlists can be compared with runtime
// policy names without exposing internal alias details to issuers.
func NormalizeOpenCodeAuthorizationTools(values []string) []string {
	allowed, _, _ := NormalizeOpenCodeToolPolicy(false, values, nil, true)
	return allowed
}

// normalizeOpenCodeToolNames canonicalizes OpenCode-native permissions while
// preserving brokered/custom tool identifiers. OpenCode selects apply_patch for
// GPT-family models and edit/write for others, so those aliases are one governed
// mutation capability.
func normalizeOpenCodeToolNames(values []string) []string {
	mutation := false
	result := make([]string, 0, len(values)+2)
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		switch normalized := strings.ToLower(trimmed); normalized {
		case "apply_patch", "edit", "write":
			mutation = true
		case "bash", "glob", "grep", openCodeToolRead:
			result = append(result, normalized)
		default:
			result = append(result, trimmed)
		}
	}
	if mutation {
		result = append(result, "apply_patch", "edit", "write")
	}
	return sortedUniqueToolNames(result)
}

func sortedUniqueToolNames(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
