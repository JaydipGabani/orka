package acp

import (
	"slices"
	"testing"
)

func TestOpenCodeDefaultAllowedToolsReturnsCopy(t *testing.T) {
	want := []string{"Read", "Write", "Edit", "Bash", "Glob", "Grep"}
	first := OpenCodeDefaultAllowedTools()
	if !slices.Equal(first, want) {
		t.Fatalf("defaults = %#v, want %#v", first, want)
	}
	first[0] = "changed"
	if got := OpenCodeDefaultAllowedTools(); !slices.Equal(got, want) {
		t.Fatalf("defaults shared mutable storage: %#v", got)
	}
}

func TestNormalizeOpenCodeToolPolicy(t *testing.T) {
	allowed, disallowed, allowBash := NormalizeOpenCodeToolPolicy(
		true,
		OpenCodeDefaultAllowedTools(),
		nil,
		true,
	)
	if want := []string{"glob", "read"}; !slices.Equal(allowed, want) {
		t.Fatalf("read-intent allowed = %#v, want %#v", allowed, want)
	}
	if want := []string{"apply_patch", "bash", "edit", "grep", "write"}; !slices.Equal(disallowed, want) {
		t.Fatalf("read-intent disallowed = %#v, want %#v", disallowed, want)
	}
	if allowBash {
		t.Fatal("read-intent policy retained bash")
	}

	allowed, _, allowBash = NormalizeOpenCodeToolPolicy(false, []string{"Edit"}, nil, false)
	if want := []string{"apply_patch", "edit", "write"}; !slices.Equal(allowed, want) {
		t.Fatalf("mutation aliases = %#v, want %#v", allowed, want)
	}
	if allowBash {
		t.Fatal("write-intent policy changed explicit bash denial")
	}
	if got := OpenCodeEffectiveAllowedTools([]string{"bash", "read", "write"}, []string{"write"}, false); !slices.Equal(got, []string{"read"}) {
		t.Fatalf("effective tools = %#v, want read only", got)
	}
	if got := NormalizeOpenCodeAuthorizationTools([]string{"Read", "Edit", "Bash"}); !slices.Equal(got, []string{"apply_patch", "bash", "edit", "read", "write"}) {
		t.Fatalf("authorization tools = %#v, want public names normalized with mutation aliases", got)
	}

	explicitEmpty := []string{}
	allowed, _, _ = NormalizeOpenCodeToolPolicy(false, explicitEmpty, nil, false)
	if allowed == nil || len(allowed) != 0 {
		t.Fatalf("explicit empty policy = %#v, want non-nil empty", allowed)
	}
}

func TestBuiltInRuntimeNativeToolPolicy(t *testing.T) {
	for _, provider := range []string{"codex", "claude", "copilot"} {
		if !IsBuiltInRuntimeNativeTool(provider, "WebSearch") || !IsBuiltInRuntimeNativeTool(provider, "bash") {
			t.Fatalf("%s native tool policy omitted a reviewed tool", provider)
		}
		if IsBuiltInRuntimeNativeTool(provider, "custom_tool") {
			t.Fatalf("%s native tool policy accepted a custom tool", provider)
		}
	}
	if !IsBuiltInRuntimeNativeTool("opencode", "apply_patch") || IsBuiltInRuntimeNativeTool("opencode", "WebSearch") {
		t.Fatal("OpenCode native tool policy does not match the reviewed runtime surface")
	}

	tools := BuiltInRuntimeNativeToolNames("opencode")
	if len(tools) == 0 {
		t.Fatal("OpenCode native tool policy is empty")
	}
	tools[0] = "changed"
	if IsBuiltInRuntimeNativeTool("opencode", "changed") {
		t.Fatal("BuiltInRuntimeNativeToolNames returned mutable policy storage")
	}
}
