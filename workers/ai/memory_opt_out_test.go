package main

import (
	"slices"
	"testing"
)

func TestMemoryAutoEnableExplicitOptOut(t *testing.T) {
	t.Setenv("ORKA_CONTROLLER_URL", "http://controller.invalid")
	t.Setenv("ORKA_TASK_NAMESPACE", "fixture")
	t.Setenv("ORKA_TASK_NAME", "proposal")
	t.Setenv("ORKA_MEMORY_TOOLS_AUTO_ENABLE", " false ")
	if got := autoEnableMemoryTools([]string{"file_read"}); !slices.Equal(got, []string{"file_read"}) {
		t.Fatalf("opt-out added ambient memory tools: %v", got)
	}
	if got := autoEnableMemoryTools([]string{"remember"}); !slices.Equal(got, []string{"remember"}) {
		t.Fatalf("opt-out altered explicit selection: %v", got)
	}
}
