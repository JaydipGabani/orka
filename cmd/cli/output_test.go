package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestPrintGenericTableRendersTypedSingleObject(t *testing.T) {
	cmd := &cobra.Command{}
	var out strings.Builder
	cmd.SetOut(&out)
	type detail struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	}
	var value detail
	value.Metadata.Name, value.Metadata.Namespace, value.Status.Phase = "cli-hello", "cli-ns", "Completed"
	if err := printGenericTable(cmd, &value); err != nil {
		t.Fatalf("printGenericTable() error = %v", err)
	}
	if strings.Contains(out.String(), "No resources found") || !strings.Contains(out.String(), "cli-hello") || !strings.Contains(out.String(), "Completed") {
		t.Fatalf("table output = %q", out.String())
	}
}

const (
	tableTestItemsKey = "items"
	tableTestStateKey = "state"
)

func TestPrintGenericTableLabelsForgeRecordsByNumber(t *testing.T) {
	cmd := &cobra.Command{}
	var out strings.Builder
	cmd.SetOut(&out)
	const namespace = "monitor-ns"
	value := map[string]any{tableTestItemsKey: []any{map[string]any{
		"monitorNamespace": namespace,
		"number":           float64(358),
		"title":            strings.Repeat("long title ", 12),
		tableTestStateKey:  "open",
		"workflowPhase":    "approval_required",
		"updatedAt":        "2026-08-30T17:00:00Z",
	}}}
	if err := printGenericTable(cmd, value); err != nil {
		t.Fatalf("printGenericTable() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"#358 long title", "…", namespace, "open/approval_required"} {
		if !strings.Contains(got, want) {
			t.Fatalf("table output %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "-\t") || strings.Contains(got, strings.Repeat("long title ", 12)) {
		t.Fatalf("table output %q rendered a dash name or an untruncated title", got)
	}
}
