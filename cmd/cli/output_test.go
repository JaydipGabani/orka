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
