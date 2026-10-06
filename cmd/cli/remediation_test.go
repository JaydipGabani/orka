package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRemediationIngestRejectsChecksBeforeCreatingJournal(t *testing.T) {
	for name, checks := range map[string]string{"empty": `{}`, "malformed": `{broken`} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			input, checkFile, state := filepath.Join(root, "report.json"), filepath.Join(root, "checks.json"), filepath.Join(root, "state")
			report := `{"title":"Synthetic case","problem":"A bounded synthetic failure","restricted":false}`
			if err := os.WriteFile(input, []byte(report), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(checkFile, []byte(checks), 0600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			command := newRemediationIngestCmd()
			command.SetOut(&output)
			command.SetErr(&output)
			command.SetArgs([]string{"--input", input, "--checks", checkFile, "--state-dir", state})
			if err := command.Execute(); err == nil {
				t.Fatal("invalid supplied checks were accepted")
			}
			if _, err := os.Lstat(state); !os.IsNotExist(err) {
				t.Fatalf("rejected checks consumed the selected journal path: %v", err)
			}
			retry := newRemediationIngestCmd()
			retry.SetOut(&output)
			retry.SetErr(&output)
			retry.SetArgs([]string{"--input", input, "--state-dir", state})
			if err := retry.Execute(); err != nil {
				t.Fatalf("corrected input could not reuse the unconsumed journal path: %v", err)
			}
			status := newRemediationWorkCmd(remediationStatusOperation)
			status.SetOut(&output)
			status.SetErr(&output)
			status.SetArgs([]string{"--state-dir", state})
			if err := status.Execute(); err != nil {
				t.Fatalf("corrected intake could not be inspected: %v", err)
			}
		})
	}
}
