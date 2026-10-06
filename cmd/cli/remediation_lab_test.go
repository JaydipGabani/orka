package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation"
	"github.com/orka-agents/orka/internal/remediation/journal"
	"github.com/orka-agents/orka/internal/remediation/lab"
)

func labTestOptions(t *testing.T) remediationLabOptions {
	t.Helper()
	root := t.TempDir()
	workDir := filepath.Join(root, "work")
	if err := os.Mkdir(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	return remediationLabOptions{
		stateDir: filepath.Join(root, "journal"), workDir: workDir, agentName: "synthetic-agent",
		taskType: "ai", timeout: remediation.DefaultTimeout, profileFile: "synthetic-profile.json",
		sourceFiles: []string{"source/example.go"}, approval: "sha256:" + strings.Repeat("a", 64),
		patchFile: "synthetic.patch", changeDescription: "Synthetic reviewed source change",
	}
}

func labTestRoot() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	root := &cobra.Command{Use: "orka", SilenceErrors: true, SilenceUsage: true}
	root.PersistentFlags().AddFlagSet(newRootCmd().PersistentFlags())
	parent := &cobra.Command{Use: "remediate"}
	parent.AddCommand(newRemediationLabCommands()...)
	root.AddCommand(parent)
	var output, diagnostic bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&diagnostic)
	return root, &output, &diagnostic
}

func TestRemediationLabCommandShape(t *testing.T) {
	t.Parallel()
	commands := newRemediationLabCommands()
	if len(commands) != 4 {
		t.Fatal("expected exactly four lab commands")
	}
	for index, name := range []string{"lab-plan", "lab-validate", "lab-run", "lab-verify"} {
		command := commands[index]
		if command.Name() != name || command.RunE == nil || command.Args == nil ||
			!command.SilenceErrors || !command.SilenceUsage {
			t.Errorf("unexpected command shape for %s", name)
		}
		for _, flag := range []string{"state-dir", "agent", "task-type", "token-file", "model-data-approved", "timeout", "work-dir"} {
			if command.Flags().Lookup(flag) == nil {
				t.Errorf("%s is missing --%s", name, flag)
			}
		}
		if command.Flags().Lookup("task-type").DefValue != "ai" ||
			command.Flags().Lookup("timeout").DefValue != remediation.DefaultTimeout.String() ||
			command.Flags().Lookup("model-data-approved").DefValue != "false" {
			t.Errorf("%s has unsafe or unexpected defaults", name)
		}
		if !strings.Contains(command.Long, "human-approved and privileged") ||
			!strings.Contains(command.Long, "candidate isolation is separate") ||
			!strings.Contains(command.Long, "do not automatically provision AKS") {
			t.Errorf("%s lacks the explicit lab trust boundary", name)
		}
		if name == "lab-plan" {
			if command.Flags().Lookup("lab-profile") == nil || command.Flags().Lookup("source-file") == nil ||
				command.Flags().Lookup("approve-plan") != nil {
				t.Fatal("lab-plan flag surface is incorrect")
			}
			if command.Flags().Lookup("source-file").Value.Type() != "stringArray" {
				t.Fatal("--source-file must be repeatable without splitting a path on commas")
			}
			if err := command.ParseFlags([]string{"--source-file=source/a,b.go", "--source-file=README.md"}); err != nil {
				t.Fatal(err)
			}
			files, err := command.Flags().GetStringArray("source-file")
			if err != nil || !reflect.DeepEqual(files, []string{"source/a,b.go", "README.md"}) {
				t.Fatal("source-file flags did not preserve their exact order and values")
			}
		} else if command.Flags().Lookup("approve-plan") == nil || command.Flags().Lookup("lab-profile") != nil ||
			command.Flags().Lookup("source-file") != nil {
			t.Errorf("%s must approve the saved plan, not replace its profile or source selection", name)
		}
		for _, flag := range []string{"patch-file", "change-description"} {
			if (command.Flags().Lookup(flag) != nil) != (name == "lab-verify") {
				t.Errorf("--%s must be exclusive to lab-verify", flag)
			}
		}
	}
}

func TestRemediationLabRootFlags(t *testing.T) {
	t.Parallel()
	root, _, _ := labTestRoot()
	command, _, err := root.Find([]string{"remediate", "lab-plan"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server", "namespace", "token", "txn-token", "txn-token-file", "kubeconfig"} {
		if command.InheritedFlags().Lookup(name) == nil {
			t.Errorf("lab command did not inherit root --%s", name)
		}
	}
}

func TestRemediationLabFlagValidation(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation string
		change    func(*remediationLabOptions)
	}{
		{"missing-state", "lab-plan", func(o *remediationLabOptions) { o.stateDir = "" }},
		{"relative-state", "lab-plan", func(o *remediationLabOptions) { o.stateDir = "journal" }},
		{"missing-agent", "lab-run", func(o *remediationLabOptions) { o.agentName = "" }},
		{"unknown-type", "lab-run", func(o *remediationLabOptions) { o.taskType = "container" }},
		{"case-type", "lab-run", func(o *remediationLabOptions) { o.taskType = "AI" }},
		{"blank-type", "lab-run", func(o *remediationLabOptions) { o.taskType = "" }},
		{"zero-timeout", "lab-plan", func(o *remediationLabOptions) { o.timeout = 0 }},
		{"negative-timeout", "lab-plan", func(o *remediationLabOptions) { o.timeout = -time.Second }},
		{"large-timeout", "lab-plan", func(o *remediationLabOptions) { o.timeout = 2*time.Hour + time.Nanosecond }},
		{"missing-work", "lab-plan", func(o *remediationLabOptions) { o.workDir = "" }},
		{"relative-work", "lab-plan", func(o *remediationLabOptions) { o.workDir = "work" }},
		{"missing-profile", "lab-plan", func(o *remediationLabOptions) { o.profileFile = "" }},
		{"no-files", "lab-plan", func(o *remediationLabOptions) { o.sourceFiles = nil }},
		{"excess-files", "lab-plan", func(o *remediationLabOptions) { o.sourceFiles = make([]string, 33) }},
		{"blank-file", "lab-plan", func(o *remediationLabOptions) { o.sourceFiles = []string{" \t"} }},
		{"missing-validation-approval", "lab-validate", func(o *remediationLabOptions) { o.approval = "" }},
		{"missing-execution-approval", "lab-run", func(o *remediationLabOptions) { o.approval = "" }},
		{"missing-verification-approval", "lab-verify", func(o *remediationLabOptions) { o.approval = "" }},
		{"abbreviated-approval", "lab-run", func(o *remediationLabOptions) { o.approval = "sha256:abc" }},
		{"uppercase-approval", "lab-validate", func(o *remediationLabOptions) { o.approval = "sha256:" + strings.Repeat("A", 64) }},
		{"missing-patch", "lab-verify", func(o *remediationLabOptions) { o.patchFile = "" }},
		{"missing-description", "lab-verify", func(o *remediationLabOptions) { o.changeDescription = "" }},
		{"blank-description", "lab-verify", func(o *remediationLabOptions) { o.changeDescription = " \n\t" }},
		{"large-description", "lab-verify", func(o *remediationLabOptions) { o.changeDescription = strings.Repeat("x", (16<<10)+1) }},
		{"invalid-description", "lab-verify", func(o *remediationLabOptions) { o.changeDescription = "\xff" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := labTestOptions(t)
			test.change(&options)
			if err := options.validate(test.operation); err == nil {
				t.Fatal("invalid command flags were accepted")
			}
		})
	}
	t.Run("inclusive-limits", func(t *testing.T) {
		t.Parallel()
		options := labTestOptions(t)
		options.timeout = 2 * time.Hour
		options.sourceFiles = make([]string, 32)
		for index := range options.sourceFiles {
			options.sourceFiles[index] = "file-" + strconv.Itoa(index) + ".go"
		}
		for _, operation := range []string{"lab-plan", "lab-validate", "lab-run", "lab-verify"} {
			for _, taskType := range []string{"ai", "agent"} {
				options.taskType = taskType
				if err := options.validate(operation); err != nil {
					t.Fatalf("valid boundary options were rejected: %v", err)
				}
			}
		}
	})
}

func TestRemediationLabRejectsUnsafeScratch(t *testing.T) {
	for _, scenario := range []string{"nonprivate", "missing", "symlink", "checkout", "journal", "journal-child", "journal-parent"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			options := labTestOptions(t)
			switch scenario {
			case "nonprivate":
				if err := os.Chmod(options.workDir, 0755); err != nil {
					t.Fatal(err)
				}
			case "missing":
				options.workDir = filepath.Join(options.workDir, "absent")
			case "symlink":
				alias := filepath.Join(filepath.Dir(options.workDir), "alias")
				if err := os.Symlink(options.workDir, alias); err != nil {
					t.Fatal(err)
				}
				options.workDir = alias
			case "checkout":
				if err := os.Mkdir(filepath.Join(filepath.Dir(options.workDir), ".git"), 0700); err != nil {
					t.Fatal(err)
				}
			case "journal":
				options.stateDir = options.workDir
			case "journal-child":
				options.stateDir = filepath.Dir(options.workDir)
			case "journal-parent":
				options.stateDir = filepath.Join(options.workDir, "journal")
			}
			if err := options.validate("lab-plan"); err == nil {
				t.Fatal("unsafe or overlapping scratch directory was accepted")
			}
		})
	}
}

func TestRemediationLabNoModelFlagsAndInputs(t *testing.T) {
	for _, operation := range []string{"lab-plan", "lab-validate", "lab-verify"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			options := labTestOptions(t)
			options.agentName, options.taskType = "", ""
			options.modelApproved = false
			options.tokenFile = filepath.Join(t.TempDir(), "absent-backend-token")
			options.profileFile = filepath.Join(t.TempDir(), "profile.json")
			profile := []byte(`{"version":1}`)
			if err := os.WriteFile(options.profileFile, profile, 0600); err != nil {
				t.Fatal(err)
			}
			if err := options.validate(operation); err != nil {
				t.Fatalf("no-model command required backend configuration: %v", err)
			}
			got, token, err := options.readInputs(operation)
			if err != nil || token != "" {
				t.Fatal("no-model command attempted to read backend credentials")
			}
			if operation == "lab-plan" && !bytes.Equal(got, profile) {
				t.Fatal("planning did not preserve the explicit reviewed profile")
			}
			if operation != "lab-plan" && got != nil {
				t.Fatal("validation must use the persisted plan instead of reading a new profile")
			}
		})
	}
}

func TestRemediationLabVerifySuppliedProposal(t *testing.T) {
	t.Parallel()
	options := labTestOptions(t)
	options.agentName, options.taskType = "", ""
	options.tokenFile = filepath.Join(t.TempDir(), "absent-backend-token")
	options.patchFile = filepath.Join(t.TempDir(), "reviewed.patch")
	options.changeDescription = "Synthetic reviewed source change\nwith a preserved description."
	patch := "diff --git a/example.txt b/example.txt\n--- a/example.txt\n+++ b/example.txt\n@@ -1 +1 @@\n-before\n+after\n"
	if err := os.WriteFile(options.patchFile, []byte(patch), 0600); err != nil {
		t.Fatal(err)
	}
	if err := options.validate("lab-verify"); err != nil {
		t.Fatalf("supplied-patch verification required model configuration: %v", err)
	}
	proposal, err := options.suppliedPatchProposal()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if json.Unmarshal(encoded, &got) != nil {
		t.Fatal("supplied proposal did not encode as JSON")
	}
	want := map[string]any{
		"summary": options.changeDescription,
		"patch":   patch,
		"declaredChanges": []any{
			map[string]any{"kind": "source", "description": options.changeDescription},
		},
		"limitations": []any{},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("supplied proposal did not preserve the exact diff and required declaration shape")
	}
}

func TestRemediationLabVerifyInputBounds(t *testing.T) {
	for _, difference := range []int{-1, 0, 1} {
		t.Run("patch-bytes", func(t *testing.T) {
			t.Parallel()
			const prefix = "diff --git a/example.txt b/example.txt\n--- a/example.txt\n+++ b/example.txt\n@@ -1 +1 @@\n-before\n+"
			patch := prefix + strings.Repeat("x", (256<<10)+difference-len(prefix)-1) + "\n"
			options := labTestOptions(t)
			options.patchFile = filepath.Join(t.TempDir(), "candidate.patch")
			if err := os.WriteFile(options.patchFile, []byte(patch), 0600); err != nil {
				t.Fatal(err)
			}
			proposal, err := options.suppliedPatchProposal()
			if difference > 0 {
				if err == nil || proposal.Patch != "" {
					t.Fatal("patch above 256 KiB must fail without returning its content")
				}
			} else if err != nil || proposal.Patch != patch {
				t.Fatal("bounded patch bytes were not preserved exactly")
			}
		})
		t.Run("description-bytes", func(t *testing.T) {
			t.Parallel()
			options := labTestOptions(t)
			options.changeDescription = strings.Repeat("x", (16<<10)+difference)
			err := options.validate("lab-verify")
			if (err != nil) != (difference > 0) {
				t.Fatal("change-description byte limit is not exactly 16 KiB")
			}
		})
	}
	for _, scenario := range []string{"empty", "blank", "invalid-utf8", "nonprivate", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			options := labTestOptions(t)
			options.patchFile = filepath.Join(t.TempDir(), "candidate.patch")
			content, mode := "synthetic patch content\n", os.FileMode(0600)
			switch scenario {
			case "empty":
				content = ""
			case "blank":
				content = " \n\t"
			case "invalid-utf8":
				content = "\xff"
			case "nonprivate":
				mode = 0644
			}
			if err := os.WriteFile(options.patchFile, []byte(content), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(options.patchFile, mode); err != nil {
				t.Fatal(err)
			}
			if scenario == "symlink" {
				alias := options.patchFile + "-alias"
				if err := os.Symlink(options.patchFile, alias); err != nil {
					t.Fatal(err)
				}
				options.patchFile = alias
			}
			proposal, err := options.suppliedPatchProposal()
			if err == nil || proposal.Patch != "" || strings.Contains(err.Error(), "synthetic patch content") {
				t.Fatal("unsafe patch input must fail without returning or printing its contents")
			}
		})
	}
}

func TestRemediationLabProfileAndPrivateTokenLimits(t *testing.T) {
	for _, difference := range []int{-1, 0, 1} {
		t.Run("profile-boundary", func(t *testing.T) {
			t.Parallel()
			filename := filepath.Join(t.TempDir(), "profile.json")
			raw := []byte(`{"version":1}` + strings.Repeat(" ", lab.MaxProfileBytes+difference-len(`{"version":1}`)))
			if err := os.WriteFile(filename, raw, 0600); err != nil {
				t.Fatal(err)
			}
			options := remediationLabOptions{profileFile: filename}
			got, _, err := options.readInputs("lab-plan")
			if difference > 0 {
				if err == nil {
					t.Fatal("profile above the 64-KiB limit was accepted")
				}
			} else if err != nil || !bytes.Equal(got, raw) {
				t.Fatalf("bounded profile was not passed through exactly: %v", err)
			}
		})
	}
	for _, scenario := range []string{"private", "nonprivate", "empty", "oversized", "symlink"} {
		t.Run("token-"+scenario, func(t *testing.T) {
			t.Parallel()
			filename := filepath.Join(t.TempDir(), "token")
			content, mode := " synthetic-test-token\n", os.FileMode(0600)
			switch scenario {
			case "nonprivate":
				mode = 0644
			case "empty":
				content = " \n\t"
			case "oversized":
				content = strings.Repeat("x", (16<<10)+1)
			}
			if err := os.WriteFile(filename, []byte(content), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filename, mode); err != nil {
				t.Fatal(err)
			}
			if scenario == "symlink" {
				alias := filename + "-alias"
				if err := os.Symlink(filename, alias); err != nil {
					t.Fatal(err)
				}
				filename = alias
			}
			_, token, err := (remediationLabOptions{tokenFile: filename}).readInputs("lab-run")
			if scenario == "private" {
				if err != nil || token != "synthetic-test-token" {
					t.Fatal("private token file did not override authentication as an exact trimmed value")
				}
			} else if err == nil || token != "" {
				t.Fatal("unsafe token input must fail without returning content")
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-test-token") {
				t.Fatal("token read failure exposed file contents")
			}
		})
	}
}

func TestRemediationLabErrorsEmitOnlySummary(t *testing.T) {
	for _, args := range [][]string{
		{"remediate", "lab-plan"},
		{"remediate", "lab-validate"},
		{"remediate", "lab-run"},
		{"remediate", "lab-verify"},
		{"remediate", "lab-plan", "synthetic-sensitive-argument"},
		{"remediate", "lab-plan", "--timeout=synthetic-sensitive-value"},
		{"remediate", "lab-run", "--not-a-lab-flag=synthetic-sensitive-value"},
	} {
		t.Run("command-error", func(t *testing.T) {
			t.Parallel()
			root, output, diagnostic := labTestRoot()
			root.SetArgs(args)
			err := root.Execute()
			if err == nil {
				t.Fatal("invalid command unexpectedly succeeded")
			}
			var summary remediation.Summary
			decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
			if decodeErr := decoder.Decode(&summary); decodeErr != nil || summary.Phase != "blocked" {
				t.Fatal("command error did not emit a blocked Summary JSON object")
			}
			if decodeErr := decoder.Decode(new(any)); !errors.Is(decodeErr, io.EOF) {
				t.Fatal("command wrote more than one Summary")
			}
			if strings.Contains(output.String()+diagnostic.String()+err.Error(), "synthetic-sensitive") {
				t.Fatal("command diagnostics exposed argument content")
			}
		})
	}

	t.Run("blocked-plan-preserves-summary-and-closes-journal", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "absent-kubeconfig"))
		options := labTestOptions(t)
		raw := []byte(`{"title":"Synthetic restricted report","problem":"Synthetic technical issue","restricted":true}`)
		store, err := journal.Create(options.stateDir, pv.Digest(raw))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		initial, err := remediation.Initialize(store, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		profile := filepath.Join(t.TempDir(), "profile.json")
		profileRaw := []byte(`{"synthetic-private-profile":true}`)
		_, profileErr := lab.ParseProfile(profileRaw)
		if profileErr == nil {
			t.Fatal("synthetic profile must fail validation before any public source access")
		}
		if err := os.WriteFile(profile, profileRaw, 0600); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Error("blocked lab plan must not contact the Orka API")
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		root, output, diagnostic := labTestRoot()
		root.SetArgs([]string{
			"remediate", "lab-plan", "--state-dir", options.stateDir,
			"--work-dir", options.workDir,
			"--lab-profile", profile, "--source-file", "source/example.go",
			"--server", server.URL, "--token-file", filepath.Join(t.TempDir(), "absent-backend-token"),
		})
		err = root.ExecuteContext(t.Context())
		if err == nil {
			t.Fatal("no-model planning accepted an invalid explicit profile")
		}
		if err.Error() != profileErr.Error() {
			t.Fatalf("safe pre-plan error was hidden: got %q, want %q", err.Error(), profileErr.Error())
		}
		if strings.Contains(output.String(), profileErr.Error()) {
			t.Fatal("pre-plan error was duplicated into public Summary output")
		}
		var summary remediation.Summary
		if json.Unmarshal(output.Bytes(), &summary) != nil || summary.RunID != initial.RunID || summary.Phase != initial.Phase {
			t.Fatal("blocked Engine operation did not retain its actual journal Summary")
		}
		for _, content := range []string{"Synthetic restricted report", "Synthetic technical issue", "synthetic-private-profile", "synthetic-cli-token"} {
			if strings.Contains(output.String()+diagnostic.String()+err.Error(), content) {
				t.Fatal("blocked command exposed report, profile, or authentication contents")
			}
		}
		reopened, err := journal.Open(options.stateDir)
		if err != nil {
			t.Fatalf("CLI did not release its journal after the blocked operation: %v", err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("blocked-engine-summary", func(t *testing.T) {
		t.Parallel()
		cmd := &cobra.Command{}
		var output bytes.Buffer
		cmd.SetOut(&output)
		want := remediation.Summary{
			RunID: "synthetic-run", Phase: "blocked", Reason: "approval_required",
			PlanDigest: "sha256:" + strings.Repeat("a", 64),
			Lab: &remediation.LabProgress{
				RunsDirectory:  "/synthetic/private/lab-runs",
				BaselineIntent: true,
				Attempts:       []remediation.LabAttempt{{Feedback: "synthetic rejection", Intent: false}},
				TrustStatement: lab.TrustStatement,
			},
		}
		err := writeRemediationLabSummary(cmd, want, remediation.ErrBlocked)
		var got remediation.Summary
		if err != remediation.ErrBlocked || json.Unmarshal(output.Bytes(), &got) != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("blocked Engine Summary, Lab progress, or error classification was lost")
		}
		if strings.Contains(output.String(), remediation.ErrBlocked.Error()) {
			t.Fatal("Engine error was duplicated into public Summary output")
		}
	})
	t.Run("cancelled-before-inputs", func(t *testing.T) {
		t.Parallel()
		options := labTestOptions(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		cmd := &cobra.Command{}
		cmd.SetContext(ctx)
		_, err := options.run(cmd, "lab-plan")
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled command did not stop before reading inputs or constructing network clients")
		}
	})
}
