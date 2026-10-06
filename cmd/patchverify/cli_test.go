package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/patchverification/local"
)

func TestCLIRejectsInvalidInputs(t *testing.T) {
	for _, arguments := range [][]string{
		nil, {"unknown"}, {"start"}, {"get", "--db", "relative", "--run", "none"},
		{"cancel", "--db", "/tmp/unused.db"}, {"evidence", "--db", "/tmp/unused.db", "--run", "none", "--raw"},
		{"get", "--db", "/tmp/unused.db", "--run", "none", "--extra"},
	} {
		var stdout, stderr bytes.Buffer
		if code := runCLI(context.Background(), arguments, &stdout, &stderr, nil); code != 2 {
			t.Fatalf("bad arguments accepted: %v code=%d", arguments, code)
		}
	}
	requestPath := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(requestPath, []byte(`{"unexpected": "private-diagnostic"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	arguments := []string{"start", "--db", filepath.Join(t.TempDir(), "evidence.db"), "--request", requestPath}
	code := runCLI(context.Background(), arguments, &stdout, &stderr, nil)
	if code != 2 || !strings.Contains(stdout.String(), "Unable to verify") ||
		strings.Contains(stdout.String(), "private-diagnostic") {
		t.Fatalf("invalid request did not fail safely: %d %s", code, stdout.String())
	}
}

func TestCLIMissingRun(t *testing.T) {
	for _, operation := range []string{"get", "evidence", "cancel", "recover"} {
		var stdout, stderr bytes.Buffer
		arguments := []string{
			operation, "--db", filepath.Join(t.TempDir(), "evidence.db"), "--run", "pv-" + strings.Repeat("a", 64),
		}
		code := runCLI(context.Background(), arguments, &stdout, &stderr, nil)
		if code != 2 || strings.Contains(stdout.String(), "Verified for these checks") {
			t.Fatalf("missing run accepted: %s %d %s", operation, code, stdout.String())
		}
	}
}

type cliRunner struct {
	started       chan struct{}
	notReproduced bool
	calls         int
}

func (*cliRunner) ResolveImage(_ context.Context, image, platform string) (pv.Environment, error) {
	return pv.Environment{Image: image, Platform: platform, ImageID: pv.Digest([]byte("test image"))}, nil
}

func (*cliRunner) FreezeEnvironment(environment pv.Environment) (pv.Environment, error) {
	return environment, nil
}

func (runner *cliRunner) RunCheck(
	ctx context.Context, manifest pv.Manifest, binding pv.Binding, side string, check pv.Check, _, _ string,
) (pv.ExecutionEvidence, error) {
	runner.calls++
	identity, tree, output := binding.OriginalTaskID, manifest.Sources.Original.Tree, check.Healthy.Stdout
	if side == pv.Patched {
		identity, tree = binding.PatchedTaskID, manifest.Sources.Patched.Tree
	} else if check.Kind == pv.Reproduction && !runner.notReproduced {
		output = check.Failure.Stdout
	}
	started := time.Now().UTC()
	evidence := pv.ExecutionEvidence{Observation: pv.Observation{
		RunID: binding.RunID, AttemptID: binding.AttemptID, TaskID: identity, ManifestDigest: binding.ManifestDigest,
		Side: side, CheckID: check.ID, SourceTree: tree, ImageID: manifest.Environment.ImageID,
		Origin: "runner", ContainerID: "test-" + side + "-" + check.ID,
		StartedAt: started, FinishedAt: started.Add(time.Millisecond), Executed: true, ExitCode: new(0),
		StdoutDigest: pv.Digest([]byte(output)), StdoutBytes: len(output), StderrDigest: pv.Digest(nil)},
		Blobs: map[string][]byte{pv.Digest([]byte(output)): []byte(output), pv.Digest(nil): {}}}
	if runner.started != nil {
		close(runner.started)
		<-ctx.Done()
		return evidence, errors.New("unit-only cancellation")
	}
	return evidence, nil
}

func cliFixture(t *testing.T, runner *cliRunner) (string, dependencyFactory) {
	t.Helper()
	request := pv.Request{
		Problem: "unit-only comparison", Scope: []string{"normal and boundary"},
		Repository: "/unit-only/repo", ChecksDir: "/unit-only/checks",
		OriginalCommit: strings.Repeat("a", 40), PatchedCommit: strings.Repeat("b", 40),
		Image: "tool@" + pv.Digest([]byte("image")), Profile: pv.Offline, Platform: "linux/amd64",
		Checks: []pv.Check{
			{
				ID: "normal", Kind: pv.Normal, Command: []string{"/checks/test"}, Healthy: pv.Expectation{Stdout: "healthy\n"},
				Failure: pv.Expectation{Stdout: "broken\n"}, TimeoutSeconds: 2,
			},
			{
				ID: "problem", Kind: pv.Reproduction, Command: []string{"/checks/test"},
				Healthy: pv.Expectation{Stdout: "healthy\n"},
				Failure: pv.Expectation{Stdout: "broken\n"}, TimeoutSeconds: 2,
			},
		}}
	content, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(filename, content, 0600); err != nil {
		t.Fatal(err)
	}
	return filename, func(configuration) local.Dependencies {
		return local.Dependencies{
			Runner: runner, Release: func(*pv.PreparedSources) error { return nil },
			Quiescent: func(context.Context) error { return nil }, PollInterval: 5 * time.Millisecond,
			Prepare: func(_ context.Context, request pv.Request) (*pv.PreparedSources, error) {
				provenance := map[string][]byte{}
				for _, value := range []string{"unit-original", "unit-patched", "unit-diff"} {
					provenance[pv.Digest([]byte(value))] = []byte(value)
				}
				prepared := &pv.PreparedSources{Provenance: provenance, Root: "/unit-only/prepared", Sources: pv.Sources{
					Repository: request.Repository,
					Original: pv.SourceIdentity{
						Commit: request.OriginalCommit, Tree: strings.Repeat("c", 40),
						ArchiveDigest: pv.Digest([]byte("unit-original")),
					},
					Patched: pv.SourceIdentity{
						Commit: request.PatchedCommit, Tree: strings.Repeat("d", 40),
						ArchiveDigest: pv.Digest([]byte("unit-patched")),
					},
					DiffDigest: pv.Digest([]byte("unit-diff")),
				}}
				if request.Action == pv.ValidateReport {
					delete(prepared.Provenance, prepared.Sources.Patched.ArchiveDigest)
					delete(prepared.Provenance, prepared.Sources.DiffDigest)
					prepared.Sources.Patched, prepared.Sources.DiffDigest = pv.SourceIdentity{}, ""
				}
				return prepared, nil
			}}
	}
}

func cliWriteRequest(test *testing.T, filename string, request pv.Request) {
	test.Helper()
	content, err := json.Marshal(request)
	if err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(filename, content, 0600); err != nil {
		test.Fatal(err)
	}
}

func TestCLIReportActions(test *testing.T) {
	for _, scenario := range []struct {
		name string
		want pv.Conclusion
		code int
	}{
		{"reproduced", pv.Reproduced, 0}, {"not-reproduced", pv.NotReproduced, 0},
		{"unsupported", pv.UnableToValidate, 2},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			runner := &cliRunner{notReproduced: scenario.name == "not-reproduced"}
			filename, factory := cliFixture(test, runner)
			request, err := local.ReadRequest(filename)
			if err != nil {
				test.Fatal(err)
			}
			request.Action, request.PatchedCommit = pv.ValidateReport, ""
			if scenario.name == "unsupported" {
				request.RequiredEnvironment = []pv.EnvironmentRequirement{{Kind: "cluster", Name: "test-cluster"}}
			}
			cliWriteRequest(test, filename, request)
			var stdout, stderr bytes.Buffer
			arguments := []string{"start", "--db", filepath.Join(test.TempDir(), "evidence.db"), "--request", filename}
			code := runCLI(test.Context(), arguments, &stdout, &stderr, factory)
			decoder := json.NewDecoder(&stdout)
			var initial, final local.Summary
			if decoder.Decode(&initial) != nil || decoder.Decode(&final) != nil || code != scenario.code ||
				final.Action != pv.ValidateReport || final.Overall.Conclusion != scenario.want ||
				final.Progress.Required != len(request.Checks) || final.ReportDigest == "" {
				test.Fatalf("report CLI failed: %+v, code=%d, stderr=%s", final, code, stderr.String())
			}
			if scenario.name == "unsupported" && runner.calls != 0 {
				test.Fatal("unsupported report ran a workload")
			}
		})
	}
}

func TestCLILinkedRequest(test *testing.T) {
	runner := &cliRunner{}
	filename, factory := cliFixture(test, runner)
	request, err := local.ReadRequest(filename)
	if err != nil {
		test.Fatal(err)
	}
	request.Action, request.PatchedCommit = pv.ValidateReport, ""
	cliWriteRequest(test, filename, request)
	var stdout, stderr bytes.Buffer
	dbPath := filepath.Join(test.TempDir(), "evidence.db")
	arguments := []string{"start", "--db", dbPath, "--request", filename}
	if code := runCLI(test.Context(), arguments, &stdout, &stderr, factory); code != 0 {
		test.Fatalf("report start: %d %s", code, stderr.String())
	}
	decoder := json.NewDecoder(&stdout)
	var initial, report local.Summary
	if decoder.Decode(&initial) != nil || decoder.Decode(&report) != nil {
		test.Fatal("missing report summaries")
	}
	request = pv.Request{Action: pv.VerifyPatch, EarlierValidation: report.RunID,
		PatchedCommit: strings.Repeat("b", 40), DeclaredChanges: []pv.DeclaredChange{
			{Kind: "configuration", Paths: []string{"settings.json"}, Description: "retain managed setting"},
		}}
	cliWriteRequest(test, filename, request)
	stdout.Reset()
	if code := runCLI(test.Context(), arguments, &stdout, &stderr, factory); code != 0 {
		test.Fatalf("linked start: %d %s %s", code, stdout.String(), stderr.String())
	}
	decoder = json.NewDecoder(&stdout)
	var verification local.Summary
	if decoder.Decode(&initial) != nil || decoder.Decode(&verification) != nil ||
		verification.Overall.Conclusion != pv.Verified || verification.ReportDigest != report.ReportDigest ||
		verification.EarlierValidation == nil || verification.EarlierValidation.RunID != report.RunID || runner.calls != 6 {
		test.Fatalf("linked CLI did not rerun both versions: %+v, calls=%d", verification, runner.calls)
	}
}

func TestCLIProgressEvidenceAndCancel(t *testing.T) {
	request, factory := cliFixture(t, &cliRunner{})
	dbPath := filepath.Join(t.TempDir(), "evidence.db")
	var stdout, stderr bytes.Buffer
	arguments := []string{"start", "--db", dbPath, "--request", request}
	if code := runCLI(context.Background(), arguments, &stdout, &stderr, factory); code != 0 {
		t.Fatalf("start failed: %d %s %s", code, stdout.String(), stderr.String())
	}
	decoder := json.NewDecoder(&stdout)
	var initial, final local.Summary
	if decoder.Decode(&initial) != nil || decoder.Decode(&final) != nil || initial.RunID != final.RunID ||
		initial.JobStatus != "running" || final.Overall.Conclusion != pv.Verified {
		t.Fatal("early and final JSON summaries are inconsistent")
	}
	for _, operation := range []string{"get", "evidence"} {
		stdout.Reset()
		code := runCLI(context.Background(), []string{operation, "--db", dbPath, "--run", final.RunID}, &stdout, &stderr, nil)
		if code != 0 || !json.Valid(stdout.Bytes()) ||
			!strings.Contains(stdout.String(), `"executionBackend":"local-docker"`) {
			t.Fatalf("%s failed: %d %s", operation, code, stdout.String())
		}
	}
	stdout.Reset()
	arguments = []string{
		"evidence", "--db", dbPath, "--run", final.RunID, "--digest", pv.Digest([]byte("healthy\n")), "--raw",
	}
	code := runCLI(context.Background(), arguments, &stdout, &stderr, nil)
	if code != 0 || stdout.String() != "healthy\n" {
		t.Fatal("raw evidence did not preserve exact bytes")
	}
	stdout.Reset()
	arguments = []string{
		"evidence", "--db", dbPath, "--run", final.RunID, "--digest", pv.Digest([]byte("healthy\n")), "--max-bytes", "2",
	}
	code = runCLI(context.Background(), arguments, &stdout, &stderr, nil)
	if code != 2 || stdout.Len() != 0 {
		t.Fatal("oversized inspection was not refused")
	}
	stdout.Reset()
	code = runCLI(context.Background(), []string{"cancel", "--db", dbPath, "--run", final.RunID}, &stdout, &stderr, nil)
	var cancelled local.Summary
	if code != 0 || json.Unmarshal(stdout.Bytes(), &cancelled) != nil ||
		cancelled.State != pv.RunFinalized || cancelled.Overall.Conclusion != pv.Verified {
		t.Fatal("CLI cancellation changed completed verification")
	}
}

func TestCLIProcessHelper(_ *testing.T) {
	if os.Getenv("PATCHVERIFY_CLI_TEST_HELPER") != "1" {
		return
	}
	for index, argument := range os.Args {
		if argument == "--" {
			os.Exit(runCLI(context.Background(), os.Args[index+1:], os.Stdout, os.Stderr, nil))
		}
	}
	os.Exit(2)
}

func TestCLIIndependentProcessCancellation(t *testing.T) {
	runner := &cliRunner{started: make(chan struct{})}
	request, factory := cliFixture(t, runner)
	dbPath := filepath.Join(t.TempDir(), "evidence.db")
	reader, writer := io.Pipe()
	defer func() { _ = reader.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- runCLI(ctx, []string{"start", "--db", dbPath, "--request", request}, writer, io.Discard, factory)
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	decoder := json.NewDecoder(reader)
	var initial local.Summary
	if err := decoder.Decode(&initial); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.started:
	case <-ctx.Done():
		t.Fatal("check did not start")
	}
	arguments := []string{"-test.run=^TestCLIProcessHelper$", "--", "recover", "--db", dbPath, "--run", initial.RunID}
	command := exec.CommandContext(ctx, os.Args[0], arguments...)
	command.Env = []string{"PATCHVERIFY_CLI_TEST_HELPER=1", "PATH=" + os.Getenv("PATH")}
	if err := command.Run(); err == nil {
		t.Fatal("another process recovered a live owner")
	}
	arguments = []string{"-test.run=^TestCLIProcessHelper$", "--", "cancel", "--db", dbPath, "--run", initial.RunID}
	command = exec.CommandContext(ctx, os.Args[0], arguments...)
	command.Env = []string{"PATCHVERIFY_CLI_TEST_HELPER=1", "PATH=" + os.Getenv("PATH")}
	output, err := command.Output()
	if err != nil || !bytes.Contains(output, []byte(`"state":"cancelled"`)) {
		t.Fatalf("independent CLI could not cancel: %v %s", err, output)
	}
	var final local.Summary
	if err := decoder.Decode(&final); err != nil ||
		final.State != pv.RunCancelled || final.Overall.Conclusion != pv.UnableToVerify {
		t.Fatalf("supervisor did not observe durable cancellation: %+v %v", final, err)
	}
	if code := <-done; code != 2 {
		t.Fatalf("cancelled start returned code %d", code)
	}
}
