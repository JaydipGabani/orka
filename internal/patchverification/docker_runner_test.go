package patchverification

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDockerRunCheckRejectsUnfrozenInputs(test *testing.T) {
	for _, scenario := range []string{"binding", "check", "side", "image", "tool", "limits"} {
		test.Run(scenario, func(test *testing.T) {
			manifest, sourceDir, checksDir := dockerTestStaging(test)
			binding, _ := testEvidence(manifest)
			check, side := manifest.Checks[0], Original
			runner := DockerRunner{DockerBinary: "/nonexistent/orka-docker"}
			switch scenario {
			case "binding":
				binding.ManifestDigest = Digest(nil)
			case "check":
				check.Command = []string{"/checks/changed"}
			case "side":
				side = "foreign"
			case "image":
				manifest.Environment.Image = "alpine:latest"
				binding, _ = testEvidence(manifest)
			case "limits":
				runner.MaxOutputBytes = -1
			}
			evidence, err := runner.RunCheck(context.Background(), manifest, binding, side, check, sourceDir, checksDir)
			if err == nil || evidence.Observation.SetupError == "" || evidence.Observation.Executed || usable(evidence.Observation) {
				test.Fatalf("unfrozen or unavailable setup yielded usable evidence: %+v, %v", evidence.Observation, err)
			}
		})
	}
}

func TestDockerSubjectState(test *testing.T) {
	for _, scenario := range []string{"success", "missing-tool", "oom", "running", "daemon-error", "missing-start", "capture-failed", "exit-mismatch"} {
		test.Run(scenario, func(test *testing.T) {
			state := dockerState{StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now()}
			var attachErr error
			switch scenario {
			case "missing-tool":
				state.ExitCode = 127
			case "oom":
				state.OOMKilled = true
			case "running":
				state.Running = true
			case "daemon-error":
				state.Error = "private engine details"
			case "missing-start":
				state.StartedAt = time.Time{}
			case "capture-failed":
				attachErr = errors.New("private CLI details")
			case "exit-mismatch":
				state.ExitCode = 1
			}
			var observation Observation
			err := dockerObserveSubject(&observation, state, attachErr)
			if (err == nil) != (scenario == "success") || (err != nil && strings.Contains(err.Error(), "private")) {
				test.Fatalf("incorrect or unsafe state interpretation: %v", err)
			}
		})
	}
}

func TestDockerCleanupUsesExactIDs(test *testing.T) {
	var calls [][]string
	runner := DockerRunner{command: func(ctx context.Context, arguments ...string) *exec.Cmd {
		if ctx.Err() != nil {
			test.Fatal("cleanup inherited canceled subject context")
		}
		calls = append(calls, arguments)
		return exec.CommandContext(ctx, "/bin/true")
	}}
	execution := &dockerExecution{runner: runner, containers: []*dockerContainer{{id: strings.Repeat("a", 64)}, {id: strings.Repeat("b", 64)}}}
	if err := execution.cleanup(); err != nil {
		test.Fatal(err)
	}
	wanted := [][]string{{"rm", "--force", "--volumes", strings.Repeat("b", 64)}, {"rm", "--force", "--volumes", strings.Repeat("a", 64)}}
	if !reflect.DeepEqual(calls, wanted) {
		test.Fatalf("cleanup did not remove exact IDs in reverse order: %v", calls)
	}
}

func TestDockerCaptureBlobIntegrity(test *testing.T) {
	output := &dockerOutput{limit: 4}
	_, _ = output.Write([]byte("123456"))
	evidence := ExecutionEvidence{Blobs: make(map[string][]byte)}
	captured := dockerCapture(&evidence, output)
	if captured.Bytes != 4 || !captured.Truncated || !evidence.Observation.OutputTruncated || Digest(evidence.Blobs[captured.Digest]) != captured.Digest || len(evidence.Blobs[captured.Digest]) != captured.Bytes {
		test.Fatal("output metadata does not match bounded host blob")
	}
}

func TestDockerServiceCapture(test *testing.T) {
	for _, scenario := range []string{"empty", "diagnostics", "truncated"} {
		test.Run(scenario, func(test *testing.T) {
			stdout, stderr := &dockerOutput{limit: 128}, &dockerOutput{limit: 128}
			_, _ = stdout.Write([]byte("ready:fixture\n"))
			if scenario == "truncated" {
				stderr.limit = 4
			}
			if scenario != "empty" {
				_, _ = stderr.Write([]byte("private-fixture-diagnostic"))
			}
			evidence := ExecutionEvidence{Blobs: make(map[string][]byte)}
			err := dockerCaptureService(&evidence, "fixture", stdout, stderr)
			if (err == nil) != (scenario == "empty") || (err != nil && strings.Contains(err.Error(), "private-fixture-diagnostic")) {
				test.Fatal("fixture diagnostics did not fail closed with a generic error")
			}
			if len(evidence.Blobs) != 1 || string(evidence.Blobs[evidence.Observation.ServiceOutputs["fixture"].Digest]) != "ready:fixture\n" {
				test.Fatal("unreferenced or private fixture diagnostic blob was captured")
			}
			if evidence.Observation.OutputTruncated != (scenario == "truncated") {
				test.Fatal("fixture stderr truncation was not preserved")
			}
		})
	}
}
