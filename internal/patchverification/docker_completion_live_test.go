package patchverification

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDockerLiveAnchorInspectionDeadline(test *testing.T) {
	runner, environment := dockerLiveRunner(test, dockerTestGo)
	manifest, sourceDir, checksDir := dockerLiveServiceManifest(test, runner, environment)
	dockerLiveScript(test, &manifest, checksDir, "run", "#!/bin/sh\nprintf 'check-finished\\n'\n")
	baseCommand := runner.command
	anchorID := ""
	var stopDeadline time.Time
	inspectedAfterStop := false
	runner.command = func(ctx context.Context, arguments ...string) *exec.Cmd {
		if len(arguments) > 0 && arguments[0] == "stop" {
			stopDeadline, _ = ctx.Deadline()
		}
		if len(arguments) > 1 && arguments[0] == "container" && arguments[1] == "inspect" {
			containerID := arguments[len(arguments)-1]
			if anchorID == "" {
				anchorID = containerID
			}
			if containerID == anchorID && !stopDeadline.IsZero() {
				inspectedAfterStop = true
				deadline, bounded := ctx.Deadline()
				if !bounded || !deadline.After(stopDeadline) {
					test.Error("anchor inspection reused a deadline that preceded fixture shutdown")
				}
			}
		}
		return baseCommand(ctx, arguments...)
	}
	binding, _ := testEvidence(manifest)
	evidence, err := runner.RunCheck(test.Context(), manifest, binding, Original, manifest.Checks[0], sourceDir, checksDir)
	if err != nil || !usable(evidence.Observation) || !inspectedAfterStop {
		test.Fatalf("orderly shutdown lost its final anchor inspection: %v", err)
	}
}

func TestDockerLiveHTTPFragmentedRequest(test *testing.T) {
	runner, environment := dockerLiveRunner(test, dockerTestGo)
	manifest, sourceDir, checksDir := dockerLiveServiceManifest(test, runner, environment)
	content, err := os.ReadFile(filepath.Join("..", "..", "examples", "patch-verification", "http", "checks", "service.c"))
	if err != nil {
		test.Fatal(err)
	}
	manifest.Files = append(manifest.Files, FrozenFile{Path: "service.c", Content: content, Digest: Digest(content)})
	if err := os.WriteFile(filepath.Join(checksDir, "service.c"), content, 0444); err != nil {
		test.Fatal(err)
	}
	dockerLiveScript(test, &manifest, checksDir, "fixture", "#!/bin/sh\nset -eu\ngcc -std=c11 -Wall -Wextra -Werror /checks/service.c -o /tmp/service\nexec /tmp/service\n")
	manifest.Environment.Services[0].ReadyOutput = "ready\n"
	dockerLiveScript(test, &manifest, checksDir, "run", `#!/usr/bin/python3
import socket

with socket.create_connection(("127.0.0.1", 18080), timeout=2) as connection:
    connection.sendall(b"GET ")
    connection.settimeout(0.1)
    try:
        connection.recv(1)
        raise AssertionError("fixture completed before the request line arrived")
    except socket.timeout:
        pass
    connection.sendall(b"/reserve HTTP/1.1\r\nHost: localhost\r\n\r\n")
    connection.settimeout(2)
    response = b""
    while True:
        part = connection.recv(1024)
        if not part:
            break
        response += part
    assert response == b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreserved\n"
print("fragmented-request-passed", flush=True)
`)
	for index := range manifest.Checks {
		manifest.Checks[index].Healthy.Stdout = "fragmented-request-passed\n"
		manifest.Checks[index].Healthy.Services = map[string]string{"fixture": "ready\nreserve\n"}
		manifest.Checks[index].Failure.Services = manifest.Checks[index].Healthy.Services
	}
	binding, _ := testEvidence(manifest)
	evidence, err := runner.RunCheck(test.Context(), manifest, binding, Original, manifest.Checks[0], sourceDir, checksDir)
	if err != nil || !usable(evidence.Observation) || !matches(evidence.Observation, manifest.Checks[0].Healthy) {
		test.Fatalf("valid fragmented request could not be observed: %v", err)
	}
	dockerLiveBlobCheck(test, evidence)
}
