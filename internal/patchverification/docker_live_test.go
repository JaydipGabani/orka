package patchverification

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const dockerTestAlpine = "alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
const dockerTestGo = "golang@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43"

func dockerLiveRunner(test *testing.T, image string) (DockerRunner, Environment) {
	test.Helper()
	if os.Getenv("ORKA_PATCH_VERIFY_DOCKER_TEST") != "1" {
		test.Skip("set ORKA_PATCH_VERIFY_DOCKER_TEST=1 to test the local pinned Docker images")
	}
	runner := DockerRunner{}
	if image == dockerTestGo {
		runner.LauncherPath, runner.LauncherDigest = dockerLiveLauncher(test)
	}
	environment, err := runner.ResolveImage(context.Background(), image, "linux/"+runtime.GOARCH)
	if err != nil {
		test.Fatalf("opt-in live image unavailable: %v", err)
	}
	var mutex sync.Mutex
	var names []string
	runner.command = func(ctx context.Context, arguments ...string) *exec.Cmd {
		if len(arguments) > 0 && arguments[0] == "create" {
			position := slices.Index(arguments, "--name")
			mutex.Lock()
			names = append(names, arguments[position+1])
			mutex.Unlock()
		}
		return (DockerRunner{}).dockerCommand(ctx, arguments...)
	}
	test.Cleanup(func() {
		mutex.Lock()
		defer mutex.Unlock()
		for _, name := range names {
			content, err := (DockerRunner{}).control(context.Background(), "container", "inspect", "--format", "{{.Id}}", name)
			if err == nil {
				test.Errorf("owned container remained after RunCheck: %s", name)
				identifier := strings.TrimSpace(string(content))
				if sha256Pattern.MatchString("sha256:" + identifier) {
					_, _ = (DockerRunner{}).control(context.Background(), "rm", "--force", "--volumes", identifier)
				}
			}
		}
	})
	test.Logf("pinned image=%s imageID=%s platform=%s", environment.Image, environment.ImageID, environment.Platform)
	return runner, environment
}

func dockerLiveScript(test *testing.T, manifest *Manifest, checksDir, filename, content string) {
	test.Helper()
	if err := os.WriteFile(filepath.Join(checksDir, filename), []byte(content), 0755); err != nil {
		test.Fatal(err)
	}
	frozen := FrozenFile{Path: filename, Content: []byte(content), Digest: Digest([]byte(content)), Executable: true}
	for index := range manifest.Files {
		if manifest.Files[index].Path == filename {
			manifest.Files[index] = frozen
			return
		}
	}
	manifest.Files = append(manifest.Files, frozen)
}

func dockerLiveBlobCheck(test *testing.T, evidence ExecutionEvidence) {
	test.Helper()
	referenced := make(map[string]bool)
	for digest, content := range evidence.Blobs {
		if digest != Digest(content) {
			test.Fatal("host blob digest mismatch")
		}
	}
	outputs := make([]CapturedOutput, 0, 2+len(evidence.Observation.ServiceOutputs))
	outputs = append(outputs, CapturedOutput{Digest: evidence.Observation.StdoutDigest, Bytes: evidence.Observation.StdoutBytes}, CapturedOutput{Digest: evidence.Observation.StderrDigest, Bytes: evidence.Observation.StderrBytes})
	for _, output := range evidence.Observation.ServiceOutputs {
		outputs = append(outputs, output)
	}
	for _, output := range outputs {
		if output.Digest == "" && output.Bytes == 0 {
			continue
		}
		content, found := evidence.Blobs[output.Digest]
		if !found || len(content) != output.Bytes {
			test.Fatal("host output length mismatch")
		}
		referenced[output.Digest] = true
	}
	if len(referenced) != len(evidence.Blobs) {
		test.Fatal("execution contains blobs with no observation identity")
	}
}

func TestDockerLiveOfflineComparison(test *testing.T) {
	runner, environment := dockerLiveRunner(test, dockerTestAlpine)
	manifest, originalDir, checksDir := dockerTestStaging(test)
	manifest.Environment = environment
	patchedDir := filepath.Join(filepath.Dir(originalDir), "patched")
	if err := os.Mkdir(patchedDir, 0755); err != nil {
		test.Fatal(err)
	}
	for directory, output := range map[string]string{originalDir: "accepted\n", patchedDir: "rejected\n"} {
		if err := os.WriteFile(filepath.Join(directory, "result"), []byte(output), 0644); err != nil {
			test.Fatal(err)
		}
	}
	dockerLiveScript(test, &manifest, checksDir, "run", "#!/bin/sh\nset -eu\nif [ \"$1\" = normal ]; then printf 'accepted\\n'; else cat /src/result; if grep -q accepted /src/result; then exit 1; fi; fi\n")
	for index := range manifest.Checks {
		if manifest.Checks[index].Kind == Reproduction {
			manifest.Checks[index].Failure.ExitCode = 1
		}
	}
	binding, _ := testEvidence(manifest)
	observations := make([]Observation, 0, len(manifest.Checks)*2)
	identities := make(map[string]bool)
	for _, side := range []string{Original, Patched} {
		directory := originalDir
		if side == Patched {
			directory = patchedDir
		}
		for _, check := range manifest.Checks {
			evidence, err := runner.RunCheck(context.Background(), manifest, binding, side, check, directory, checksDir)
			if err != nil {
				test.Fatalf("offline %s/%s unavailable: %v", side, check.ID, err)
			}
			if !usable(evidence.Observation) || identities[evidence.Observation.ContainerID] {
				test.Fatal("check did not have usable evidence from its own container")
			}
			identities[evidence.Observation.ContainerID] = true
			dockerLiveBlobCheck(test, evidence)
			observations = append(observations, evidence.Observation)
		}
	}
	if assessment := Evaluate(manifest, binding, observations); assessment.Conclusion != Verified {
		test.Fatalf("comparison did not verify frozen checks: %+v", assessment)
	}
	test.Log("six isolated executions: two reproduction pairs and one normal-use pair verified")
}

func TestDockerLiveIsolationAndCompilation(test *testing.T) {
	runner, environment := dockerLiveRunner(test, dockerTestGo)
	manifest, sourceDir, checksDir := dockerTestStaging(test)
	manifest.Environment = environment
	dockerLiveScript(test, &manifest, checksDir, "run", `#!/usr/bin/python3
import errno
import os
import pathlib
import socket
import subprocess

assert os.getuid() == 65532 and os.getgid() == 65532
assert "ORKA_HOST_PRIVATE_TEST" not in os.environ
assert not os.environ.get("GOLANG_VERSION")
initial_env = pathlib.Path("/proc/1/environ").read_bytes().split(b"\0")
assert not any(entry.startswith(b"GOLANG_VERSION=") and entry != b"GOLANG_VERSION=" for entry in initial_env)
status = pathlib.Path("/proc/self/status").read_text()
assert "CapEff:\t0000000000000000" in status
assert "NoNewPrivs:\t1" in status and "Seccomp:\t2" in status
assert not pathlib.Path("/var/run/docker.sock").exists()
assert not pathlib.Path("/store").exists()
assert set(os.listdir("/sys/class/net")) == {"lo"}
for filename in ["/cannot-write-root", "/src/cannot-write", "/checks/run"]:
    try:
        pathlib.Path(filename).write_text("unexpected write")
        raise AssertionError("read-only mount writable")
    except OSError as failure:
        assert failure.errno in (errno.EROFS, errno.EACCES)
for family in (socket.AF_INET, socket.AF_INET6, socket.AF_NETLINK, socket.AF_PACKET):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        try:
            socket.socket(family, kind)
            raise AssertionError("offline socket family allowed")
        except OSError as failure:
            assert failure.errno in (errno.EPERM, errno.EACCES)
left_socket, right_socket = socket.socketpair()
left_socket.send(b"local")
assert right_socket.recv(5) == b"local"
left_socket.close()
right_socket.close()
subprocess.run(["gcc", "-x", "c", "-o", "/tmp/check-c", "-"], input=b"#include <stdio.h>\nint main(void) { puts(\"compiled\"); return 0; }\n", check=True, capture_output=True)
assert subprocess.check_output(["/tmp/check-c"]) == b"compiled\n"
pathlib.Path("/tmp/check.go").write_text('package main\nimport "fmt"\nfunc main() { fmt.Println("compiled") }\n')
subprocess.run(["go", "build", "-o", "/tmp/check-go", "/tmp/check.go"], check=True, capture_output=True)
assert subprocess.check_output(["/tmp/check-go"]) == b"compiled\n"
print("sandboxed", flush=True)
`)
	manifest.Checks[0].TimeoutSeconds = 90
	test.Setenv("ORKA_HOST_PRIVATE_TEST", "must-not-be-visible")
	binding, _ := testEvidence(manifest)
	evidence, err := runner.RunCheck(context.Background(), manifest, binding, Original, manifest.Checks[0], sourceDir, checksDir)
	if err != nil {
		test.Fatalf("offline compiler and isolation check unavailable: %v", err)
	}
	if evidence.Observation.ExitCode == nil || *evidence.Observation.ExitCode != 0 || evidence.Observation.StdoutDigest != Digest([]byte("sandboxed\n")) {
		test.Fatalf("sandbox probe failed: exit=%v stdoutBytes=%d stderrBytes=%d", evidence.Observation.ExitCode, evidence.Observation.StdoutBytes, evidence.Observation.StderrBytes)
	}
	dockerLiveBlobCheck(test, evidence)
	content, err := os.ReadFile(filepath.Join(checksDir, "run"))
	if err != nil || Digest(content) != manifest.Files[0].Digest {
		test.Fatal("subject altered frozen host checks")
	}
	test.Log("read-only mounts, empty credentials, uid/caps/seccomp, Unix-only sockets, and C/Go compilation passed")
}

func TestDockerLiveTimeoutCancellationAndOutput(test *testing.T) {
	for _, scenario := range []string{"timeout", "cancellation", "cancel-create", "output-limit", "missing-tool", "missing-image"} {
		test.Run(scenario, func(test *testing.T) {
			runner, environment := dockerLiveRunner(test, dockerTestAlpine)
			manifest, sourceDir, checksDir := dockerTestStaging(test)
			manifest.Environment = environment
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			script := "#!/bin/sh\nsleep 60 &\nprintf 'descendant-started\\n'\nwait\n"
			switch scenario {
			case "timeout":
				manifest.Checks[0].TimeoutSeconds = 1
			case "cancellation":
				baseCommand := runner.command
				runner.command = func(ctx context.Context, arguments ...string) *exec.Cmd {
					if len(arguments) > 0 && arguments[0] == "start" {
						time.AfterFunc(500*time.Millisecond, cancel)
					}
					return baseCommand(ctx, arguments...)
				}
			case "cancel-create":
				baseCommand := runner.command
				runner.command = func(ctx context.Context, arguments ...string) *exec.Cmd {
					if len(arguments) > 0 && arguments[0] == "create" {
						cancel()
					}
					return baseCommand(ctx, arguments...)
				}
			case "output-limit":
				runner.MaxOutputBytes = 128
				script = "#!/bin/sh\nhead -c 1000000 /dev/zero\nsleep 60\n"
			case "missing-tool":
				script = "#!/bin/sh\nexec /nonexistent/orka-test-tool\n"
			case "missing-image":
				manifest.Environment.Image = "alpine@" + Digest([]byte("missing-local-image"))
			}
			dockerLiveScript(test, &manifest, checksDir, "run", script)
			binding, _ := testEvidence(manifest)
			evidence, err := runner.RunCheck(ctx, manifest, binding, Original, manifest.Checks[0], sourceDir, checksDir)
			if err == nil || evidence.Observation.SetupError == "" || usable(evidence.Observation) {
				test.Fatalf("incomplete execution was accepted: %s, %v", scenario, err)
			}
			switch scenario {
			case "timeout", "cancellation":
				if !evidence.Observation.Executed || evidence.Observation.TimedOut != (scenario == "timeout") || evidence.Observation.StdoutDigest != Digest([]byte("descendant-started\n")) {
					test.Fatal("timeout or cancellation did not supervise a live descendant process")
				}
			case "output-limit":
				if !evidence.Observation.OutputTruncated || evidence.Observation.StdoutBytes != 128 {
					test.Fatal("subject output was not bounded and marked incomplete")
				}
			case "missing-tool":
				if evidence.Observation.ExitCode == nil || *evidence.Observation.ExitCode != 127 {
					test.Fatal("missing executable did not remain a setup failure")
				}
			}
		})
	}
}
