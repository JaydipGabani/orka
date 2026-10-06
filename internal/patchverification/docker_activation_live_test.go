package patchverification

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func dockerLiveActivationProfile(test *testing.T, denyIPv6 bool) string {
	test.Helper()
	content, err := dockerSeccomp("linux/"+runtime.GOARCH, LocalServices)
	if err != nil {
		test.Fatal(err)
	}
	if denyIPv6 {
		var profile dockerSeccompProfile
		if err := json.Unmarshal(content, &profile); err != nil {
			test.Fatal(err)
		}
		profile.Syscalls = slices.DeleteFunc(profile.Syscalls, func(rule dockerSeccompRule) bool {
			return slices.Contains(rule.Names, "socket") && rule.Args[0].Value == 10
		})
		content, err = json.Marshal(profile)
		if err != nil {
			test.Fatal(err)
		}
	}
	filename := filepath.Join(test.TempDir(), "seccomp.json")
	if err := os.WriteFile(filename, content, 0600); err != nil {
		test.Fatal(err)
	}
	return filename
}

func TestDockerLiveActivationRejectsUnsupported(test *testing.T) {
	launcher, _ := dockerLiveLauncher(test)
	for _, scenario := range []struct {
		name     string
		bind     string
		connect  string
		denyIPv6 bool
	}{
		{"multiple-fixture-ports", "18080,18081", "-", false},
		{"fixture-outbound", "18080", "18081", false},
		{"ephemeral-fixture-port", "0", "-", false},
		{"empty-fixture-port", "", "-", false},
		{"ipv6-unavailable", "18080", "-", true},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			profile := dockerLiveActivationProfile(test, scenario.denyIPv6)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := dockerLiveAuxiliary(test, ctx, "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--security-opt", "seccomp="+profile, "--user", "65532:65532", "--mount", "type=bind,src="+launcher+",dst=/network-launcher,readonly", "--entrypoint", "/network-launcher", dockerTestGo, "--bind-tcp", scenario.bind, "--connect-tcp", scenario.connect, "--", "/bin/echo", "must-not-execute")
			content, err := command.Output()
			failure, exited := err.(*exec.ExitError)
			if !exited || failure.ExitCode() != 125 || len(content) != 0 {
				test.Fatalf("unsupported activation executed a command or fell back: %v", err)
			}
			if scenario.denyIPv6 && !strings.Contains(string(failure.Stderr), "dual-stack IPv6 fixture port") {
				test.Fatalf("missing explicit IPv6 prerequisite diagnostic: %s", failure.Stderr)
			}
		})
	}
}

const dockerActivationReexecProbe = `import ctypes
import os
import socket
import subprocess

assert os.environ.pop("ORKA_LISTEN_FD") == "3"
listener = socket.socket(fileno=3)
assert listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
class Instruction(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("yes", ctypes.c_ubyte), ("no", ctypes.c_ubyte), ("value", ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("instructions", ctypes.POINTER(Instruction))]
instruction = Instruction(6, 0, 0, 0x7fff0000)
program = Program(1, ctypes.pointer(instruction))
assert ctypes.CDLL(None).prctl(22, 2, ctypes.byref(program), 0, 0) == 0
command = ["/network-launcher", "--bind-tcp", "-", "--connect-tcp", "-", "--", "/usr/bin/python3", "-c",
           'import os; assert "ORKA_LISTEN_FD" not in os.environ; assert all(not os.path.exists("/proc/self/fd/" + str(descriptor)) for descriptor in range(3, 8)); print("closed")']
assert subprocess.check_output(command, pass_fds=(3,), env=dict(os.environ, ORKA_LISTEN_FD="99")) == b"closed\n"
rebound = subprocess.run(["/network-launcher", "--bind-tcp", "18080", "--connect-tcp", "-", "--", "/bin/echo", "must-not-execute"], pass_fds=(3,), capture_output=True)
assert rebound.returncode == 125 and rebound.stdout == b""
listener.close()
print("activation-reexec-passed")
`

func TestDockerLiveActivationReexec(test *testing.T) {
	launcher, _ := dockerLiveLauncher(test)
	profile := dockerLiveActivationProfile(test, false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := dockerLiveAuxiliary(test, ctx, "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--security-opt", "seccomp="+profile, "--user", "65532:65532", "--env", "ORKA_LISTEN_FD=99", "--mount", "type=bind,src="+launcher+",dst=/network-launcher,readonly", "--entrypoint", "/network-launcher", dockerTestGo, "--bind-tcp", "18080", "--connect-tcp", "-", "--", "/usr/bin/python3", "-c", dockerActivationReexecProbe)
	content, err := command.CombinedOutput()
	if err != nil || string(content) != "activation-reexec-passed\n" {
		test.Fatalf("activation descriptor or inherited filter was regained: %v: %s", err, content)
	}
}

func TestDockerLiveSocketActivatedDemoFixture(test *testing.T) {
	runner, environment := dockerLiveRunner(test, dockerTestGo)
	manifest, sourceDir, checksDir := dockerLiveServiceManifest(test, runner, environment)
	for _, filename := range []string{"service.sh", "service.c"} {
		content, err := os.ReadFile(filepath.Join("..", "..", "examples", "patch-verification", "http", "checks", filename))
		if err != nil {
			test.Fatal(err)
		}
		if filename == "service.sh" {
			dockerLiveScript(test, &manifest, checksDir, "fixture", string(content))
		} else {
			if err := os.WriteFile(filepath.Join(checksDir, filename), content, 0644); err != nil {
				test.Fatal(err)
			}
			manifest.Files = append(manifest.Files, FrozenFile{Path: filename, Content: content, Digest: Digest(content)})
		}
	}
	manifest.Environment.Services[0].ReadyOutput = "ready\n"
	dockerLiveScript(test, &manifest, checksDir, "run", "#!/usr/bin/python3\nimport http.client\nfor host in ('127.0.0.1', '::1'):\n    connection = http.client.HTTPConnection(host, 18080, timeout=2)\n    connection.request('GET', '/reserve')\n    response = connection.getresponse()\n    assert response.status == 200 and response.read() == b'reserved\\n'\n    connection.close()\nprint('demo-service-passed')\n")
	for index := range manifest.Checks {
		manifest.Checks[index].Healthy.Stdout = "demo-service-passed\n"
		manifest.Checks[index].Healthy.Services = map[string]string{"fixture": "ready\nreserve\nreserve\n"}
		manifest.Checks[index].Failure.Services = manifest.Checks[index].Healthy.Services
	}
	binding, _ := testEvidence(manifest)
	evidence, err := runner.RunCheck(context.Background(), manifest, binding, Original, manifest.Checks[0], sourceDir, checksDir)
	if err != nil || !usable(evidence.Observation) || !matches(evidence.Observation, manifest.Checks[0].Healthy) {
		test.Fatalf("socket-activated C fixture or orderly shutdown failed: %v: %s", err, evidence.Blobs[evidence.Observation.StderrDigest])
	}
	dockerLiveBlobCheck(test, evidence)
}
