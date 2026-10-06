package patchverification

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const dockerHTTPFixture = `#!/usr/bin/python3
import http.server
import os
import pathlib
import signal
import socket

assert not pathlib.Path("/src").exists()
stopped = False
def stop_fixture(signum, frame):
    global stopped
    stopped = True

class Fixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print("request:" + self.path, flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"fixture\n")
    def log_message(self, format_text, *arguments):
        pass

listener = socket.socket(fileno=int(os.environ.pop("ORKA_LISTEN_FD")))
listener.set_inheritable(False)
assert listener.family == socket.AF_INET6 and listener.getsockname()[1] == 18080
assert listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
server = http.server.HTTPServer(("::", 18080), Fixture, bind_and_activate=False)
server.socket.close()
server.socket = listener
server.server_address = listener.getsockname()
server.server_name, server.server_port = "localhost", 18080
server.timeout = 0.1
signal.signal(signal.SIGTERM, stop_fixture)
print("ready:fixture", flush=True)
while not stopped:
    server.handle_request()
server.server_close()
print("stopped:fixture", flush=True)
`

func dockerLiveServiceManifest(test *testing.T, runner DockerRunner, environment Environment) (Manifest, string, string) {
	test.Helper()
	manifest, sourceDir, checksDir := dockerTestStaging(test)
	manifest.Environment = environment
	manifest.Environment.Profile = LocalServices
	manifest.Environment.Services = []Service{{ID: "fixture", Command: []string{"/checks/fixture"}, Port: 18080, ReadyOutput: "ready:fixture\n"}}
	var err error
	manifest.Environment, err = runner.FreezeEnvironment(manifest.Environment)
	if err != nil {
		test.Fatal(err)
	}
	dockerLiveScript(test, &manifest, checksDir, "fixture", dockerHTTPFixture)
	for index, check := range manifest.Checks {
		output := "ready:fixture\nrequest:/" + check.Command[1] + "\nstopped:fixture\n"
		manifest.Checks[index].Healthy.Services = map[string]string{"fixture": output}
		manifest.Checks[index].Failure.Services = map[string]string{"fixture": output}
	}
	return manifest, sourceDir, checksDir
}

func TestDockerLiveLocalServicesComparison(test *testing.T) {
	runner, environment := dockerLiveRunner(test, dockerTestGo)
	manifest, originalDir, checksDir := dockerLiveServiceManifest(test, runner, environment)
	patchedDir := filepath.Join(filepath.Dir(originalDir), "patched")
	if err := os.Mkdir(patchedDir, 0755); err != nil {
		test.Fatal(err)
	}
	for directory, output := range map[string]string{originalDir: "accepted\n", patchedDir: "rejected\n"} {
		if err := os.WriteFile(filepath.Join(directory, "result"), []byte(output), 0644); err != nil {
			test.Fatal(err)
		}
	}
	dockerLiveScript(test, &manifest, checksDir, "run", `#!/usr/bin/python3
import errno
import http.client
import os
import pathlib
import socket
import sys

assert set(os.listdir("/sys/class/net")) == {"lo"}
for route in pathlib.Path("/proc/net/route").read_text().splitlines()[1:]:
    assert route.split()[0] == "lo"
connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=2)
connection.request("GET", "/" + sys.argv[1])
response = connection.getresponse()
assert response.status == 200 and response.read() == b"fixture\n"
connection.close()
for family, address in [(socket.AF_INET, ("192.0.2.1", 443)), (socket.AF_INET6, ("2001:db8::1", 443))]:
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(0.5)
    try:
        connection.connect(address)
        raise AssertionError("external TCP reachable")
    except OSError as failure:
                assert failure.errno in (errno.EPERM, errno.EACCES, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL)
    finally:
        connection.close()
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raise AssertionError("UDP socket permitted")
except OSError as failure:
    assert failure.errno == errno.EPERM
try:
    socket.getaddrinfo("orka-verification.invalid", 443)
    raise AssertionError("external DNS resolved")
except socket.gaierror:
    pass
for family in (socket.AF_NETLINK, socket.AF_PACKET):
    try:
        socket.socket(family, socket.SOCK_RAW)
        raise AssertionError("forbidden socket family allowed")
    except OSError as failure:
        assert failure.errno in (errno.EPERM, errno.EACCES)
if sys.argv[1] == "normal":
    print("accepted", flush=True)
else:
    print(pathlib.Path("/src/result").read_text(), end="", flush=True)
`)
	binding, _ := testEvidence(manifest)
	observations := make([]Observation, 0, len(manifest.Checks)*2)
	for _, side := range []string{Original, Patched} {
		directory := originalDir
		if side == Patched {
			directory = patchedDir
		}
		for _, check := range manifest.Checks {
			evidence, err := runner.RunCheck(context.Background(), manifest, binding, side, check, directory, checksDir)
			if err != nil {
				test.Fatalf("loopback %s/%s unavailable: %v", side, check.ID, err)
			}
			if !usable(evidence.Observation) {
				test.Fatal("loopback check produced unusable evidence")
			}
			if *evidence.Observation.ExitCode != 0 {
				test.Fatalf("controlled loopback probe failed: %s", evidence.Blobs[evidence.Observation.StderrDigest])
			}
			dockerLiveBlobCheck(test, evidence)
			observations = append(observations, evidence.Observation)
		}
	}
	if assessment := Evaluate(manifest, binding, observations); assessment.Conclusion != Verified {
		test.Fatalf("local HTTP comparison failed: %+v", assessment)
	}
	test.Log("HTTP reachable in both versions; external IPv4, IPv6, UDP/DNS blocked; final fixture output matched")
}

func TestDockerLiveServiceFailures(test *testing.T) {
	for _, scenario := range []string{"readiness-missing", "readiness-on-stderr", "unexpected-stderr", "early-exit", "exit-during-check", "truncated", "shutdown-truncated"} {
		test.Run(scenario, func(test *testing.T) {
			runner, environment := dockerLiveRunner(test, dockerTestGo)
			manifest, sourceDir, checksDir := dockerLiveServiceManifest(test, runner, environment)
			script := "#!/bin/sh\nexec /bin/sleep 60\n"
			switch scenario {
			case "readiness-missing":
				runner.SetupTimeout = 2 * time.Second
			case "readiness-on-stderr":
				runner.SetupTimeout = 2 * time.Second
				script = "#!/bin/sh\nprintf 'ready:fixture\\n' >&2\nexec /bin/sleep 60\n"
			case "early-exit":
				script = "#!/bin/sh\nprintf 'ready:fixture\\n'\nexit 0\n"
			case "unexpected-stderr":
				script = strings.Replace(dockerHTTPFixture, "import signal", "import signal\nimport sys\nprint('private-fixture-diagnostic', file=sys.stderr, flush=True)", 1)
			case "exit-during-check":
				script = "#!/usr/bin/python3\nimport time\nprint('ready:fixture', flush=True)\ntime.sleep(1)\n"
				dockerLiveScript(test, &manifest, checksDir, "run", "#!/bin/sh\nexec /bin/sleep 60\n")
			case "truncated":
				runner.MaxOutputBytes = 128
				script = "#!/usr/bin/python3\nimport time\nprint('ready:fixture', flush=True)\nprint('x' * 10000, flush=True)\ntime.sleep(60)\n"
			case "shutdown-truncated":
				runner.MaxOutputBytes = 128
				script = strings.Replace(dockerHTTPFixture, `print("stopped:fixture", flush=True)`, `print("x" * 10000, flush=True)`, 1)
			}
			dockerLiveScript(test, &manifest, checksDir, "fixture", script)
			binding, _ := testEvidence(manifest)
			evidence, err := runner.RunCheck(context.Background(), manifest, binding, Original, manifest.Checks[0], sourceDir, checksDir)
			if err == nil || evidence.Observation.SetupError == "" || usable(evidence.Observation) {
				test.Fatalf("fixture failure was usable: %s, %v", scenario, err)
			}
			dockerLiveBlobCheck(test, evidence)
			if strings.Contains(evidence.Observation.SetupError, "private-fixture-diagnostic") {
				test.Fatal("fixture diagnostics leaked into setup errors")
			}
			if strings.HasPrefix(scenario, "readiness-") && evidence.Observation.Executed {
				test.Fatal("subject executed before observer-owned readiness")
			}
			if strings.Contains(scenario, "truncated") && !evidence.Observation.OutputTruncated {
				test.Fatal("truncated service evidence not marked")
			}
		})
	}
}

func TestDockerLiveServiceSpoofing(test *testing.T) {
	runner, environment := dockerLiveRunner(test, dockerTestGo)
	manifest, sourceDir, checksDir := dockerLiveServiceManifest(test, runner, environment)
	dockerLiveScript(test, &manifest, checksDir, "run", "#!/bin/sh\nprintf 'ready:fixture\\nrequest:/one\\nstopped:fixture\\n'\n")
	manifest.Checks[0].Healthy.Stdout = "ready:fixture\nrequest:/one\nstopped:fixture\n"
	binding, observations := testEvidence(manifest)
	for index, observation := range observations {
		for _, check := range manifest.Checks {
			if check.ID == observation.CheckID {
				output := check.Healthy.Services["fixture"]
				observations[index].ServiceOutputs = map[string]CapturedOutput{"fixture": {Digest: Digest([]byte(output)), Bytes: len(output)}}
			}
		}
	}
	evidence, err := runner.RunCheck(context.Background(), manifest, binding, Patched, manifest.Checks[0], sourceDir, checksDir)
	if err != nil || !usable(evidence.Observation) {
		test.Fatalf("spoofing probe setup failed: %v", err)
	}
	if evidence.Observation.StdoutDigest != Digest([]byte(manifest.Checks[0].Healthy.Stdout)) {
		test.Fatal("subject spoof did not reach subject stdout")
	}
	if captured := evidence.Observation.ServiceOutputs["fixture"]; captured.Digest != Digest([]byte("ready:fixture\nstopped:fixture\n")) || matches(evidence.Observation, manifest.Checks[0].Healthy) {
		test.Fatal("subject stdout forged independent fixture evidence")
	}
	observations[3] = evidence.Observation
	if result := Evaluate(manifest, binding, observations); result.Conclusion != UnableToVerify {
		test.Fatalf("forged service output produced %s", result.Conclusion)
	}
}

func TestDockerLiveServiceCancellation(test *testing.T) {
	for _, scenario := range []string{"timeout", "cancellation"} {
		test.Run(scenario, func(test *testing.T) {
			runner, environment := dockerLiveRunner(test, dockerTestGo)
			manifest, sourceDir, checksDir := dockerLiveServiceManifest(test, runner, environment)
			dockerLiveScript(test, &manifest, checksDir, "run", "#!/bin/sh\nsleep 60 &\nprintf 'descendant-started\\n'\nwait\n")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "timeout" {
				manifest.Checks[0].TimeoutSeconds = 1
			} else {
				baseCommand := runner.command
				starts := 0
				runner.command = func(ctx context.Context, arguments ...string) *exec.Cmd {
					if len(arguments) > 0 && arguments[0] == "start" {
						starts++
						if starts == 3 {
							time.AfterFunc(500*time.Millisecond, cancel)
						}
					}
					return baseCommand(ctx, arguments...)
				}
			}
			binding, _ := testEvidence(manifest)
			evidence, err := runner.RunCheck(ctx, manifest, binding, Patched, manifest.Checks[0], sourceDir, checksDir)
			if err == nil || usable(evidence.Observation) || !evidence.Observation.Executed || evidence.Observation.TimedOut != (scenario == "timeout") {
				test.Fatalf("fixture-backed cancellation did not fail closed: %v", err)
			}
			if evidence.Observation.StdoutDigest != Digest([]byte("descendant-started\n")) || evidence.Observation.ServiceOutputs["fixture"].Digest != Digest([]byte("ready:fixture\nstopped:fixture\n")) {
				test.Fatal("subject descendants were not supervised before orderly fixture shutdown")
			}
		})
	}
}
