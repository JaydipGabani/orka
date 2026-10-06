package patchverification

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const dockerPortFixture = `#!/usr/bin/python3
import errno
import os
import pathlib
import signal
import socket
import sys

identifier, address = sys.argv[1:3]
own_port, other_port = map(int, sys.argv[3:5])
assert not pathlib.Path("/src").exists()
for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
    for port in (other_port, 18082, 0):
        with socket.socket(family, socket.SOCK_STREAM) as forbidden:
            try:
                forbidden.bind((host, port))
                raise AssertionError("fixture bound a foreign port")
            except OSError as failure:
                assert failure.errno in (errno.EACCES, errno.EPERM)
    for port in (own_port, other_port, 18082, 53):
        with socket.socket(family, socket.SOCK_STREAM) as forbidden:
            try:
                forbidden.connect((host, port))
                raise AssertionError("fixture initiated a connection")
            except OSError as failure:
                assert failure.errno in (errno.EACCES, errno.EPERM)
    try:
        socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        raise AssertionError("fixture opened UDP")
    except OSError as failure:
        assert failure.errno == errno.EPERM
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    raise AssertionError("fixture opened an abstract-socket bypass")
except OSError as failure:
    assert failure.errno == errno.EPERM

server = socket.socket(fileno=int(os.environ.pop("ORKA_LISTEN_FD")))
server.set_inheritable(False)
assert server.fileno() == 3 and server.family == socket.AF_INET6
assert server.getsockname() == ("::", own_port, 0, 0)
assert server.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 0
assert server.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
server.settimeout(0.1)
stopped = False
def stop_fixture(signum, frame):
    global stopped
    stopped = True
signal.signal(signal.SIGTERM, stop_fixture)
print("ready:" + identifier, flush=True)
while not stopped:
    try:
        connection, peer = server.accept()
    except socket.timeout:
        continue
    with connection:
        connection.settimeout(1)
        message = connection.recv(64)
        assert message == b"request"
        print("request:" + identifier, flush=True)
        connection.sendall(b"fixture\n")
server.close()
print("stopped:" + identifier, flush=True)
`

const dockerPortClient = `#!/usr/bin/python3
import ctypes
import errno
import os
import pathlib
import socket
import subprocess

assert "ORKA_LISTEN_FD" not in os.environ
try:
    os.fstat(3)
    raise AssertionError("subject inherited a listening descriptor")
except OSError as failure:
    assert failure.errno == errno.EBADF
assert set(os.listdir("/sys/class/net")) == {"lo"}
for route in pathlib.Path("/proc/net/route").read_text().splitlines()[1:]:
    assert route.split()[0] == "lo"
for family, host, port in ((socket.AF_INET, "127.0.0.1", 18080), (socket.AF_INET6, "::1", 18081), (socket.AF_INET6, "::ffff:127.0.0.1", 18080)):
    with socket.socket(family, socket.SOCK_STREAM | socket.SOCK_CLOEXEC, socket.IPPROTO_TCP) as connection:
        connection.settimeout(1)
        connection.connect((host, port))
        connection.sendall(b"request")
        assert connection.recv(64) == b"fixture\n"
for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"), (socket.AF_INET6, "::ffff:127.0.0.1")):
    for port in (18082, 53, 65535, 0):
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            try:
                connection.connect((host, port))
                raise AssertionError("client connected to an undeclared port")
            except OSError as failure:
                assert failure.errno in (errno.EACCES, errno.EPERM)
    for port in (18080, 18081, 18082, 0):
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            try:
                listener.bind((host, port))
                raise AssertionError("client impersonated a listening fixture")
            except OSError as failure:
                assert failure.errno in (errno.EACCES, errno.EPERM)
    for kind, protocol in ((socket.SOCK_DGRAM, 0), (socket.SOCK_DGRAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK, socket.IPPROTO_UDP), (socket.SOCK_RAW, socket.IPPROTO_TCP), (socket.SOCK_STREAM, 132)):
        try:
            socket.socket(family, kind, protocol)
            raise AssertionError("non-TCP socket permitted")
        except OSError as failure:
            assert failure.errno == errno.EPERM
for family, host in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET, "169.254.169.254"), (socket.AF_INET, "172.17.0.1"), (socket.AF_INET6, "2001:db8::1")):
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.5)
        try:
            connection.connect((host, 18080))
            raise AssertionError("declared port escaped the network-none namespace")
        except OSError as failure:
            assert failure.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL)
try:
    socket.getaddrinfo("orka-verification.invalid", 18080)
    raise AssertionError("external DNS resolved")
except socket.gaierror:
    pass
for family in (socket.AF_UNIX, socket.AF_NETLINK, socket.AF_PACKET):
    try:
        socket.socket(family, socket.SOCK_STREAM)
        raise AssertionError("socket-family bypass permitted")
    except OSError as failure:
        assert failure.errno == errno.EPERM
left_socket, right_socket = socket.socketpair()
left_socket.send(b"local")
assert right_socket.recv(5) == b"local"
left_socket.close()
right_socket.close()
libc = ctypes.CDLL(None, use_errno=True)
assert libc.unshare(0x40000000) == -1 and ctypes.get_errno() == errno.EPERM
assert libc.setns(-1, 0x40000000) == -1 and ctypes.get_errno() == errno.EPERM
assert libc.syscall(425, 1, 0) == -1 and ctypes.get_errno() == errno.EPERM
assert libc.prctl(38, 0, 0, 0, 0) == -1
child = 'import errno, socket\nfor action, port in (("connect", 18082), ("bind", 18080)):\n    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:\n        try:\n            getattr(connection, action)(("127.0.0.1", port))\n            raise AssertionError("inherited restriction removed")\n        except OSError as failure:\n            assert failure.errno in (errno.EACCES, errno.EPERM)\nprint("inherited")\n'
assert subprocess.check_output(["/usr/bin/python3", "-c", child]) == b"inherited\n"
assert subprocess.check_output(["/orka-runner/network-launcher", "--bind-tcp", "-", "--connect-tcp", "18082", "--", "/usr/bin/python3", "-c", child]) == b"inherited\n"
rebound = subprocess.run(["/orka-runner/network-launcher", "--bind-tcp", "18080", "--connect-tcp", "-", "--", "/bin/echo", "must-not-execute"], capture_output=True)
assert rebound.returncode == 125 and rebound.stdout == b""
print("network-policy-passed", flush=True)
`

func TestDockerLiveDeclaredTCPPolicy(test *testing.T) {
	runner, environment := dockerLiveRunner(test, dockerTestGo)
	manifest, sourceDir, checksDir := dockerTestStaging(test)
	manifest.Environment = environment
	manifest.Environment.Profile = LocalServices
	manifest.Environment.Services = []Service{
		{ID: "fixture-v4", Command: []string{"/checks/fixture", "fixture-v4", "127.0.0.1", "18080", "18081"}, Port: 18080, ReadyOutput: "ready:fixture-v4\n"},
		{ID: "fixture-v6", Command: []string{"/checks/fixture", "fixture-v6", "::1", "18081", "18080"}, Port: 18081, ReadyOutput: "ready:fixture-v6\n"},
	}
	var err error
	manifest.Environment, err = runner.FreezeEnvironment(manifest.Environment)
	if err != nil {
		test.Fatal(err)
	}
	dockerLiveScript(test, &manifest, checksDir, "fixture", dockerPortFixture)
	dockerLiveScript(test, &manifest, checksDir, "run", dockerPortClient)
	for index := range manifest.Checks {
		manifest.Checks[index].Healthy.Stdout = "network-policy-passed\n"
		manifest.Checks[index].Healthy.Services = map[string]string{
			"fixture-v4": "ready:fixture-v4\nrequest:fixture-v4\nrequest:fixture-v4\nstopped:fixture-v4\n",
			"fixture-v6": "ready:fixture-v6\nrequest:fixture-v6\nstopped:fixture-v6\n",
		}
		manifest.Checks[index].Failure.Services = manifest.Checks[index].Healthy.Services
	}
	binding, _ := testEvidence(manifest)
	evidence, err := runner.RunCheck(context.Background(), manifest, binding, Original, manifest.Checks[0], sourceDir, checksDir)
	if err != nil {
		test.Fatalf("declared-port fixture setup failed: %v", err)
	}
	if !usable(evidence.Observation) || !matches(evidence.Observation, manifest.Checks[0].Healthy) {
		test.Fatalf("controlled network probe failed: %s", evidence.Blobs[evidence.Observation.StderrDigest])
	}
	dockerLiveBlobCheck(test, evidence)
	test.Log("declared IPv4/IPv6/mapped TCP works; undeclared and DNS ports, all client binds, foreign fixture binds, fixture connects, UDP/raw/SCTP/abstract sockets, external declared-port egress, namespace/io_uring bypasses and re-exec widening denied")
}

func TestDockerLiveFrozenInputSnapshot(test *testing.T) {
	runner, environment := dockerLiveRunner(test, dockerTestGo)
	manifest, sourceDir, checksDir := dockerLiveServiceManifest(test, runner, environment)
	dockerLiveScript(test, &manifest, checksDir, "run", "#!/bin/sh\nprintf 'frozen-check-ran\\n'\n")
	baseCommand := runner.command
	changed := false
	runner.command = func(ctx context.Context, arguments ...string) *exec.Cmd {
		if !changed && len(arguments) > 1 && arguments[0] == "image" && arguments[1] == "inspect" {
			changed = true
			for _, filename := range []string{filepath.Join(checksDir, "run"), runner.LauncherPath} {
				if err := os.WriteFile(filename, []byte("#!/bin/sh\nprintf 'caller-file-spoof\\n'\n"), 0755); err != nil {
					test.Fatal(err)
				}
			}
		}
		return baseCommand(ctx, arguments...)
	}
	binding, _ := testEvidence(manifest)
	evidence, err := runner.RunCheck(context.Background(), manifest, binding, Original, manifest.Checks[0], sourceDir, checksDir)
	if err != nil || !changed || !usable(evidence.Observation) || evidence.Observation.StdoutDigest != Digest([]byte("frozen-check-ran\n")) {
		test.Fatalf("caller input mutation affected runner-owned snapshots: %v", err)
	}
	for _, blob := range evidence.Blobs {
		if strings.Contains(string(blob), "caller-file-spoof") {
			test.Fatal("unfrozen caller bytes reached the container")
		}
	}
	dockerLiveBlobCheck(test, evidence)
	test.Log("caller check and launcher mutations after validation cannot replace runner-owned frozen mounts")
}
