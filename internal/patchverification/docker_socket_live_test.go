package patchverification

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

const dockerSocketSyscallProbe = `import ctypes
import errno
import json
import socket
import struct

libc = ctypes.CDLL(None, use_errno=True)
class IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]
class Message(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("name_length", ctypes.c_uint),
                ("iov", ctypes.POINTER(IOVec)), ("iov_length", ctypes.c_size_t),
                ("control", ctypes.c_void_p), ("control_length", ctypes.c_size_t),
                ("flags", ctypes.c_int)]
class MultiMessage(ctypes.Structure):
    _fields_ = [("message", Message), ("length", ctypes.c_uint)]
libc.sendto.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
libc.sendto.restype = ctypes.c_ssize_t
libc.sendmsg.argtypes = [ctypes.c_int, ctypes.POINTER(Message), ctypes.c_int]
libc.sendmsg.restype = ctypes.c_ssize_t
libc.sendmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(MultiMessage), ctypes.c_uint, ctypes.c_int]
libc.sendmmsg.restype = ctypes.c_int

def fast_open(client, host, port, operation):
    address = struct.pack("=H", client.family) + struct.pack("!H", port)
    if client.family == socket.AF_INET:
        address += socket.inet_pton(client.family, host) + bytes(8)
    else:
        address += bytes(4) + socket.inet_pton(client.family, host) + bytes(4)
    destination = ctypes.create_string_buffer(address)
    payload = ctypes.create_string_buffer(b"probe")
    vector = IOVec(ctypes.cast(payload, ctypes.c_void_p), 5)
    message = Message(ctypes.cast(destination, ctypes.c_void_p), len(address), ctypes.pointer(vector), 1, None, 0, 0)
    flags = 0x20000000 | socket.MSG_NOSIGNAL
    ctypes.set_errno(0)
    if operation == "sendto":
        result = libc.sendto(client.fileno(), payload, 5, flags, destination, len(address))
    elif operation == "sendmsg":
        result = libc.sendmsg(client.fileno(), ctypes.byref(message), flags)
    else:
        messages = MultiMessage(message, 0)
        result = libc.sendmmsg(client.fileno(), ctypes.byref(messages), 1, flags)
    return ctypes.get_errno() if result == -1 else 0

results = {}
for family, host, label in ((socket.AF_INET, "127.0.0.1", "ipv4"), (socket.AF_INET6, "::1", "ipv6")):
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listening = False
        port = 18082
        try:
            listener.listen(8)
            port = listener.getsockname()[1]
            listening = True
            results["implicit-listen-" + label] = {"errno": 0}
        except OSError as failure:
            results["implicit-listen-" + label] = {"errno": failure.errno}
        listener.settimeout(0.5)
        for operation in ("sendto", "sendmsg", "sendmmsg"):
            with socket.socket(family, socket.SOCK_STREAM | socket.SOCK_NONBLOCK) as client:
                failure = fast_open(client, host, port, operation)
                connected = False
                if listening and failure in (0, errno.EINPROGRESS, errno.EAGAIN):
                    accepted, _ = listener.accept()
                    accepted.close()
                    connected = True
                results["fastopen-" + operation + "-" + label] = {"errno": failure, "connected": connected}

try:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
except OSError as failure:
    results["datagram-disconnect-rebind"] = {"errno": failure.errno}
else:
    with left, right:
        unspecified = ctypes.create_string_buffer(struct.pack("=H", socket.AF_UNSPEC))
        assert libc.connect(left.fileno(), unspecified, 2) == 0
        try:
            left.bind("\0orka-disconnected-datagram")
            results["datagram-disconnect-rebind"] = {"errno": 0, "connected": True}
        except OSError as failure:
            results["datagram-disconnect-rebind"] = {"errno": failure.errno}

for flags in (0, socket.SOCK_CLOEXEC, socket.SOCK_NONBLOCK, socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK):
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM | flags)
    with left, right:
        left.send(b"private")
        assert right.recv(7) == b"private"
print(json.dumps(results), flush=True)
`

func TestDockerLiveSocketSyscallConfinement(test *testing.T) {
	launcher, _ := dockerLiveLauncher(test)
	profile, err := dockerSeccomp("linux/"+runtime.GOARCH, LocalServices)
	if err != nil {
		test.Fatal(err)
	}
	filename := filepath.Join(test.TempDir(), "seccomp.json")
	if err := os.WriteFile(filename, profile, 0600); err != nil {
		test.Fatal(err)
	}
	for _, role := range []struct {
		name string
		bind string
	}{{"subject", "-"}, {"fixture", "18080"}} {
		test.Run(role.name, func(test *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := dockerLiveAuxiliary(test, ctx, "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--security-opt", "seccomp="+filename, "--user", "65532:65532", "--mount", "type=bind,src="+launcher+",dst=/network-launcher,readonly", "--entrypoint", "/network-launcher", dockerTestGo, "--bind-tcp", role.bind, "--connect-tcp", "-", "--", "/usr/bin/python3", "-c", dockerSocketSyscallProbe)
			content, err := command.CombinedOutput()
			if err != nil {
				test.Fatalf("isolated syscall probe failed: %v: %s", err, content)
			}
			var results map[string]struct {
				Errno     syscall.Errno `json:"errno"`
				Connected bool          `json:"connected"`
			}
			if err := json.Unmarshal(content, &results); err != nil || len(results) != 9 {
				test.Fatalf("incomplete syscall results: %v: %s", err, content)
			}
			for name, result := range results {
				test.Logf("%s: errno=%d connected=%t", name, result.Errno, result.Connected)
				if (result.Errno != syscall.EPERM && result.Errno != syscall.EACCES) || result.Connected {
					test.Errorf("%s bypassed %s confinement", name, role.name)
				}
			}
		})
	}
}
