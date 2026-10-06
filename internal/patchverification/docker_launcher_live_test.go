package patchverification

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func dockerLiveAuxiliary(test *testing.T, ctx context.Context, arguments ...string) *exec.Cmd {
	test.Helper()
	name := "orka-patch-runner-v2-" + strings.ToLower(rand.Text())
	test.Cleanup(func() {
		content, err := (DockerRunner{}).control(context.Background(), "container", "inspect", "--format", "{{.Id}}", name)
		if err == nil {
			identifier := strings.TrimSpace(string(content))
			test.Errorf("owned auxiliary container remained: %s", name)
			if sha256Pattern.MatchString("sha256:" + identifier) {
				_, _ = (DockerRunner{}).control(context.Background(), "rm", "--force", "--volumes", identifier)
			}
		}
	})
	return (DockerRunner{}).dockerCommand(ctx, append([]string{"run", "--name", name}, arguments...)...)
}

func dockerLiveLauncher(test *testing.T) (string, string) {
	test.Helper()
	if os.Getenv("ORKA_PATCH_VERIFY_DOCKER_TEST") != "1" {
		test.Skip("set ORKA_PATCH_VERIFY_DOCKER_TEST=1 to build the trusted local launcher")
	}
	source, err := filepath.Abs("launcher/landlock.c")
	if err != nil {
		test.Fatal(err)
	}
	output := test.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := dockerLiveAuxiliary(test, ctx, "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--memory", "512m", "--pids-limit", "128", "--tmpfs", "/tmp:rw,nosuid,nodev,size=67108864", "--mount", "type=bind,src="+source+",dst=/input/landlock.c,readonly", "--mount", "type=bind,src="+output+",dst=/output", "--entrypoint", "/usr/bin/gcc", dockerTestGo, "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o", "/output/network-launcher", "/input/landlock.c")
	if content, err := command.CombinedOutput(); err != nil {
		test.Fatalf("trusted launcher build failed: %v: %s", err, content)
	}
	filename := filepath.Join(output, "network-launcher")
	content, err := os.ReadFile(filename)
	if err != nil {
		test.Fatal(err)
	}
	return filename, Digest(content)
}

func TestDockerLiveLandlockProbe(test *testing.T) {
	launcher, digest := dockerLiveLauncher(test)
	profile, err := dockerSeccomp("linux/"+runtime.GOARCH, LocalServices)
	if err != nil {
		test.Fatal(err)
	}
	filename := filepath.Join(test.TempDir(), "seccomp.json")
	if err := os.WriteFile(filename, profile, 0600); err != nil {
		test.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := dockerLiveAuxiliary(test, ctx, "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--security-opt", "seccomp="+filename, "--user", "65532:65532", "--mount", "type=bind,src="+launcher+",dst=/network-launcher,readonly", "--entrypoint", "/network-launcher", dockerTestGo, "--bind-tcp", "18080", "--connect-tcp", "-", "--", "/usr/bin/python3", "-c", `import errno, os, socket
assert os.environ.pop("ORKA_LISTEN_FD") == "3"
listener = socket.socket(fileno=3)
listener.set_inheritable(False)
assert listener.family == socket.AF_INET6 and listener.getsockname() == ("::", 18080, 0, 0)
assert listener.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 0
assert listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
listener.close()
print("landlock-probe-passed")`)
	content, err := command.Output()
	if err != nil || string(content) != "landlock-probe-passed\n" {
		var failure *exec.ExitError
		if typed, ok := err.(*exec.ExitError); ok {
			failure = typed
		}
		if failure != nil {
			test.Logf("probe diagnostics: %s", failure.Stderr)
		}
		test.Fatalf("Landlock TCP probe failed: %v", err)
	}
	test.Logf("trusted static launcher %s: one owned descriptor listening on the declared dual-stack TCP port", digest)
}

func TestDockerLiveLandlockUnavailable(test *testing.T) {
	launcher, _ := dockerLiveLauncher(test)
	profile, err := dockerSeccomp("linux/"+runtime.GOARCH, Offline)
	if err != nil {
		test.Fatal(err)
	}
	filename := filepath.Join(test.TempDir(), "seccomp.json")
	if err := os.WriteFile(filename, profile, 0600); err != nil {
		test.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := dockerLiveAuxiliary(test, ctx, "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--security-opt", "seccomp="+filename, "--user", "65532:65532", "--mount", "type=bind,src="+launcher+",dst=/network-launcher,readonly", "--entrypoint", "/network-launcher", dockerTestGo, "--bind-tcp", "18080", "--connect-tcp", "-", "--", "/bin/echo", "must-not-execute")
	content, err := command.Output()
	failure, exited := err.(*exec.ExitError)
	if !exited || failure.ExitCode() != 125 || len(content) != 0 || string(failure.Stderr) != "local TCP confinement unavailable\n" {
		test.Fatal("blocked Landlock did not fail closed before executing the command")
	}
	test.Log("when confinement syscalls are unavailable, the launcher exits 125 before executing any subject")
}
