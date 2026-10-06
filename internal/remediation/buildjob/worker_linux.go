//go:build linux

package buildjob

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	diagnosticPattern      = regexp.MustCompile(`(?:^|\s)(?:\./)?([a-zA-Z0-9_][a-zA-Z0-9_./+-]{0,239}):([1-9][0-9]{0,6})(?::([0-9]{1,6}))?:\s*(.*)`)
	compilerFailurePattern = regexp.MustCompile(`(?:^error:|^fatal error:|^undefined:|^cannot use |^undeclared |^unknown field |not declared|undefined reference)`)
)

type buildctlProcess struct {
	executable        string
	environment       []string
	registryDirectory string
}

func (process buildctlProcess) run(ctx context.Context, args []string, directory string, output io.Writer) error {
	return process.command(ctx, args, directory, output, output)
}

func (process buildctlProcess) command(ctx context.Context, args []string, directory string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, process.executable, args...)
	command.Dir = directory
	home, dockerConfig := filepath.Join(directory, "home"), filepath.Join(directory, "home", ".docker")
	if process.registryDirectory != "" {
		home, dockerConfig = filepath.Dir(process.registryDirectory), process.registryDirectory
	}
	command.Env = append([]string{
		"PATH=/usr/bin:/bin", "HOME=" + home,
		"DOCKER_CONFIG=" + dockerConfig,
		"TMPDIR=" + filepath.Join(directory, "scratch"),
		"XDG_CACHE_HOME=" + filepath.Join(directory, "home", ".cache"),
	}, process.environment...)
	command.Stdout, command.Stderr = stdout, stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 5 * time.Second
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		// buildctl v0.31.1 writes --ref-file in a defer. Give its signal handler
		// time to cancel the RPC and return before WaitDelay forces termination.
		err := unix.Kill(-command.Process.Pid, unix.SIGTERM)
		if err == unix.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	return command.Run()
}

func writeSource(root *os.Root, name string, body []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(body)
	return closeFile(file, err)
}

func readPrivateMetadata(root *os.Root, name string, maximum int64) ([]byte, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	body, err := readBounded(file, maximum)
	return body, closeFile(file, err)
}

func writeTermination(name string, body []byte) error {
	file, err := os.OpenFile(name, os.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !singleLink(info) {
		_ = file.Close()
		return failure(ErrInvalid, "worker-termination-file-invalid")
	}
	if err := file.Truncate(0); err != nil {
		return closeFile(file, err)
	}
	_, err = file.Write(body)
	return closeFile(file, err)
}

func singleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

// LimitWorkerProcess is called only by the dedicated worker executable.
// PID limits belong to kubelet's podPidsLimit: RLIMIT_NPROC counts every process
// sharing the node's real UID, including unrelated nonroot Pods.
func LimitWorkerProcess() error {
	for _, limit := range []struct {
		resource int
		value    uint64
	}{{unix.RLIMIT_NOFILE, 1024}} {
		var current unix.Rlimit
		if err := unix.Getrlimit(limit.resource, &current); err != nil {
			return failure(ErrInvalid, "worker-process-limit-unavailable")
		}
		if limit.value < current.Max {
			current.Max = limit.value
		}
		if current.Cur > current.Max {
			current.Cur = current.Max
		}
		if err := unix.Setrlimit(limit.resource, &current); err != nil {
			return failure(ErrInvalid, "worker-process-limit-not-enforced")
		}
	}
	return nil
}
