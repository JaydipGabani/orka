//go:build linux

package lab

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type limitedOutput struct {
	writer io.Writer
	limit  int
	wrote  int
	err    error
	cancel context.CancelFunc
}

func (output *limitedOutput) Write(data []byte) (int, error) {
	allowed := min(len(data), output.limit-output.wrote)
	written, err := output.writer.Write(data[:allowed])
	output.wrote += written
	if err != nil {
		output.err = ErrIO
	} else if allowed != len(data) {
		output.err = ErrTooLarge
	}
	if output.err != nil {
		output.cancel()
		return written, output.err
	}
	return written, nil
}

func runDriver(ctx context.Context, disk *runDisk, operation Operation) ([]byte, error) {
	if err := disk.validatePath(); err != nil {
		return nil, err
	}
	executable, err := unix.Openat(int(disk.file.Fd()), "driver", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrIO
	}
	driver := os.NewFile(uintptr(executable), "lab-driver")
	defer func() { _ = driver.Close() }()
	stderr, err := disk.create("stderr.log", 0600)
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithTimeout(ctx, MaxRuntime)
	defer cancel()
	var stdout bytes.Buffer
	out := &limitedOutput{writer: &stdout, limit: MaxResultBytes, cancel: cancel}
	errOut := &limitedOutput{writer: stderr, limit: MaxStderrBytes, cancel: cancel}
	command := exec.Command("/proc/self/fd/3", string(operation), filepath.Join(disk.path, "request.json"))
	command.ExtraFiles = []*os.File{driver}
	command.Dir = disk.path
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + disk.path, "TMPDIR=" + disk.path, "LANG=C", "LC_ALL=C"}
	command.Stdout, command.Stderr = out, errOut
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = time.Second
	executionErr := runChildGroup(runCtx, command)
	syncErr, closeErr := stderr.Sync(), stderr.Close()
	if out.err != nil || errOut.err != nil {
		return nil, errors.Join(out.err, errOut.err)
	}
	if syncErr != nil || closeErr != nil {
		return nil, ErrIO
	}
	if executionErr != nil {
		return nil, executionErr
	}
	return stdout.Bytes(), nil
}

func runChildGroup(ctx context.Context, command *exec.Cmd) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return ErrDriver
	}
	exited := make(chan error, 1)
	go func() {
		var info unix.Siginfo
		for {
			err := unix.Waitid(unix.P_PID, command.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
			if !errors.Is(err, unix.EINTR) {
				exited <- err
				return
			}
		}
	}()
	var waitErr error
	select {
	case waitErr = <-exited:
	case <-ctx.Done():
		// The leader has not been reaped, so its PID/group cannot be recycled.
		killErr := unix.Kill(-command.Process.Pid, unix.SIGKILL)
		waitErr = <-exited
		if killErr != nil && !errors.Is(killErr, unix.ESRCH) {
			waitErr = ErrDriver
		}
	}
	if waitErr == nil {
		// Also stop descendants that outlived a normally exiting leader, before
		// Wait reaps it. Never signal a name or a process group after reaping.
		if err := unix.Kill(-command.Process.Pid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
			waitErr = ErrDriver
		}
	} else {
		// If observation failed, do not signal an unproven group. os.Process
		// retains the child's handle; stop that child rather than waiting forever.
		_ = command.Process.Kill()
	}
	commandErr := command.Wait()
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrDriver, err)
	}
	if waitErr != nil || commandErr != nil {
		return ErrDriver
	}
	return nil
}
