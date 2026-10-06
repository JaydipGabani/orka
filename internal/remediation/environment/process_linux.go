//go:build linux

package environment

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func (a *Adapter) lock(ctx context.Context, name string) (func(), error) {
	unlock, _, err := a.lockFile(ctx, name)
	return unlock, err
}

func (a *Adapter) lockFile(ctx context.Context, name string) (func(), bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, failure(Infrastructure, "operation-cancelled")
	}
	path := filepath.Join(a.config.OutputRoot, name+".lock")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	}
	if err != nil {
		return nil, false, failure(Infrastructure, "operation-lock-unavailable")
	}
	unlock := func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return unlock, created, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			unlock()
			return nil, false, failure(Infrastructure, "operation-lock-unavailable")
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			unlock()
			return nil, false, failure(Infrastructure, "operation-cancelled")
		case <-timer.C:
		}
	}
}

type boundedOutput struct {
	mu       sync.Mutex
	data     []byte
	limit    int64
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if int64(n)+int64(len(b.data)) > b.limit {
		b.overflow = true
		drop := int64(n) + int64(len(b.data)) - b.limit
		if drop >= int64(len(b.data)) {
			p = p[drop-int64(len(b.data)):]
			b.data = b.data[:0]
		} else {
			copy(b.data, b.data[drop:])
			b.data = b.data[:int64(len(b.data))-drop]
		}
	}
	b.data = append(b.data, p...)
	return n, nil
}

func runBuildctl(ctx context.Context, b BuildKitConfig, arguments []string, directory string, limit int64) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	executable, err := os.Lstat(b.Command[0])
	if err != nil || !executable.Mode().IsRegular() || executable.Mode().Perm()&0111 == 0 ||
		executable.Mode().Perm()&0022 != 0 || executable.Size() > 256<<20 {
		return nil, false, failure(NeedsAdapter, "buildctl-prerequisite-missing")
	}
	data, err := readApprovedFile(filepath.Dir(b.Command[0]), filepath.Base(b.Command[0]), 256<<20)
	if err != nil || digest(data) != b.ExecutableDigest {
		return nil, false, failure(NeedsAdapter, "buildctl-executable-mismatch")
	}
	pinned, err := os.Open(b.Command[0])
	if err != nil {
		return nil, false, failure(NeedsAdapter, "buildctl-prerequisite-missing")
	}
	defer func() { _ = pinned.Close() }()
	current, err := pinned.Stat()
	if err != nil || !os.SameFile(executable, current) {
		return nil, false, failure(NeedsAdapter, "buildctl-executable-changed")
	}
	output := &boundedOutput{limit: limit}
	command := exec.CommandContext(ctx, "/proc/self/fd/3", arguments...)
	command.ExtraFiles = []*os.File{pinned}
	command.Dir = directory
	command.Env = []string{
		"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C",
		"HOME=" + filepath.Join(directory, "home"), "TMPDIR=" + filepath.Join(directory, "scratch"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
	}
	command.Stdout, command.Stderr = output, output
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 2 * time.Second
	err = command.Run()
	// A descendant must not outlive buildctl even if it closes the output pipes.
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	if ctx.Err() != nil {
		return output.data, output.overflow, ctx.Err()
	}
	if err != nil {
		return output.data, output.overflow, failure(BuildFailed, "buildctl-failed")
	}
	return output.data, output.overflow, nil
}

func compilerDiagnostics(data []byte) []Diagnostic {
	codes := []struct {
		code     string
		patterns []string
	}{
		{"compiler-syntax", []string{"syntax error", "unexpected token"}},
		{"compiler-type", []string{"undefined:", "cannot use ", "incompatible type", "error:"}},
		{"linker-symbol", []string{"undefined reference", "undefined symbol"}},
		{"dependency-unavailable", []string{"failed to resolve", "failed to fetch", "no such host"}},
		{"patch-apply-failed", []string{"patch failed", "patch does not apply", "hunk #", "malformed patch"}},
	}
	text := strings.ToLower(string(data))
	var result []Diagnostic
	for _, rule := range codes {
		count := 0
		for _, pattern := range rule.patterns {
			count += strings.Count(text, pattern)
		}
		if count > 0 {
			result = append(result, Diagnostic{Code: rule.code, Count: min(count, 100)})
		}
	}
	result = append(result, identifierDiagnostics(data)...)
	return result
}

var compilerIdentifier = regexp.MustCompile(`(?m)(?:^|\s)([A-Za-z0-9_./-]+\.go):([1-9][0-9]{0,6}):([1-9][0-9]{0,4}): undefined: ([A-Za-z_][A-Za-z0-9_]{0,95})\s*$`)

func identifierDiagnostics(data []byte) []Diagnostic {
	var diagnostics []Diagnostic
	for _, match := range compilerIdentifier.FindAllStringSubmatch(string(data), 16) {
		name := match[1]
		if !relativePath(name) || strings.HasPrefix(name, "../") {
			continue
		}
		line, _ := strconv.Atoi(match[2])
		column, _ := strconv.Atoi(match[3])
		diagnostics = append(diagnostics, Diagnostic{Code: "undefined-identifier", Count: 1,
			Path: name, Line: line, Column: column, Identifier: match[4]})
	}
	return diagnostics
}
