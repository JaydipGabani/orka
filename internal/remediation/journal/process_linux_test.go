package journal

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCloseReleasesOwnershipWithInheritedDescriptor(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	flags, err := unix.FcntlInt(s.disk.file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("ownership descriptor must be close-on-exec")
	}
	command := processCommand(t, dir, "hold-inherited")
	// Hold the same open file description in a child to deterministically model
	// the fork-to-exec window, before CLOEXEC has closed inherited descriptors.
	command.ExtraFiles = []*os.File{s.disk.file}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stdin.Close(); err != nil {
			t.Error(err)
		}
		if err := command.Wait(); err != nil {
			t.Errorf("inherited-descriptor child failed: %v\n%s", err, stderr.String())
		}
	})
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "journal-result: inherited" {
		t.Fatalf("child did not retain the inherited descriptor: %v", scanner.Err())
	}
	assertOpenError(t, dir, ErrLocked)
	closeStore(t, s)
	replacement := reopen(t, dir)
	if cp := commit(t, replacement, 1, "planned", nil); cp.Revision != 2 {
		t.Fatal("reopened owner did not persist its next revision")
	}
	// Closing the old Store again must not release the new owner's lock.
	closeStore(t, s)
	assertOpenError(t, dir, ErrLocked)
}

func TestCloseReportsUnlockFailureAndClosesDescriptor(t *testing.T) {
	t.Parallel()
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "journal-unlock-failure")
	d := &disk{file: file}
	if err := d.close(); !errors.Is(err, ErrIO) {
		t.Fatalf("unlock failure was not reported: %v", err)
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("descriptor was not closed after unlock failure: %v", err)
	}
}

func TestOwnershipExcludesIndependentOpens(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	assertOpenError(t, dir, ErrLocked)
	if got := runProcess(t, dir, "locked"); got != "locked" {
		t.Fatalf("independent process acquired a live journal: %s", got)
	}
	closeStore(t, s)
	if got := runProcess(t, dir, "commit"); got != "committed" {
		t.Fatalf("Close did not release ownership: %s", got)
	}
	if cp := load(t, reopen(t, dir)); cp.Revision != 2 {
		t.Fatal("independent process commit was not persistent")
	}
}

func TestIndependentProcessesCannotBothCommitSameRevision(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	closeStore(t, s)
	type result struct {
		output []byte
		err    error
	}
	results := make(chan result, 2)
	for range 2 {
		command := processCommand(t, dir, "commit")
		go func() {
			output, err := command.CombinedOutput()
			results <- result{output, err}
		}()
	}
	successes := 0
	for range 2 {
		r := <-results
		if r.err != nil {
			t.Fatalf("child failed: %v\n%s", r.err, r.output)
		}
		switch processResult(t, r.output) {
		case "committed":
			successes++
		case "locked", "conflict":
		default:
			t.Fatal("unexpected child result")
		}
	}
	if successes != 1 {
		t.Fatalf("same revision committed %d times", successes)
	}
	if got := runProcess(t, dir, "commit"); got != "conflict" {
		t.Fatalf("reopened stale revision accepted: %s", got)
	}
	s = reopen(t, dir)
	if cp := load(t, s); cp.Revision != 2 || cp.Phase != "planned" {
		t.Fatal("process exclusion did not preserve the committed state")
	}
}

func TestProcessDeathReleasesOwnership(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	initial := load(t, s)
	closeStore(t, s)
	command := processCommand(t, dir, "hold")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "journal-result: ready" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("child did not obtain ownership: %v, %s", scanner.Err(), stderr.String())
	}
	assertOpenError(t, dir, ErrLocked)
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("terminated child unexpectedly exited successfully")
	}
	s = reopen(t, dir)
	if cp := load(t, s); cp.RunID != initial.RunID || cp.Revision != initial.Revision {
		t.Fatal("process death altered journal identity or revision")
	}
	commit(t, s, 1, "planned", nil)
}

func TestJournalProcessHelper(t *testing.T) {
	mode := os.Getenv("ORKA_JOURNAL_TEST_MODE")
	if mode == "" {
		return
	}
	if mode == "hold-inherited" {
		inherited := os.NewFile(3, "journal-inherited-directory")
		defer func() {
			if err := inherited.Close(); err != nil {
				t.Error(err)
			}
		}()
		if err := privateDirectory(int(inherited.Fd())); err != nil {
			t.Fatal(err)
		}
		fmt.Println("journal-result: inherited")
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			t.Fatal(err)
		}
		return
	}
	s, err := Open(os.Getenv("ORKA_JOURNAL_TEST_DIRECTORY"))
	if errors.Is(err, ErrLocked) {
		fmt.Println("journal-result: locked")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore(t, s)
	switch mode {
	case "locked":
		t.Fatal("opened journal despite expected live owner")
	case "commit":
		_, err := s.Commit(1, "planned", nil)
		if errors.Is(err, ErrConflict) {
			fmt.Println("journal-result: conflict")
		} else if err != nil {
			t.Fatal(err)
		} else {
			fmt.Println("journal-result: committed")
		}
	case "hold":
		fmt.Println("journal-result: ready")
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unsupported process helper mode")
	}
}

func processCommand(t *testing.T, dir, mode string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, executable, "-test.run=^TestJournalProcessHelper$")
	command.Env = append(os.Environ(),
		"ORKA_JOURNAL_TEST_MODE="+mode, "ORKA_JOURNAL_TEST_DIRECTORY="+dir)
	return command
}

func runProcess(t *testing.T, dir, mode string) string {
	t.Helper()
	output, err := processCommand(t, dir, mode).CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, output)
	}
	return processResult(t, output)
}

func processResult(t *testing.T, output []byte) string {
	t.Helper()
	for line := range strings.SplitSeq(string(output), "\n") {
		if result, ok := strings.CutPrefix(line, "journal-result: "); ok {
			return result
		}
	}
	t.Fatalf("missing child result: %s", output)
	return ""
}
