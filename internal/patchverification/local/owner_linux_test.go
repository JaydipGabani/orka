package local

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOwnerExclusion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "evidence.db")
	runID := "pv-" + strings.Repeat("a", 64)
	owner, err := AcquireOwner(dbPath, runID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	if second, err := AcquireOwner(dbPath, runID); !errors.Is(err, ErrLiveOwner) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("live owner not excluded: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err := AcquireOwner(dbPath, runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dbPath+".patchverify-locks", runID)); err != nil {
		t.Fatal("lock inode must survive release", err)
	}
}

func TestOwnerRejectsAliases(t *testing.T) {
	directory := t.TempDir()
	runID := "pv-" + strings.Repeat("b", 64)
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "alias.db")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	if owner, err := AcquireOwner(alias, runID); err == nil {
		_ = owner.Close()
		t.Fatal("database symlink accepted")
	}
	if owner, err := AcquireOwner(target, "../../elsewhere"); err == nil {
		_ = owner.Close()
		t.Fatal("invalid run ID accepted")
	}
	hardlink := filepath.Join(directory, "hardlink.db")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if owner, err := AcquireOwner(hardlink, runID); err == nil {
		_ = owner.Close()
		t.Fatal("hardline database accepted")
	}
}

func TestReadRequestRejectsFIFO(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "request.json")
	if err := unix.Mkfifo(filename, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(filename); err == nil {
		t.Fatal("FIFO request accepted")
	}
}
