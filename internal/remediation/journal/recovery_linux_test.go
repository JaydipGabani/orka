package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRecoveryDiscardsOnlyUnpublishedStaging(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	cp := commit(t, s, 1, "awaiting_task", json.RawMessage(`{"taskID":"synthetic-task"}`))
	before := names(t, dir)
	pending := filepath.Join(dir, pendingPrefix+strings.Repeat("a", 32))
	write(t, pending, []byte(`{"incomplete":`))
	closeStore(t, s)
	s = reopen(t, dir)
	if !reflect.DeepEqual(load(t, s), cp) || !slices.Equal(names(t, dir), before) {
		t.Fatal("recovery changed the last checkpoint or retained unpublished staging")
	}
	if next := commit(t, s, 2, "waiting_for_evidence", nil); next.Revision != 3 {
		t.Fatal("recovered journal could not make progress")
	}

	empty := filepath.Join(t.TempDir(), "incomplete")
	if err := os.Mkdir(empty, 0700); err != nil {
		t.Fatal(err)
	}
	pending = filepath.Join(empty, pendingPrefix+strings.Repeat("b", 32))
	write(t, pending, []byte("incomplete"))
	assertOpenError(t, empty, ErrCorrupt)
	if _, err := os.Stat(pending); err != nil {
		t.Fatal("invalid journal was modified during failed recovery")
	}
}

func TestCorruptPublishedCheckpointsNeverFallBack(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, string, Checkpoint)
	}{
		{"truncated-latest", func(t *testing.T, dir string, cp Checkpoint) {
			write(t, latestFile(t, dir), []byte(`{"version":`))
		}},
		{"empty-latest", func(t *testing.T, dir string, cp Checkpoint) {
			write(t, latestFile(t, dir), nil)
		}},
		{"wrong-content-hash", func(t *testing.T, dir string, cp Checkpoint) {
			cp.Phase = "other_phase"
			data, err := json.Marshal(cp)
			if err != nil {
				t.Fatal(err)
			}
			write(t, latestFile(t, dir), data)
		}},
		{"foreign-input", func(t *testing.T, dir string, cp Checkpoint) {
			cp.InputDigest = digest([]byte("another synthetic input"))
			replaceCheckpoint(t, dir, cp)
		}},
		{"foreign-run", func(t *testing.T, dir string, cp Checkpoint) {
			cp.RunID = "rem-" + strings.Repeat("b", 32)
			replaceCheckpoint(t, dir, cp)
		}},
		{"unsupported-version", func(t *testing.T, dir string, cp Checkpoint) {
			cp.Version++
			replaceCheckpoint(t, dir, cp)
		}},
		{"missing-time", func(t *testing.T, dir string, cp Checkpoint) {
			cp.UpdatedAt = time.Time{}
			replaceCheckpoint(t, dir, cp)
		}},
		{"empty-phase", func(t *testing.T, dir string, cp Checkpoint) {
			cp.Phase = ""
			replaceCheckpoint(t, dir, cp)
		}},
		{"initial-phase", func(t *testing.T, dir string, cp Checkpoint) {
			for _, name := range names(t, dir) {
				seq, _, _, ok := splitRecordName(name, checkpointPrefix)
				if ok && seq == 1 {
					if err := os.Remove(filepath.Join(dir, name)); err != nil {
						t.Fatal(err)
					}
				}
			}
			cp.Revision, cp.Phase, cp.Data = 1, "not_ingested", nil
			addCheckpoint(t, dir, cp)
		}},
		{"duplicate-revision", func(t *testing.T, dir string, cp Checkpoint) {
			cp.Phase = "duplicate"
			addCheckpoint(t, dir, cp)
		}},
		{"gap", func(t *testing.T, dir string, cp Checkpoint) {
			if err := os.Remove(latestFile(t, dir)); err != nil {
				t.Fatal(err)
			}
			cp.Revision++
			addCheckpoint(t, dir, cp)
		}},
		{"missing-initial", func(t *testing.T, dir string, cp Checkpoint) {
			for _, name := range names(t, dir) {
				if seq, _, _, ok := splitRecordName(name, checkpointPrefix); ok && seq == 1 {
					if err := os.Remove(filepath.Join(dir, name)); err != nil {
						t.Fatal(err)
					}
				}
			}
		}},
		{"unknown-field", func(t *testing.T, dir string, cp Checkpoint) {
			replaceJSON(t, dir, cp, func(data []byte) []byte {
				return append(data[:len(data)-1], []byte(`,"unexpected":"synthetic"}`)...)
			})
		}},
		{"duplicate-field", func(t *testing.T, dir string, cp Checkpoint) {
			replaceJSON(t, dir, cp, func(data []byte) []byte {
				return append(data[:len(data)-1], []byte(`,"phase":"duplicate"}`)...)
			})
		}},
		{"trailing-whitespace", func(t *testing.T, dir string, cp Checkpoint) {
			replaceJSON(t, dir, cp, func(data []byte) []byte { return append(data, '\n') })
		}},
		{"invalid-utf8-data", func(t *testing.T, dir string, cp Checkpoint) {
			cp.Data = json.RawMessage{'"', 0xff, '"'}
			replaceCheckpoint(t, dir, cp)
		}},
		{"unknown-latest-entry", func(t *testing.T, dir string, cp Checkpoint) {
			write(t, filepath.Join(dir, "latest"), []byte("incomplete"))
		}},
		{"malformed-staging-name", func(t *testing.T, dir string, cp Checkpoint) {
			write(t, filepath.Join(dir, pendingPrefix+"not-a-nonce"), nil)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, dir := newStore(t)
			cp := commit(t, s, 1, "awaiting_task", nil)
			closeStore(t, s)
			tc.mutate(t, dir, cp)
			assertOpenError(t, dir, ErrCorrupt)
			// A failed Open must release its directory flock.
			assertOpenError(t, dir, ErrCorrupt)
		})
	}
}

func TestLoadRevalidatesPublishedState(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	commit(t, s, 1, "awaiting_task", nil)
	write(t, latestFile(t, dir), []byte("truncated"))
	if _, err := s.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load trusted cached state: %v", err)
	}
	if _, err := s.Commit(2, "next", nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Commit bypassed corruption: %v", err)
	}
	if _, err := s.PutArtifact("next", nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("PutArtifact bypassed corruption: %v", err)
	}
}

func TestCorruptArtifactsAndOversizedFiles(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"truncated", "changed", "oversized", "duplicate", "gap"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			s, dir := newStore(t)
			content := []byte("synthetic artifact")
			ref, err := s.PutArtifact("proof", content)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, recordName(artifactPrefix, 1, ref.Digest, "-proof"))
			wantErr := ErrCorrupt
			switch kind {
			case "truncated":
				write(t, file, content[:2])
			case "changed":
				write(t, file, bytes.Repeat([]byte{'x'}, len(content)))
			case "oversized":
				if err := os.Truncate(file, MaxArtifactBytes+1); err != nil {
					t.Fatal(err)
				}
				wantErr = ErrTooLarge
			case "duplicate":
				write(t, filepath.Join(dir, recordName(artifactPrefix, 2, ref.Digest, "-proof")), content)
			case "gap":
				if err := os.Rename(file, filepath.Join(dir, recordName(artifactPrefix, 2, ref.Digest, "-proof"))); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.ReadArtifact(ref); !errors.Is(err, wantErr) {
				t.Fatalf("bad artifact returned success: %v", err)
			}
			if _, err := s.PutArtifact(ref.Name, content); !errors.Is(err, wantErr) {
				t.Fatalf("replay bypassed artifact corruption: %v", err)
			}
			closeStore(t, s)
			assertOpenError(t, dir, wantErr)
		})
	}
	for _, kind := range []string{"checkpoint", "staging"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			s, dir := newStore(t)
			file, limit := latestFile(t, dir), MaxCheckpointBytes
			if kind == "staging" {
				file, limit = filepath.Join(dir, pendingPrefix+strings.Repeat("a", 32)), MaxArtifactBytes
				write(t, file, nil)
			}
			if err := os.Truncate(file, int64(limit)+1); err != nil {
				t.Fatal(err)
			}
			closeStore(t, s)
			assertOpenError(t, dir, ErrTooLarge)
		})
	}
}

func TestPathAndPermissionRejection(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	for _, path := range []string{"relative", "/", parent + "//journal", parent + "/./journal",
		parent + "/child/../journal", parent + "/journal/", parent + "/bad\x00path"} {
		if s, err := Create(path, digest(nil)); !errors.Is(err, ErrUnsafePath) {
			if s != nil {
				closeStore(t, s)
			}
			t.Fatalf("noncanonical path accepted: %v", err)
		}
		assertOpenError(t, path, ErrUnsafePath)
	}
	s, dir := newStore(t)
	closeStore(t, s)
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	assertOpenError(t, alias, ErrUnsafePath)
	if other, err := Create(filepath.Join(alias, "child"), digest(nil)); !errors.Is(err, ErrUnsafePath) {
		if other != nil {
			closeStore(t, other)
		}
		t.Fatalf("symlink ancestor accepted: %v", err)
	}
	ancestorAlias := filepath.Join(parent, "ancestor")
	if err := os.Symlink(filepath.Dir(dir), ancestorAlias); err != nil {
		t.Fatal(err)
	}
	assertOpenError(t, filepath.Join(ancestorAlias, filepath.Base(dir)), ErrUnsafePath)
	for _, mode := range []fs.FileMode{0755, 0710, 0770, 0500, 0700 | fs.ModeSetgid, 0700 | fs.ModeSticky} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		assertOpenError(t, dir, ErrUnsafePath)
		assertMode(t, dir, mode.Perm())
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s = reopen(t, dir)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("live directory permission drift accepted: %v", err)
	}
}

func TestEntryAliasesPermissionsAndTypes(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "0644", "0400", "setuid", "staging-symlink"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			s, dir := newStore(t)
			file := latestFile(t, dir)
			closeStore(t, s)
			switch kind {
			case "symlink", "staging-symlink":
				target := filepath.Join(t.TempDir(), "target")
				write(t, target, []byte("synthetic"))
				if kind == "symlink" {
					if err := os.Remove(file); err != nil {
						t.Fatal(err)
					}
				} else {
					file = filepath.Join(dir, pendingPrefix+strings.Repeat("a", 32))
				}
				if err := os.Symlink(target, file); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(file, filepath.Join(t.TempDir(), "alias")); err != nil {
					t.Fatal(err)
				}
			case "fifo", "directory":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "fifo" {
					err = unix.Mkfifo(file, 0600)
				} else {
					err = os.Mkdir(file, 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
			default:
				mode := fs.FileMode(0644)
				switch kind {
				case "0400":
					mode = 0400
				case "setuid":
					mode = 0600 | fs.ModeSetuid
				}
				if err := os.Chmod(file, mode); err != nil {
					t.Fatal(err)
				}
			}
			assertOpenError(t, dir, ErrUnsafePath)
		})
	}
}

func TestLiveDirectoryReplacementIsRejected(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"symlink", "new-directory"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			s, dir := newStore(t)
			moved := dir + "-moved"
			if err := os.Rename(dir, moved); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "symlink" {
				err = os.Symlink(moved, dir)
			} else {
				err = os.Mkdir(dir, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Load(); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("directory replacement was accepted: %v", err)
			}
			if _, err := s.Commit(1, "planned", nil); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("write followed a replacement: %v", err)
			}
		})
	}
}

func TestOwnershipChecks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing fixture ownership requires root")
	}
	for _, kind := range []string{"directory", "file"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := newStore(t)
			path := dir
			if kind == "file" {
				path = latestFile(t, dir)
			}
			closeStore(t, s)
			if err := os.Chown(path, 1, -1); err != nil {
				t.Fatal(err)
			}
			assertOpenError(t, dir, ErrUnsafePath)
		})
	}
}

func TestArtifactNamesAndRedactedErrors(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	for _, name := range []string{"", ".", "..", "../outside", "/absolute", "a/b", `a\b`,
		"a\x00b", ".hidden", strings.Repeat("a", maxNameBytes+1), "a b", "non-ascii-\u00e9"} {
		if _, err := s.PutArtifact(name, nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe artifact name accepted: %v", err)
		}
		if _, err := s.ReadArtifact(Artifact{Name: name, Digest: digest(nil)}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe reference name accepted: %v", err)
		}
	}
	if _, err := s.PutArtifact(strings.Repeat("a", maxNameBytes), nil); err != nil {
		t.Fatalf("exact name limit rejected: %v", err)
	}
	marker := "synthetic-private-marker"
	for _, operation := range []func() error{
		func() error { _, err := Create(filepath.Join(dir, marker), marker); return err },
		func() error { _, err := Open(filepath.Join(dir, marker)); return err },
		func() error { _, err := s.Commit(1, "planned", json.RawMessage(marker)); return err },
		func() error { _, err := s.PutArtifact("../"+marker, []byte(marker)); return err },
		func() error { _, err := s.ReadArtifact(Artifact{Name: "valid", Digest: marker}); return err },
	} {
		if err := operation(); err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), dir) {
			t.Fatalf("error absent or includes private input: %v", err)
		}
	}
}

func TestPublishNeverOverwritesAndCleansStaging(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	name := filepath.Base(latestFile(t, dir))
	before, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.disk.publish(name, []byte("conflict")); !errors.Is(err, ErrConflict) {
		t.Fatalf("atomic publisher overwrote a file: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || !bytes.Equal(before, after) || len(names(t, dir)) != 1 {
		t.Fatal("failed publication changed durable content or retained staging")
	}
}

func TestWriteFailureRequiresReopen(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"checkpoint", "artifact"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			s, dir := newStore(t)
			original := s.disk.file
			// O_PATH permits descriptor-relative publication but rejects fsync.
			// Keep the original descriptor open so its ownership lock still holds.
			fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			fault := os.NewFile(uintptr(fd), "journal-sync-failure")
			s.disk.file = fault
			restore := func() {
				if fault != nil {
					s.disk.file = original
					if err := fault.Close(); err != nil {
						t.Error(err)
					}
					fault = nil
				}
			}
			defer restore()
			if operation == "checkpoint" {
				_, err = s.Commit(1, "planned", nil)
			} else {
				_, err = s.PutArtifact("proof", []byte("synthetic artifact"))
			}
			if !errors.Is(err, ErrIO) {
				t.Fatalf("publication reported success after failed fsync: %v", err)
			}
			if _, err := s.Load(); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("uncertain write did not require recovery: %v", err)
			}
			if _, err := s.Commit(1, "planned", nil); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("uncertain write allowed another commit: %v", err)
			}
			restore()
			closeStore(t, s)
			s = reopen(t, dir)
			if operation == "checkpoint" {
				if cp := load(t, s); cp.Revision != 2 || cp.Phase != "planned" {
					t.Fatal("recovery lost the complete checkpoint published before failed fsync")
				}
				if _, err := s.Commit(1, "planned", nil); !errors.Is(err, ErrConflict) {
					t.Fatalf("ambiguous publication was replayed: %v", err)
				}
			} else {
				ref := Artifact{Name: "proof", Digest: digest([]byte("synthetic artifact")), Bytes: len("synthetic artifact")}
				if content, err := s.ReadArtifact(ref); err != nil || string(content) != "synthetic artifact" {
					t.Fatalf("recovery lost the complete artifact published before failed fsync: %v", err)
				}
			}
			commit(t, s, load(t, s).Revision, "next", nil)
		})
	}
}

func assertOpenError(t *testing.T, dir string, want error) {
	t.Helper()
	s, err := Open(dir)
	if s != nil {
		closeStore(t, s)
	}
	if !errors.Is(err, want) {
		t.Fatalf("Open error = %v, want %v", err, want)
	}
}

func latestFile(t *testing.T, dir string) string {
	t.Helper()
	var latest string
	for _, name := range names(t, dir) {
		if strings.HasPrefix(name, checkpointPrefix) {
			latest = name
		}
	}
	if latest == "" {
		t.Fatal("test journal has no checkpoint")
	}
	return filepath.Join(dir, latest)
}

func addCheckpoint(t *testing.T, dir string, cp Checkpoint) {
	t.Helper()
	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, recordName(checkpointPrefix, cp.Revision, digest(data), ".json")), data)
}

func replaceCheckpoint(t *testing.T, dir string, cp Checkpoint) {
	t.Helper()
	if err := os.Remove(latestFile(t, dir)); err != nil {
		t.Fatal(err)
	}
	addCheckpoint(t, dir, cp)
}

func replaceJSON(t *testing.T, dir string, cp Checkpoint, mutate func([]byte) []byte) {
	t.Helper()
	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(latestFile(t, dir)); err != nil {
		t.Fatal(err)
	}
	data = mutate(data)
	write(t, filepath.Join(dir, recordName(checkpointPrefix, cp.Revision, digest(data), ".json")), data)
}
