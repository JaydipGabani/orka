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
	"sync"
	"testing"
	"time"
)

func TestCreateReopenPreservesStateAndArtifacts(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	initial := load(t, s)
	if initial.Version != 1 || initial.Revision != 1 || initial.Phase != "ingested" ||
		initial.InputDigest != digest([]byte("synthetic input")) || initial.Data != nil ||
		initial.UpdatedAt.IsZero() || initial.UpdatedAt.Location() != time.UTC ||
		!strings.HasPrefix(initial.RunID, "rem-") || !validHex(initial.RunID[4:], 32) {
		t.Fatalf("invalid initial checkpoint: %+v", initial)
	}
	assertMode(t, dir, 0700)
	closeStore(t, s)
	s = reopen(t, dir)
	if got := load(t, s); !reflect.DeepEqual(got, initial) {
		t.Fatal("initial checkpoint changed on reopen")
	}
	content := []byte("synthetic artifact\n")
	ref, err := s.PutArtifact("candidate.patch", content)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Name != "candidate.patch" || ref.Digest != digest(content) || ref.Bytes != len(content) {
		t.Fatalf("invalid artifact reference: %+v", ref)
	}
	cp := commit(t, s, initial.Revision, "verification_pending",
		json.RawMessage(`{ "taskID": "synthetic-task", "artifactDigest": "`+ref.Digest+`" }`))
	if cp.Revision != 2 || cp.Version != initial.Version || cp.RunID != initial.RunID ||
		cp.InputDigest != initial.InputDigest || cp.Phase != "verification_pending" {
		t.Fatal("commit changed immutable identity or failed to advance")
	}
	want := cp
	want.Data = bytes.Clone(cp.Data)
	cp.Data[0] = '!'
	got := load(t, s)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("returned checkpoint aliases stored state or did not match persisted JSON")
	}
	got.Data[0] = '?'
	closeStore(t, s)
	s = reopen(t, dir)
	if got := load(t, s); !reflect.DeepEqual(got, want) {
		t.Fatal("committed checkpoint changed on reopen")
	}
	read, err := s.ReadArtifact(ref)
	if err != nil || !bytes.Equal(read, content) {
		t.Fatalf("artifact did not survive reopen: %v", err)
	}
	read[0] = '!'
	read, err = s.ReadArtifact(ref)
	if err != nil || !bytes.Equal(read, content) {
		t.Fatal("returned artifact aliases stored content")
	}
	for _, name := range names(t, dir) {
		assertMode(t, filepath.Join(dir, name), 0600)
	}
}

func TestCreateNeverAdoptsExistingDirectory(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	initial := load(t, s)
	for _, input := range []string{initial.InputDigest, digest([]byte("different input"))} {
		other, err := Create(dir, input)
		if other != nil {
			closeStore(t, other)
		}
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("existing journal was adopted: %v", err)
		}
	}
	if !reflect.DeepEqual(load(t, s), initial) {
		t.Fatal("existing state was changed")
	}
	empty := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(empty, 0700); err != nil {
		t.Fatal(err)
	}
	if other, err := Create(empty, initial.InputDigest); !errors.Is(err, ErrConflict) {
		if other != nil {
			closeStore(t, other)
		}
		t.Fatalf("existing empty directory was adopted: %v", err)
	}
	if len(names(t, empty)) != 0 {
		t.Fatal("existing directory was modified")
	}
}

func TestCommitRevisionExclusion(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	if _, err := s.Commit(0, "planned", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("zero revision accepted: %v", err)
	}
	if _, err := s.Commit(2, "planned", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("future revision accepted: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := s.Commit(1, "planned", nil)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	var successes, conflicts int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected commit error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 || load(t, s).Revision != 2 {
		t.Fatalf("revision exclusion failed: %d successes, %d conflicts", successes, conflicts)
	}
	closeStore(t, s)
	s = reopen(t, dir)
	if _, err := s.Commit(1, "planned", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision after reopen accepted: %v", err)
	}
	if _, err := s.Commit(2, "next_step", json.RawMessage(`null`)); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactReplayAndReferenceValidation(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	content := []byte("synthetic artifact")
	ref, err := s.PutArtifact("result.json", content)
	if err != nil {
		t.Fatal(err)
	}
	before := names(t, dir)
	file := filepath.Join(dir, recordName(artifactPrefix, 1, ref.Digest, "-"+ref.Name))
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := s.PutArtifact(ref.Name, bytes.Clone(content))
	if err != nil || replayed != ref || !slices.Equal(before, names(t, dir)) {
		t.Fatalf("exact replay was not idempotent: %v", err)
	}
	after, err := os.Stat(file)
	if err != nil || !os.SameFile(info, after) || info.ModTime() != after.ModTime() {
		t.Fatal("replay replaced or rewrote an immutable artifact")
	}
	if _, err := s.PutArtifact(ref.Name, []byte("different content")); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting artifact write accepted: %v", err)
	}
	if !slices.Equal(before, names(t, dir)) {
		t.Fatal("conflicting write published a file")
	}
	bad := ref
	bad.Bytes++
	if _, err := s.ReadArtifact(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong artifact length accepted: %v", err)
	}
	bad = ref
	bad.Digest = digest([]byte("different content"))
	if _, err := s.ReadArtifact(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong digest accepted: %v", err)
	}
	bad = ref
	bad.Name = "missing"
	if _, err := s.ReadArtifact(bad); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing artifact returned success: %v", err)
	}
	empty, err := s.PutArtifact("empty", nil)
	if err != nil || empty.Bytes != 0 || empty.Digest != digest(nil) {
		t.Fatalf("empty artifact rejected: %v", err)
	}
	if content, err := s.ReadArtifact(empty); err != nil || len(content) != 0 {
		t.Fatalf("empty artifact read failed: %v", err)
	}
	other, err := s.PutArtifact("another-name", content)
	if err != nil || other.Digest != ref.Digest || other.Name == ref.Name {
		t.Fatalf("independent artifact name failed: %v", err)
	}
}

func TestInvalidInputDoesNotAdvanceState(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"", strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 63), "sha512:" + strings.Repeat("a", 64)} {
		dir := filepath.Join(t.TempDir(), "invalid")
		if s, err := Create(dir, input); !errors.Is(err, ErrInvalid) {
			if s != nil {
				closeStore(t, s)
			}
			t.Fatalf("invalid digest accepted: %v", err)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("invalid input created a directory")
		}
	}
	s, _ := newStore(t)
	for _, tc := range []struct {
		phase string
		data  json.RawMessage
	}{
		{phase: ""}, {phase: " "}, {phase: strings.Repeat("x", 129)}, {phase: "\xff"},
		{phase: "planned", data: json.RawMessage{}},
		{phase: "planned", data: json.RawMessage(`{"incomplete":`)},
		{phase: "planned", data: json.RawMessage(`{} {}`)},
		{phase: "planned", data: json.RawMessage{'"', 0xff, '"'}},
	} {
		if _, err := s.Commit(1, tc.phase, tc.data); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid phase/data accepted: %v", err)
		}
		if load(t, s).Revision != 1 {
			t.Fatal("invalid commit advanced the revision")
		}
	}
	commit(t, s, 1, "planned", json.RawMessage(`[]`))
}

func TestRunIDsAreIndependentOfInput(t *testing.T) {
	t.Parallel()
	first, _ := newStore(t)
	second, _ := newStore(t)
	if load(t, first).RunID == load(t, second).RunID {
		t.Fatal("independent journals reused an input-derived run ID")
	}
}

func TestCloseAndZeroStore(t *testing.T) {
	t.Parallel()
	s, dir := newStore(t)
	closeStore(t, s)
	closeStore(t, s)
	for _, store := range []*Store{s, {}, nil} {
		if _, err := store.Load(); !errors.Is(err, ErrClosed) {
			t.Fatalf("closed Load: %v", err)
		}
		if _, err := store.Commit(1, "planned", nil); !errors.Is(err, ErrClosed) {
			t.Fatalf("closed Commit: %v", err)
		}
		if _, err := store.PutArtifact("name", nil); !errors.Is(err, ErrClosed) {
			t.Fatalf("closed PutArtifact: %v", err)
		}
		if _, err := store.ReadArtifact(Artifact{Name: "name", Digest: digest(nil)}); !errors.Is(err, ErrClosed) {
			t.Fatalf("closed ReadArtifact: %v", err)
		}
		closeStore(t, store)
	}
	reopen(t, dir)
}

func TestSizeBoundaries(t *testing.T) {
	t.Run("artifact", func(t *testing.T) {
		s, _ := newStore(t)
		content := bytes.Repeat([]byte{'a'}, MaxArtifactBytes)
		ref, err := s.PutArtifact("at-limit", content)
		if err != nil || ref.Bytes != MaxArtifactBytes {
			t.Fatalf("exact artifact limit rejected: %v", err)
		}
		got, err := s.ReadArtifact(ref)
		if err != nil || !bytes.Equal(content, got) {
			t.Fatalf("artifact at limit was truncated: %v", err)
		}
		if _, err := s.PutArtifact("over-limit", append(content, 'b')); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("oversized artifact accepted: %v", err)
		}
		ref.Bytes = MaxArtifactBytes + 1
		if _, err := s.ReadArtifact(ref); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("oversized reference accepted: %v", err)
		}
		ref.Bytes = -1
		if _, err := s.ReadArtifact(ref); !errors.Is(err, ErrInvalid) {
			t.Fatalf("negative reference size accepted: %v", err)
		}
	})
	t.Run("encoded-checkpoint", func(t *testing.T) {
		s, dir := newStore(t)
		cp := load(t, s)
		cp.Revision, cp.Phase = 2, "planned"
		cp.UpdatedAt = time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
		cp.Data = json.RawMessage(`""`)
		base, _, err := encodeCheckpoint(cp)
		if err != nil {
			t.Fatal(err)
		}
		fill := MaxCheckpointBytes - len(base)
		for _, delta := range []int{-1, 0, 1} {
			cp.Data = json.RawMessage(`"` + strings.Repeat("a", fill+delta) + `"`)
			encoded, _, err := encodeCheckpoint(cp)
			if delta > 0 {
				if !errors.Is(err, ErrTooLarge) {
					t.Fatalf("oversized encoded checkpoint accepted: %v", err)
				}
				continue
			}
			if err != nil || len(encoded) != MaxCheckpointBytes+delta {
				t.Fatalf("encoded checkpoint boundary failed: %v, length %d", err, len(encoded))
			}
		}
		cp.Data = json.RawMessage(`"` + strings.Repeat("a", fill) + `"`)
		encoded, _, err := encodeCheckpoint(cp)
		if err != nil {
			t.Fatal(err)
		}
		closeStore(t, s)
		write(t, filepath.Join(dir, recordName(checkpointPrefix, 2, digest(encoded), ".json")), encoded)
		s = reopen(t, dir)
		if got := load(t, s); !reflect.DeepEqual(got, cp) {
			t.Fatal("checkpoint at exact encoded limit was not recovered intact")
		}
		committed := commit(t, s, 2, "planned", cp.Data)
		persisted, err := os.ReadFile(filepath.Join(dir, recordName(checkpointPrefix, 3, s.currentHash, ".json")))
		if err != nil || len(persisted) > MaxCheckpointBytes || !bytes.Equal(committed.Data, cp.Data) {
			t.Fatalf("near-limit commit was truncated or oversized: %v", err)
		}
		for _, length := range []int{MaxCheckpointBytes, MaxCheckpointBytes + 1} {
			oversized := json.RawMessage(`"` + strings.Repeat("b", length-2) + `"`)
			if _, err := s.Commit(3, "planned", oversized); !errors.Is(err, ErrTooLarge) {
				t.Fatalf("oversized checkpoint committed: %v", err)
			}
		}
		if load(t, s).Revision != 3 {
			t.Fatal("oversized commit changed state")
		}
	})
}

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "journal")
	s, err := Create(dir, digest([]byte("synthetic input")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeStore(t, s) })
	return s, dir
}

func reopen(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeStore(t, s) })
	return s
}

func closeStore(t *testing.T, s *Store) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Error(err)
	}
}

func load(t *testing.T, s *Store) Checkpoint {
	t.Helper()
	cp, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func commit(t *testing.T, s *Store, revision uint64, phase string, data json.RawMessage) Checkpoint {
	t.Helper()
	cp, err := s.Commit(revision, phase, data)
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]string, 0, len(entries))
	for _, e := range entries {
		result = append(result, e.Name())
	}
	return result
}

func write(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func assertMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("permissions = %o, want %o", info.Mode().Perm(), want)
	}
}
