package journal

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// MaxCheckpointBytes includes the entire encoded Checkpoint, not just Data.
	MaxCheckpointBytes = 1 << 20
	MaxArtifactBytes   = 32 << 20
	maxNameBytes       = 96
	checkpointPrefix   = "checkpoint-"
	artifactPrefix     = "artifact-"
	pendingPrefix      = ".pending-"
)

var (
	ErrInvalid          = errors.New("journal: invalid input")
	ErrUnsafePath       = errors.New("journal: unsafe path, ownership, or permissions")
	ErrLocked           = errors.New("journal: another store holds the ownership lock")
	ErrConflict         = errors.New("journal: conflicting state")
	ErrCorrupt          = errors.New("journal: corrupt published state")
	ErrTooLarge         = errors.New("journal: size limit exceeded")
	ErrClosed           = errors.New("journal: store is closed")
	ErrRecoveryRequired = errors.New("journal: close and reopen after a write failure")
	ErrIO               = errors.New("journal: filesystem operation failed")
	ErrUnsupported      = errors.New("journal: Linux is required")
)

type Checkpoint struct {
	Version     int             `json:"version"`
	RunID       string          `json:"runID"`
	Revision    uint64          `json:"revision"`
	Phase       string          `json:"phase"`
	InputDigest string          `json:"inputDigest"`
	UpdatedAt   time.Time       `json:"updatedAt"`
	Data        json.RawMessage `json:"data,omitempty"`
}

type Artifact struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Bytes  int    `json:"bytes"`
}

// Store owns one journal exclusively. Do not copy a Store; use its pointer.
type Store struct {
	mu          sync.Mutex
	disk        *disk
	current     Checkpoint
	currentHash string
	failed      bool
	closeErr    error
}

type disk struct {
	path string
	file *os.File
}

type entry struct {
	name string
	size int64
}

type storedArtifact struct {
	ref      Artifact
	filename string
}

type snapshot struct {
	checkpoint Checkpoint
	hash       string
	artifacts  map[string]storedArtifact
	pending    []string
}

// Create creates a new private journal without creating ancestors or replacing
// an existing directory. inputDigest must be a canonical SHA-256 digest.
func Create(dir, inputDigest string) (*Store, error) {
	if !validDigest(inputDigest) {
		return nil, fmt.Errorf("%w: canonical SHA-256 input digest required", ErrInvalid)
	}
	id, err := randomHex()
	if err != nil {
		return nil, err
	}
	d, err := openDisk(dir, true)
	if err != nil {
		return nil, err
	}
	cp := Checkpoint{
		Version: 1, RunID: "rem-" + id, Revision: 1, Phase: "ingested",
		InputDigest: inputDigest, UpdatedAt: time.Now().UTC(),
	}
	content, cp, err := encodeCheckpoint(cp)
	if err == nil {
		err = d.publish(recordName(checkpointPrefix, cp.Revision, digest(content), ".json"), content)
	}
	if err != nil {
		return nil, errors.Join(err, d.close())
	}
	return &Store{disk: d, current: cp, currentHash: digest(content)}, nil
}

// Open exclusively opens and validates an existing journal. It does not infer
// execution outcomes or replay an interrupted coordination step.
func Open(dir string) (*Store, error) {
	d, err := openDisk(dir, false)
	if err != nil {
		return nil, err
	}
	s := &Store{disk: d}
	state, err := s.reload()
	if err == nil {
		err = d.discardPending(state.pending)
	}
	if err != nil {
		return nil, errors.Join(err, d.close())
	}
	s.current, s.currentHash = state.checkpoint, state.hash
	return s, nil
}

// Load revalidates published state and returns a detached copy of the latest
// checkpoint. Callers must compare InputDigest before resuming another input.
func (s *Store) Load() (Checkpoint, error) {
	if s == nil {
		return Checkpoint{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.reload()
	if err != nil {
		return Checkpoint{}, err
	}
	return state.checkpoint, nil
}

// Commit publishes exactly one next revision. Data must be nil or valid UTF-8 JSON.
// Phase is a nonblank UTF-8 label of at most 128 bytes, without workflow-specific
// interpretation. The returned Data is the JSON representation actually stored.
func (s *Store) Commit(expectedRevision uint64, phase string, data json.RawMessage) (Checkpoint, error) {
	if s == nil {
		return Checkpoint{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.reload()
	if err != nil {
		return Checkpoint{}, err
	}
	if expectedRevision != state.checkpoint.Revision || expectedRevision == ^uint64(0) {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint revision", ErrConflict)
	}
	if len(data) > MaxCheckpointBytes {
		return Checkpoint{}, ErrTooLarge
	}
	if !validPhase(phase) || (data != nil && (!utf8.Valid(data) || !json.Valid(data))) {
		return Checkpoint{}, fmt.Errorf("%w: phase or checkpoint data", ErrInvalid)
	}
	cp := state.checkpoint
	cp.Revision++
	cp.Phase, cp.Data, cp.UpdatedAt = phase, data, time.Now().UTC()
	content, cp, err := encodeCheckpoint(cp)
	if err != nil {
		return Checkpoint{}, err
	}
	hash := digest(content)
	if err := s.disk.publish(recordName(checkpointPrefix, cp.Revision, hash, ".json"), content); err != nil {
		s.failed = true
		return Checkpoint{}, err
	}
	s.current, s.currentHash = cp, hash
	// The caller must not be able to mutate the store's identity snapshot.
	cp.Data = bytes.Clone(cp.Data)
	return cp, nil
}

// PutArtifact stores immutable content under a single-component ASCII name
// (1-96 bytes, beginning with an alphanumeric, then alphanumerics, '.', '_' or
// '-'). An exact name/content replay is idempotent; a conflicting write fails.
func (s *Store) PutArtifact(name string, content []byte) (Artifact, error) {
	if s == nil {
		return Artifact{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validName(name) {
		return Artifact{}, fmt.Errorf("%w: artifact name", ErrInvalid)
	}
	if len(content) > MaxArtifactBytes {
		return Artifact{}, ErrTooLarge
	}
	state, err := s.reload()
	if err != nil {
		return Artifact{}, err
	}
	ref := Artifact{Name: name, Digest: digest(content), Bytes: len(content)}
	if existing, ok := state.artifacts[name]; ok {
		if existing.ref != ref {
			return Artifact{}, fmt.Errorf("%w: artifact content", ErrConflict)
		}
		stored, err := s.disk.read(existing.filename, MaxArtifactBytes)
		if err != nil {
			return Artifact{}, err
		}
		if !bytes.Equal(stored, content) {
			return Artifact{}, fmt.Errorf("%w: artifact content", ErrConflict)
		}
		return existing.ref, nil
	}
	filename := recordName(artifactPrefix, uint64(len(state.artifacts))+1, ref.Digest, "-"+name)
	if err := s.disk.publish(filename, content); err != nil {
		s.failed = true
		return Artifact{}, err
	}
	return ref, nil
}

// ReadArtifact verifies the name, digest and exact length before returning
// content. A reference is not permission to read arbitrary filesystem paths.
func (s *Store) ReadArtifact(ref Artifact) ([]byte, error) {
	if s == nil {
		return nil, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validName(ref.Name) || !validDigest(ref.Digest) || ref.Bytes < 0 {
		return nil, fmt.Errorf("%w: artifact reference", ErrInvalid)
	}
	if ref.Bytes > MaxArtifactBytes {
		return nil, ErrTooLarge
	}
	state, err := s.reload()
	if err != nil {
		return nil, err
	}
	existing, ok := state.artifacts[ref.Name]
	if !ok {
		return nil, fmt.Errorf("%w: journal artifact", fs.ErrNotExist)
	}
	if existing.ref != ref {
		return nil, fmt.Errorf("%w: artifact reference", ErrConflict)
	}
	content, err := s.disk.read(existing.filename, MaxArtifactBytes)
	if err != nil {
		return nil, err
	}
	if len(content) != ref.Bytes || digest(content) != ref.Digest {
		return nil, fmt.Errorf("%w: artifact content", ErrCorrupt)
	}
	return content, nil
}

// Close releases ownership. It is safe to call more than once.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disk != nil {
		s.closeErr = s.disk.close()
		s.disk = nil
	}
	return s.closeErr
}

func (s *Store) reload() (snapshot, error) {
	if s.disk == nil {
		return snapshot{}, ErrClosed
	}
	if s.failed {
		return snapshot{}, ErrRecoveryRequired
	}
	state, err := s.disk.scan()
	if err != nil {
		return snapshot{}, err
	}
	if s.current.Version != 0 && (state.checkpoint.Revision != s.current.Revision ||
		state.checkpoint.RunID != s.current.RunID || state.checkpoint.InputDigest != s.current.InputDigest ||
		state.hash != s.currentHash) {
		return snapshot{}, fmt.Errorf("%w: state changed outside the owning store", ErrCorrupt)
	}
	return state, nil
}

func (d *disk) scan() (snapshot, error) {
	entries, err := d.entries()
	if err != nil {
		return snapshot{}, err
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	state := snapshot{artifacts: make(map[string]storedArtifact)}
	var artifactSequence uint64
	for _, e := range entries {
		if validPendingName(e.name) {
			if e.size > MaxArtifactBytes {
				return snapshot{}, ErrTooLarge
			}
			state.pending = append(state.pending, e.name)
			continue
		}
		if sequence, hash, suffix, ok := splitRecordName(e.name, checkpointPrefix); ok && suffix == ".json" {
			if sequence != state.checkpoint.Revision+1 {
				return snapshot{}, fmt.Errorf("%w: checkpoint sequence", ErrCorrupt)
			}
			content, err := d.read(e.name, MaxCheckpointBytes)
			if err != nil {
				return snapshot{}, err
			}
			cp, err := decodeCheckpoint(content)
			if err != nil {
				return snapshot{}, err
			}
			if digest(content) != hash || cp.Revision != sequence {
				return snapshot{}, fmt.Errorf("%w: checkpoint digest or revision", ErrCorrupt)
			}
			if sequence == 1 {
				if cp.Phase != "ingested" || cp.Data != nil {
					return snapshot{}, fmt.Errorf("%w: initial checkpoint", ErrCorrupt)
				}
			} else if cp.RunID != state.checkpoint.RunID || cp.InputDigest != state.checkpoint.InputDigest {
				return snapshot{}, fmt.Errorf("%w: checkpoint input or run identity", ErrCorrupt)
			}
			state.checkpoint, state.hash = cp, hash
			continue
		}
		if sequence, hash, suffix, ok := splitRecordName(e.name, artifactPrefix); ok && strings.HasPrefix(suffix, "-") {
			name := suffix[1:]
			if !validName(name) || sequence != artifactSequence+1 {
				return snapshot{}, fmt.Errorf("%w: artifact sequence or name", ErrCorrupt)
			}
			if _, duplicate := state.artifacts[name]; duplicate {
				return snapshot{}, fmt.Errorf("%w: duplicate artifact", ErrCorrupt)
			}
			content, err := d.read(e.name, MaxArtifactBytes)
			if err != nil {
				return snapshot{}, err
			}
			if digest(content) != hash {
				return snapshot{}, fmt.Errorf("%w: artifact digest", ErrCorrupt)
			}
			state.artifacts[name] = storedArtifact{
				ref: Artifact{Name: name, Digest: hash, Bytes: len(content)}, filename: e.name,
			}
			artifactSequence = sequence
			continue
		}
		return snapshot{}, fmt.Errorf("%w: unrecognized journal entry", ErrCorrupt)
	}
	if state.checkpoint.Revision == 0 {
		return snapshot{}, fmt.Errorf("%w: missing initial checkpoint", ErrCorrupt)
	}
	return state, nil
}

func encodeCheckpoint(cp Checkpoint) ([]byte, Checkpoint, error) {
	content, err := json.Marshal(cp)
	if err != nil {
		return nil, Checkpoint{}, fmt.Errorf("%w: checkpoint encoding", ErrInvalid)
	}
	if len(content) > MaxCheckpointBytes {
		return nil, Checkpoint{}, ErrTooLarge
	}
	var stored Checkpoint
	if err := json.Unmarshal(content, &stored); err != nil {
		return nil, Checkpoint{}, fmt.Errorf("%w: checkpoint encoding", ErrInvalid)
	}
	return content, stored, nil
}

func decodeCheckpoint(content []byte) (Checkpoint, error) {
	var cp Checkpoint
	if !utf8.Valid(content) || json.Unmarshal(content, &cp) != nil || cp.Version != 1 ||
		!strings.HasPrefix(cp.RunID, "rem-") || !validHex(strings.TrimPrefix(cp.RunID, "rem-"), 32) ||
		cp.Revision == 0 || !validPhase(cp.Phase) || !validDigest(cp.InputDigest) || cp.UpdatedAt.IsZero() {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint format", ErrCorrupt)
	}
	canonical, _, err := encodeCheckpoint(cp)
	if err != nil || !bytes.Equal(content, canonical) {
		return Checkpoint{}, fmt.Errorf("%w: noncanonical checkpoint", ErrCorrupt)
	}
	return cp, nil
}

func recordName(prefix string, sequence uint64, hash, suffix string) string {
	return fmt.Sprintf("%s%020d-%s%s", prefix, sequence, strings.TrimPrefix(hash, "sha256:"), suffix)
}

func splitRecordName(name, prefix string) (uint64, string, string, bool) {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || len(rest) < 85 || rest[20] != '-' || !validHex(rest[21:85], 64) {
		return 0, "", "", false
	}
	sequence, err := strconv.ParseUint(rest[:20], 10, 64)
	if err != nil || sequence == 0 || fmt.Sprintf("%020d", sequence) != rest[:20] {
		return 0, "", "", false
	}
	return sequence, "sha256:" + rest[21:85], rest[85:], true
}

func validPendingName(name string) bool {
	suffix, ok := strings.CutPrefix(name, pendingPrefix)
	return ok && validHex(suffix, 32)
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > maxNameBytes {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i == 0 || c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func validPhase(phase string) bool {
	return len(phase) <= 128 && strings.TrimSpace(phase) != "" && utf8.ValidString(phase)
}

func validDigest(value string) bool {
	raw, ok := strings.CutPrefix(value, "sha256:")
	return ok && validHex(raw, 64)
}

func validHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for i := range len(value) {
		if c := value[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func randomHex() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("%w: generate journal identity", ErrIO)
	}
	return hex.EncodeToString(id[:]), nil
}
