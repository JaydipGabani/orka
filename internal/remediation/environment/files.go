package environment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func readApprovedFile(directory, name string, limit int64) ([]byte, error) {
	if !relativePath(name) || !exactDirectory(directory) {
		return nil, failure(NeedsAdapter, "unsafe-approved-file")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, failure(Infrastructure, "approved-root-unavailable")
	}
	defer func() { _ = root.Close() }()
	prefix := ""
	for segment := range strings.SplitSeq(name, "/") {
		prefix = filepath.Join(prefix, segment)
		info, err := root.Lstat(prefix)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, failure(NeedsAdapter, "unsafe-approved-file")
		}
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, failure(Infrastructure, "approved-file-unavailable")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, failure(NeedsAdapter, "approved-file-limit")
	}
	return readBounded(file, limit)
}

func writePrivate(directory, name string, data []byte) error {
	if !relativePath(name) || !exactDirectory(directory) {
		return failure(Infrastructure, "private-write-failed")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return failure(Infrastructure, "private-write-failed")
	}
	defer func() { _ = root.Close() }()
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return failure(Infrastructure, "private-write-failed")
	}
	staging := "write-" + hex.EncodeToString(random)
	file, err := root.OpenFile(staging, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return failure(Infrastructure, "private-write-failed")
	}
	defer func() { _ = root.Remove(staging) }()
	_, writeErr := file.Write(data)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || root.Rename(staging, name) != nil {
		return failure(Infrastructure, "private-write-failed")
	}
	dir, err := os.Open(directory)
	if err != nil {
		return failure(Infrastructure, "private-write-failed")
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return failure(Infrastructure, "private-write-failed")
	}
	return nil
}

type operationRecord struct {
	Receipt         Receipt     `json:"receipt"`
	Observation     Observation `json:"observation"`
	CancelRequested bool        `json:"cancelRequested,omitempty"`
}

type buildRecord struct {
	ID      string          `json:"id"`
	State   string          `json:"state"`
	Result  *BuildResult    `json:"result,omitempty"`
	Failure *Error          `json:"failure,omitempty"`
	Job     *buildJobRecord `json:"job,omitempty"`
}

const (
	buildStarted  = "started"
	buildComplete = "complete"
	buildFailed   = "failed"
)

type runJournal struct {
	Version            int                           `json:"version"`
	RunID              string                        `json:"runID,omitempty"`
	ConfigDigest       string                        `json:"configDigest"`
	BindDigest         string                        `json:"bindDigest"`
	Operations         map[string]*operationRecord   `json:"operations"`
	Builds             map[string]*buildRecord       `json:"builds"`
	BuildCancellations map[string]*buildCancellation `json:"buildCancellations,omitempty"`
	// Zero is an unknown legacy origin, not an intact-history attestation.
	// Rewriting a legacy snapshot must never promote this field.
	BuildHistoryVersion    int    `json:"buildHistoryVersion,omitempty"`
	BuildHistoryIncomplete bool   `json:"buildHistoryIncomplete,omitempty"`
	JournalDigest          string `json:"journalDigest,omitempty"`
	persisted              bool
}

func runName(runID string) string {
	return "run-" + strings.TrimPrefix(digest([]byte(runID)), "sha256:")
}

func (a *Adapter) loadRun(runID string, bind Bind) (*runJournal, error) {
	file := runName(runID) + ".json"
	data, err := readApprovedFile(a.config.OutputRoot, file, 32<<20)
	if err != nil {
		// NotExist is deliberately checked on the trusted root, not inferred from
		// a potentially credential-bearing error string.
		if _, statErr := os.Lstat(filepath.Join(a.config.OutputRoot, file)); errors.Is(statErr, os.ErrNotExist) {
			return &runJournal{
				Version: Version, ConfigDigest: a.digest, BindDigest: jsonDigest(bind),
				Operations: map[string]*operationRecord{}, Builds: map[string]*buildRecord{},
				BuildHistoryVersion: 1, BuildHistoryIncomplete: true,
			}, nil
		}
		return nil, failure(Unknown, "run-journal-unavailable")
	}
	var state runJournal
	if rejectDuplicateJSON(data) != nil || json.Unmarshal(data, &state) != nil || state.Version != Version ||
		(state.RunID != "" && state.RunID != runID) ||
		(state.BuildHistoryVersion != 0 && state.BuildHistoryVersion != 1) ||
		state.BindDigest != jsonDigest(bind) || state.Operations == nil || state.Builds == nil ||
		len(state.Operations)+len(state.Builds)+len(state.BuildCancellations) > 128 ||
		(state.BuildHistoryVersion == 1 && !digestPattern.MatchString(state.JournalDigest)) ||
		(state.JournalDigest != "" && state.JournalDigest != runJournalDigest(&state)) {
		return nil, failure(Unknown, "run-journal-binding-mismatch")
	}
	state.persisted = true
	return &state, nil
}

func (a *Adapter) saveRun(runID string, state *runJournal) error {
	if state.RunID != "" && state.RunID != runID {
		return failure(Unknown, "run-journal-binding-mismatch")
	}
	state.RunID = runID
	state.JournalDigest = runJournalDigest(state)
	data, err := json.Marshal(state)
	if err != nil || len(data) > 32<<20 {
		return failure(Infrastructure, "run-journal-limit")
	}
	if err := writePrivate(a.config.OutputRoot, runName(runID)+".json", data); err != nil {
		return err
	}
	state.persisted = true
	return nil
}

func runJournalDigest(state *runJournal) string {
	copy := *state
	copy.JournalDigest = ""
	return jsonDigest(copy)
}

// A missing journal can be a fresh admission only for a new caller and a newly
// allocated run lock. Receipt reconstruction must retain incomplete history:
// its recovered object handles say nothing about other, lost build records.
func (a *Adapter) lockRun(ctx context.Context, runID string, bind Bind, allowNew bool) (*runJournal, func(), error) {
	unlock, created, err := a.lockFile(ctx, runName(runID))
	if err != nil {
		return nil, nil, err
	}
	state, err := a.loadRun(runID, bind)
	if err != nil {
		unlock()
		return nil, nil, err
	}
	if !state.persisted && created && allowNew {
		state.RunID, state.BuildHistoryVersion, state.BuildHistoryIncomplete = runID, 1, false
	}
	return state, unlock, nil
}

func (a *Adapter) admitOperation(state *runJournal, except string) error {
	if len(state.Operations)+len(state.Builds)+len(state.BuildCancellations) >= a.config.Limits.MaxOperations {
		return failure(NeedsAdapter, "run-operation-limit")
	}
	for key, previous := range state.Operations {
		if previous == nil {
			return failure(Unknown, "run-operation-unavailable")
		}
		if key != except && !previous.Observation.CleanupComplete {
			return failure(Unknown, "previous-cleanup-unsettled")
		}
	}
	for key, previous := range state.Builds {
		if previous == nil {
			return failure(Unknown, "run-build-unavailable")
		}
		if key != except && previous.State == buildStarted {
			return failure(Unknown, "previous-build-unsettled")
		}
	}
	return nil
}
