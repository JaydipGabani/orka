package patchverification

import (
	"encoding/json"
	"errors"
)

type RunState string

const (
	RunRunning     RunState = "running"
	RunFinalized   RunState = "finalized"
	RunCancelled   RunState = "cancelled"
	RunInterrupted RunState = "interrupted"
	RunInvalid     RunState = "invalid"

	MaxManifestBytes    = 1 << 20
	MaxObservationBytes = 32 << 10
	MaxOutputBytes      = 64 << 10
	MaxProvenanceBytes  = 32 << 20
	MaxRunBlobBytes     = 128 << 20
	MaxFrozenFiles      = 128
	MaxServices         = 8
	MaxIncidents        = 256
)

var (
	ErrRunNotFound = errors.New("verification run not found")
	ErrBinding     = errors.New("verification identity mismatch")
	ErrConflict    = errors.New("verification conflicting delivery")
	ErrClosed      = errors.New("verification run is closed")
	ErrIntegrity   = errors.New("verification evidence integrity failure")
	ErrLimit       = errors.New("verification storage limit exceeded")
	ErrEvidence    = errors.New("verification evidence is invalid")
)

type BlobReference struct {
	Digest string `json:"digest"`
	Bytes  int    `json:"bytes"`
}

type EvidenceRecord struct {
	Observation Observation `json:"observation"`
	Digest      string      `json:"digest"`
	Rejection   string      `json:"rejection,omitempty"`
}

type Incident struct {
	Kind   string `json:"kind"`
	Slot   string `json:"slot"`
	Digest string `json:"digest"`
	Reason string `json:"reason"`
}

type Seal struct {
	Digest     string     `json:"digest"`
	Content    []byte     `json:"content"`
	Assessment Assessment `json:"assessment"`
}

type Record struct {
	Manifest   Manifest         `json:"manifest"`
	Binding    Binding          `json:"binding"`
	Provenance []BlobReference  `json:"provenance"`
	Evidence   []EvidenceRecord `json:"evidence"`
	State      RunState         `json:"state"`
	Assessment Assessment       `json:"assessment"`
	Seal       *Seal            `json:"seal,omitempty"`
	Incidents  []Incident       `json:"incidents"`
}

func NewRunBinding(manifest Manifest, attemptID, originalTaskID, patchedTaskID string) (Binding, error) {
	if err := ValidateManifest(manifest); err != nil {
		return Binding{}, err
	}
	digest, err := ManifestDigest(manifest)
	if err != nil {
		return Binding{}, err
	}
	binding := Binding{AttemptID: attemptID, OriginalTaskID: originalTaskID, PatchedTaskID: patchedTaskID, ManifestDigest: digest}
	binding.RunID = deterministicRunID(binding)
	return binding, ValidateRunBinding(manifest, binding)
}

func ValidateRunBinding(manifest Manifest, binding Binding) error {
	digest, err := ManifestDigest(manifest)
	if err != nil {
		return err
	}
	if ValidateBinding(manifest.Action, binding) != nil || !identifierPattern.MatchString(binding.OriginalTaskID) ||
		(binding.PatchedTaskID != "" && !identifierPattern.MatchString(binding.PatchedTaskID)) ||
		binding.ManifestDigest != digest || binding.RunID != deterministicRunID(binding) {
		return ErrBinding
	}
	return nil
}

func deterministicRunID(binding Binding) string {
	binding.RunID = ""
	content, _ := json.Marshal(binding)
	return "pv-" + Digest(content)[len("sha256:"):]
}
