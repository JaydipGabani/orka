package validation

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

// These two wire envelopes mirror the standalone store's version-1 seal. The
// contained manifests and observations deliberately use the public pv types.
type creationEnvelope struct {
	Manifest   pv.Manifest        `json:"manifest"`
	Binding    pv.Binding         `json:"binding"`
	Provenance []pv.BlobReference `json:"provenance"`
}

type sealEnvelope struct {
	CreationDigest string        `json:"creationDigest"`
	EvidenceDigest string        `json:"evidenceDigest"`
	State          pv.RunState   `json:"state"`
	Assessment     pv.Assessment `json:"assessment"`
	ExcludedSlots  []int         `json:"excludedSlots,omitempty"`
}

func verifyRecord(staged Staged, submission *pv.KubernetesSubmission, record *pv.Record) ([]pv.BlobReference, error) {
	if err := verifyRecordEnvelope(staged, submission, record); err != nil {
		return nil, err
	}
	references := evidenceReferences{byDigest: make(map[string]int)}
	if err := verifyProvenance(staged.Provenance, record, &references); err != nil {
		return nil, err
	}
	observations, err := verifyObservations(record, &references)
	if err != nil {
		return nil, err
	}
	assessment := pv.Evaluate(record.Manifest, record.Binding, observations)
	if !reflect.DeepEqual(record.Assessment, assessment) {
		return nil, errors.New("validation assessment contradicts the frozen observations")
	}
	if err := verifySeal(record); err != nil {
		return nil, err
	}
	result := make([]pv.BlobReference, 0, len(references.byDigest))
	for digest, size := range references.byDigest {
		result = append(result, pv.BlobReference{Digest: digest, Bytes: size})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Digest < result[j].Digest })
	return result, nil
}

func verifyRecordEnvelope(staged Staged, submission *pv.KubernetesSubmission, record *pv.Record) error {
	if submission.Binding == nil || submission.RunID == "" || record.Binding != *submission.Binding ||
		pv.ValidateRunBinding(record.Manifest, record.Binding) != nil || matchManifest(staged, record.Manifest) != nil {
		return pv.ErrBinding
	}
	pinnedDigest, _ := pv.ManifestDigest(submission.Manifest)
	if record.Binding.ManifestDigest != pinnedDigest {
		return pv.ErrBinding
	}
	if record.State != pv.RunFinalized || len(record.Incidents) != 0 || record.Seal == nil || submission.Failure != "" {
		return errors.New("validation did not finalize with uncontested sealed evidence")
	}
	required := len(pv.ActionSides(record.Manifest.Action)) * len(record.Manifest.Checks)
	if len(record.Evidence) != required || submission.RecordedChecks != len(record.Evidence) ||
		submission.Assessment == nil || !reflect.DeepEqual(*submission.Assessment, record.Assessment) {
		return errors.New("validation terminal summary is missing or contradicts the complete evidence")
	}
	return nil
}

type evidenceReferences struct {
	byDigest map[string]int
	total    int
}

func (r *evidenceReferences) add(reference pv.BlobReference, limit int) error {
	if !digestPattern.MatchString(reference.Digest) || reference.Bytes < 0 || reference.Bytes > limit {
		return pv.ErrIntegrity
	}
	if size, found := r.byDigest[reference.Digest]; found {
		if size != reference.Bytes {
			return pv.ErrIntegrity
		}
		return nil
	}
	if r.total > pv.MaxRunBlobBytes-reference.Bytes {
		return pv.ErrLimit
	}
	r.total += reference.Bytes
	r.byDigest[reference.Digest] = reference.Bytes
	return nil
}

func verifyProvenance(expected []pv.BlobReference, record *pv.Record, references *evidenceReferences) error {
	want := make(map[string]int, len(expected))
	for _, reference := range expected {
		if _, duplicate := want[reference.Digest]; duplicate {
			return pv.ErrIntegrity
		}
		want[reference.Digest] = reference.Bytes
	}
	if len(record.Provenance) != len(want) || len(want) == 0 || len(want) > pv.MaxFrozenFiles+4 {
		return pv.ErrIntegrity
	}
	for _, reference := range record.Provenance {
		if size, exists := want[reference.Digest]; !exists || size != reference.Bytes {
			return pv.ErrIntegrity
		}
		delete(want, reference.Digest)
		if err := references.add(reference, pv.MaxProvenanceBytes); err != nil {
			return err
		}
	}
	// Verify that even a custom stager has supplied every manifest reference.
	requiredDigests := []string{record.Manifest.Sources.Original.ArchiveDigest}
	if record.Manifest.Action != pv.ValidateReport {
		requiredDigests = append(requiredDigests, record.Manifest.Sources.Patched.ArchiveDigest, record.Manifest.Sources.DiffDigest)
	}
	if record.Manifest.Sources.PatchDigest != "" {
		requiredDigests = append(requiredDigests, record.Manifest.Sources.PatchDigest)
	}
	for _, file := range record.Manifest.Files {
		requiredDigests = append(requiredDigests, file.Digest)
		if size, found := references.byDigest[file.Digest]; !found || size != len(file.Content) {
			return pv.ErrIntegrity
		}
	}
	uniqueRequired := make(map[string]bool)
	for _, digest := range requiredDigests {
		if _, found := references.byDigest[digest]; !found {
			return pv.ErrIntegrity
		}
		uniqueRequired[digest] = true
	}
	if len(uniqueRequired) != len(references.byDigest) {
		return pv.ErrIntegrity
	}
	return nil
}

func verifyObservations(record *pv.Record, references *evidenceReferences) ([]pv.Observation, error) {
	observations := make([]pv.Observation, 0, len(record.Evidence))
	slots := make(map[string]bool)
	for _, evidence := range record.Evidence {
		observation := evidence.Observation
		slot := observation.Side + ":" + observation.CheckID
		content, err := json.Marshal(observation)
		if err != nil || len(content) > pv.MaxObservationBytes || pv.Digest(content) != evidence.Digest ||
			evidence.Rejection != "" || slots[slot] || pv.ValidateObservation(record.Manifest, record.Binding, observation) != nil {
			return nil, pv.ErrIntegrity
		}
		if observation.Executed && (observation.ContainerID == "" || !identifier.MatchString(observation.JobUID) ||
			!identifier.MatchString(observation.PodUID)) {
			return nil, pv.ErrEvidence
		}
		slots[slot] = true
		for _, reference := range []pv.BlobReference{
			{Digest: observation.StdoutDigest, Bytes: observation.StdoutBytes},
			{Digest: observation.StderrDigest, Bytes: observation.StderrBytes},
		} {
			if !observation.Executed && reference.Digest == "" && reference.Bytes == 0 {
				continue
			}
			if err := references.add(reference, pv.MaxOutputBytes); err != nil {
				return nil, err
			}
		}
		services := make(map[string]bool)
		for _, service := range record.Manifest.Environment.Services {
			services[service.ID] = true
			output, found := observation.ServiceOutputs[service.ID]
			if !found && !observation.Executed {
				continue
			}
			if !found {
				return nil, pv.ErrIntegrity
			}
			if err := references.add(pv.BlobReference{Digest: output.Digest, Bytes: output.Bytes}, pv.MaxOutputBytes); err != nil {
				return nil, err
			}
		}
		for service := range observation.ServiceOutputs {
			if !services[service] {
				return nil, pv.ErrIntegrity
			}
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func verifySeal(record *pv.Record) error {
	seal := record.Seal
	if seal == nil || len(seal.Content) == 0 || len(seal.Content) > 65536 ||
		pv.Digest(seal.Content) != seal.Digest || !reflect.DeepEqual(seal.Assessment, record.Assessment) {
		return pv.ErrIntegrity
	}
	var envelope sealEnvelope
	if decodeJSON(seal.Content, &envelope) != nil || envelope.State != record.State ||
		!reflect.DeepEqual(envelope.Assessment, record.Assessment) || len(envelope.ExcludedSlots) != 0 {
		return pv.ErrIntegrity
	}
	creation, err := json.Marshal(creationEnvelope{record.Manifest, record.Binding, record.Provenance})
	if err != nil || len(creation) > 2*pv.MaxManifestBytes || pv.Digest(creation) != envelope.CreationDigest {
		return pv.ErrIntegrity
	}
	evidence, err := json.Marshal(record.Evidence)
	if err != nil || pv.Digest(evidence) != envelope.EvidenceDigest {
		return pv.ErrIntegrity
	}
	return nil
}
