package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"sync"
)

type fieldEvidence struct {
	SHA256    string   `json:"sha256"`
	MarkerIDs []string `json:"markerIDs"`
}

type cloudEventEvidence struct {
	Subject *fieldEvidence `json:"subject,omitempty"`
	Source  *fieldEvidence `json:"source,omitempty"`
}

type httpObservation struct {
	Route                       string               `json:"route"`
	BodySHA256                  string               `json:"bodySHA256"`
	MarkerIDs                   []string             `json:"markerIDs"`
	CloudEvents                 []cloudEventEvidence `json:"cloudEvents"`
	CloudEventsTruncated        bool                 `json:"cloudEventsTruncated"`
	SyntheticCredentialObserved bool                 `json:"syntheticCredentialObserved"`
	TLSDataIngress              bool                 `json:"tlsDataIngress,omitempty"`
}

type respObservation struct {
	Command                     string `json:"command"`
	SyntheticCredentialObserved bool   `json:"syntheticCredentialObserved"`
	// This marks an admitted fixed-fixture tuple, not execution or client-side health.
	MetricQueryMatched bool `json:"metricQueryMatched,omitempty"`
}

type evidence struct {
	SchemaVersion            string            `json:"schemaVersion"`
	RunID                    string            `json:"runID"`
	Generation               uint64            `json:"generation"`
	HTTP                     []httpObservation `json:"http"`
	RESP                     []respObservation `json:"resp"`
	DroppedHTTP              uint64            `json:"droppedHTTP"`
	DroppedRESP              uint64            `json:"droppedRESP"`
	RejectedHTTPConnections  uint64            `json:"rejectedHTTPConnections"`
	RejectedRESPConnections  uint64            `json:"rejectedRESPConnections"`
	DuplicateHTTP            uint64            `json:"duplicateHTTP,omitempty"`
	RejectedAdminConnections uint64            `json:"rejectedAdminConnections,omitempty"`
}

type evidenceStore struct {
	mu        sync.Mutex
	state     evidence
	httpLimit int
	respLimit int
	seenHTTP  map[[sha256.Size]byte]struct{}
}

func newEvidenceStore(cfg config) *evidenceStore {
	store := &evidenceStore{
		state: evidence{
			SchemaVersion: schemaVersion, RunID: cfg.RunID, Generation: 1,
			HTTP: []httpObservation{}, RESP: []respObservation{},
		},
		httpLimit: cfg.Limits.HTTPObservations, respLimit: cfg.Limits.RESPObservations,
	}
	if cfg.HTTPSetEvidence {
		store.seenHTTP = make(map[[sha256.Size]byte]struct{})
	}
	return store
}

func (s *evidenceStore) generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Generation
}

func (s *evidenceStore) snapshot() evidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := s.state
	// Records and their nested slices are immutable once admitted to the store.
	snapshot.HTTP = append([]httpObservation{}, s.state.HTTP...)
	snapshot.RESP = append([]respObservation{}, s.state.RESP...)
	return snapshot
}

func (s *evidenceStore) recordHTTP(generation uint64, observation httpObservation) {
	var identity [sha256.Size]byte
	if s.seenHTTP != nil {
		identity = semanticHTTPIdentity(observation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.state.Generation {
		return
	}
	if s.seenHTTP != nil {
		if _, seen := s.seenHTTP[identity]; seen {
			increment(&s.state.DuplicateHTTP)
			return
		}
	}
	if len(s.state.HTTP) >= s.httpLimit {
		increment(&s.state.DroppedHTTP)
		return
	}
	s.state.HTTP = append(s.state.HTTP, observation)
	if s.seenHTTP != nil {
		s.seenHTTP[identity] = struct{}{}
	}
}

func semanticHTTPIdentity(o httpObservation) [sha256.Size]byte {
	o.BodySHA256 = ""
	o.MarkerIDs = slices.Clone(o.MarkerIDs)
	slices.Sort(o.MarkerIDs)
	o.CloudEvents = slices.Clone(o.CloudEvents)
	field := func(value *fieldEvidence) *fieldEvidence {
		if value == nil {
			return nil
		}
		copy := *value
		copy.MarkerIDs = slices.Clone(value.MarkerIDs)
		slices.Sort(copy.MarkerIDs)
		return &copy
	}
	for i := range o.CloudEvents {
		o.CloudEvents[i].Subject = field(o.CloudEvents[i].Subject)
		o.CloudEvents[i].Source = field(o.CloudEvents[i].Source)
	}
	sort.Slice(o.CloudEvents, func(i, j int) bool {
		left, _ := json.Marshal(o.CloudEvents[i])
		right, _ := json.Marshal(o.CloudEvents[j])
		return bytes.Compare(left, right) < 0
	})
	encoded, _ := json.Marshal(o)
	return sha256.Sum256(encoded)
}

func (s *evidenceStore) recordRESP(generation uint64, observation respObservation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.state.Generation {
		return
	}
	if len(s.state.RESP) >= s.respLimit {
		increment(&s.state.DroppedRESP)
		return
	}
	s.state.RESP = append(s.state.RESP, observation)
}

func (s *evidenceStore) rejectedConnection(resp bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if resp {
		increment(&s.state.RejectedRESPConnections)
	} else {
		increment(&s.state.RejectedHTTPConnections)
	}
}

func (s *evidenceStore) rejectedAdminConnection() {
	s.mu.Lock()
	defer s.mu.Unlock()
	increment(&s.state.RejectedAdminConnections)
}

func (s *evidenceStore) reset(runID string, generation uint64) (evidence, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if runID != s.state.RunID || generation != s.state.Generation || generation == ^uint64(0) {
		return evidence{}, false
	}
	s.state = evidence{
		SchemaVersion: schemaVersion, RunID: runID, Generation: generation + 1,
		HTTP: []httpObservation{}, RESP: []respObservation{},
	}
	clear(s.seenHTTP)
	return s.state, true
}

func increment(value *uint64) {
	if *value != ^uint64(0) {
		*value++
	}
}

func digestHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func markerHits(markers []markerConfig, data []byte) []string {
	hits := make([]string, 0, len(markers))
	sum := ""
	for _, marker := range markers {
		if marker.SHA256 != "" {
			// Hash markers match the entire field, without exposing future
			// synthetic challenge subjects in a readable configuration.
			if sum == "" {
				sum = digestHex(data)
			}
			if sum == marker.SHA256 {
				hits = append(hits, marker.ID)
			}
		} else if bytes.Contains(data, []byte(marker.Value)) {
			hits = append(hits, marker.ID)
		}
	}
	return hits
}
