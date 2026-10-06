package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

type observer struct {
	config      config
	store       *evidenceStore
	adminDigest [sha256.Size]byte
	canary      [sha256.Size]byte
	routes      map[string]bool
	canaryPaths map[string]string
	activity    activity
}

type activity struct {
	mu       sync.Mutex
	stopping bool
	wg       sync.WaitGroup
}

func (a *activity) enter() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopping {
		return false
	}
	a.wg.Add(1)
	return true
}

func (a *activity) stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopping = true
}

func newObserver(cfg config, admin, canary [sha256.Size]byte) *observer {
	routes := make(map[string]bool, len(cfg.Channels)+1)
	routes["/metric"] = true
	for _, channel := range cfg.Channels {
		routes["/events/"+channel] = true
	}
	canaryPaths := make(map[string]string, len(cfg.ChannelCanaries))
	for _, pin := range cfg.ChannelCanaries {
		canaryPaths["/events/"+pin.Channel] = pin.SHA256
	}
	return &observer{
		config: cfg, store: newEvidenceStore(cfg), adminDigest: admin,
		canary: canary, routes: routes, canaryPaths: canaryPaths,
	}
}

func (o *observer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !o.beginHTTP(w) {
		return
	}
	defer o.activity.wg.Done()
	switch r.URL.Path {
	case "/state", "/reset":
		o.admin(w, r)
	default:
		o.serveDataHTTP(w, r, false)
	}
}

func (o *observer) serveIngressHTTP(w http.ResponseWriter, r *http.Request) {
	if !o.beginHTTP(w) {
		return
	}
	defer o.activity.wg.Done()
	o.serveDataHTTP(w, r, false)
}

func (o *observer) serveIngressHTTPS(w http.ResponseWriter, r *http.Request) {
	if !o.beginHTTP(w) {
		return
	}
	defer o.activity.wg.Done()
	if r.TLS == nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	o.serveDataHTTP(w, r, true)
}

func (o *observer) beginHTTP(w http.ResponseWriter) bool {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !o.activity.enter() {
		writeError(w, http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (o *observer) serveDataHTTP(w http.ResponseWriter, r *http.Request, tlsDataIngress bool) {
	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			OK bool `json:"ok"`
		}{OK: true})
	default:
		if !o.routes[r.URL.Path] {
			writeError(w, http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost && (r.URL.Path != "/metric" || r.Method != http.MethodGet) {
			writeError(w, http.StatusMethodNotAllowed)
			return
		}
		o.receive(w, r, tlsDataIngress)
	}
}

func (o *observer) authorized(r *http.Request) bool {
	values := r.Header.Values(adminHeader)
	if len(values) != 1 || len(values[0]) < 32 || len(values[0]) > maxAdminTokenBytes {
		return false
	}
	digest := sha256.Sum256([]byte(values[0]))
	return subtle.ConstantTimeCompare(digest[:], o.adminDigest[:]) == 1
}

func (o *observer) admin(w http.ResponseWriter, r *http.Request) {
	if !o.authorized(r) {
		writeError(w, http.StatusUnauthorized)
		return
	}
	if r.URL.Path == "/state" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, o.store.snapshot())
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed)
		return
	}
	o.reset(w, r)
}

func (o *observer) reset(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	defer clear(data)
	if err != nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	var request struct {
		RunID      string `json:"runID"`
		Generation uint64 `json:"generation"`
	}
	if decodeStrict(data, &request) != nil || !validID(request.RunID) || request.Generation == 0 {
		writeError(w, http.StatusBadRequest)
		return
	}
	state, ok := o.store.reset(request.RunID, request.Generation)
	if !ok {
		writeError(w, http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (o *observer) receive(w http.ResponseWriter, r *http.Request, tlsDataIngress bool) {
	generation := o.store.generation()
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(o.config.Limits.HTTPBodyBytes)))
	defer clear(data)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeError(w, http.StatusRequestEntityTooLarge)
		} else {
			writeError(w, http.StatusBadRequest)
		}
		return
	}
	events, truncated := o.cloudEvents(r, data)
	o.store.recordHTTP(generation, httpObservation{
		Route: r.URL.Path, BodySHA256: digestHex(data), MarkerIDs: markerHits(o.config.Markers, data),
		CloudEvents: events, CloudEventsTruncated: truncated,
		SyntheticCredentialObserved: o.syntheticHeader(r),
		TLSDataIngress:              tlsDataIngress,
	})
	writeJSON(w, http.StatusOK, struct {
		Value int `json:"value"`
	}{})
}

func (o *observer) syntheticHeader(r *http.Request) bool {
	values := r.Header.Values("Aeg-Sas-Key")
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > maxAdminTokenBytes {
		return false
	}
	digest := sha256.Sum256([]byte(values[0]))
	if expected, ok := o.canaryPaths[r.URL.Path]; ok {
		return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(digest[:])), []byte(expected)) == 1
	}
	return subtle.ConstantTimeCompare(digest[:], o.canary[:]) == 1
}

func (o *observer) field(value *string) *fieldEvidence {
	if value == nil {
		return nil
	}
	data := []byte(*value)
	return &fieldEvidence{SHA256: digestHex(data), MarkerIDs: markerHits(o.config.Markers, data)}
}

func (o *observer) cloudEvents(r *http.Request, data []byte) ([]cloudEventEvidence, bool) {
	result := make([]cloudEventEvidence, 0, 1)
	subject, source := singleHeader(r, "Ce-Subject"), singleHeader(r, "Ce-Source")
	if subject != nil || source != nil {
		result = append(result, cloudEventEvidence{Subject: o.field(subject), Source: o.field(source)})
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return result, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	batch := data[0] == '['
	if batch {
		if _, err := decoder.Token(); err != nil {
			return result, false
		}
	}
	for !batch || decoder.More() {
		if len(result) >= maxCloudEvents {
			return result, true
		}
		var event struct {
			Subject *string `json:"subject"`
			Source  *string `json:"source"`
		}
		if err := decoder.Decode(&event); err != nil {
			return result, false
		}
		if event.Subject != nil || event.Source != nil {
			result = append(result, cloudEventEvidence{Subject: o.field(event.Subject), Source: o.field(event.Source)})
		}
		if !batch {
			break
		}
	}
	return result, false
}

func singleHeader(r *http.Request, key string) *string {
	values := r.Header.Values(key)
	if len(values) != 1 {
		return nil
	}
	return &values[0]
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: strings.ToLower(http.StatusText(status))})
}
