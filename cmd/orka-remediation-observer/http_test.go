package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func requireJSONKeys(t *testing.T, data []byte, want ...string) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal("wire response was not a JSON object")
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Fatal("wire response did not match the documented evidence fields")
	}
}

func TestHTTPDigestOnlyEvidence(t *testing.T) {
	f := startTestObserver(t, nil)
	subject := "subject-" + f.config.Markers[0].Value
	source := "source-" + f.config.Markers[1].Value
	body, err := json.Marshal(map[string]string{"subject": subject, "source": source, "data": f.canary})
	if err != nil {
		t.Fatal("marshal synthetic event")
	}
	headers := http.Header{
		"Aeg-Sas-Key": {f.canary},
		"Ce-Subject":  {subject},
		"Ce-Source":   {source},
	}
	response := f.request(t, http.MethodPost, "/events/alpha?ignored="+f.canary, "", body, headers)
	requireStatus(t, response, http.StatusOK)
	if string(response.body) != "{\"value\":0}\n" {
		t.Fatal("metric-compatible acknowledgement changed")
	}
	controlBody := []byte("control-" + f.control)
	requireStatus(t, f.request(t, http.MethodPost, "/metric", "", controlBody,
		http.Header{"Aeg-Sas-Key": {f.control}}), http.StatusOK)
	requireStatus(t, f.request(t, http.MethodPost, "/events/beta", "", nil,
		http.Header{"Aeg-Sas-Key": {f.canary, f.control}}), http.StatusOK)

	stateResponse := f.request(t, http.MethodGet, "/state", f.admin, nil, nil)
	requireStatus(t, stateResponse, http.StatusOK)
	assertNoDisclosure(t, stateResponse.body, f.admin, f.canary, f.control, subject, source, string(body))
	requireJSONKeys(t, stateResponse.body, "schemaVersion", "runID", "generation", "http", "resp",
		"droppedHTTP", "droppedRESP", "rejectedHTTPConnections", "rejectedRESPConnections")
	state := f.state(t)
	if len(state.HTTP) != 3 || len(state.RESP) != 0 {
		t.Fatal("state did not contain exactly the three HTTP observations")
	}
	observation := state.HTTP[0]
	if observation.Route != "/events/alpha" || observation.BodySHA256 != wireDigest(string(body)) ||
		!slices.Equal(observation.MarkerIDs, []string{"first-marker", "second-marker"}) ||
		!observation.SyntheticCredentialObserved || observation.CloudEventsTruncated {
		t.Fatal("positive HTTP digest or marker evidence was incorrect")
	}
	if len(observation.CloudEvents) != 2 {
		t.Fatal("both binary and structured CloudEvent metadata must be observed")
	}
	wantSubject := &fieldEvidence{SHA256: wireDigest(subject), MarkerIDs: []string{"first-marker"}}
	wantSource := &fieldEvidence{SHA256: wireDigest(source), MarkerIDs: []string{"second-marker"}}
	for _, event := range observation.CloudEvents {
		if !reflect.DeepEqual(event.Subject, wantSubject) || !reflect.DeepEqual(event.Source, wantSource) {
			t.Fatal("CloudEvent metadata must retain only independently verified digests and marker IDs")
		}
	}
	control := state.HTTP[1]
	if control.BodySHA256 != wireDigest(string(controlBody)) || control.SyntheticCredentialObserved ||
		len(control.MarkerIDs) != 0 || len(control.CloudEvents) != 0 {
		t.Fatal("normal HTTP control was falsely marked or lost its body digest")
	}
	if state.HTTP[2].SyntheticCredentialObserved {
		t.Fatal("ambiguous credential headers must not count as a canary match")
	}
	var document struct {
		HTTP []json.RawMessage `json:"http"`
	}
	if err := json.Unmarshal(stateResponse.body, &document); err != nil || len(document.HTTP) != 3 {
		t.Fatal("HTTP evidence array missing on the wire")
	}
	requireJSONKeys(t, document.HTTP[0], "route", "bodySHA256", "markerIDs", "cloudEvents",
		"cloudEventsTruncated", "syntheticCredentialObserved")
}

func TestHTTPAdminAuthorization(t *testing.T) {
	f := startTestObserver(t, nil)
	requireStatus(t, f.request(t, http.MethodPost, "/metric", "", []byte(f.control), nil), http.StatusOK)
	cases := []struct {
		name   string
		header []string
	}{
		{name: "missing"},
		{name: "wrong", header: []string{f.control}},
		{name: "canary-is-not-admin", header: []string{f.canary}},
		{name: "too-short", header: []string{"short"}},
		{name: "too-long", header: []string{strings.Repeat("x", 4097)}},
		{name: "duplicate", header: []string{f.admin, f.admin}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, route := range []struct{ method, path string }{
				{http.MethodGet, "/state"}, {http.MethodPost, "/reset"},
			} {
				response := f.request(t, route.method, route.path, "",
					resetBody(f.config.RunID, 1), http.Header{adminHeader: tc.header})
				requireStatus(t, response, http.StatusUnauthorized)
				assertNoDisclosure(t, response.body, f.admin, f.canary, f.control)
			}
			state := f.state(t)
			if state.Generation != 1 || len(state.HTTP) != 1 {
				t.Fatal("unauthorized administrative access mutated evidence")
			}
		})
	}
	requireStatus(t, f.request(t, http.MethodPost, "/state", f.admin, nil, nil),
		http.StatusMethodNotAllowed)
	requireStatus(t, f.request(t, http.MethodGet, "/reset", f.admin, nil, nil),
		http.StatusMethodNotAllowed)
}

func TestHTTPResetExactFenceAndStrictJSON(t *testing.T) {
	f := startTestObserver(t, nil)
	requireStatus(t, f.request(t, http.MethodPost, "/metric", "", []byte(f.control), nil), http.StatusOK)
	conn := dialTest(t, f.config.RESPAddress)
	sendWire(t, conn, respFrame("PING"))
	requireWire(t, conn, "+PONG\r\n")
	before := f.state(t)
	cases := []struct {
		name   string
		body   []byte
		status int
	}{
		{"wrong-run", resetBody("another-run", 1), http.StatusConflict},
		{"future-generation", resetBody(f.config.RunID, 2), http.StatusConflict},
		{"zero-generation", resetBody(f.config.RunID, 0), http.StatusBadRequest},
		{"missing-generation", []byte(`{"runID":"synthetic-run"}`), http.StatusBadRequest},
		{"null-generation", []byte(`{"runID":"synthetic-run","generation":null}`), http.StatusBadRequest},
		{"fraction", []byte(`{"runID":"synthetic-run","generation":1.5}`), http.StatusBadRequest},
		{"string", []byte(`{"runID":"synthetic-run","generation":"1"}`), http.StatusBadRequest},
		{"negative", []byte(`{"runID":"synthetic-run","generation":-1}`), http.StatusBadRequest},
		{"alias", []byte(`{"RunID":"synthetic-run","generation":1}`), http.StatusBadRequest},
		{"duplicate", []byte(`{"runID":"synthetic-run","generation":1,"generation":1}`), http.StatusBadRequest},
		{"unknown", []byte(`{"runID":"synthetic-run","generation":1,"extra":true}`), http.StatusBadRequest},
		{"trailing", append(resetBody(f.config.RunID, 1), []byte("{}")...), http.StatusBadRequest},
		{"oversized", []byte(strings.Repeat(" ", 1025)), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin, tc.body, nil), tc.status)
			if !reflect.DeepEqual(f.state(t), before) {
				t.Fatal("rejected reset changed evidence or the exact run fence")
			}
		})
	}
	response := f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil)
	requireStatus(t, response, http.StatusOK)
	after := decodeState(t, response.body)
	if after.Generation != 2 || after.RunID != f.config.RunID || len(after.HTTP) != 0 || len(after.RESP) != 0 {
		t.Fatal("successful reset did not atomically advance the generation and clear evidence")
	}
	requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin,
		resetBody(f.config.RunID, 1), nil), http.StatusConflict)
	if !reflect.DeepEqual(f.state(t), after) {
		t.Fatal("stale reset changed the new generation")
	}
}

func TestHTTPBodyByteBounds(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		for _, size := range []int{63, 64, 65} {
			name := "fixed-"
			if chunked {
				name = "chunked-"
			}
			name += strconv.Itoa(size)
			t.Run(name, func(t *testing.T) {
				f := startTestObserver(t, func(cfg *config) { cfg.Limits.HTTPBodyBytes = 64 })
				body := []byte(strings.Repeat("é", 33))[:size]
				request, err := http.NewRequest(http.MethodPost, f.url+"/metric", bytes.NewReader(body))
				if err != nil {
					t.Fatal("create bounded HTTP request")
				}
				if chunked {
					request.ContentLength = -1
				}
				response, err := exchangeHTTP(f.client, request)
				if err != nil {
					t.Fatal(err)
				}
				wantStatus, wantCount := http.StatusOK, 1
				if size > 64 {
					wantStatus, wantCount = http.StatusRequestEntityTooLarge, 0
				}
				requireStatus(t, response, wantStatus)
				state := f.state(t)
				if len(state.HTTP) != wantCount || state.DroppedHTTP != 0 {
					t.Fatal("body byte limit did not reject oversized input before observation")
				}
				if wantCount == 1 && state.HTTP[0].BodySHA256 != wireDigest(string(body)) {
					t.Fatal("accepted body digest did not cover the exact encoded bytes")
				}
			})
		}
	}
}

func TestHTTPCloudEventQuota(t *testing.T) {
	cases := []struct {
		name      string
		count     int
		header    bool
		truncated bool
	}{
		{"at-bound", 16, false, false},
		{"over-bound", 17, false, true},
		{"headers-share-bound", 16, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startTestObserver(t, nil)
			events := make([]map[string]string, tc.count)
			for index := range events {
				events[index] = map[string]string{"subject": f.config.Markers[0].Value}
			}
			body, err := json.Marshal(events)
			if err != nil {
				t.Fatal("marshal synthetic event batch")
			}
			headers := http.Header{}
			if tc.header {
				headers.Set("Ce-Subject", f.config.Markers[0].Value)
			}
			requireStatus(t, f.request(t, http.MethodPost, "/events/alpha", "", body, headers), http.StatusOK)
			state := f.state(t)
			if len(state.HTTP) != 1 || len(state.HTTP[0].CloudEvents) != 16 ||
				state.HTTP[0].CloudEventsTruncated != tc.truncated {
				t.Fatal("CloudEvent evidence exceeded or misreported its quota")
			}
			for _, event := range state.HTTP[0].CloudEvents {
				if event.Subject == nil || event.Subject.SHA256 != wireDigest(f.config.Markers[0].Value) {
					t.Fatal("bounded CloudEvent evidence lost the expected digest")
				}
			}
		})
	}
}

func TestHTTPRoutes(t *testing.T) {
	f := startTestObserver(t, nil)
	cases := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/metric", http.StatusOK},
		{http.MethodPost, "/metric", http.StatusOK},
		{http.MethodPut, "/metric", http.StatusMethodNotAllowed},
		{http.MethodPost, "/events/alpha", http.StatusOK},
		{http.MethodGet, "/events/alpha", http.StatusMethodNotAllowed},
		{http.MethodPost, "/events/unconfigured", http.StatusNotFound},
		{http.MethodPost, "/Metric", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			requireStatus(t, f.request(t, tc.method, tc.path, "", nil, nil), tc.status)
		})
	}
	if len(f.state(t).HTTP) != 3 {
		t.Fatal("health, method errors, or unconfigured routes were recorded as ingress")
	}
}
