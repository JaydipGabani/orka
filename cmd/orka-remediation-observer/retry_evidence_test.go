package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type retryRequest struct {
	at      time.Duration
	round   int
	subject int
	reason  int
	channel string
}

func retryOffsets(window time.Duration) []time.Duration {
	var result []time.Duration
	for elapsed, delay := time.Duration(0), 5*time.Millisecond; elapsed <= window; delay *= 2 {
		result = append(result, elapsed)
		elapsed += delay
	}
	return result
}

func publishingSubject(index, round int) string {
	return fmt.Sprintf("/synthetic/namespace-%d/scaledobject/challenge-%d", index, round)
}

func publishingRetryRequests(window, tail time.Duration, filtered bool) []retryRequest {
	var result []retryRequest
	for round := range 2 {
		duration, start := window+tail, time.Duration(0)
		if round == 1 {
			duration, start = tail, window
		}
		for _, offset := range retryOffsets(duration) {
			for subject := range 2 {
				for reason := range 2 {
					for _, channel := range []string{"a", "b", "grid-a", "grid-b", "grid-credential-attack", "cluster-http"} {
						if filtered && channel != "cluster-http" &&
							channel != []string{"a", "b"}[subject] &&
							channel != []string{"grid-a", "grid-b"}[subject] {
							continue
						}
						result = append(result, retryRequest{start + offset, round, subject, reason, channel})
					}
				}
			}
		}
	}
	slices.SortStableFunc(result, func(a, b retryRequest) int {
		if a.at < b.at {
			return -1
		}
		if a.at > b.at {
			return 1
		}
		return 0
	})
	return result
}

func startRetryObserver(t *testing.T, changes func(*config)) *tlsIngressFixture {
	t.Helper()
	return startTLSIngressObserver(t, func(c *config) {
		a, b := c.ChannelCanaries[0].SHA256, c.ChannelCanaries[1].SHA256
		c.HTTPSetEvidence = true
		c.Limits.HTTPConnections = maxPublishingConnections
		c.Channels = []string{"a", "b", "grid-a", "grid-b", "grid-credential-attack", "cluster-http"}
		c.ChannelCanaries = []channelCanaryConfig{
			{Channel: "grid-a", SHA256: a}, {Channel: "grid-b", SHA256: b}, {Channel: "grid-credential-attack", SHA256: a},
		}
		c.Markers = nil
		for round := range 2 {
			for subject := range 2 {
				id := fmt.Sprintf("round-%d-subject-%d", round, subject)
				if round == 1 && subject == 1 {
					id = "credential-final-1"
				}
				c.Markers = append(c.Markers, markerConfig{
					ID:     id,
					SHA256: wireDigest(publishingSubject(subject, round)),
				})
			}
		}
		if changes != nil {
			changes(c)
		}
	})
}

func retryWire(f *tlsIngressFixture, request retryRequest, id int) (string, http.Header, []byte, error) {
	headers := http.Header{"Content-Type": {"application/json"}}
	body := map[string]any{"reason": fmt.Sprintf("failed-reason-%d", request.reason), "sequence": id}
	subject := publishingSubject(request.subject, request.round)
	source := "/synthetic/controller/keda"
	endpoint := f.ingressURL + "/events/" + request.channel
	if strings.HasPrefix(request.channel, "grid-") {
		endpoint = f.dataURL + "/events/" + request.channel + "?api-version=2018-01-01"
		key := f.canary
		if request.channel == "grid-b" {
			key = f.control
		}
		headers.Set("Aeg-Sas-Key", key)
		headers.Set("Content-Type", "application/cloudevents-batch+json; charset=utf-8")
		event := map[string]any{
			"specversion": "1.0", "id": fmt.Sprint(id), "source": source, "subject": subject,
			"type": "keda.scaledobject.failed.v1",
			"time": time.Unix(0, int64(request.at)).UTC().Format(time.RFC3339Nano), "data": body,
		}
		data, err := json.Marshal([]map[string]any{event})
		return endpoint, headers, data, err
	}
	headers.Set("Ce-Subject", subject)
	headers.Set("Ce-Source", source)
	headers.Set("Ce-Type", "keda.scaledobject.failed.v1")
	headers.Set("Ce-Id", fmt.Sprint(id))
	data, err := json.Marshal(body)
	return endpoint, headers, data, err
}

func TestKEDARetryCadenceRetainsBoundedEvidenceAtMinAndMaxWindows(t *testing.T) {
	// The public controller emits two failed events per reconcile; both
	// ScaledObjects start with 5ms exponential retry. No client deduplication.
	if count := len(retryOffsets(5115*time.Millisecond)) * 2 * 2 * 6; count != 264 {
		t.Fatalf("public retry model produced %d requests, want 264", count)
	}
	for _, arm := range []string{"original", "control", "candidate"} {
		for _, bounds := range []struct {
			name         string
			window, tail time.Duration
		}{{"minimum", 10 * time.Second, 2 * time.Second}, {"maximum", 180 * time.Second, 30 * time.Second}} {
			t.Run(arm+"/"+bounds.name, func(t *testing.T) {
				f := startRetryObserver(t, nil)
				requests := publishingRetryRequests(bounds.window, bounds.tail, arm == "candidate")
				peak := 0
				for left, right := 0, 0; right < len(requests); right++ {
					for requests[right].at-requests[left].at >= 5*time.Second {
						left++
					}
					peak = max(peak, right-left+1)
				}
				if peak > maxPublishingConnections {
					t.Fatal("the configured data capacity cannot contain a full read-deadline of modeled attempts")
				}
				if arm != "candidate" && peak != 240 {
					t.Fatalf("modeled in-flight request bound = %d, want 240", peak)
				}
				for i := 0; i < len(requests); {
					end := i + 1
					for end < len(requests) && requests[end].at == requests[i].at {
						end++
					}
					errs := make(chan error, end-i)
					var pending sync.WaitGroup
					for j := i; j < end; j++ {
						pending.Go(func() {
							endpoint, headers, body, err := retryWire(f, requests[j], j)
							if err == nil {
								var response wireResponse
								response, err = requestHTTP(f.client, http.MethodPost, endpoint, "", body, headers)
								if err == nil && response.status != http.StatusOK {
									err = fmt.Errorf("synthetic publish status %d", response.status)
								}
							}
							errs <- err
						})
					}
					// Actual administrative TLS remains usable during each
					// fan-out burst, not only after all clients finish.
					_ = f.state(t)
					pending.Wait()
					close(errs)
					for err := range errs {
						if err != nil {
							t.Fatal("a modeled publishing request was rejected")
						}
					}
					i = end
				}
				state := f.state(t)
				wantDistinct := 24
				if arm == "candidate" {
					wantDistinct = 12
				}
				if len(state.HTTP) != wantDistinct || state.DuplicateHTTP != uint64(len(requests)-wantDistinct) ||
					state.DroppedHTTP != 0 || state.RejectedHTTPConnections != 0 || state.RejectedAdminConnections != 0 {
					t.Fatalf("retry accounting: distinct=%d duplicate=%d dropped=%d dataReject=%d adminReject=%d sent=%d",
						len(state.HTTP), state.DuplicateHTTP, state.DroppedHTTP, state.RejectedHTTPConnections,
						state.RejectedAdminConnections, len(requests))
				}
				for _, record := range state.HTTP {
					tls := strings.HasPrefix(record.Route, "/events/grid-")
					if record.TLSDataIngress != tls || record.SyntheticCredentialObserved != tls ||
						len(record.CloudEvents) != 1 || record.CloudEvents[0].Subject == nil ||
						len(record.CloudEvents[0].Subject.MarkerIDs) != 1 {
						t.Fatal("a first occurrence lost TLS, credential, or challenge identity")
					}
				}
				assertCredentialCadenceEvidence(t, state, arm)
			})
		}
	}
}

func assertCredentialCadenceEvidence(t *testing.T, state evidence, arm string) {
	t.Helper()
	initialAttack, finalAttack := false, false
	for _, record := range state.HTTP {
		if record.Route != "/events/grid-credential-attack" {
			continue
		}
		if arm == "candidate" {
			t.Fatal("namespace filtering alone must not permit undelegated cluster-key traffic")
		}
		subject := record.CloudEvents[0].Subject
		initialAttack = initialAttack || subject.SHA256 == wireDigest(publishingSubject(1, 0))
		finalAttack = finalAttack || subject.SHA256 == wireDigest(publishingSubject(1, 1)) &&
			slices.Contains(subject.MarkerIDs, "credential-final-1")
	}
	if arm != "candidate" && (!initialAttack || !finalAttack) {
		t.Fatal("both initial and held-out B-event credential attacks must be positively observed")
	}
}

func TestSetEvidenceRetainsNewWrongHeaderCrossAndFinalSignals(t *testing.T) {
	f := startRetryObserver(t, nil)
	base := retryRequest{subject: 0, channel: "grid-a"}
	endpoint, headers, body, err := retryWire(f, base, 0)
	if err != nil {
		t.Fatal("encode baseline fixture")
	}
	for i := range 300 {
		_, _, varied, err := retryWire(f, base, i)
		if err != nil {
			t.Fatal("encode retry fixture")
		}
		response, err := requestHTTP(f.client, http.MethodPost, endpoint, "", varied, headers)
		if err != nil {
			t.Fatal("send synthetic retry")
		}
		requireStatus(t, response, http.StatusOK)
	}
	before := f.state(t)
	if len(before.HTTP) != 1 || before.DuplicateHTTP != 299 || before.DroppedHTTP != 0 {
		t.Fatal("repeated semantic evidence exhausted its bounded first-occurrence set")
	}
	headers.Del("Aeg-Sas-Key")
	requireStatus(t, f.dataRequest(t, "/events/grid-a", headers, body), http.StatusOK)
	for _, change := range []retryRequest{{subject: 1, channel: "grid-a"}, {round: 1, subject: 0, channel: "grid-a"}} {
		endpoint, headers, body, err = retryWire(f, change, 400)
		if err != nil {
			t.Fatal("encode distinct semantic fixture")
		}
		response, err := requestHTTP(f.client, http.MethodPost, endpoint, "", body, headers)
		if err != nil {
			t.Fatal("send distinct semantic fixture")
		}
		requireStatus(t, response, http.StatusOK)
	}
	after := f.state(t)
	if len(after.HTTP) != 4 || after.HTTP[1].SyntheticCredentialObserved ||
		!reflect.DeepEqual(before.HTTP, after.HTTP[:1]) {
		t.Fatal("deduplication concealed new wrong-header, cross-namespace, or final-challenge evidence")
	}
}

func TestPublishingAdminCapacityIsIndependentAndExhaustionIsExplicit(t *testing.T) {
	f := startRetryObserver(t, func(c *config) { c.Limits.HTTPReadTimeoutMillis = 5000 })
	connections := make([]net.Conn, 0, maxPublishingConnections)
	for range maxPublishingConnections {
		connections = append(connections, dialTest(t, f.config.IngressHTTPSAddress))
	}
	eventually(t, func() bool {
		f.server.ingressTLSLn.mu.Lock()
		defer f.server.ingressTLSLn.mu.Unlock()
		return len(f.server.ingressTLSLn.active) == maxPublishingConnections
	})
	state := f.state(t)
	if state.RejectedHTTPConnections != 0 || state.RejectedAdminConnections != 0 {
		t.Fatal("full data capacity consumed administrative slots")
	}
	excess := dialTest(t, f.config.IngressHTTPAddress)
	requireClosed(t, excess)
	eventually(t, func() bool { return f.state(t).RejectedHTTPConnections == 1 })
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func TestSetEvidenceBoundAndResetPreserveFailureSignals(t *testing.T) {
	f := startRetryObserver(t, func(c *config) { c.Limits.HTTPObservations = 1 })
	request := retryRequest{subject: 0, channel: "grid-a"}
	endpoint, headers, body, err := retryWire(f, request, 0)
	if err != nil {
		t.Fatal("encode fixture")
	}
	for range 2 {
		response, err := requestHTTP(f.client, http.MethodPost, endpoint, "", body, headers)
		if err != nil {
			t.Fatal("send fixture")
		}
		requireStatus(t, response, http.StatusOK)
	}
	headers.Del("Aeg-Sas-Key")
	requireStatus(t, f.dataRequest(t, "/events/grid-a", headers, body), http.StatusOK)
	state := f.state(t)
	if len(state.HTTP) != 1 || state.DuplicateHTTP != 1 || state.DroppedHTTP != 1 {
		t.Fatal("new distinct evidence was silently discarded at capacity")
	}
	requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil), http.StatusOK)
	state = f.state(t)
	if state.Generation != 2 || len(state.HTTP) != 0 || state.DuplicateHTTP != 0 || state.DroppedHTTP != 0 {
		t.Fatal("reset did not clear the bounded semantic index and duplicate accounting")
	}
	requireStatus(t, f.dataRequest(t, "/events/grid-a", headers, body), http.StatusOK)
	state = f.state(t)
	if len(state.HTTP) != 1 || state.HTTP[0].SyntheticCredentialObserved {
		t.Fatal("a previous generation suppressed new evidence")
	}
}

func TestSemanticIdentityIgnoresBodyButRetainsAllObservedMeaning(t *testing.T) {
	record := httpObservation{
		Route: "/events/grid-a", BodySHA256: wireDigest("body one"), TLSDataIngress: true, SyntheticCredentialObserved: true,
		MarkerIDs: []string{"b", "a"},
		CloudEvents: []cloudEventEvidence{{
			Subject: &fieldEvidence{SHA256: wireDigest("subject"), MarkerIDs: []string{"b", "a"}},
			Source:  &fieldEvidence{SHA256: wireDigest("source"), MarkerIDs: []string{}},
		}},
	}
	key := semanticHTTPIdentity(record)
	clone := record
	clone.BodySHA256 = wireDigest("body two")
	clone.MarkerIDs = []string{"a", "b"}
	if key != semanticHTTPIdentity(clone) {
		t.Fatal("retry body or marker order changed semantic identity")
	}
	for _, change := range []func(*httpObservation){
		func(r *httpObservation) { r.Route = "/events/grid-b" },
		func(r *httpObservation) { r.TLSDataIngress = false },
		func(r *httpObservation) { r.SyntheticCredentialObserved = false },
		func(r *httpObservation) { r.CloudEventsTruncated = true },
		func(r *httpObservation) { r.CloudEvents = nil },
	} {
		changed := record
		change(&changed)
		if key == semanticHTTPIdentity(changed) {
			t.Fatal("a distinct failure or route was deduplicated")
		}
	}
	if !bytes.Equal([]byte(record.MarkerIDs[0]), []byte("b")) {
		t.Fatal("computing identity mutated the retained first observation")
	}
}
