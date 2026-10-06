package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func concurrentTraffic(f *testObserver, rounds int) error {
	conn, err := net.DialTimeout("tcp", f.config.RESPAddress, testDeadline)
	if err != nil {
		return errors.New("concurrent RESP dial failed")
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		return errors.New("concurrent RESP deadline failed")
	}
	for range rounds {
		response, err := requestHTTP(f.client, http.MethodPost, f.url+"/metric", "",
			[]byte(f.config.Markers[0].Value), http.Header{"Aeg-Sas-Key": {f.canary}})
		if err != nil || response.status != http.StatusOK {
			return errors.New("concurrent HTTP ingress failed")
		}
		if _, err := io.WriteString(conn, respFrame("AUTH", f.canary)); err != nil {
			return errors.New("concurrent RESP write failed")
		}
		reply := make([]byte, 5)
		if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "+OK\r\n" {
			return errors.New("concurrent RESP acknowledgement failed")
		}
	}
	return nil
}

func concurrentSnapshots(f *testObserver, stop <-chan struct{}) error {
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		response, err := requestHTTP(f.client, http.MethodGet, f.url+"/state", f.admin, nil, nil)
		if err != nil || response.status != http.StatusOK {
			return errors.New("concurrent state request failed")
		}
		var state evidence
		if json.Unmarshal(response.body, &state) != nil || state.RunID != f.config.RunID ||
			state.Generation == 0 || state.HTTP == nil || state.RESP == nil ||
			len(state.HTTP) > f.config.Limits.HTTPObservations || len(state.RESP) > f.config.Limits.RESPObservations {
			return errors.New("concurrent snapshot violated identity or observation quotas")
		}
	}
}

func concurrentResets(f *testObserver, rounds int) error {
	for range rounds {
		response, err := requestHTTP(f.client, http.MethodGet, f.url+"/state", f.admin, nil, nil)
		if err != nil || response.status != http.StatusOK {
			return errors.New("read reset fence during concurrent ingress")
		}
		var state evidence
		if json.Unmarshal(response.body, &state) != nil {
			return errors.New("decode reset fence during concurrent ingress")
		}
		response, err = requestHTTP(f.client, http.MethodPost, f.url+"/reset", f.admin,
			resetBody(f.config.RunID, state.Generation), nil)
		if err != nil || response.status != http.StatusOK {
			return errors.New("reset during concurrent ingress")
		}
	}
	return nil
}

func exerciseConcurrentTraffic(t *testing.T, f *testObserver, workers, rounds int, reset bool) {
	t.Helper()
	stop := make(chan struct{})
	reader := make(chan error, 1)
	go func() { reader <- concurrentSnapshots(f, stop) }()
	errs := make(chan error, workers+2)
	var writers sync.WaitGroup
	for range workers {
		writers.Go(func() { errs <- concurrentTraffic(f, rounds) })
	}
	if reset {
		writers.Go(func() { errs <- concurrentResets(f, rounds) })
	}
	writers.Wait()
	close(stop)
	errs <- <-reader
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestConcurrentObservationQuotas(t *testing.T) {
	f := startTestObserver(t, func(cfg *config) {
		cfg.Limits.HTTPObservations = 4
		cfg.Limits.RESPObservations = 4
	})
	exerciseConcurrentTraffic(t, f, 8, 4, false)
	state := f.state(t)
	if state.Generation != 1 || len(state.HTTP) != 4 || len(state.RESP) != 4 ||
		state.DroppedHTTP != 28 || state.DroppedRESP != 28 ||
		state.RejectedHTTPConnections != 0 || state.RejectedRESPConnections != 0 {
		t.Fatal("concurrent ingress lost observations or exceeded bounded storage")
	}
	response := f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil)
	requireStatus(t, response, http.StatusOK)
	state = decodeState(t, response.body)
	if state.Generation != 2 || len(state.HTTP) != 0 || len(state.RESP) != 0 ||
		state.DroppedHTTP != 0 || state.DroppedRESP != 0 ||
		state.RejectedHTTPConnections != 0 || state.RejectedRESPConnections != 0 {
		t.Fatal("reset did not clear all quota counters and observations")
	}
}

func TestConcurrentIngressStateAndResets(t *testing.T) {
	f := startTestObserver(t, func(cfg *config) {
		cfg.Limits.HTTPObservations = 4
		cfg.Limits.RESPObservations = 4
	})
	exerciseConcurrentTraffic(t, f, 4, 8, true)
	state := f.state(t)
	if state.Generation != 9 {
		t.Fatal("concurrent reset sequence lost an epoch")
	}
	requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin,
		resetBody(f.config.RunID, state.Generation), nil), http.StatusOK)
	if err := concurrentTraffic(f, 1); err != nil {
		t.Fatal(err)
	}
	state = f.state(t)
	if state.Generation != 10 || len(state.HTTP) != 1 || len(state.RESP) != 1 ||
		!state.HTTP[0].SyntheticCredentialObserved || !state.RESP[0].SyntheticCredentialObserved ||
		state.DroppedHTTP != 0 || state.DroppedRESP != 0 {
		t.Fatal("fresh positive controls failed after concurrent ingress and resets")
	}
}

func TestConcurrentResetCompareAndSwap(t *testing.T) {
	f := startTestObserver(t, nil)
	const clients = 12
	start := make(chan struct{})
	results := make(chan wireResponse, clients)
	errs := make(chan error, clients)
	var group sync.WaitGroup
	for range clients {
		group.Go(func() {
			<-start
			response, err := requestHTTP(f.client, http.MethodPost, f.url+"/reset", f.admin,
				resetBody(f.config.RunID, 1), nil)
			results <- response
			errs <- err
		})
	}
	close(start)
	group.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	successes, conflicts := 0, 0
	for response := range results {
		switch response.status {
		case http.StatusOK:
			successes++
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("concurrent reset status = %d", response.status)
		}
	}
	if successes != 1 || conflicts != clients-1 || f.state(t).Generation != 2 {
		t.Fatal("reset was not a single-winner compare-and-swap on the exact run generation")
	}
}

func TestEvidenceCountersAndGenerationDoNotWrap(t *testing.T) {
	value := ^uint64(0) - 1
	increment(&value)
	increment(&value)
	if value != ^uint64(0) {
		t.Fatal("observation counter overflowed instead of saturating")
	}
	store := newEvidenceStore(testConfig(syntheticValue()))
	store.state.Generation = ^uint64(0)
	if _, ok := store.reset(store.state.RunID, ^uint64(0)); ok {
		t.Fatal("reset wrapped the generation fence")
	}
	store.recordHTTP(0, httpObservation{Route: "/metric"})
	store.recordRESP(0, respObservation{Command: "PING"})
	state := store.snapshot()
	if state.Generation != ^uint64(0) || len(state.HTTP) != 0 || len(state.RESP) != 0 {
		t.Fatal("generation wraparound admitted stale observations")
	}
}
