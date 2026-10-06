package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func ingressHTTPConnections(server *runningServer) int {
	return activeConnections(server.httpLn) + activeConnections(server.ingressLn)
}

func (f *ingressFixture) waitHTTPIdle(t *testing.T) {
	t.Helper()
	eventually(t, func() bool { return ingressHTTPConnections(f.server) == 0 })
}

func TestIngressRawTargetsNeverProxyOrBypassWhitelist(t *testing.T) {
	f := startIngressObserver(t, nil)
	for _, tc := range []struct{ method, target string }{
		{http.MethodOptions, "*"},
		{http.MethodConnect, f.config.HTTPAddress},
		{http.MethodGet, f.url + "/state"},
		{http.MethodPost, f.url + "/reset"},
	} {
		conn := dialTest(t, f.config.IngressHTTPAddress)
		sendWire(t, conn, fmt.Sprintf("%s %s HTTP/1.1\r\nHost: localhost\r\n"+
			"%s: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			tc.method, tc.target, adminHeader, f.admin))
		requireHTTPReply(t, bufio.NewReader(conn), http.StatusNotFound)
	}
	state := f.state(t)
	if state.Generation != 1 || len(state.HTTP) != 0 || len(state.RESP) != 0 {
		t.Fatal("non-origin or unconfigured ingress targets reached the admin server or evidence store")
	}
}

func TestIngressAndTLSShareConnectionQuota(t *testing.T) {
	for _, holdTLS := range []bool{false, true} {
		name := "ingress-holds-slot"
		if holdTLS {
			name = "tls-handshake-holds-slot"
		}
		t.Run(name, func(t *testing.T) {
			f := startIngressObserver(t, func(cfg *config) {
				cfg.Limits.HTTPConnections = 1
				cfg.Limits.HTTPReadTimeoutMillis = 5000
			})
			heldAddress, rejectedAddress := f.config.IngressHTTPAddress, f.config.HTTPAddress
			if holdTLS {
				heldAddress, rejectedAddress = rejectedAddress, heldAddress
			}
			held := dialTest(t, heldAddress)
			eventually(t, func() bool { return ingressHTTPConnections(f.server) == 1 })
			excess := dialTest(t, rejectedAddress)
			if len(requireClosed(t, excess)) != 0 {
				t.Fatal("a second HTTP listener bypassed the global connection quota")
			}
			eventually(t, func() bool {
				return f.server.observer.store.snapshot().RejectedHTTPConnections == 1
			})
			_ = held.Close()
			f.waitHTTPIdle(t)
			if f.state(t).RejectedHTTPConnections != 1 {
				t.Fatal("shared HTTP rejection counter did not count the rejected cross-listener connection")
			}
			f.waitHTTPIdle(t)
			requireStatus(t, f.ingressRequest(t, http.MethodPost, "/metric", "", nil, nil), http.StatusOK)
			f.waitHTTPIdle(t)
			requireStatus(t, f.request(t, http.MethodPost, "/metric", "", nil, nil), http.StatusOK)
			f.waitHTTPIdle(t)
			if len(f.state(t).HTTP) != 2 {
				t.Fatal("either listener failed to recover a released global connection slot")
			}
		})
	}
}

func TestIngressConcurrentConnectionCap(t *testing.T) {
	const limit, attempts = 4, 16
	f := startIngressObserver(t, func(cfg *config) {
		cfg.Limits.HTTPConnections = limit
		cfg.Limits.HTTPReadTimeoutMillis = 5000
	})
	start := make(chan struct{})
	results := make(chan net.Conn, attempts)
	errs := make(chan error, attempts)
	var clients sync.WaitGroup
	for index := range attempts {
		address := f.config.IngressHTTPAddress
		if index%2 == 0 {
			address = f.config.HTTPAddress
		}
		clients.Go(func() {
			<-start
			conn, err := net.DialTimeout("tcp", address, testDeadline)
			results <- conn
			errs <- err
		})
	}
	close(start)
	clients.Wait()
	close(results)
	close(errs)
	connections := make([]net.Conn, 0, attempts)
	for conn := range results {
		if conn != nil {
			connections = append(connections, conn)
			t.Cleanup(func() { _ = conn.Close() })
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal("concurrent synthetic client could not dial a listener")
		}
	}
	eventually(t, func() bool {
		state := f.server.observer.store.snapshot()
		return uint64(ingressHTTPConnections(f.server))+state.RejectedHTTPConnections == attempts
	})
	if ingressHTTPConnections(f.server) != limit {
		t.Fatal("concurrent accepts exceeded or underfilled the global HTTP connection cap")
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	f.waitHTTPIdle(t)
	state := f.state(t)
	if state.RejectedHTTPConnections != attempts-limit || len(state.HTTP) != 0 {
		t.Fatal("shared HTTP connection accounting diverged from actual bounded admission")
	}
}

func TestIngressAndTLSShareBodyAndObservationLimits(t *testing.T) {
	f := startIngressObserver(t, func(cfg *config) {
		cfg.Limits.HTTPBodyBytes = 64
		cfg.Limits.HTTPObservations = 2
	})
	for index, url := range []string{f.ingressURL, f.url, f.ingressURL, f.url} {
		size := 63 + index%2
		body := bytes.Repeat([]byte{0xc3, 0xa9}, 33)[:size]
		response, err := requestHTTP(f.client, http.MethodPost, url+"/metric", "", body, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireStatus(t, response, http.StatusOK)
	}
	for _, url := range []string{f.ingressURL, f.url} {
		body := bytes.Repeat([]byte{0xc3, 0xa9}, 33)[:65]
		request, err := http.NewRequest(http.MethodPost, url+"/metric", bytes.NewReader(body))
		if err != nil {
			t.Fatal("create shared body-limit request")
		}
		request.ContentLength = -1
		response, err := exchangeHTTP(f.client, request)
		if err != nil {
			t.Fatal(err)
		}
		requireStatus(t, response, http.StatusRequestEntityTooLarge)
	}
	state := f.state(t)
	if len(state.HTTP) != 2 || state.DroppedHTTP != 2 {
		t.Fatal("listeners did not share the body bound, evidence quota, and dropped-HTTP counter")
	}
	requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil),
		http.StatusOK)
	state = f.state(t)
	if state.Generation != 2 || len(state.HTTP) != 0 || state.DroppedHTTP != 0 {
		t.Fatal("HTTPS reset did not clear shared ingress evidence and counters")
	}
}

func TestIngressBodyCannotCrossHTTPSReset(t *testing.T) {
	f := startIngressObserver(t, nil)
	body := f.config.Markers[0].Value
	conn, reader := beginHTTPBody(t, f.config.IngressHTTPAddress, len(body))
	requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil),
		http.StatusOK)
	sendWire(t, conn, body)
	requireHTTPReply(t, reader, http.StatusOK)
	state := f.state(t)
	if state.Generation != 2 || len(state.HTTP) != 0 {
		t.Fatal("an in-flight plaintext body contaminated the HTTPS-reset generation")
	}
	requireStatus(t, f.ingressRequest(t, http.MethodPost, "/events/alpha", "", []byte(body),
		http.Header{"Aeg-Sas-Key": {f.canary}}), http.StatusOK)
	state = f.state(t)
	if len(state.HTTP) != 1 || !state.HTTP[0].SyntheticCredentialObserved {
		t.Fatal("fresh plaintext canary control failed after HTTPS reset")
	}
}

func TestIngressSlowClientDeadline(t *testing.T) {
	f := startIngressObserver(t, func(cfg *config) { cfg.Limits.HTTPReadTimeoutMillis = 150 })
	conn, _ := beginHTTPBody(t, f.config.IngressHTTPAddress, 100)
	sendWire(t, conn, "x")
	start := time.Now()
	requireClosed(t, conn)
	if time.Since(start) > time.Second {
		t.Fatal("plaintext ingress did not inherit the bounded HTTP read deadline")
	}
	if len(f.state(t).HTTP) != 0 {
		t.Fatal("partial plaintext ingress became evidence")
	}
}

func TestIngressShutdownReapsAllListenersAtCapacity(t *testing.T) {
	f := startIngressObserver(t, func(cfg *config) {
		cfg.Limits.HTTPConnections = 4
		cfg.Limits.HTTPReadTimeoutMillis = 5000
		cfg.Limits.RESPReadTimeoutMillis = 5000
		cfg.Limits.ShutdownTimeoutMillis = 300
	})
	body, _ := beginHTTPBody(t, f.config.IngressHTTPAddress, 100)
	tlsBody, err := tls.DialWithDialer(&net.Dialer{Timeout: testDeadline},
		"tcp", f.config.HTTPAddress, f.clientTLS.Clone())
	if err != nil {
		t.Fatal("connect verified TLS body client")
	}
	t.Cleanup(func() { _ = tlsBody.Close() })
	if err := tlsBody.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatal("set TLS body client deadline")
	}
	beginHTTPBodyOnConn(t, tlsBody, 100)
	handshake := dialTest(t, f.config.HTTPAddress)
	headers := dialTest(t, f.config.IngressHTTPAddress)
	sendWire(t, headers, "POST /metric HTTP/1.1\r\nHost: ")
	resp := dialTest(t, f.config.RESPAddress)
	sendWire(t, resp, respFrame("PING"))
	requireWire(t, resp, "+PONG\r\n")
	sendWire(t, resp, "*1\r\n$4\r\nPI")
	eventually(t, func() bool {
		return ingressHTTPConnections(f.server) == 4 && activeConnections(f.server.respLn) == 1
	})
	excess := dialTest(t, f.config.IngressHTTPAddress)
	requireClosed(t, excess)
	start := time.Now()
	if err := f.stop(); err != nil {
		t.Fatalf("shutdown split listeners at capacity: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("shutdown waited for the five-second HTTP/RESP deadlines")
	}
	for _, conn := range []net.Conn{body, tlsBody, handshake, headers, resp} {
		requireClosed(t, conn)
	}
	if ingressHTTPConnections(f.server) != 0 || activeConnections(f.server.respLn) != 0 ||
		len(f.server.httpLn.slots) != 0 || len(f.server.respLn.slots) != 0 {
		t.Fatal("shutdown leaked tracked connections or global admission slots")
	}
	for _, address := range []string{f.config.HTTPAddress, f.config.IngressHTTPAddress, f.config.RESPAddress} {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Fatal("shutdown left an accepting listener")
		}
	}
}

func TestIngressStartupFailureClosesOtherListeners(t *testing.T) {
	f, release := newIngressConfig(t)
	release()
	blocker, err := net.Listen("tcp", f.config.IngressHTTPAddress)
	if err != nil {
		t.Fatal("occupy reserved ingress port")
	}
	t.Cleanup(func() { _ = blocker.Close() })
	if server, err := startServer(f.config); err == nil {
		_ = server.shutdown()
		t.Fatal("startup ignored an occupied ingress port")
	}
	for _, address := range []string{f.config.HTTPAddress, f.config.RESPAddress} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("ingress startup failure leaked another protocol listener")
		}
		_ = listener.Close()
	}
	_ = blocker.Close()
	f.server, err = startServer(f.config)
	if err != nil {
		t.Fatal("startup did not recover after releasing the ingress port")
	}
	t.Cleanup(func() {
		if err := f.stop(); err != nil {
			t.Errorf("cleanup recovered ingress server: %v", err)
		}
	})
	requireStatus(t, f.ingressRequest(t, http.MethodPost, "/metric", "", nil, nil), http.StatusOK)
	if len(f.state(t).HTTP) != 1 {
		t.Fatal("recovered ingress listener did not share the admin evidence store")
	}
}

func TestIngressConcurrentTrafficResetAndShutdown(t *testing.T) {
	f := startIngressObserver(t, func(cfg *config) {
		cfg.Limits.HTTPObservations = 4
		cfg.Limits.RESPObservations = 4
	})
	errs := make(chan error, 4)
	var writers sync.WaitGroup
	for range 4 {
		writers.Go(func() {
			for range 8 {
				response, err := requestHTTP(f.client, http.MethodPost, f.ingressURL+"/events/alpha", "",
					[]byte(f.config.Markers[0].Value), http.Header{"Aeg-Sas-Key": {f.canary}})
				if err != nil || response.status != http.StatusOK {
					errs <- errors.New("concurrent plaintext ingress failed")
					return
				}
			}
			errs <- nil
		})
	}
	exerciseConcurrentTraffic(t, f.testObserver, 4, 8, true)
	writers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	state := f.state(t)
	if state.Generation != 9 || len(state.HTTP) > 4 || len(state.RESP) > 4 ||
		state.RejectedHTTPConnections != 0 {
		t.Fatal("concurrent listeners violated the shared generation, evidence quota, or connection cap")
	}
	if err := f.stop(); err != nil {
		t.Fatal("shutdown failed after concurrent cross-listener resets")
	}
}

func TestIngressImmediateShutdownJoinsServers(t *testing.T) {
	for range 5 {
		f := startIngressObserver(t, nil)
		if err := f.stop(); err != nil {
			t.Fatal("shutdown racing with split-listener startup failed")
		}
		if ingressHTTPConnections(f.server) != 0 || len(f.server.httpLn.slots) != 0 {
			t.Fatal("immediate split-listener shutdown retained a connection slot")
		}
	}
}

func TestIngressListenerFailureIsReported(t *testing.T) {
	f := startIngressObserver(t, nil)
	requireStatus(t, f.ingressRequest(t, http.MethodGet, "/healthz", "", nil, nil), http.StatusOK)
	if err := f.server.ingressLn.Listener.Close(); err != nil {
		t.Fatal("interrupt the ingress listener")
	}
	select {
	case <-f.server.failures:
	case <-time.After(testDeadline):
		t.Fatal("ingress listener failure was not reported to the command lifecycle")
	}
	if err := f.stop(); err != nil {
		t.Fatal("shutdown failed after an ingress listener failure")
	}
}

func TestIngressCannotEnableWithoutValidAdminTLS(t *testing.T) {
	for _, mode := range []string{"missing", "invalid-key", "public-key-file"} {
		t.Run(mode, func(t *testing.T) {
			f, release := newIngressConfig(t)
			release()
			switch mode {
			case "missing":
				f.config.TLS = tlsFiles{}
			case "invalid-key":
				f.config.TLS.KeyFile += ".invalid"
				writeTestFile(t, f.config.TLS.KeyFile, []byte(strings.Repeat("synthetic-invalid-key", 4)), 0400)
			case "public-key-file":
				if err := os.Chmod(f.config.TLS.KeyFile, 0444); err != nil {
					t.Fatal("make synthetic TLS key world-readable for rejection test")
				}
			}
			if server, err := startServer(f.config); err == nil {
				_ = server.shutdown()
				t.Fatal("plaintext ingress started without a private valid HTTPS admin identity")
			}
		})
	}
}
