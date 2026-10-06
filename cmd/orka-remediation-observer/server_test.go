package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func beginHTTPBody(t *testing.T, address string, size int) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn := dialTest(t, address)
	return beginHTTPBodyOnConn(t, conn, size)
}

func beginHTTPBodyOnConn(t *testing.T, conn net.Conn, size int) (net.Conn, *bufio.Reader) {
	t.Helper()
	sendWire(t, conn, fmt.Sprintf("POST /metric HTTP/1.1\r\nHost: localhost\r\n"+
		"Content-Length: %d\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n", size))
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read continue response: %T", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusContinue {
		t.Fatal("server did not begin reading the fenced HTTP body")
	}
	return conn, reader
}

func requireHTTPReply(t *testing.T, reader *bufio.Reader, status int) {
	t.Helper()
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read HTTP reply: %T", err)
	}
	defer func() { _ = response.Body.Close() }()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatalf("drain HTTP reply: %T", err)
	}
	if response.StatusCode != status {
		t.Fatalf("HTTP status = %d, want %d", response.StatusCode, status)
	}
}

func TestResetFencesInFlightHTTPAndRESP(t *testing.T) {
	f := startTestObserver(t, nil)
	body := f.config.Markers[0].Value
	httpConn, httpReader := beginHTTPBody(t, f.config.HTTPAddress, len(body))
	respConn := dialTest(t, f.config.RESPAddress)
	sendWire(t, respConn, respFrame("PING"))
	requireWire(t, respConn, "+PONG\r\n")

	// A 100 Continue response proves receive captured its generation before reset.
	response := f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil)
	requireStatus(t, response, http.StatusOK)
	sendWire(t, httpConn, body)
	requireHTTPReply(t, httpReader, http.StatusOK)
	sendWire(t, respConn, respFrame("AUTH", f.canary))
	requireWire(t, respConn, "+OK\r\n")
	state := f.state(t)
	if state.Generation != 2 || len(state.HTTP) != 0 || len(state.RESP) != 0 {
		t.Fatal("requests or RESP connections admitted before reset contaminated the new generation")
	}
	requireStatus(t, f.request(t, http.MethodPost, "/metric", "", []byte(body),
		http.Header{"Aeg-Sas-Key": {f.canary}}), http.StatusOK)
	freshRESP := dialTest(t, f.config.RESPAddress)
	sendWire(t, freshRESP, respFrame("AUTH", f.canary))
	requireWire(t, freshRESP, "+OK\r\n")
	state = f.state(t)
	if len(state.HTTP) != 1 || len(state.RESP) != 1 ||
		!state.HTTP[0].SyntheticCredentialObserved || !state.RESP[0].SyntheticCredentialObserved ||
		state.DroppedHTTP != 0 || state.DroppedRESP != 0 {
		t.Fatal("fresh positive controls failed after generation fencing")
	}
}

func TestSlowClientsAreBounded(t *testing.T) {
	for _, protocol := range []string{"http-headers", "http-body", "resp-frame"} {
		t.Run(protocol, func(t *testing.T) {
			f := startTestObserver(t, func(cfg *config) {
				cfg.Limits.HTTPReadTimeoutMillis = 150
				cfg.Limits.RESPReadTimeoutMillis = 150
			})
			var conn net.Conn
			switch protocol {
			case "http-headers":
				conn = dialTest(t, f.config.HTTPAddress)
				sendWire(t, conn, "POST /metric HTTP/1.1\r\nHost: localhost\r\n")
			case "http-body":
				conn, _ = beginHTTPBody(t, f.config.HTTPAddress, 52)
				sendWire(t, conn, "x")
			case "resp-frame":
				conn = dialTest(t, f.config.RESPAddress)
				sendWire(t, conn, "*2\r\n$4\r\nAUTH\r\n$52\r\nx")
			}
			start := time.Now()
			requireClosed(t, conn)
			if time.Since(start) > time.Second {
				t.Fatal("slow client outlived the configured 150ms read budget")
			}
			state := f.state(t)
			if len(state.HTTP) != 0 || len(state.RESP) != 0 {
				t.Fatal("incomplete slow-client input became evidence")
			}
			requireStatus(t, f.request(t, http.MethodPost, "/metric", "", nil, nil), http.StatusOK)
			control := dialTest(t, f.config.RESPAddress)
			sendWire(t, control, respFrame("PING"))
			requireWire(t, control, "+PONG\r\n")
			state = f.state(t)
			if len(state.HTTP) != 1 || len(state.RESP) != 1 {
				t.Fatal("normal controls failed after a slow client was reaped")
			}
		})
	}
}

func TestConnectionQuotaAndSlotRecovery(t *testing.T) {
	for _, resp := range []bool{false, true} {
		name := "HTTP"
		if resp {
			name = "RESP"
		}
		t.Run(name, func(t *testing.T) {
			f := startTestObserver(t, func(cfg *config) {
				cfg.Limits.HTTPConnections = 1
				cfg.Limits.RESPConnections = 1
			})
			address, listener := f.config.HTTPAddress, f.server.httpLn
			if resp {
				address, listener = f.config.RESPAddress, f.server.respLn
			}
			first := dialTest(t, address)
			if resp {
				sendWire(t, first, respFrame("PING"))
				requireWire(t, first, "+PONG\r\n")
			} else {
				sendWire(t, first, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
				requireHTTPReply(t, bufio.NewReader(first), http.StatusOK)
			}
			eventually(t, func() bool { return activeConnections(listener) == 1 })
			excess := dialTest(t, address)
			if len(requireClosed(t, excess)) != 0 {
				t.Fatal("excess connection was served rather than rejected")
			}
			if err := first.Close(); err != nil {
				t.Fatal("close occupied connection slot")
			}
			eventually(t, func() bool { return activeConnections(listener) == 0 })
			eventually(t, func() bool {
				state := f.state(t)
				if resp {
					return state.RejectedRESPConnections == 1 && state.RejectedHTTPConnections == 0
				}
				return state.RejectedHTTPConnections == 1 && state.RejectedRESPConnections == 0
			})
			eventually(t, func() bool { return activeConnections(listener) == 0 })
			replacement := dialTest(t, address)
			if resp {
				sendWire(t, replacement, respFrame("PING"))
				requireWire(t, replacement, "+PONG\r\n")
			} else {
				sendWire(t, replacement, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
				requireHTTPReply(t, bufio.NewReader(replacement), http.StatusOK)
			}
			_ = replacement.Close()
			eventually(t, func() bool { return activeConnections(listener) == 0 })
			response := f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil)
			requireStatus(t, response, http.StatusOK)
			state := decodeState(t, response.body)
			if state.Generation != 2 || len(state.HTTP) != 0 || len(state.RESP) != 0 ||
				state.RejectedHTTPConnections != 0 || state.RejectedRESPConnections != 0 {
				t.Fatal("reset retained connection-rejection counters or prior observations")
			}
		})
	}
}

func TestShutdownReapsStalledConnections(t *testing.T) {
	f := startTestObserver(t, func(cfg *config) {
		cfg.Limits.HTTPReadTimeoutMillis = 5000
		cfg.Limits.RESPReadTimeoutMillis = 5000
		cfg.Limits.ShutdownTimeoutMillis = 300
	})
	body, _ := beginHTTPBody(t, f.config.HTTPAddress, 100)
	headers := dialTest(t, f.config.HTTPAddress)
	sendWire(t, headers, "POST /metric HTTP/1.1\r\nHost: ")
	resp := dialTest(t, f.config.RESPAddress)
	sendWire(t, resp, respFrame("PING"))
	requireWire(t, resp, "+PONG\r\n")
	sendWire(t, resp, "*2\r\n$4\r\nAUTH\r\n$52\r\nx")
	eventually(t, func() bool {
		return activeConnections(f.server.httpLn) == 2 && activeConnections(f.server.respLn) == 1
	})
	start := time.Now()
	if err := f.stop(); err != nil {
		t.Fatalf("shutdown with stalled readers: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("shutdown waited for the five-second connection deadlines")
	}
	for _, conn := range []net.Conn{body, headers, resp} {
		requireClosed(t, conn)
	}
	if activeConnections(f.server.httpLn) != 0 || activeConnections(f.server.respLn) != 0 {
		t.Fatal("shutdown retained tracked connections")
	}
	for _, address := range []string{f.config.HTTPAddress, f.config.RESPAddress} {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Fatal("shutdown left an accepting listener")
		}
	}
}

func TestImmediateShutdownJoinsServers(t *testing.T) {
	for range 10 {
		f := startTestObserver(t, nil)
		if err := f.stop(); err != nil {
			t.Fatalf("shutdown racing with listener startup: %v", err)
		}
		if activeConnections(f.server.httpLn) != 0 || activeConnections(f.server.respLn) != 0 {
			t.Fatal("immediate shutdown leaked a connection")
		}
	}
}
