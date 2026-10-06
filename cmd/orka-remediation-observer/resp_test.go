package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestRESPCanaryAndOwnNormalControl(t *testing.T) {
	f := startTestObserver(t, nil)
	conn := dialTest(t, f.config.RESPAddress)
	hello := "%2\r\n+server\r\n+synthetic-observer\r\n+proto\r\n:3\r\n"
	cases := []struct {
		args     []string
		response string
		command  string
		canary   bool
	}{
		{[]string{"AUTH", f.control}, "+OK\r\n", "AUTH", false},
		{[]string{"AUTH", f.canary}, "+OK\r\n", "AUTH", true},
		{[]string{"aUtH", "synthetic-user", f.canary}, "+OK\r\n", "AUTH", true},
		{[]string{"AUTH", f.canary + "-suffix"}, "+OK\r\n", "AUTH", false},
		{[]string{"HELLO", "3", "AUTH", "synthetic-user", f.canary}, hello, "HELLO", true},
		{[]string{"HELLO", "3", "AUTH", "synthetic-user", f.control}, hello, "HELLO", false},
		{[]string{"HELLO", "2"}, "-ERR unsupported\r\n", "HELLO", false},
		{[]string{"PING", f.canary}, "+PONG\r\n", "PING", false},
		{[]string{"CLIENT", "SETNAME", f.canary}, "+OK\r\n", "CLIENT", false},
		{[]string{"SELECT", f.control}, "+OK\r\n", "SELECT", false},
		{[]string{f.canary, f.control}, "-ERR unsupported\r\n", "UNKNOWN", false},
		{[]string{""}, "-ERR unsupported\r\n", "UNKNOWN", false},
	}
	for _, tc := range cases {
		sendWire(t, conn, respFrame(tc.args...))
		requireWire(t, conn, tc.response)
	}
	state := f.state(t)
	if len(state.RESP) != len(cases) || len(state.HTTP) != 0 {
		t.Fatal("RESP observations did not match the acknowledged commands")
	}
	for index, tc := range cases {
		got := state.RESP[index]
		if got.Command != tc.command || got.SyntheticCredentialObserved != tc.canary {
			t.Fatalf("command %d lost digest-positive evidence or falsely marked its own control", index)
		}
	}
	response := f.request(t, http.MethodGet, "/state", f.admin, nil, nil)
	var document struct {
		RESP []json.RawMessage `json:"resp"`
	}
	if err := json.Unmarshal(response.body, &document); err != nil || len(document.RESP) != len(cases) {
		t.Fatal("RESP evidence array missing on the wire")
	}
	for _, observation := range document.RESP {
		requireJSONKeys(t, observation, "command", "syntheticCredentialObserved")
	}
	assertNoDisclosure(t, response.body, f.admin, f.canary, f.control, "synthetic-user")
}

func TestRESPRejectsMalformedAndOversizedFrames(t *testing.T) {
	f := startTestObserver(t, nil)
	cases := []struct {
		name      string
		frame     string
		halfClose bool
	}{
		{"empty-array", "*0\r\n", false},
		{"negative-array", "*-1\r\n", false},
		{"oversized-array", "*17\r\n", false},
		{"overflow-array", "*999999999999999999999\r\n", false},
		{"signed-array", "*+1\r\n", false},
		{"nondecimal-array", "*x\r\n", false},
		{"array-without-cr", "*1\n", false},
		{"inline-command", "PING\r\n", false},
		{"nonbulk-argument", "*1\r\n+PING\r\n", false},
		{"negative-bulk", "*1\r\n$-1\r\n", false},
		{"oversized-bulk", "*1\r\n$65537\r\n", false},
		{"nondecimal-bulk", "*1\r\n$4x\r\n", false},
		{"invalid-bulk-terminator", "*1\r\n$4\r\nPINGxx", false},
		{"truncated-bulk", "*1\r\n$4\r\nPIN", true},
		{"truncated-array", "*2\r\n$4\r\nPING\r\n", true},
		{"overlong-length", "*" + strings.Repeat("9", 600) + "\r\n", false},
		{"malformed-before-valid-pipeline", "*0\r\n" + respFrame("PING"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := dialTest(t, f.config.RESPAddress)
			sendWire(t, conn, tc.frame)
			if tc.halfClose {
				tcp, ok := conn.(*net.TCPConn)
				if !ok {
					t.Fatal("expected a real TCP client")
				}
				if err := tcp.CloseWrite(); err != nil {
					t.Fatal("half-close malformed frame")
				}
			}
			requireWire(t, conn, "-ERR malformed frame\r\n")
			if len(requireClosed(t, conn)) != 0 {
				t.Fatal("observer continued processing after a malformed frame")
			}
			state := f.state(t)
			if len(state.RESP) != 0 || state.DroppedRESP != 0 {
				t.Fatal("malformed input was admitted as a RESP observation")
			}
		})
	}
	conn := dialTest(t, f.config.RESPAddress)
	args := append([]string{"CLIENT"}, make([]string, 15)...)
	sendWire(t, conn, respFrame(args...))
	requireWire(t, conn, "+OK\r\n")
	sendWire(t, conn, respFrame("PING"))
	requireWire(t, conn, "+PONG\r\n")
	if len(f.state(t).RESP) != 2 {
		t.Fatal("valid maximum-width frame or normal control failed after malformed traffic")
	}
}

func TestRESPByteBudgetBoundaries(t *testing.T) {
	frame := respFrame("PING")
	for _, limit := range []int{len(frame) - 1, len(frame), len(frame) + 1} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			f := startTestObserver(t, func(cfg *config) {
				cfg.Limits.RESPBytes = limit
				cfg.Limits.RESPCommands = 1
			})
			conn := dialTest(t, f.config.RESPAddress)
			sendWire(t, conn, frame)
			want, observations := "+PONG\r\n", 1
			if limit < len(frame) {
				want, observations = "-ERR malformed frame\r\n", 0
			}
			requireWire(t, conn, want)
			if len(requireClosed(t, conn)) != 0 || len(f.state(t).RESP) != observations {
				t.Fatal("RESP byte budget boundary was not enforced against the encoded frame")
			}
		})
	}
}

func TestRESPBudgetsArePerConnection(t *testing.T) {
	t.Run("cumulative-bytes", func(t *testing.T) {
		frame := respFrame("PING")
		f := startTestObserver(t, func(cfg *config) { cfg.Limits.RESPBytes = 2*len(frame) - 1 })
		conn := dialTest(t, f.config.RESPAddress)
		sendWire(t, conn, frame+frame)
		requireWire(t, conn, "+PONG\r\n-ERR malformed frame\r\n")
		requireClosed(t, conn)
		state := f.state(t)
		if len(state.RESP) != 1 || state.DroppedRESP != 0 {
			t.Fatal("RESP byte budget was reset for each pipelined frame")
		}
	})
	t.Run("command-count", func(t *testing.T) {
		f := startTestObserver(t, func(cfg *config) { cfg.Limits.RESPCommands = 2 })
		conn := dialTest(t, f.config.RESPAddress)
		sendWire(t, conn, strings.Repeat(respFrame("PING"), 3))
		requireWire(t, conn, "+PONG\r\n+PONG\r\n")
		if len(requireClosed(t, conn)) != 0 {
			t.Fatal("observer acknowledged a command beyond its connection quota")
		}
		state := f.state(t)
		if len(state.RESP) != 2 || state.DroppedRESP != 0 {
			t.Fatal("observer admitted a command beyond its connection quota")
		}
	})
}
