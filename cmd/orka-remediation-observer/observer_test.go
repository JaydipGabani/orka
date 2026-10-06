package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const testDeadline = 3 * time.Second

type testObserver struct {
	server  *runningServer
	config  config
	admin   string
	canary  string
	control string
	client  *http.Client
	url     string
	once    sync.Once
	stopErr error
}

type wireResponse struct {
	status int
	header http.Header
	body   []byte
}

func syntheticValue() string {
	return rand.Text() + rand.Text()
}

func wireDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func testConfig(canary string) config {
	cfg := defaultConfig()
	cfg.SchemaVersion = "v1"
	cfg.RunID = "synthetic-run"
	cfg.HTTPAddress = "127.0.0.1:18080"
	cfg.RESPAddress = "127.0.0.1:18081"
	cfg.AdminTokenFile = "synthetic-admin.key"
	cfg.SyntheticCanarySHA256 = wireDigest(canary)
	cfg.Markers = []markerConfig{
		{ID: "first-marker", Value: syntheticValue()},
		{ID: "second-marker", Value: syntheticValue()},
	}
	cfg.Channels = []string{"alpha", "beta"}
	cfg.Limits.HTTPReadTimeoutMillis = 2500
	cfg.Limits.RESPReadTimeoutMillis = 2500
	cfg.Limits.ShutdownTimeoutMillis = 500
	return cfg
}

func testListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func startTestObserver(t *testing.T, change func(*config)) *testObserver {
	t.Helper()
	f := &testObserver{admin: syntheticValue(), canary: syntheticValue(), control: syntheticValue()}
	f.config = testConfig(f.canary)
	httpLn, respLn := testListener(t), testListener(t)
	f.config.HTTPAddress, f.config.RESPAddress = httpLn.Addr().String(), respLn.Addr().String()
	if change != nil {
		change(&f.config)
	}
	if err := f.config.validate(); err != nil {
		t.Fatalf("invalid test configuration: %v", err)
	}
	o := newObserver(f.config, sha256.Sum256([]byte(f.admin)), sha256.Sum256([]byte(f.canary)))
	f.server = serveListeners(o, httpLn, respLn, nil, nil, nil)
	f.url = "http://" + f.config.HTTPAddress
	f.client = &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
		Timeout:   testDeadline,
	}
	t.Cleanup(func() {
		f.client.CloseIdleConnections()
		if err := f.stop(); err != nil {
			t.Errorf("observer cleanup: %v", err)
		}
	})
	return f
}

func (f *testObserver) stop() error {
	f.once.Do(func() { f.stopErr = f.server.shutdown() })
	return f.stopErr
}

func exchangeHTTP(client *http.Client, request *http.Request) (wireResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return wireResponse{}, errors.New("HTTP exchange failed")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return wireResponse{}, errors.New("HTTP response exceeded test read bound")
	}
	return wireResponse{status: response.StatusCode, header: response.Header, body: data}, nil
}

func requestHTTP(client *http.Client, method, url, token string, body []byte,
	headers http.Header,
) (wireResponse, error) {
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return wireResponse{}, errors.New("invalid test request")
	}
	if headers != nil {
		request.Header = headers.Clone()
	}
	if token != "" {
		request.Header.Set(adminHeader, token)
	}
	return exchangeHTTP(client, request)
}

func (f *testObserver) request(t *testing.T, method, path, token string, body []byte,
	headers http.Header,
) wireResponse {
	t.Helper()
	response, err := requestHTTP(f.client, method, f.url+path, token, body, headers)
	if err != nil {
		t.Fatal(err)
	}
	if response.header.Get("Cache-Control") != "no-store" ||
		response.header.Get("X-Content-Type-Options") != "nosniff" ||
		response.header.Get("Content-Type") != "application/json" {
		t.Fatal("response omitted observer safety headers")
	}
	return response
}

func requireStatus(t *testing.T, response wireResponse, want int) {
	t.Helper()
	if response.status != want {
		t.Fatalf("HTTP status = %d, want %d", response.status, want)
	}
}

func decodeState(t *testing.T, data []byte) evidence {
	t.Helper()
	var state evidence
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal("state was not valid evidence JSON")
	}
	if state.SchemaVersion != "v1" || state.HTTP == nil || state.RESP == nil {
		t.Fatal("state omitted the schema version or non-null observation arrays")
	}
	return state
}

func (f *testObserver) state(t *testing.T) evidence {
	t.Helper()
	response := f.request(t, http.MethodGet, "/state", f.admin, nil, nil)
	requireStatus(t, response, http.StatusOK)
	state := decodeState(t, response.body)
	if state.RunID != f.config.RunID || state.Generation == 0 {
		t.Fatal("state lost the exact run identity or generation")
	}
	assertNoDisclosure(t, response.body, f.admin, f.canary, f.control)
	for _, marker := range f.config.Markers {
		assertNoDisclosure(t, response.body, marker.Value)
	}
	return state
}

func assertNoDisclosure(t *testing.T, data []byte, values ...string) {
	t.Helper()
	for _, value := range values {
		if value != "" && bytes.Contains(data, []byte(value)) {
			t.Fatal("response or log disclosed a synthetic private value")
		}
	}
}

func resetBody(runID string, generation uint64) []byte {
	return []byte(fmt.Sprintf(`{"runID":%q,"generation":%d}`, runID, generation))
}

func dialTest(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, testDeadline)
	if err != nil {
		t.Fatalf("dial loopback listener: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	return conn
}

func respFrame(args ...string) string {
	var frame strings.Builder
	fmt.Fprintf(&frame, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&frame, "$%d\r\n%s\r\n", len(arg), arg)
	}
	return frame.String()
}

func sendWire(t *testing.T, conn net.Conn, data string) {
	t.Helper()
	if _, err := io.WriteString(conn, data); err != nil {
		t.Fatalf("write synthetic wire payload: %T", err)
	}
}

func requireWire(t *testing.T, conn io.Reader, want string) {
	t.Helper()
	data := make([]byte, len(want))
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatalf("read protocol reply: %T", err)
	}
	if string(data) != want {
		t.Fatal("unexpected protocol reply")
	}
}

func requireClosed(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	data, err := io.ReadAll(io.LimitReader(conn, 64*1024))
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("connection did not close cleanly within its deadline: %T", err)
	}
	if len(data) == 64*1024 {
		t.Fatal("connection exceeded the bounded test drain")
	}
	return data
}

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(testDeadline)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition did not converge before the test deadline")
}

func activeConnections(listener *trackedListener) int {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return len(listener.active)
}

func testFiles(t *testing.T) string {
	t.Helper()
	// Keep generated fixtures inside the repository's ignored artifact directory.
	base := filepath.Join("..", "..", "bin")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatalf("create artifact directory: %v", err)
	}
	dir := filepath.Join(base, "observer-fixture-"+strconv.FormatInt(time.Now().UnixNano(), 36)+"-"+rand.Text())
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatalf("create private fixture directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove private fixture directory: %v", err)
		}
	})
	return dir
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal("write synthetic fixture")
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal("set synthetic fixture permissions")
	}
}
