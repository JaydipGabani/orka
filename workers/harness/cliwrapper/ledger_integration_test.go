package cliwrapper

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/harness"
	"github.com/orka-agents/orka/internal/harness/ledger"
)

func startLedgerWrapperServer(
	t *testing.T,
	adapter RuntimeAdapter,
	mutate func(*Config),
) (string, string, func()) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.AllowUnauthenticated = true
	cfg.Generic.Command = testEchoCommand
	cfg.LedgerPath = filepath.Join(t.TempDir(), "wrapper-ledger.db")
	if mutate != nil {
		mutate(&cfg)
	}
	server, err := NewServer(cfg, adapter)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv := httptest.NewServer(server.Handler())
	cleanup := func() {
		srv.Close()
		if err := server.Close(); err != nil {
			t.Errorf("Server.Close: %v", err)
		}
	}
	return srv.URL, cfg.LedgerPath, cleanup
}

func postWrapperStartTurn(
	t *testing.T,
	baseURL string,
	token string,
	request harness.StartTurnRequest,
) (int, string) {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal StartTurn request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+harness.TurnsPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new StartTurn request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("StartTurn request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read StartTurn response: %v", err)
	}
	return resp.StatusCode, string(data)
}

func openTestLedger(t *testing.T, path string) *ledger.Ledger {
	t.Helper()
	admissionLedger, err := ledger.Open(path)
	if err != nil {
		t.Fatalf("open test ledger: %v", err)
	}
	t.Cleanup(func() {
		if err := admissionLedger.Close(); err != nil {
			t.Errorf("close test ledger: %v", err)
		}
	})
	return admissionLedger
}

func cancelWrapperTurn(t *testing.T, client *harness.Client, request harness.StartTurnRequest) {
	t.Helper()
	if _, err := client.CancelTurn(context.Background(), harness.CancelTurnRequest{
		Version:          harness.ProtocolVersion,
		Namespace:        request.Namespace,
		TaskName:         request.TaskName,
		SessionName:      request.SessionName,
		RuntimeSessionID: request.RuntimeSessionID,
		TurnID:           request.TurnID,
		CorrelationID:    request.CorrelationID,
		Reason:           "test cleanup",
	}); err != nil {
		t.Fatalf("CancelTurn: %v", err)
	}
}

func TestServerLedgerDuplicateStartTurnIsIdempotentConflict(t *testing.T) {
	baseURL, _, cleanup := startLedgerWrapperServer(t, NewFakeAdapter(FakeBehaviorCancellation), nil)
	defer cleanup()
	client, err := harness.NewClient(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	request := validWrapperStartTurnRequest()
	if _, err := client.StartTurn(context.Background(), request); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	// In-flight duplicate replays produce the registry's duplicate response.
	status, body := postWrapperStartTurn(t, baseURL, "", request)
	if status != http.StatusConflict || !strings.Contains(body, "turn already exists") {
		t.Fatalf("in-flight duplicate = %d %q, want 409 turn already exists", status, body)
	}
	cancelWrapperTurn(t, client, request)
	collectWrapperFrames(t, client, request.TurnID, 0)
}

func TestServerLedgerDuplicateAfterEvictionIsCompletedConflict(t *testing.T) {
	baseURL, ledgerPath, cleanup := startLedgerWrapperServer(
		t,
		NewFakeAdapter(FakeBehaviorSuccess),
		func(cfg *Config) { cfg.TurnRetention = 20 * time.Millisecond },
	)
	defer cleanup()
	client, err := harness.NewClient(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	request := validWrapperStartTurnRequest()
	if _, err := client.StartTurn(context.Background(), request); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	frames := collectWrapperFrames(t, client, request.TurnID, 0)
	if frames[len(frames)-1].Type != harness.FrameTurnCompleted {
		t.Fatalf("last frame = %#v, want completed", frames[len(frames)-1])
	}
	// After in-memory eviction the durable ledger still refuses to re-run the
	// settled turn, exactly like the registry's consumed-turn tombstone.
	eventually(t, 2*time.Second, func() bool {
		status, body := postWrapperStartTurn(t, baseURL, "", request)
		return status == http.StatusConflict && strings.Contains(body, "turn already completed")
	})

	// The terminal receipt is durable and carries the terminal result payload.
	admissionLedger := openTestLedger(t, ledgerPath)
	record, err := admissionLedger.GetTurn(context.Background(), string(request.TurnID))
	if err != nil {
		t.Fatalf("GetTurn: %v", err)
	}
	if record.State != ledger.TurnTerminal {
		t.Fatalf("State = %s, want %s", record.State, ledger.TurnTerminal)
	}
	receipt := string(record.TerminalReceipt)
	if !strings.Contains(receipt, string(harness.FrameTurnCompleted)) || !strings.Contains(receipt, `"ok"`) {
		t.Fatalf("TerminalReceipt = %q, want completed frame payload", receipt)
	}
	if record.TerminalReceiptDigest != ledger.ReceiptDigest(record.TerminalReceipt) {
		t.Fatalf("TerminalReceiptDigest = %q, want digest of stored receipt", record.TerminalReceiptDigest)
	}
	if record.TaskUID != string(request.TurnID) {
		t.Fatalf("TaskUID = %q, want turn ID fallback", record.TaskUID)
	}
	if record.Attempt != 1 {
		t.Fatalf("Attempt = %d, want default 1", record.Attempt)
	}
}

func TestServerLedgerRejectsDigestMismatchPermanently(t *testing.T) {
	baseURL, _, cleanup := startLedgerWrapperServer(t, NewFakeAdapter(FakeBehaviorCancellation), nil)
	defer cleanup()
	client, err := harness.NewClient(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	request := validWrapperStartTurnRequest()
	if _, err := client.StartTurn(context.Background(), request); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	mismatched := request
	mismatched.Input.Prompt = "a different prompt for the same turn ID"
	status, body := postWrapperStartTurn(t, baseURL, "", mismatched)
	if status != http.StatusBadRequest || !strings.Contains(body, "different request digest") {
		t.Fatalf("mismatched replay = %d %q, want 400 different request digest", status, body)
	}
	cancelWrapperTurn(t, client, request)
	collectWrapperFrames(t, client, request.TurnID, 0)
	// The mismatch rejection is permanent even after the original turn settles.
	status, body = postWrapperStartTurn(t, baseURL, "", mismatched)
	if status != http.StatusBadRequest || !strings.Contains(body, "different request digest") {
		t.Fatalf("settled mismatched replay = %d %q, want 400 different request digest", status, body)
	}
}

func TestServerLedgerAcceptedAndTerminalStatesAreDurable(t *testing.T) {
	baseURL, ledgerPath, cleanup := startLedgerWrapperServer(t, NewFakeAdapter(FakeBehaviorCancellation), nil)
	defer cleanup()
	client, err := harness.NewClient(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	request := validWrapperStartTurnRequest()
	request.Metadata = map[string]string{
		ledgerTaskUIDMetadataKey: "task-uid-1234",
		ledgerAttemptMetadataKey: "3",
	}
	if _, err := client.StartTurn(context.Background(), request); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	admissionLedger := openTestLedger(t, ledgerPath)
	record, err := admissionLedger.GetTurn(context.Background(), string(request.TurnID))
	if err != nil {
		t.Fatalf("GetTurn: %v", err)
	}
	if record.State != ledger.TurnAccepted {
		t.Fatalf("State = %s, want %s", record.State, ledger.TurnAccepted)
	}
	if record.TaskUID != "task-uid-1234" || record.Attempt != 3 {
		t.Fatalf("TaskUID/Attempt = %q/%d, want metadata values", record.TaskUID, record.Attempt)
	}
	cancelWrapperTurn(t, client, request)
	collectWrapperFrames(t, client, request.TurnID, 0)
	eventually(t, 2*time.Second, func() bool {
		record, err := admissionLedger.GetTurn(context.Background(), string(request.TurnID))
		return err == nil && record.State == ledger.TurnTerminal &&
			strings.Contains(string(record.TerminalReceipt), string(harness.FrameTurnCancelled))
	})
}

func TestServerLedgerMarksCapacityRejection(t *testing.T) {
	baseURL, ledgerPath, cleanup := startLedgerWrapperServer(t, NewFakeAdapter(FakeBehaviorCancellation), nil)
	defer cleanup()
	client, err := harness.NewClient(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	first := validWrapperStartTurnRequest()
	if _, err := client.StartTurn(context.Background(), first); err != nil {
		t.Fatalf("StartTurn(first): %v", err)
	}
	second := validWrapperStartTurnRequest()
	second.TurnID = "turn-capacity-b"
	second.CorrelationID = "corr-b"
	status, body := postWrapperStartTurn(t, baseURL, "", second)
	if status != http.StatusConflict || !strings.Contains(body, "maximum concurrent turns reached") {
		t.Fatalf("capacity StartTurn = %d %q, want 409 capacity conflict", status, body)
	}
	admissionLedger := openTestLedger(t, ledgerPath)
	record, err := admissionLedger.GetTurn(context.Background(), string(second.TurnID))
	if err != nil {
		t.Fatalf("GetTurn(rejected): %v", err)
	}
	if record.State != ledger.TurnRejected {
		t.Fatalf("State = %s, want %s", record.State, ledger.TurnRejected)
	}
	if record.RejectReason != "maximum concurrent turns reached" {
		t.Fatalf("RejectReason = %q, want capacity reason", record.RejectReason)
	}
	cancelWrapperTurn(t, client, first)
	collectWrapperFrames(t, client, first.TurnID, 0)
}

func TestServerLedgerCloseAdmissionAndUnsettledTurns(t *testing.T) {
	const adminToken = "admin-token-123"
	baseURL, _, cleanup := startLedgerWrapperServer(
		t,
		NewFakeAdapter(FakeBehaviorCancellation),
		func(cfg *Config) {
			cfg.AllowUnauthenticated = false
			cfg.AuthValue = adminToken
		},
	)
	defer cleanup()
	client, err := harness.NewClient(baseURL, harness.WithBearerToken(adminToken))
	if err != nil {
		t.Fatal(err)
	}

	// Admin endpoints require the same bearer auth as mutating endpoints.
	resp, err := http.Get(baseURL + AdminUnsettledTurnsPath)
	if err != nil {
		t.Fatalf("GET unsettled-turns: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated unsettled-turns = %d, want 401", resp.StatusCode)
	}
	unauthClose, err := http.Post(baseURL+AdminCloseAdmissionPath, "application/json", nil)
	if err != nil {
		t.Fatalf("POST close-admission: %v", err)
	}
	_ = unauthClose.Body.Close()
	if unauthClose.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated close-admission = %d, want 401", unauthClose.StatusCode)
	}

	request := validWrapperStartTurnRequest()
	if _, err := client.StartTurn(context.Background(), request); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	unsettled := getUnsettledTurns(t, baseURL, adminToken)
	if unsettled.Generation == "" {
		t.Fatalf("Generation = %q, want ledger generation watermark", unsettled.Generation)
	}
	if len(unsettled.Turns) != 1 || unsettled.Turns[0].TurnID != string(request.TurnID) ||
		unsettled.Turns[0].State != string(ledger.TurnAccepted) {
		t.Fatalf("unsettled turns = %#v, want one accepted turn", unsettled.Turns)
	}

	first := postCloseAdmission(t, baseURL, adminToken)
	if !first.Closed || first.ClosedAt.IsZero() {
		t.Fatalf("close-admission = %#v, want closed with timestamp", first)
	}
	second := postCloseAdmission(t, baseURL, adminToken)
	if !second.Closed || !second.ClosedAt.Equal(first.ClosedAt) {
		t.Fatalf("repeat close-admission = %#v, want idempotent %v", second, first.ClosedAt)
	}

	late := validWrapperStartTurnRequest()
	late.TurnID = "turn-after-close"
	late.CorrelationID = "corr-after-close"
	status, body := postWrapperStartTurn(t, baseURL, adminToken, late)
	if status != http.StatusServiceUnavailable || !strings.Contains(body, "admission is closed") {
		t.Fatalf("post-close StartTurn = %d %q, want 503 admission is closed", status, body)
	}

	// Already-admitted turns still settle after the close.
	cancelWrapperTurn(t, client, request)
	collectWrapperFrames(t, client, request.TurnID, 0)
	eventually(t, 2*time.Second, func() bool {
		return len(getUnsettledTurns(t, baseURL, adminToken).Turns) == 0
	})
}

func TestServerWithoutLedgerRejectsAdminEndpoints(t *testing.T) {
	baseURL, cleanup := startWrapperServer(t, NewFakeAdapter(FakeBehaviorSuccess))
	defer cleanup()
	resp, err := http.Get(baseURL + AdminUnsettledTurnsPath)
	if err != nil {
		t.Fatalf("GET unsettled-turns: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unsettled-turns without ledger = %d, want 503", resp.StatusCode)
	}
	closeResp, err := http.Post(baseURL+AdminCloseAdmissionPath, "application/json", nil)
	if err != nil {
		t.Fatalf("POST close-admission: %v", err)
	}
	_ = closeResp.Body.Close()
	if closeResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("close-admission without ledger = %d, want 503", closeResp.StatusCode)
	}
}

func TestNewServerFailsOnUnopenableLedgerPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowUnauthenticated = true
	cfg.Generic.Command = testEchoCommand
	cfg.LedgerPath = filepath.Join(t.TempDir(), "missing-parent", "wrapper-ledger.db")
	if _, err := NewServer(cfg, NewFakeAdapter(FakeBehaviorSuccess)); err == nil {
		t.Fatal("NewServer with unopenable ledger path = nil error, want startup failure")
	}
}

func TestLoadConfigFromEnvReadsLedgerPath(t *testing.T) {
	t.Setenv(EnvLedgerPath, "/var/lib/orka/wrapper-ledger.db")
	cfg, err := LoadConfigFromEnvUnvalidated()
	if err != nil {
		t.Fatalf("LoadConfigFromEnvUnvalidated: %v", err)
	}
	if cfg.LedgerPath != "/var/lib/orka/wrapper-ledger.db" {
		t.Fatalf("LedgerPath = %q, want env value", cfg.LedgerPath)
	}
}

func getUnsettledTurns(t *testing.T, baseURL, token string) UnsettledTurnsResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+AdminUnsettledTurnsPath, nil)
	if err != nil {
		t.Fatalf("new unsettled-turns request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET unsettled-turns: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unsettled-turns status = %d, want 200", resp.StatusCode)
	}
	var decoded UnsettledTurnsResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode unsettled-turns response: %v", err)
	}
	return decoded
}

func postCloseAdmission(t *testing.T, baseURL, token string) CloseAdmissionResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+AdminCloseAdmissionPath, nil)
	if err != nil {
		t.Fatalf("new close-admission request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST close-admission: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("close-admission status = %d, want 200", resp.StatusCode)
	}
	var decoded CloseAdmissionResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode close-admission response: %v", err)
	}
	return decoded
}
