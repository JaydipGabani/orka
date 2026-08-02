package referenceadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orka-agents/orka/pkg/oms/conformance"
	"github.com/orka-agents/orka/pkg/oms/protocol"
)

func TestReferenceAdapterPassesConformance(t *testing.T) {
	t.Parallel()
	server := openTestAdapter(t, filepath.Join(t.TempDir(), "oms.db"))
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := conformance.Check(ctx, conformance.Target{
		BaseURL: httpServer.URL, AuthorizationValue: testCredential(), Binding: conformance.DefaultBinding(),
		HTTPClient: httpServer.Client(), RunID: "single-process", InsecureLoopbackOnly: true,
	})
	if !result.Passed {
		t.Fatalf("conformance failed in %s: %s", result.Phase, result.Message)
	}
}

func TestReferenceAdapterStateSurvivesReopen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "oms.db")
	first := openTestAdapter(t, path)
	firstHTTP := httptest.NewServer(first.Handler())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	checkpoint, prepared := conformance.Prepare(ctx, conformance.Target{
		BaseURL: firstHTTP.URL, AuthorizationValue: testCredential(), Binding: conformance.DefaultBinding(),
		HTTPClient: firstHTTP.Client(), RunID: "restart-proof", InsecureLoopbackOnly: true,
	})
	if !prepared.Passed {
		firstHTTP.Close()
		_ = first.Close()
		t.Fatalf("prepare failed: %s", prepared.Message)
	}
	firstHTTP.Close()
	if err := first.Close(); err != nil {
		t.Fatalf("close first adapter: %v", err)
	}

	second := openTestAdapter(t, path)
	secondHTTP := httptest.NewServer(second.Handler())
	t.Cleanup(secondHTTP.Close)
	verified := conformance.VerifyAfterRestart(ctx, conformance.Target{
		BaseURL: secondHTTP.URL, AuthorizationValue: testCredential(), HTTPClient: secondHTTP.Client(),
		InsecureLoopbackOnly: true,
	}, checkpoint)
	if !verified.Passed {
		t.Fatalf("restart verification failed: %s", verified.Message)
	}
}

func TestReferenceAdapterAcceptsPlanMaximumContent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	adapter, err := Open(context.Background(), Config{
		DatabasePath: filepath.Join(t.TempDir(), "oms.db"), BearerToken: testCredential(),
		SnapshotTTL: time.Minute, MaxSnapshotRecords: 64,
		Clock: func() time.Time { return time.Unix(0, clock.Load()).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	httpServer := httptest.NewServer(adapter.Handler())
	t.Cleanup(httpServer.Close)
	binding := conformance.DefaultBinding()
	storeBinding := protocol.StoreResolutionBinding{
		ClusterID: binding.ClusterID, NamespaceUID: binding.NamespaceUID,
		BackendUID: binding.BackendUID, TenantID: binding.TenantID,
	}
	resolveBody := postTestJSON(t, httpServer.Client(), httpServer.URL+protocol.PathStoreResolve, protocol.StoreResolveRequest{
		ProtocolVersion: protocol.Version, Binding: storeBinding, StoreName: "maximum-content",
	})
	resolved, err := protocol.DecodeStoreResolveResponse(resolveBody)
	if err != nil {
		t.Fatalf("decode store resolution: %v", err)
	}
	binding.StoreUUID = resolved.StoreUUID
	claimBody := postTestJSON(t, httpServer.Client(), httpServer.URL+protocol.PathOwnershipClaim, protocol.OwnershipClaimRequest{
		ProtocolVersion: protocol.Version, Binding: binding,
	})
	claim, err := protocol.DecodeOwnershipClaimResponse(claimBody)
	if err != nil || claim.Result != protocol.ResultApplied {
		t.Fatalf("ownership claim = %#v, err = %v", claim, err)
	}
	mutation := protocol.MutationEnvelope{
		ProtocolVersion: protocol.Version, OperationID: "mop-maximum-content", Binding: binding,
		MemoryID: "mem-maximum-content", Kind: protocol.MutationKindCreate, Generation: 1,
		State: &protocol.MutationState{
			Content: strings.Repeat("\n", protocol.MaxContentBytes), Tags: []string{"maximum"}, Metadata: map[string]string{},
		},
	}
	if err := protocol.PrepareMutation(&mutation); err != nil {
		t.Fatalf("PrepareMutation(): %v", err)
	}
	receiptBody := postTestJSON(t, httpServer.Client(), httpServer.URL+protocol.PathMutations, mutation)
	receipt, err := protocol.DecodeMutationReceipt(receiptBody)
	if err != nil || receipt.Result != protocol.ResultApplied {
		t.Fatalf("maximum-content receipt = %#v, err = %v", receipt, err)
	}
	search := protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword,
		Query: "", PageSize: 1, PageToken: "",
	}
	for i := range maxActiveSearchSnapshotsPerAuthority {
		response, decodeErr := protocol.DecodeSearchResponse(postTestJSON(
			t, httpServer.Client(), httpServer.URL+protocol.PathSearch, search,
		))
		if decodeErr != nil || len(response.Records) != 1 || response.Records[0].Content != mutation.State.Content {
			t.Fatalf("maximum-content search %d = %#v, err = %v", i, response, decodeErr)
		}
	}
	body, status := postTestJSONStatus(t, httpServer.Client(), httpServer.URL+protocol.PathSearch, search)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("snapshot quota status = %d, want %d: %s", status, http.StatusServiceUnavailable, body)
	}
	capacity, err := protocol.DecodeErrorResponse(body)
	if err != nil || capacity.Code != protocol.ErrorCodeSnapshotCapacity {
		t.Fatalf("snapshot quota response = %#v, err = %v", capacity, err)
	}
	clock.Store(now.Add(2 * time.Minute).UnixNano())
	postTestJSON(t, httpServer.Client(), httpServer.URL+protocol.PathSearch, search)
	var active int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active snapshots after expiry cleanup = %d, want 1", active)
	}
}

func TestReferenceAdapterRejectsOversizedSearchSnapshot(t *testing.T) {
	adapter := openTestAdapter(t, filepath.Join(t.TempDir(), "oms.db"))
	httpServer := httptest.NewServer(adapter.Handler())
	t.Cleanup(httpServer.Close)
	binding := resolveAndClaimReferenceBinding(t, httpServer, "snapshot-bytes")
	content := strings.Repeat("\n", protocol.MaxContentBytes)
	recordCount := maxSearchSnapshotBytes/(2*protocol.MaxContentBytes) + 1
	for i := range recordCount {
		mutation := protocol.MutationEnvelope{
			ProtocolVersion: protocol.Version, OperationID: fmt.Sprintf("mop-snapshot-bytes-%d", i), Binding: binding,
			MemoryID: fmt.Sprintf("mem-snapshot-bytes-%d", i), Kind: protocol.MutationKindCreate, Generation: 1,
			State: &protocol.MutationState{Content: content, Tags: []string{}, Metadata: map[string]string{}},
		}
		if err := protocol.PrepareMutation(&mutation); err != nil {
			t.Fatal(err)
		}
		postTestJSON(t, httpServer.Client(), httpServer.URL+protocol.PathMutations, mutation)
	}
	body, status := postTestJSONStatus(t, httpServer.Client(), httpServer.URL+protocol.PathSearch, protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, Query: "", PageSize: 1,
	})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("oversized snapshot status = %d, want %d: %s", status, http.StatusServiceUnavailable, body)
	}
	response, err := protocol.DecodeErrorResponse(body)
	if err != nil || response.Code != protocol.ErrorCodeSnapshotCapacity {
		t.Fatalf("oversized snapshot response = %#v, err = %v", response, err)
	}
}

func TestReferenceAdapterGlobalSearchSnapshotQuota(t *testing.T) {
	adapter := openTestAdapter(t, filepath.Join(t.TempDir(), "oms.db"))
	now := time.Now().UTC()
	for i := range maxActiveSearchSnapshotsGlobal {
		_, err := adapter.db.db.Exec(`INSERT INTO pagination_snapshots(
			snapshot_id, authority_digest, request_fingerprint, requested_mode, actual_mode,
			page_size, entry_count, created_at, expires_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`, fmt.Sprintf("seed-%032d", i), fmt.Sprintf("authority-%d", i),
			"fingerprint", protocol.SearchModeKeyword, protocol.SearchModeKeyword, 1, 0, formatTime(now), formatTime(now.Add(time.Hour)))
		if err != nil {
			t.Fatal(err)
		}
	}
	tx, err := adapter.db.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := ensureSearchSnapshotCountCapacityInTx(context.Background(), tx, "new-authority"); !errors.Is(err, errSnapshotCapacity) {
		t.Fatalf("global snapshot admission error = %v, want %v", err, errSnapshotCapacity)
	}
}

func resolveAndClaimReferenceBinding(t *testing.T, server *httptest.Server, storeName string) protocol.Binding {
	t.Helper()
	binding := conformance.DefaultBinding()
	resolved, err := protocol.DecodeStoreResolveResponse(postTestJSON(t, server.Client(), server.URL+protocol.PathStoreResolve,
		protocol.StoreResolveRequest{
			ProtocolVersion: protocol.Version,
			Binding: protocol.StoreResolutionBinding{
				ClusterID: binding.ClusterID, NamespaceUID: binding.NamespaceUID,
				BackendUID: binding.BackendUID, TenantID: binding.TenantID,
			},
			StoreName: storeName,
		}))
	if err != nil {
		t.Fatal(err)
	}
	binding.StoreUUID = resolved.StoreUUID
	claim, err := protocol.DecodeOwnershipClaimResponse(postTestJSON(t, server.Client(), server.URL+protocol.PathOwnershipClaim,
		protocol.OwnershipClaimRequest{ProtocolVersion: protocol.Version, Binding: binding}))
	if err != nil || claim.Result != protocol.ResultApplied {
		t.Fatalf("ownership claim = %#v, err = %v", claim, err)
	}
	return binding
}

func postTestJSON(t *testing.T, client *http.Client, target string, value any) []byte {
	t.Helper()
	responseBody, status := postTestJSONStatus(t, client, target, value)
	if status != http.StatusOK {
		t.Fatalf("POST %s returned HTTP %d: %s", target, status, responseBody)
	}
	return responseBody
}

func postTestJSONStatus(t *testing.T, client *http.Client, target string, value any) ([]byte, int) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testCredential())
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close() //nolint:errcheck
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return responseBody, response.StatusCode
}

const referenceAdapterLockProbePathEnv = "ORKA_REFERENCE_ADAPTER_LOCK_PROBE_PATH"

func TestReferenceAdapterProcessLockSubprocessProbe(t *testing.T) {
	path := os.Getenv(referenceAdapterLockProbePathEnv)
	if path == "" {
		return
	}
	lock, err := acquireProcessLock(context.Background(), path)
	if err != nil {
		return
	}
	_ = lock.close()
	t.Fatalf("subprocess acquired actively locked database inode %q", path)
}

func TestReferenceAdapterProcessLockRejectsFilesystemAliases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "oms.db")
	first, err := openDatabase(ctx, path)
	if err != nil {
		t.Fatalf("openDatabase(first): %v", err)
	}
	defer first.close() //nolint:errcheck

	symlinkPath := filepath.Join(dir, "oms-symlink.db")
	if err := os.Symlink(path, symlinkPath); err != nil {
		t.Fatalf("create symlink alias: %v", err)
	}
	hardlinkPath := filepath.Join(dir, "oms-hardlink.db")
	if err := os.Link(path, hardlinkPath); err != nil {
		t.Fatalf("create hard-link alias: %v", err)
	}

	for name, alias := range map[string]string{"symlink": symlinkPath, "hard-link": hardlinkPath} {
		t.Run(name, func(t *testing.T) {
			if second, err := openDatabase(ctx, alias); err == nil {
				_ = second.close()
				t.Fatalf("openDatabase(%s alias) bypassed the in-process lock registry", name)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestReferenceAdapterProcessLockSubprocessProbe$")
			command.Env = append(os.Environ(), referenceAdapterLockProbePathEnv+"="+alias)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("subprocess process-lock probe for %s alias failed: %v\n%s", name, err, output)
			}
		})
	}
}

func TestReferenceAdapterRejectsSecondActiveProcess(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "oms.db")
	first := openTestAdapter(t, path)
	if _, err := Open(context.Background(), Config{DatabasePath: path, BearerToken: testCredential() + "-other"}); err == nil {
		t.Fatal("second Open() succeeded while the first process lock was active")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first adapter: %v", err)
	}
	second, err := Open(context.Background(), Config{DatabasePath: path, BearerToken: testCredential()})
	if err != nil {
		t.Fatalf("Open() after releasing process lock: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second adapter: %v", err)
	}
}

func testCredential() string {
	return "fixture-" + "credential"
}

func openTestAdapter(t *testing.T, path string) *Server {
	t.Helper()
	server, err := Open(context.Background(), Config{
		DatabasePath: path, BearerToken: testCredential(), CapabilityTTL: time.Minute,
		SnapshotTTL: time.Minute, MaxSnapshotRecords: 64,
	})
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func TestReferenceAdapterMutationRequiresExactDurableRoutingFence(t *testing.T) {
	adapter := openTestAdapter(t, filepath.Join(t.TempDir(), "oms.db"))
	httpServer := httptest.NewServer(adapter.Handler())
	t.Cleanup(httpServer.Close)
	binding := conformance.DefaultBinding()
	resolvedBody := postTestJSON(t, httpServer.Client(), httpServer.URL+protocol.PathStoreResolve, protocol.StoreResolveRequest{
		ProtocolVersion: protocol.Version,
		Binding: protocol.StoreResolutionBinding{
			ClusterID: binding.ClusterID, NamespaceUID: binding.NamespaceUID, BackendUID: binding.BackendUID, TenantID: binding.TenantID,
		},
		StoreName: "exact-routing-fence",
	})
	resolved, err := protocol.DecodeStoreResolveResponse(resolvedBody)
	if err != nil {
		t.Fatal(err)
	}
	binding.StoreUUID = resolved.StoreUUID
	postTestJSON(t, httpServer.Client(), httpServer.URL+protocol.PathOwnershipClaim, protocol.OwnershipClaimRequest{
		ProtocolVersion: protocol.Version, Binding: binding,
	})
	fenced := binding
	fenced.RoutingEpoch++
	postTestJSON(t, httpServer.Client(), httpServer.URL+protocol.PathRoutingFence, protocol.RoutingFenceRequest{
		ProtocolVersion: protocol.Version, Binding: fenced,
	})

	stale := fenced
	stale.RoutingEpoch = binding.RoutingEpoch
	staleMutation := protocol.MutationEnvelope{
		ProtocolVersion: protocol.Version, OperationID: "mop-fence-stale", Binding: stale,
		MemoryID: "mem-fence-stale", Kind: protocol.MutationKindCreate, Generation: 1,
		State: &protocol.MutationState{Content: "must be fenced", Tags: []string{}, Metadata: map[string]string{}},
	}
	if err := protocol.PrepareMutation(&staleMutation); err != nil {
		t.Fatal(err)
	}
	staleBody, status := postTestJSONStatus(t, httpServer.Client(), httpServer.URL+protocol.PathMutations, staleMutation)
	if status != http.StatusConflict {
		t.Fatalf("stale routing status = %d, want %d", status, http.StatusConflict)
	}
	staleReceipt, err := protocol.DecodeMutationReceipt(staleBody)
	if err != nil || staleReceipt.Result != protocol.ResultIdentityConflict {
		t.Fatalf("stale routing receipt = %#v, err = %v", staleReceipt, err)
	}

	future := fenced
	future.RoutingEpoch++
	futureMutation := protocol.MutationEnvelope{
		ProtocolVersion: protocol.Version, OperationID: "mop-fence-future", Binding: future,
		MemoryID: "mem-fence-future", Kind: protocol.MutationKindCreate, Generation: 1,
		State: &protocol.MutationState{Content: "future route", Tags: []string{}, Metadata: map[string]string{}},
	}
	if err := protocol.PrepareMutation(&futureMutation); err != nil {
		t.Fatal(err)
	}
	futureBody, status := postTestJSONStatus(t, httpServer.Client(), httpServer.URL+protocol.PathMutations, futureMutation)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("future routing status = %d, want %d", status, http.StatusServiceUnavailable)
	}
	futureReceipt, err := protocol.DecodeMutationReceipt(futureBody)
	if err != nil || futureReceipt.Result != protocol.ResultRetryableError {
		t.Fatalf("future routing receipt = %#v, err = %v", futureReceipt, err)
	}

	exact := protocol.MutationEnvelope{
		ProtocolVersion: protocol.Version, OperationID: "mop-fence-exact", Binding: fenced,
		MemoryID: "mem-fence-exact", Kind: protocol.MutationKindCreate, Generation: 1,
		State: &protocol.MutationState{Content: "exact fence", Tags: []string{}, Metadata: map[string]string{}},
	}
	if err := protocol.PrepareMutation(&exact); err != nil {
		t.Fatal(err)
	}
	receipt, err := protocol.DecodeMutationReceipt(postTestJSON(t, httpServer.Client(), httpServer.URL+protocol.PathMutations, exact))
	if err != nil || receipt.Result != protocol.ResultApplied {
		t.Fatalf("exact-fence receipt = %#v, err = %v", receipt, err)
	}
}

func TestReferenceAdapterAuthenticatesBeforeClosedRouteDispatch(t *testing.T) {
	handler := (&Server{authValue: testCredential()}).Handler()
	for _, tc := range []struct {
		name, method, path, authorization, code string
		status                                  int
	}{
		{name: "wrong method unauthenticated", method: http.MethodGet, path: protocol.PathMutations, status: http.StatusUnauthorized, code: protocol.ErrorCodeUnauthorized},
		{name: "wrong method authenticated", method: http.MethodGet, path: protocol.PathMutations, authorization: "Bearer " + testCredential(), status: http.StatusMethodNotAllowed, code: protocol.ErrorCodeMethodNotAllowed},
		{name: "unknown path authenticated", method: http.MethodPost, path: "/v1/unknown", authorization: "Bearer " + testCredential(), status: http.StatusNotFound, code: protocol.ErrorCodeNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			request.Header.Set("Authorization", tc.authorization)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, tc.status, response.Body.Bytes())
			}
			if response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("closed headers = %#v", response.Header())
			}
			decoded, decodeErr := protocol.DecodeErrorResponse(response.Body.Bytes())
			if decodeErr != nil || decoded.Code != tc.code {
				t.Fatalf("error response = %#v, err = %v", decoded, decodeErr)
			}
			if tc.status == http.StatusMethodNotAllowed && response.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("Allow = %q, want POST", response.Header().Get("Allow"))
			}
		})
	}
}

func TestReferenceAdapterPersistsOwnershipConflictReceipt(t *testing.T) {
	adapter := openTestAdapter(t, filepath.Join(t.TempDir(), "oms.db"))
	binding := conformance.DefaultBinding()
	mutation := protocol.MutationEnvelope{
		ProtocolVersion: protocol.Version, OperationID: "mop-unowned", Binding: binding,
		MemoryID: "mem-unowned", Kind: protocol.MutationKindCreate, Generation: 1,
		State: &protocol.MutationState{Content: "unowned", Tags: []string{}, Metadata: map[string]string{}},
	}
	if err := protocol.PrepareMutation(&mutation); err != nil {
		t.Fatal(err)
	}
	firstAt := time.Date(2026, 7, 30, 19, 0, 0, 0, time.UTC)
	first, err := adapter.db.applyMutation(context.Background(), &mutation, firstAt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := adapter.db.applyMutation(context.Background(), &mutation, firstAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.Result != protocol.ResultIdentityConflict || second.Result != first.Result ||
		!second.CompletedAt.Equal(first.CompletedAt) {
		t.Fatalf("ownership conflict replay first=%#v second=%#v", first, second)
	}
}
