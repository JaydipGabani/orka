package kd6adapter

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"net/http/httptest"

	"github.com/orka-agents/orka/internal/oms/conformance"
	"github.com/orka-agents/orka/internal/oms/protocol"
	_ "modernc.org/sqlite"
)

const (
	kd6ControlLockProbePathEnv = "ORKA_KD6_CONTROL_LOCK_PROBE_PATH"
	kd6TestJSONMediaType       = "application/json"
)

type ambiguousAfterProviderSuccessStore struct {
	ContentStore
	failed bool
}

type lookupErrorStore struct {
	ContentStore
	err error
}

func (s lookupErrorStore) LookupMutation(context.Context, ContentOperationLookup) (ContentOperationLookupResult, error) {
	return ContentOperationLookupResult{}, s.err
}

type mutationErrorStore struct {
	ContentStore
	err error
}

type fixedSearchSnapshotStore struct {
	ContentStore
	snapshot ContentSearchSnapshot
}

func (s fixedSearchSnapshotStore) StartSearch(context.Context, ContentSearchRequest) (ContentSearchSnapshot, error) {
	return s.snapshot, nil
}

type terminalLookupStore struct {
	ContentStore
	operationID string
	result      ContentMutationResult
}

type delayedLookupVisibilityStore struct {
	ContentStore
	status ContentOperationLookupResult
	err    error
	hidden atomic.Bool
	failed atomic.Bool
}

func (s terminalLookupStore) LookupMutation(ctx context.Context, lookup ContentOperationLookup) (ContentOperationLookupResult, error) {
	if lookup.OperationID == s.operationID {
		result := s.result
		return ContentOperationLookupResult{Status: ContentOperationLookupCompleted, Result: &result}, nil
	}
	return s.ContentStore.LookupMutation(ctx, lookup)
}

func (s *delayedLookupVisibilityStore) LookupMutation(
	ctx context.Context,
	lookup ContentOperationLookup,
) (ContentOperationLookupResult, error) {
	if s.hidden.Load() {
		if s.err != nil {
			return ContentOperationLookupResult{}, s.err
		}
		return s.status, nil
	}
	return s.ContentStore.LookupMutation(ctx, lookup)
}

func (s *delayedLookupVisibilityStore) Mutate(ctx context.Context, mutation ContentMutation) (ContentMutationResult, error) {
	result, err := s.ContentStore.Mutate(ctx, mutation)
	if err == nil && s.failed.CompareAndSwap(false, true) {
		s.hidden.Store(true)
		return ContentMutationResult{}, &StoreError{Code: "KD6_TEST_DELAYED_VISIBILITY", Retryable: true}
	}
	return result, err
}

func (s mutationErrorStore) Mutate(context.Context, ContentMutation) (ContentMutationResult, error) {
	return ContentMutationResult{}, s.err
}

func (s *ambiguousAfterProviderSuccessStore) Mutate(ctx context.Context, mutation ContentMutation) (ContentMutationResult, error) {
	result, err := s.ContentStore.Mutate(ctx, mutation)
	if err != nil || s.failed {
		return result, err
	}
	s.failed = true
	return ContentMutationResult{}, &StoreError{Code: "KD6_TEST_RESPONSE_LOST", Retryable: true}
}

func TestKD6ControlProcessLockSubprocessProbe(t *testing.T) {
	path := os.Getenv(kd6ControlLockProbePathEnv)
	if path == "" {
		return
	}
	lock, err := acquireProcessLock(context.Background(), path)
	if err != nil {
		return
	}
	_ = lock.close()
	t.Fatalf("subprocess acquired actively locked control database inode %q", path)
}

func TestKD6ControlProcessLockRejectsFilesystemAliases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "oms-control.db")
	first, err := openControlDatabase(ctx, path)
	if err != nil {
		t.Fatalf("openControlDatabase(first): %v", err)
	}
	defer first.close() //nolint:errcheck

	symlinkPath := filepath.Join(dir, "oms-control-symlink.db")
	if err := os.Symlink(path, symlinkPath); err != nil {
		t.Fatalf("create symlink alias: %v", err)
	}
	hardlinkPath := filepath.Join(dir, "oms-control-hardlink.db")
	if err := os.Link(path, hardlinkPath); err != nil {
		t.Fatalf("create hard-link alias: %v", err)
	}

	for name, alias := range map[string]string{"symlink": symlinkPath, "hard-link": hardlinkPath} {
		t.Run(name, func(t *testing.T) {
			if second, err := openControlDatabase(ctx, alias); err == nil {
				_ = second.close()
				t.Fatalf("openControlDatabase(%s alias) bypassed the in-process lock registry", name)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestKD6ControlProcessLockSubprocessProbe$")
			command.Env = append(os.Environ(), kd6ControlLockProbePathEnv+"="+alias)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("subprocess process-lock probe for %s alias failed: %v\n%s", name, err, output)
			}
		})
	}
}

func TestKD6AdapterConformanceAndRestartWithoutContentMirroring(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(t.TempDir(), "oms-control.db")
	open := func() *Server {
		server, openErr := Open(ctx, Config{
			DatabasePath: databasePath, BearerToken: testInboundToken, ContentStore: contentStore,
			StoreMappings: map[string]string{conformanceStoreName: fakeProviderStoreID},
			Clock:         func() time.Time { return provider.clock }, EnableConformanceFailpoints: true,
		})
		if openErr != nil {
			t.Fatal(openErr)
		}
		return server
	}

	adapter := open()
	endpoint := httptest.NewServer(adapter.Handler())
	target := conformance.Target{
		BaseURL: endpoint.URL, AuthorizationValue: testInboundToken, StoreName: conformanceStoreName,
		RunID: "kd6-adapter-test", DisableProxy: true, InsecureLoopbackOnly: true,
		ProviderCommitGapProof: true,
	}
	checkpoint, prepared := conformance.Prepare(ctx, target)
	if !prepared.Passed {
		t.Fatalf("prepare failed: %#v", prepared)
	}
	provider.mu.Lock()
	mutationsAfterPrepare := provider.mutateCalls
	provider.mu.Unlock()
	if checkpoint.ProviderCommitGapMutation == nil {
		t.Fatal("prepare checkpoint omitted the provider-commit gap mutation")
	}

	if _, err := Open(ctx, Config{
		DatabasePath: databasePath, BearerToken: testInboundToken, ContentStore: contentStore,
		StoreMappings: map[string]string{conformanceStoreName: fakeProviderStoreID},
	}); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("second active adapter Open() error = %v", err)
	}
	endpoint.Close()
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}

	adapter = open()
	endpoint = httptest.NewServer(adapter.Handler())
	target.BaseURL = endpoint.URL
	verified := conformance.VerifyAfterRestart(ctx, target, checkpoint)
	if !verified.Passed {
		t.Fatalf("verify failed: %#v", verified)
	}
	provider.mu.Lock()
	mutationsAfterVerify := provider.mutateCalls
	provider.mu.Unlock()
	if mutationsAfterVerify != mutationsAfterPrepare {
		t.Fatalf("restart recovery issued a second provider mutation: prepare=%d verify=%d", mutationsAfterPrepare, mutationsAfterVerify)
	}
	endpoint.Close()
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}

	assertControlDatabaseContainsNoContent(t, databasePath, "oms-conformance-kd6-adapter-test")
}

func TestKD6AdapterReloadsInboundBearerToken(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "inbound-token")
	if err := os.WriteFile(tokenPath, []byte("old-inbound-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenProvider, err := NewFileBearerTokenProvider(tokenPath, "inbound OMS bearer token")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := Open(ctx, Config{
		DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerTokenProvider: tokenProvider,
		ContentStore: contentStore, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close() //nolint:errcheck
	endpoint := httptest.NewServer(adapter.Handler())
	defer endpoint.Close()

	assertHealthStatus(t, endpoint.URL, "old-inbound-token", http.StatusOK)
	if err := os.WriteFile(tokenPath, []byte("new-inbound-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertHealthStatus(t, endpoint.URL, "old-inbound-token", http.StatusUnauthorized)
	assertHealthStatus(t, endpoint.URL, "new-inbound-token", http.StatusOK)
}

func TestKD6AdapterRejectsMismatchedMutationRecordBeforeControlCommit(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	provider.mutationRecordIdentityMismatch = true
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := Open(ctx, Config{
		DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerToken: testInboundToken,
		ContentStore: contentStore, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
		Clock: func() time.Time { return provider.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close() //nolint:errcheck
	endpoint := httptest.NewServer(adapter.Handler())
	defer endpoint.Close()
	binding := resolveAndClaimKD6Binding(t, endpoint.URL)

	mutation := newKD6TestMutation(t, binding, "mop-record-mismatch", "mem-record-mismatch", "mismatched durable content")
	receiptBody, status := postOMSStatus(t, endpoint.URL, protocol.PathMutations, mutation)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("mutation status = %d, want %d", status, http.StatusServiceUnavailable)
	}
	receipt, err := protocol.DecodeMutationReceipt(receiptBody)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Result != protocol.ResultRetryableError {
		t.Fatalf("mutation result = %q, want %q", receipt.Result, protocol.ResultRetryableError)
	}
	var intents, receipts int
	if err := adapter.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_intents WHERE operation_id = ?`, mutation.OperationID).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := adapter.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_receipts WHERE operation_id = ?`, mutation.OperationID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if intents != 1 || receipts != 0 {
		t.Fatalf("ambiguous mismatch control state intents=%d receipts=%d, want 1/0", intents, receipts)
	}
	replayedBody, replayedStatus := postOMSStatus(t, endpoint.URL, protocol.PathMutations, mutation)
	if replayedStatus != http.StatusServiceUnavailable || !bytes.Equal(replayedBody, receiptBody) {
		t.Fatalf("ambiguous mismatch replay status/body = %d/%s, want %d/%s", replayedStatus, replayedBody, http.StatusServiceUnavailable, receiptBody)
	}
	getBody := postOMS(t, endpoint.URL, protocol.PathRecordsGet, protocol.GetRequest{
		ProtocolVersion: protocol.Version, Binding: binding, UpsertKey: mutation.UpsertKey,
	})
	getResponse, err := protocol.DecodeGetResponse(getBody)
	if err != nil {
		t.Fatal(err)
	}
	if getResponse.Found {
		t.Fatalf("mismatched provider result was committed: %#v", getResponse.Record)
	}
}

func TestKD6AdapterPreservesIntentWhenProviderReportsNotFoundForLiveDelete(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const deleteOperationID = "mop-live-delete-not-found"
	adapter, err := Open(ctx, Config{
		DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerToken: testInboundToken,
		ContentStore: terminalLookupStore{
			ContentStore: contentStore, operationID: deleteOperationID,
			result: ContentMutationResult{
				Outcome: ContentOutcomeNotFound, ProviderID: "provider-live-delete",
				Version: "delete-v2", UpdatedAt: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
			},
		},
		StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
		Clock:         func() time.Time { return provider.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close() //nolint:errcheck
	endpoint := httptest.NewServer(adapter.Handler())
	defer endpoint.Close()
	binding := resolveAndClaimKD6Binding(t, endpoint.URL)

	create := newKD6TestMutation(t, binding, "mop-live-delete-create", "mem-live-delete", "live content")
	created, err := protocol.DecodeMutationReceipt(postOMS(t, endpoint.URL, protocol.PathMutations, create))
	if err != nil || created.Result != protocol.ResultApplied {
		t.Fatalf("create receipt = %#v, %v", created, err)
	}
	deleteMutation := protocol.MutationEnvelope{
		ProtocolVersion: protocol.Version, OperationID: deleteOperationID, Binding: binding,
		MemoryID: create.MemoryID, Kind: protocol.MutationKindDelete, Generation: 2,
		ExpectedGeneration: 1, ExpectedBackendVersion: created.BackendVersion,
	}
	if err := protocol.PrepareMutation(&deleteMutation); err != nil {
		t.Fatal(err)
	}
	body, status := postOMSStatus(t, endpoint.URL, protocol.PathMutations, deleteMutation)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("delete mismatch status = %d, want %d: %s", status, http.StatusServiceUnavailable, body)
	}
	receipt, err := protocol.DecodeMutationReceipt(body)
	if err != nil || receipt.Result != protocol.ResultRetryableError {
		t.Fatalf("delete mismatch receipt = %#v, %v", receipt, err)
	}
	var intents, receipts int
	if err := adapter.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_intents WHERE operation_id = ?`, deleteOperationID).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := adapter.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_receipts WHERE operation_id = ?`, deleteOperationID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if intents != 1 || receipts != 0 {
		t.Fatalf("delete mismatch control state intents=%d receipts=%d, want 1/0", intents, receipts)
	}
}

func TestKD6AdapterPreservesSemanticOrderAndScoresAcrossRestart(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	provider.semantic = true
	provider.searchScores["mem-zulu"] = 0.95
	provider.searchScores["mem-alpha"] = 0.25
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(t.TempDir(), "control.db")
	open := func() *Server {
		adapter, openErr := Open(ctx, Config{
			DatabasePath: databasePath, BearerToken: testInboundToken,
			ContentStore: contentStore, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
			Clock: func() time.Time { return provider.clock },
		})
		if openErr != nil {
			t.Fatal(openErr)
		}
		return adapter
	}

	adapter := open()
	endpoint := httptest.NewServer(adapter.Handler())
	binding := resolveAndClaimKD6Binding(t, endpoint.URL)
	for _, mutation := range []protocol.MutationEnvelope{
		newKD6TestMutation(t, binding, "mop-ranked-low", "mem-alpha", "ranked durable low"),
		newKD6TestMutation(t, binding, "mop-ranked-high", "mem-zulu", "ranked durable high"),
	} {
		receipt, decodeErr := protocol.DecodeMutationReceipt(postOMS(t, endpoint.URL, protocol.PathMutations, mutation))
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if receipt.Result != protocol.ResultApplied {
			t.Fatalf("mutation result = %q", receipt.Result)
		}
	}
	search := protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeSemantic,
		Query: "ranked", PageSize: 1, PageToken: "",
	}
	first, err := protocol.DecodeSearchResponse(postOMS(t, endpoint.URL, protocol.PathSearch, search))
	if err != nil {
		t.Fatal(err)
	}
	if protocol.CanonicalUpsertKey(binding, "mem-alpha") >= protocol.CanonicalUpsertKey(binding, "mem-zulu") {
		t.Fatal("semantic ranking fixture does not differ from canonical key order")
	}
	if first.ActualMode != protocol.SearchModeSemantic || len(first.Records) != 1 ||
		first.Records[0].MemoryID != "mem-zulu" || first.Records[0].Score != 0.95 || first.NextPageToken == "" {
		t.Fatalf("first ranked page = %#v", first)
	}
	provider.searchScores["mem-zulu"] = 0.05
	provider.searchScores["mem-alpha"] = 0.99
	endpoint.Close()
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}

	adapter = open()
	endpoint = httptest.NewServer(adapter.Handler())
	defer endpoint.Close()
	defer adapter.Close() //nolint:errcheck
	search.PageToken = first.NextPageToken
	second, err := protocol.DecodeSearchResponse(postOMS(t, endpoint.URL, protocol.PathSearch, search))
	if err != nil {
		t.Fatal(err)
	}
	if second.ActualMode != protocol.SearchModeSemantic || len(second.Records) != 1 ||
		second.Records[0].MemoryID != "mem-alpha" || second.Records[0].Score != 0.25 || !second.Exhausted {
		t.Fatalf("second ranked page after restart = %#v", second)
	}
}

func assertControlDatabaseContainsNoContent(t *testing.T, databasePath, marker string) {
	t.Helper()
	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(marker)) {
			t.Fatalf("control database file %s contains acknowledged content marker", filepath.Base(path))
		}
	}
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	for _, table := range []string{"operation_receipts", "mutation_intents", "record_controls", "pagination_snapshots", "pagination_entries"} {
		rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var cid int
			var name, columnType string
			var notNull, primaryKey int
			var defaultValue any
			if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			switch strings.ToLower(name) {
			case "content", "tags_json", "metadata_json", "request_json", "record_json", "payload":
				_ = rows.Close()
				t.Fatalf("control table %s contains forbidden content-authority column %s", table, name)
			}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestKD6AdapterRecoversProviderSuccessAfterRestart(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(t.TempDir(), "crash-recovery.db")
	open := func(store ContentStore) *Server {
		server, openErr := Open(ctx, Config{
			DatabasePath: databasePath, BearerToken: testInboundToken, ContentStore: store,
			StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
			Clock:         func() time.Time { return provider.clock },
		})
		if openErr != nil {
			t.Fatal(openErr)
		}
		return server
	}

	ambiguousStore := &ambiguousAfterProviderSuccessStore{ContentStore: contentStore}
	first := open(ambiguousStore)
	firstEndpoint := httptest.NewServer(first.Handler())
	binding := resolveAndClaimKD6Binding(t, firstEndpoint.URL)
	mutation := newKD6TestMutation(t, binding, "mop-crash-recovery", "mem-crash-recovery", "survives provider success")
	body, status := postOMSStatus(t, firstEndpoint.URL, protocol.PathMutations, mutation)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("ambiguous mutation status = %d, want %d: %s", status, http.StatusServiceUnavailable, body)
	}
	retryReceipt, err := protocol.DecodeMutationReceipt(body)
	if err != nil || retryReceipt.Result != protocol.ResultRetryableError {
		t.Fatalf("ambiguous mutation receipt = %#v, err = %v", retryReceipt, err)
	}
	var intents, receipts, controls int
	if err := first.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := first.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err := first.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM record_controls`).Scan(&controls); err != nil {
		t.Fatal(err)
	}
	if intents != 1 || receipts != 0 || controls != 0 {
		t.Fatalf("pre-restart control state intents=%d receipts=%d controls=%d, want 1/0/0", intents, receipts, controls)
	}
	firstEndpoint.Close()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second := open(contentStore)
	defer second.Close() //nolint:errcheck
	secondEndpoint := httptest.NewServer(second.Handler())
	defer secondEndpoint.Close()
	finalReceipt, err := protocol.DecodeMutationReceipt(postOMS(t, secondEndpoint.URL, protocol.PathMutations, mutation))
	if err != nil || finalReceipt.Result != protocol.ResultApplied {
		t.Fatalf("recovered mutation receipt = %#v, err = %v", finalReceipt, err)
	}
	if err := second.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := second.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err := second.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM record_controls`).Scan(&controls); err != nil {
		t.Fatal(err)
	}
	if intents != 0 || receipts != 1 || controls != 1 {
		t.Fatalf("post-restart control state intents=%d receipts=%d controls=%d, want 0/1/1", intents, receipts, controls)
	}
	provider.mu.Lock()
	mutateCalls, lookupCalls := provider.mutateCalls, provider.operationLookupCalls
	provider.mu.Unlock()
	if mutateCalls != 1 {
		t.Fatalf("provider mutate calls = %d, want 1", mutateCalls)
	}
	if lookupCalls < 2 {
		t.Fatalf("provider operation lookup calls = %d, want at least 2", lookupCalls)
	}
}

func TestKD6AdapterPreservesIntentAcrossGenericErrorsAndRestart(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wrap     func(ContentStore) ContentStore
		recovers bool
	}{
		{name: "lookup generic error", wrap: func(store ContentStore) ContentStore {
			return lookupErrorStore{ContentStore: store, err: errors.New("generic lookup failure")}
		}, recovers: true},
		{name: "mutation context error", wrap: func(store ContentStore) ContentStore {
			return mutationErrorStore{ContentStore: store, err: context.DeadlineExceeded}
		}},
		{name: "mutation malformed response error", wrap: func(store ContentStore) ContentStore {
			return mutationErrorStore{ContentStore: store, err: &StoreError{Code: "KD6_INVALID_RESPONSE", Kind: errors.New("malformed response")}}
		}},
		{name: "mutation non-definitive divergence", wrap: func(store ContentStore) ContentStore {
			return mutationErrorStore{ContentStore: store, err: &StoreError{Code: "KD6_DIVERGED", Kind: ErrProviderDiverged}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var clock atomic.Int64
			clock.Store(time.Now().UTC().UnixNano())
			provider := newFakeKD6(t, "provider-token")
			providerServer := httptest.NewTLSServer(provider.handler())
			defer providerServer.Close()
			contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
				Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			databasePath := filepath.Join(t.TempDir(), "ambiguous-restart.db")
			open := func(store ContentStore) *Server {
				server, openErr := Open(ctx, Config{
					DatabasePath: databasePath, BearerToken: testInboundToken, ContentStore: store,
					StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
					Clock:         func() time.Time { return time.Unix(0, clock.Load()).UTC() },
				})
				if openErr != nil {
					t.Fatal(openErr)
				}
				return server
			}

			first := open(tc.wrap(contentStore))
			firstEndpoint := httptest.NewServer(first.Handler())
			binding := resolveAndClaimKD6Binding(t, firstEndpoint.URL)
			mutation := newKD6TestMutation(t, binding, "mop-ambiguous-restart", "mem-ambiguous-restart", "content")
			body, status := postOMSStatus(t, firstEndpoint.URL, protocol.PathMutations, mutation)
			if status != http.StatusServiceUnavailable {
				t.Fatalf("ambiguous mutation status = %d, want %d: %s", status, http.StatusServiceUnavailable, body)
			}
			receipt, decodeErr := protocol.DecodeMutationReceipt(body)
			if decodeErr != nil || receipt.Result != protocol.ResultRetryableError {
				t.Fatalf("ambiguous receipt = %#v, err = %v", receipt, decodeErr)
			}
			var intents, receipts int
			if err := first.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_intents`).Scan(&intents); err != nil {
				t.Fatal(err)
			}
			if err := first.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_receipts`).Scan(&receipts); err != nil {
				t.Fatal(err)
			}
			if intents != 1 || receipts != 0 {
				t.Fatalf("pre-restart intents/receipts = %d/%d, want 1/0", intents, receipts)
			}
			firstEndpoint.Close()
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			clock.Add((mutationProviderDispatchTimeout + time.Second).Nanoseconds())

			second := open(contentStore)
			defer second.Close() //nolint:errcheck
			secondEndpoint := httptest.NewServer(second.Handler())
			defer secondEndpoint.Close()
			claimBody, claimStatus := postOMSStatus(t, secondEndpoint.URL, protocol.PathOwnershipClaim, protocol.OwnershipClaimRequest{
				ProtocolVersion: protocol.Version, Binding: binding,
			})
			if claimStatus != http.StatusOK {
				t.Fatalf("restart ownership claim status = %d: %s", claimStatus, claimBody)
			}
			finalBody, finalStatus := postOMSStatus(t, secondEndpoint.URL, protocol.PathMutations, mutation)
			finalReceipt, decodeErr := protocol.DecodeMutationReceipt(finalBody)
			if tc.recovers {
				if finalStatus != http.StatusOK || decodeErr != nil || finalReceipt.Result != protocol.ResultApplied {
					t.Fatalf("recovered receipt/status = %#v/%d, err = %v", finalReceipt, finalStatus, decodeErr)
				}
			} else if finalStatus != http.StatusServiceUnavailable || decodeErr != nil || finalReceipt.Result != protocol.ResultRetryableError {
				t.Fatalf("ambiguous replay receipt/status = %#v/%d, err = %v", finalReceipt, finalStatus, decodeErr)
			}
			if !tc.recovers {
				if err := second.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_intents`).Scan(&intents); err != nil {
					t.Fatal(err)
				}
				if err := second.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_receipts`).Scan(&receipts); err != nil {
					t.Fatal(err)
				}
				if intents != 1 || receipts != 0 {
					t.Fatalf("post-restart intents/receipts = %d/%d, want 1/0", intents, receipts)
				}
			}
		})
	}
}

func TestKD6RoutingFenceWaitsForAmbiguousProviderLookup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lookup ContentOperationLookupResult
		err    error
	}{
		{name: "pending", lookup: ContentOperationLookupResult{Status: ContentOperationLookupPending}},
		{name: "not-found", lookup: ContentOperationLookupResult{Status: ContentOperationLookupNotFound}},
		{name: "divergence", err: &StoreError{Code: "KD6_INVALID_OPERATION_LOOKUP", Kind: ErrProviderDiverged}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var clock atomic.Int64
			now := time.Now().UTC().Truncate(time.Second)
			clock.Store(now.UnixNano())
			provider := newFakeKD6(t, "provider-token")
			providerServer := httptest.NewTLSServer(provider.handler())
			defer providerServer.Close()
			baseStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
				Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			delayed := &delayedLookupVisibilityStore{
				ContentStore: baseStore, status: tc.lookup, err: tc.err,
			}
			adapter, err := Open(ctx, Config{
				DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerToken: testInboundToken,
				ContentStore: delayed, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
				Clock: func() time.Time { return time.Unix(0, clock.Load()).UTC() },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close() //nolint:errcheck
			endpoint := httptest.NewServer(adapter.Handler())
			defer endpoint.Close()
			binding := resolveAndClaimKD6Binding(t, endpoint.URL)
			mutation := newKD6TestMutation(t, binding, "mop-delayed-"+tc.name, "mem-delayed-"+tc.name, "content")
			body, mutationStatus := postOMSStatus(t, endpoint.URL, protocol.PathMutations, mutation)
			receipt, decodeErr := protocol.DecodeMutationReceipt(body)
			if mutationStatus != http.StatusServiceUnavailable || decodeErr != nil || receipt.Result != protocol.ResultRetryableError {
				t.Fatalf("ambiguous mutation receipt/status = %#v/%d, err = %v", receipt, mutationStatus, decodeErr)
			}

			clock.Add((mutationProviderDispatchTimeout + time.Second).Nanoseconds())
			fenced := binding
			fenced.RoutingEpoch++
			fenceBody, fenceStatus, fenceHeaders := postOMSResponse(t, endpoint.URL, protocol.PathRoutingFence, protocol.RoutingFenceRequest{
				ProtocolVersion: protocol.Version, Binding: fenced,
			})
			if fenceStatus != http.StatusServiceUnavailable {
				t.Fatalf("blocked fence status = %d, want %d: %s", fenceStatus, http.StatusServiceUnavailable, fenceBody)
			}
			errorResponse, err := protocol.DecodeErrorResponse(fenceBody)
			if err != nil {
				t.Fatalf("blocked fence returned invalid ErrorResponse: %v: %s", err, fenceBody)
			}
			if errorResponse.Binding == nil || !protocol.BindingEqual(*errorResponse.Binding, fenced) ||
				errorResponse.Code != protocol.ErrorCodeInternal || !errorResponse.Retryable ||
				errorResponse.RetryAfterSeconds != 1 || fenceHeaders.Get("Retry-After") != "1" {
				t.Fatalf("blocked fence error = %#v", errorResponse)
			}
			var intents int
			if err := adapter.db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_intents WHERE operation_id = ?`, mutation.OperationID).Scan(&intents); err != nil {
				t.Fatal(err)
			}
			var maximum uint64
			if err := adapter.db.db.QueryRowContext(ctx, `SELECT max_routing_epoch FROM ownership_claims WHERE claim_scope_digest = ?`, protocol.ClaimScopeDigest(binding)).Scan(&maximum); err != nil {
				t.Fatal(err)
			}
			if intents != 1 || maximum != binding.RoutingEpoch {
				t.Fatalf("blocked fence state intents/max = %d/%d, want 1/%d", intents, maximum, binding.RoutingEpoch)
			}

			delayed.hidden.Store(false)
			clock.Add((mutationRecoveryLease + time.Second).Nanoseconds())
			fenceBody, fenceStatus = postOMSStatus(t, endpoint.URL, protocol.PathRoutingFence, protocol.RoutingFenceRequest{
				ProtocolVersion: protocol.Version, Binding: fenced,
			})
			response, err := protocol.DecodeRoutingFenceResponse(fenceBody)
			if fenceStatus != http.StatusOK || err != nil || response.Result != protocol.ResultApplied || response.MaximumRoutingEpoch != fenced.RoutingEpoch {
				t.Fatalf("recovered fence response/status = %#v/%d, err = %v", response, fenceStatus, err)
			}
			provider.mu.Lock()
			mutateCalls := provider.mutateCalls
			provider.mu.Unlock()
			if mutateCalls != 1 {
				t.Fatalf("provider mutate calls = %d, want 1", mutateCalls)
			}
		})
	}
}

func TestKD6AdapterSupportsOptionalSemanticAndHybridSearch(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	provider.semantic, provider.hybrid = true, true
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := Open(ctx, Config{
		DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerToken: testInboundToken,
		ContentStore: contentStore, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close() //nolint:errcheck
	endpoint := httptest.NewServer(adapter.Handler())
	defer endpoint.Close()

	binding := conformance.DefaultBinding()
	storeBinding := protocol.StoreResolutionBinding{
		ClusterID: binding.ClusterID, NamespaceUID: binding.NamespaceUID,
		BackendUID: binding.BackendUID, TenantID: binding.TenantID,
	}
	resolveBody := postOMS(t, endpoint.URL, protocol.PathStoreResolve, protocol.StoreResolveRequest{
		ProtocolVersion: protocol.Version, Binding: storeBinding, StoreName: testOMSStoreName,
	})
	resolved, err := protocol.DecodeStoreResolveResponse(resolveBody)
	if err != nil {
		t.Fatal(err)
	}
	binding.StoreUUID = resolved.StoreUUID
	capBody := postOMS(t, endpoint.URL, protocol.PathCapabilities, protocol.CapabilitiesRequest{
		ProtocolVersion: protocol.Version, Binding: binding,
	})
	capabilities, err := protocol.DecodeCapabilitiesResponse(capBody)
	if err != nil {
		t.Fatal(err)
	}
	if !capabilities.Capabilities.SemanticSearch || !capabilities.Capabilities.HybridSearch {
		t.Fatalf("capabilities = %#v", capabilities.Capabilities)
	}
	postOMS(t, endpoint.URL, protocol.PathOwnershipClaim, protocol.OwnershipClaimRequest{
		ProtocolVersion: protocol.Version, Binding: binding,
	})
	mutation := protocol.MutationEnvelope{
		ProtocolVersion: protocol.Version, OperationID: "mop-semantic-1", Binding: binding,
		MemoryID: "mem-semantic-1", Kind: protocol.MutationKindCreate, Generation: 1,
		State: &protocol.MutationState{
			Content: "semantic durable memory", Tags: []string{"semantic"}, Metadata: map[string]string{"source": "test"},
		},
	}
	if err := protocol.PrepareMutation(&mutation); err != nil {
		t.Fatal(err)
	}
	postOMS(t, endpoint.URL, protocol.PathMutations, mutation)
	searchBody := postOMS(t, endpoint.URL, protocol.PathSearch, protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeSemantic,
		Query: testDurableQuery, PageSize: 2, PageToken: "",
	})
	response, err := protocol.DecodeSearchResponse(searchBody)
	if err != nil {
		t.Fatal(err)
	}
	if response.ActualMode != protocol.SearchModeSemantic || len(response.Records) != 1 {
		t.Fatalf("search response = %#v", response)
	}
}

func TestKD6AdapterSearchAppliesSnapshotLimitAfterAuthorityIsolation(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := Open(ctx, Config{
		DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerToken: testInboundToken,
		ContentStore: contentStore, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
		MaxSnapshotRecords: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close() //nolint:errcheck
	endpoint := httptest.NewServer(adapter.Handler())
	defer endpoint.Close()

	oldBinding := resolveAndClaimKD6Binding(t, endpoint.URL)
	for i := range 2 {
		mutation := newKD6TestMutation(t, oldBinding, fmt.Sprintf("mop-old-crowd-%d", i), fmt.Sprintf("mem-old-crowd-%d", i), "authority crowding")
		receipt, decodeErr := protocol.DecodeMutationReceipt(postOMS(t, endpoint.URL, protocol.PathMutations, mutation))
		if decodeErr != nil || receipt.Result != protocol.ResultApplied {
			t.Fatalf("old mutation %d receipt = %#v, err = %v", i, receipt, decodeErr)
		}
	}

	currentBinding := oldBinding
	currentBinding.AuthorityEpoch++
	currentBinding.RoutingEpoch = 1
	claim, err := protocol.DecodeOwnershipClaimResponse(postOMS(t, endpoint.URL, protocol.PathOwnershipClaim, protocol.OwnershipClaimRequest{
		ProtocolVersion: protocol.Version, Binding: currentBinding,
	}))
	if err != nil || claim.Result != protocol.ResultApplied {
		t.Fatalf("current authority claim = %#v, err = %v", claim, err)
	}
	current := newKD6TestMutation(t, currentBinding, "mop-current-crowd", "mem-current-crowd", "authority crowding")
	receipt, err := protocol.DecodeMutationReceipt(postOMS(t, endpoint.URL, protocol.PathMutations, current))
	if err != nil || receipt.Result != protocol.ResultApplied {
		t.Fatalf("current mutation receipt = %#v, err = %v", receipt, err)
	}

	response, err := protocol.DecodeSearchResponse(postOMS(t, endpoint.URL, protocol.PathSearch, protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: currentBinding, Mode: protocol.SearchModeKeyword,
		Query: "authority crowding", PageSize: 2, PageToken: "",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Records) != 1 || response.Records[0].MemoryID != current.MemoryID || !response.Exhausted {
		t.Fatalf("authority-isolated search response = %#v", response)
	}
}

func TestKD6AdapterSearchPagesRespectEncodedResponseLimitWithoutLosingRecords(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := Open(ctx, Config{
		DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerToken: testInboundToken,
		ContentStore: contentStore, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close() //nolint:errcheck
	endpoint := httptest.NewServer(adapter.Handler())
	defer endpoint.Close()
	binding := resolveAndClaimKD6Binding(t, endpoint.URL)

	escapingContent := strings.Repeat("\u2028", protocol.MaxContentBytes/len("\u2028"))
	escapingContent += strings.Repeat("x", protocol.MaxContentBytes-len(escapingContent))
	const recordCount = protocol.MaxPageSize
	for i := range recordCount {
		mutation := newKD6TestMutation(t, binding, fmt.Sprintf("mop-escaping-%d", i), fmt.Sprintf("mem-escaping-%d", i), escapingContent)
		receipt, decodeErr := protocol.DecodeMutationReceipt(postOMS(t, endpoint.URL, protocol.PathMutations, mutation))
		if decodeErr != nil || receipt.Result != protocol.ResultApplied {
			t.Fatalf("escaping mutation %d receipt = %#v, err = %v", i, receipt, decodeErr)
		}
	}

	request := protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword,
		Query: "", PageSize: protocol.MaxPageSize, PageToken: "",
	}
	seen := make(map[string]struct{}, recordCount)
	pages := 0
	for {
		body, status := postOMSStatus(t, endpoint.URL, protocol.PathSearch, request)
		if status != http.StatusOK {
			t.Fatalf("search page %d status = %d: %s", pages, status, body)
		}
		if len(body) > protocol.MaxAdapterResponseBytes {
			t.Fatalf("search page %d encoded size = %d, limit = %d", pages, len(body), protocol.MaxAdapterResponseBytes)
		}
		response, decodeErr := protocol.DecodeSearchResponse(body)
		if decodeErr != nil {
			t.Fatalf("decode search page %d: %v", pages, decodeErr)
		}
		if pages == 0 && len(response.Records) >= request.PageSize {
			t.Fatalf("first escaping page returned %d records; expected a shorter byte-bounded prefix", len(response.Records))
		}
		for _, record := range response.Records {
			if record.Content != escapingContent {
				t.Fatalf("record %q content changed", record.MemoryID)
			}
			if _, duplicate := seen[record.MemoryID]; duplicate {
				t.Fatalf("record %q was returned more than once", record.MemoryID)
			}
			seen[record.MemoryID] = struct{}{}
		}
		pages++
		if response.Exhausted {
			break
		}
		if response.NextPageToken == "" || pages > recordCount {
			t.Fatalf("invalid continuation after page %d: %#v", pages, response)
		}
		request.PageToken = response.NextPageToken
	}
	if len(seen) != recordCount {
		t.Fatalf("search returned %d distinct records, want %d", len(seen), recordCount)
	}
}

func TestKD6AdapterSearchSnapshotQuotas(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(provider.clock.UnixNano())
	adapter, err := Open(ctx, Config{
		DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerToken: testInboundToken,
		ContentStore: contentStore, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
		SnapshotTTL: time.Minute, Clock: func() time.Time { return time.Unix(0, clock.Load()).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close() //nolint:errcheck
	endpoint := httptest.NewServer(adapter.Handler())
	defer endpoint.Close()
	binding := resolveAndClaimKD6Binding(t, endpoint.URL)
	maximumContent := strings.Repeat("\n", protocol.MaxContentBytes)
	mutation := newKD6TestMutation(t, binding, "mop-snapshot-quota", "mem-snapshot-quota", maximumContent)
	postOMS(t, endpoint.URL, protocol.PathMutations, mutation)
	request := protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword,
		Query: "", PageSize: 1, PageToken: "",
	}
	for i := range maxActiveSearchSnapshotsPerAuthority {
		response, decodeErr := protocol.DecodeSearchResponse(postOMS(t, endpoint.URL, protocol.PathSearch, request))
		if decodeErr != nil || len(response.Records) != 1 || response.Records[0].Content != maximumContent {
			t.Fatalf("maximum-content search %d = %#v, err = %v", i, response, decodeErr)
		}
	}
	provider.mu.Lock()
	providerSnapshots := provider.sequence
	provider.mu.Unlock()
	body, status := postOMSStatus(t, endpoint.URL, protocol.PathSearch, request)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("per-authority snapshot quota status = %d, want %d: %s", status, http.StatusServiceUnavailable, body)
	}
	capacity, decodeErr := protocol.DecodeErrorResponse(body)
	if decodeErr != nil || capacity.Code != protocol.ErrorCodeSnapshotCapacity {
		t.Fatalf("per-authority snapshot quota response = %#v, err = %v", capacity, decodeErr)
	}
	provider.mu.Lock()
	if provider.sequence != providerSnapshots {
		t.Fatalf("provider snapshots advanced after local quota rejection: got %d, want %d", provider.sequence, providerSnapshots)
	}
	provider.mu.Unlock()

	clock.Store(time.Unix(0, clock.Load()).Add(2 * time.Minute).UnixNano())
	postOMS(t, endpoint.URL, protocol.PathSearch, request)
	var active int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active snapshots after expiry cleanup = %d, want 1", active)
	}

	if _, err := adapter.db.db.Exec(`DELETE FROM pagination_snapshots`); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(0, clock.Load()).UTC()
	for i := range maxActiveSearchSnapshotsGlobal {
		_, err := adapter.db.db.Exec(`INSERT INTO pagination_snapshots(
			snapshot_id, authority_digest, request_fingerprint, provider_snapshot_id, provider_store_id,
			requested_mode, actual_mode, page_size, entry_count, created_at, expires_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, fmt.Sprintf("seed-%032d", i), fmt.Sprintf("authority-%d", i),
			"fingerprint", fmt.Sprintf("provider-snapshot-%d", i), fakeProviderStoreID,
			protocol.SearchModeKeyword, protocol.SearchModeKeyword, 1, 0, formatTime(now), formatTime(now.Add(time.Hour)))
		if err != nil {
			t.Fatal(err)
		}
	}
	provider.mu.Lock()
	providerSnapshots = provider.sequence
	provider.mu.Unlock()
	body, status = postOMSStatus(t, endpoint.URL, protocol.PathSearch, request)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("global snapshot quota status = %d, want %d: %s", status, http.StatusServiceUnavailable, body)
	}
	provider.mu.Lock()
	if provider.sequence != providerSnapshots {
		t.Fatalf("provider snapshots advanced after global quota rejection: got %d, want %d", provider.sequence, providerSnapshots)
	}
	provider.mu.Unlock()
}

func TestKD6AdapterRejectsOversizedSnapshotDescriptorState(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	baseStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	memoryID := "mem-oversized-descriptor"
	providerID := strings.Repeat("p", maxSearchSnapshotBytes+1)
	entry := ContentDescriptor{
		MemoryID: memoryID, Generation: 1, ProviderID: providerID, Version: "v1",
		ContentDigest: protocol.ContentDigest("content"), UpdatedAt: now,
	}
	store := fixedSearchSnapshotStore{ContentStore: baseStore, snapshot: ContentSearchSnapshot{
		SnapshotID: "provider-oversized-descriptor", ActualMode: protocol.SearchModeKeyword,
		ExpiresAt: now.Add(time.Hour), Entries: []ContentDescriptor{entry},
	}}
	adapter, err := Open(ctx, Config{
		DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerToken: testInboundToken,
		ContentStore: store, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close() //nolint:errcheck
	endpoint := httptest.NewServer(adapter.Handler())
	defer endpoint.Close()
	binding := resolveAndClaimKD6Binding(t, endpoint.URL)
	entry.UpsertKey = protocol.CanonicalUpsertKey(binding, memoryID)
	store.snapshot.Entries[0].UpsertKey = entry.UpsertKey
	adapter.content = store
	_, err = adapter.db.db.Exec(`INSERT INTO record_controls(
		authority_digest, upsert_key, memory_id, state, generation, backend_version,
		backend_memory_id, content_digest, updated_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`, protocol.AuthorityDigest(binding), entry.UpsertKey, entry.MemoryID,
		protocol.RecordStateLive, entry.Generation, entry.Version, entry.ProviderID, entry.ContentDigest, formatTime(entry.UpdatedAt))
	if err != nil {
		t.Fatal(err)
	}
	body, status := postOMSStatus(t, endpoint.URL, protocol.PathSearch, protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, Query: "", PageSize: 1,
	})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("oversized snapshot status = %d, want %d: %s", status, http.StatusServiceUnavailable, body)
	}
	response, decodeErr := protocol.DecodeErrorResponse(body)
	if decodeErr != nil || response.Code != protocol.ErrorCodeSnapshotCapacity {
		t.Fatalf("oversized snapshot response = %#v, err = %v", response, decodeErr)
	}
}

func resolveAndClaimKD6Binding(t *testing.T, baseURL string) protocol.Binding {
	t.Helper()
	binding := conformance.DefaultBinding()
	resolveBody := postOMS(t, baseURL, protocol.PathStoreResolve, protocol.StoreResolveRequest{
		ProtocolVersion: protocol.Version,
		Binding: protocol.StoreResolutionBinding{
			ClusterID: binding.ClusterID, NamespaceUID: binding.NamespaceUID,
			BackendUID: binding.BackendUID, TenantID: binding.TenantID,
		},
		StoreName: testOMSStoreName,
	})
	resolved, err := protocol.DecodeStoreResolveResponse(resolveBody)
	if err != nil {
		t.Fatal(err)
	}
	binding.StoreUUID = resolved.StoreUUID
	claimBody := postOMS(t, baseURL, protocol.PathOwnershipClaim, protocol.OwnershipClaimRequest{
		ProtocolVersion: protocol.Version, Binding: binding,
	})
	claim, err := protocol.DecodeOwnershipClaimResponse(claimBody)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Result != protocol.ResultApplied {
		t.Fatalf("ownership claim result = %q", claim.Result)
	}
	return binding
}

func newKD6TestMutation(t *testing.T, binding protocol.Binding, operationID, memoryID, content string) protocol.MutationEnvelope {
	t.Helper()
	mutation := protocol.MutationEnvelope{
		ProtocolVersion: protocol.Version, OperationID: operationID, Binding: binding,
		MemoryID: memoryID, Kind: protocol.MutationKindCreate, Generation: 1,
		State: &protocol.MutationState{
			Content: content, Tags: []string{"ranked"}, Metadata: map[string]string{"source": "test"},
		},
	}
	if err := protocol.PrepareMutation(&mutation); err != nil {
		t.Fatal(err)
	}
	return mutation
}

func postOMS(t *testing.T, baseURL, path string, requestValue any) []byte {
	t.Helper()
	responseBody, status := postOMSStatus(t, baseURL, path, requestValue)
	if status != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d: %s", path, status, http.StatusOK, responseBody)
	}
	return responseBody
}

func postOMSStatus(t *testing.T, baseURL, path string, requestValue any) ([]byte, int) {
	responseBody, status, _ := postOMSResponse(t, baseURL, path, requestValue)
	return responseBody, status
}

func postOMSResponse(t *testing.T, baseURL, path string, requestValue any) ([]byte, int, http.Header) {
	t.Helper()
	body, err := json.Marshal(requestValue)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer inbound-token")
	request.Header.Set("Content-Type", kd6TestJSONMediaType)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close() //nolint:errcheck
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return responseBody, response.StatusCode, response.Header.Clone()
}

func assertHealthStatus(t *testing.T, baseURL, token string, want int) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+protocol.PathHealth, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode != want {
		t.Fatalf("health status = %d, want %d", response.StatusCode, want)
	}
}

func TestKD6AdapterMutationRequiresExactDurableRoutingFence(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := Open(ctx, Config{
		DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerToken: testInboundToken,
		ContentStore: contentStore, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
		Clock: func() time.Time { return provider.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close() //nolint:errcheck
	endpoint := httptest.NewServer(adapter.Handler())
	defer endpoint.Close()
	binding := resolveAndClaimKD6Binding(t, endpoint.URL)
	fenced := binding
	fenced.RoutingEpoch++
	postOMS(t, endpoint.URL, protocol.PathRoutingFence, protocol.RoutingFenceRequest{
		ProtocolVersion: protocol.Version, Binding: fenced,
	})

	stale := fenced
	stale.RoutingEpoch = binding.RoutingEpoch
	staleMutation := newKD6TestMutation(t, stale, "mop-exact-fence-"+fmt.Sprint(stale.RoutingEpoch), "mem-exact-fence-"+fmt.Sprint(stale.RoutingEpoch), "fenced")
	body, status := postOMSStatus(t, endpoint.URL, protocol.PathMutations, staleMutation)
	if status != http.StatusConflict {
		t.Fatalf("stale routing epoch %d status = %d, want %d", stale.RoutingEpoch, status, http.StatusConflict)
	}
	receipt, err := protocol.DecodeMutationReceipt(body)
	if err != nil || receipt.Result != protocol.ResultIdentityConflict {
		t.Fatalf("stale routing epoch %d receipt = %+v, err=%v", stale.RoutingEpoch, receipt, err)
	}

	future := fenced
	future.RoutingEpoch++
	futureMutation := newKD6TestMutation(t, future, "mop-exact-fence-"+fmt.Sprint(future.RoutingEpoch), "mem-exact-fence-"+fmt.Sprint(future.RoutingEpoch), "fenced")
	body, status = postOMSStatus(t, endpoint.URL, protocol.PathMutations, futureMutation)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("future routing epoch %d status = %d, want %d", future.RoutingEpoch, status, http.StatusServiceUnavailable)
	}
	receipt, err = protocol.DecodeMutationReceipt(body)
	if err != nil || receipt.Result != protocol.ResultRetryableError {
		t.Fatalf("future routing epoch %d receipt = %+v, err=%v", future.RoutingEpoch, receipt, err)
	}
	provider.mu.Lock()
	callsBeforeExact := provider.mutateCalls
	provider.mu.Unlock()
	if callsBeforeExact != 0 {
		t.Fatalf("provider mutate calls for fenced requests = %d, want 0", callsBeforeExact)
	}

	exact := newKD6TestMutation(t, fenced, "mop-exact-fence-current", "mem-exact-fence-current", "exact")
	receipt, err = protocol.DecodeMutationReceipt(postOMS(t, endpoint.URL, protocol.PathMutations, exact))
	if err != nil || receipt.Result != protocol.ResultApplied {
		t.Fatalf("exact-fence receipt = %#v, err = %v", receipt, err)
	}
	provider.mu.Lock()
	callsAfterExact := provider.mutateCalls
	provider.mu.Unlock()
	if callsAfterExact != 1 {
		t.Fatalf("provider mutate calls after exact request = %d, want 1", callsAfterExact)
	}
}

func TestKD6ProviderStoreLookupOnlyMapsMissingIdentityToConflict(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	open := func(t *testing.T) (*Server, protocol.Binding) {
		t.Helper()
		adapter, openErr := Open(ctx, Config{
			DatabasePath: filepath.Join(t.TempDir(), "control.db"), BearerToken: testInboundToken,
			ContentStore: contentStore, StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
		})
		if openErr != nil {
			t.Fatal(openErr)
		}
		t.Cleanup(func() { _ = adapter.Close() })
		binding := conformance.DefaultBinding()
		storeUUID, resolveErr := adapter.db.resolveStore(ctx, protocol.StoreResolutionBinding{
			ClusterID: binding.ClusterID, NamespaceUID: binding.NamespaceUID, BackendUID: binding.BackendUID, TenantID: binding.TenantID,
		}, testOMSStoreName, ResolvedStore{ProviderStoreID: fakeProviderStoreID, CanonicalID: "canonical-store"}, time.Now().UTC())
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		binding.StoreUUID = storeUUID
		return adapter, binding
	}

	t.Run("missing identity", func(t *testing.T) {
		adapter, binding := open(t)
		binding.StoreUUID = "11111111-1111-4111-8111-111111111111"
		decision, err := adapter.db.claimOwnership(ctx, adapter.content, binding, time.Now().UTC())
		if err != nil || decision.result != protocol.ResultIdentityConflict {
			t.Fatalf("missing identity decision = %+v, err = %v", decision, err)
		}
	})

	t.Run("claim database error", func(t *testing.T) {
		adapter, binding := open(t)
		if _, err := adapter.db.db.ExecContext(ctx, `ALTER TABLE store_resolutions RENAME TO broken_store_resolutions`); err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.db.claimOwnership(ctx, adapter.content, binding, time.Now().UTC()); err == nil || errors.Is(err, errIdentityConflict) {
			t.Fatalf("claimOwnership error = %v, want propagated database error", err)
		}
	})

	t.Run("mutation database error", func(t *testing.T) {
		adapter, binding := open(t)
		decision, err := adapter.db.claimOwnership(ctx, adapter.content, binding, time.Now().UTC())
		if err != nil || decision.result != protocol.ResultApplied {
			t.Fatalf("claim decision = %+v, err = %v", decision, err)
		}
		if _, err := adapter.db.db.ExecContext(ctx, `ALTER TABLE store_resolutions RENAME TO broken_store_resolutions`); err != nil {
			t.Fatal(err)
		}
		mutation := newKD6TestMutation(t, binding, "mop-provider-db-error", "mem-provider-db-error", "content")
		if _, err := adapter.db.applyMutation(ctx, adapter.content, &mutation, time.Now().UTC()); err == nil || errors.Is(err, errIdentityConflict) {
			t.Fatalf("applyMutation error = %v, want propagated database error", err)
		}
	})
}

func TestKD6AdapterAuthenticatesBeforeClosedRouteDispatch(t *testing.T) {
	provider, err := NewStaticBearerTokenProvider(testInboundToken, "inbound OMS bearer token")
	if err != nil {
		t.Fatal(err)
	}
	handler := (&Server{authProvider: provider}).Handler()
	for _, tc := range []struct {
		name, method, path, authorization, code string
		status                                  int
	}{
		{name: "wrong method unauthenticated", method: http.MethodGet, path: protocol.PathMutations, status: http.StatusUnauthorized, code: protocol.ErrorCodeUnauthorized},
		{name: "wrong method authenticated", method: http.MethodGet, path: protocol.PathMutations, authorization: "Bearer " + testInboundToken, status: http.StatusMethodNotAllowed, code: protocol.ErrorCodeMethodNotAllowed},
		{name: "unknown path authenticated", method: http.MethodPost, path: "/v1/unknown", authorization: "Bearer " + testInboundToken, status: http.StatusNotFound, code: protocol.ErrorCodeNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			request.Header.Set("Authorization", tc.authorization)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, tc.status, response.Body.Bytes())
			}
			if response.Header().Get("Content-Type") != kd6TestJSONMediaType || response.Header().Get("Cache-Control") != "no-store" {
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

func TestOpenRejectsDuplicateNormalizedStoreMappings(t *testing.T) {
	_, err := Open(context.Background(), Config{
		BearerToken: "inbound-token", DatabasePath: filepath.Join(t.TempDir(), "control.db"),
		ContentStore:  lookupErrorStore{},
		StoreMappings: map[string]string{"store": "provider-a", " store ": "provider-b"},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicated after normalization") {
		t.Fatalf("Open() error = %v, want normalized mapping collision", err)
	}
}

func TestWriteJSONPreservesBindingInEncodingFallback(t *testing.T) {
	binding := conformance.DefaultBinding()
	recorder := httptest.NewRecorder()
	server := &Server{}
	records := make([]protocol.MemoryRecord, 20)
	for index := range records {
		memoryID := fmt.Sprintf("mem-large-%d", index)
		records[index] = protocol.MemoryRecord{
			MemoryID: memoryID, UpsertKey: protocol.CanonicalUpsertKey(binding, memoryID), State: protocol.RecordStateLive,
			Generation: 1, BackendVersion: "v1", BackendMemoryID: fmt.Sprintf("backend-%d", index),
			ContentDigest: protocol.ContentDigest(strings.Repeat("x", protocol.MaxContentBytes)),
			Content:       strings.Repeat("\n", protocol.MaxContentBytes), Tags: []string{}, Metadata: map[string]string{},
			UpdatedAt: time.Now().UTC(),
		}
	}
	server.writeJSON(recorder, http.StatusOK, protocol.SearchResponse{
		ProtocolVersion: protocol.Version, Binding: binding, RequestedMode: protocol.SearchModeKeyword,
		ActualMode: protocol.SearchModeKeyword, Records: records, Exhausted: true,
		SnapshotExpiresAt: time.Now().Add(time.Minute).UTC(),
	})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", recorder.Code)
	}
	response, err := protocol.DecodeErrorResponse(recorder.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if response.Binding == nil || *response.Binding != binding || response.Code != protocol.ErrorCodeResponseTooLarge {
		t.Fatalf("fallback response = %+v", response)
	}
}

func TestProviderOperationDigestConflictTerminalizesIntent(t *testing.T) {
	ctx := context.Background()
	provider := newFakeKD6(t, "provider-token")
	providerServer := httptest.NewTLSServer(provider.handler())
	defer providerServer.Close()
	contentStore, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: providerServer.URL, BearerToken: "provider-token", HTTPClient: providerServer.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := Open(ctx, Config{
		DatabasePath: filepath.Join(t.TempDir(), "operation-conflict.db"), BearerToken: testInboundToken,
		ContentStore: lookupErrorStore{ContentStore: contentStore, err: &StoreError{
			Code: "KD6_OPERATION_CONFLICT", Definitive: true, Kind: ErrProviderIdempotencyConflict,
		}},
		StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close() //nolint:errcheck
	endpoint := httptest.NewServer(adapter.Handler())
	defer endpoint.Close()
	binding := resolveAndClaimKD6Binding(t, endpoint.URL)
	mutation := newKD6TestMutation(t, binding, "mop-provider-conflict", "mem-provider-conflict", "content")
	body, status := postOMSStatus(t, endpoint.URL, protocol.PathMutations, mutation)
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", status, http.StatusConflict, body)
	}
	receipt, err := protocol.DecodeMutationReceipt(body)
	if err != nil || receipt.Result != protocol.ResultIdempotencyConflict {
		t.Fatalf("receipt = %#v, err = %v", receipt, err)
	}
	var intents, receipts int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM mutation_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM operation_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if intents != 0 || receipts != 1 {
		t.Fatalf("control state intents/receipts = %d/%d, want 0/1", intents, receipts)
	}
}

func TestOpenRejectsUnrepresentableSnapshotTTL(t *testing.T) {
	_, err := Open(context.Background(), Config{
		BearerToken: "inbound-token", DatabasePath: filepath.Join(t.TempDir(), "control.db"),
		ContentStore: lookupErrorStore{}, StoreMappings: map[string]string{"store": "provider"},
		SnapshotTTL: 500 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "whole number of seconds") {
		t.Fatalf("Open() error = %v", err)
	}
}
