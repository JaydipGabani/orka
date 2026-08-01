package kd6adapter

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/oms/protocol"
)

const testProviderToken = "secret"

//nolint:gocyclo
func TestHTTPSContentStoreMapsKD6ProxyContract(t *testing.T) {
	provider := newFakeKD6(t, "provider-secret")
	server := httptest.NewTLSServer(provider.handler())
	defer server.Close()

	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: server.URL, BearerToken: "provider-secret", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := store.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("strict provider transport = %#v", store.client.Transport)
	}

	resolved, err := store.ResolveStore(context.Background(), ResolveStoreRequest{
		TenantID: testTenantID, StoreName: testOMSStoreName, ProviderStoreID: fakeProviderStoreID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.CanonicalID != "kd6-store-1" {
		t.Fatalf("resolved = %#v", resolved)
	}
	capabilities, err := store.Capabilities(context.Background(), StoreRequest{TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID})
	if err != nil {
		t.Fatal(err)
	}
	if !capabilities.KeywordSearch || capabilities.SemanticSearch || capabilities.HybridSearch {
		t.Fatalf("capabilities = %#v", capabilities)
	}

	binding := protocol.Binding{
		ClusterID: "cluster-1", NamespaceUID: "namespace-1", BackendUID: "backend-1",
		AuthorityEpoch: 1, RoutingEpoch: 1, TenantID: testTenantID, StoreUUID: "00000000-0000-4000-8000-000000000001",
	}
	writerLease := claimTestWriter(t, store, binding, 1, "writer-holder-1")
	record := ContentRecord{
		UpsertKey: protocol.CanonicalUpsertKey(binding, "mem-1"), Text: "durable content",
		Tags: []string{testDurableQuery, testOMSStoreName}, Attributes: map[string]string{
			"agentname": "research-agent", "taskname": "task-1", "source": "agent",
		},
		Scope:     scopeForMutation(binding, "mem-1", 1, protocol.ContentDigest("durable content")),
		SourceURI: sourceURI(binding, "mem-1"),
	}
	mutation, err := store.Mutate(context.Background(), ContentMutation{
		TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID, WriterLease: writerLease, OperationID: "mop-1",
		MutationDigest: protocol.ContentDigest("mutation-1"), Kind: protocol.MutationKindCreate,
		UpsertKey: record.UpsertKey, Record: &record,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mutation.Outcome != ContentOutcomeApplied || mutation.Record == nil || mutation.Record.Text != record.Text {
		t.Fatalf("mutation = %#v", mutation)
	}
	provider.mu.Lock()
	captured := *provider.lastMutation
	capturedClaim := *provider.lastWriterClaim
	tenant, agent := provider.lastTenant, provider.lastAgent
	provider.mu.Unlock()
	if tenant != testTenantID {
		t.Fatalf("X-Tenant-Id = %q", tenant)
	}
	wantAgent := deriveTrustedAgentID(record.Attributes)
	if agent != wantAgent || agent == "research-agent" {
		t.Fatalf("X-Agent-Id = %q, want derived %q", agent, wantAgent)
	}
	if captured.Document == nil || captured.Document.SemanticLayer.Text != record.Text || captured.Document.Key != record.UpsertKey ||
		captured.Document.SourceURI != record.SourceURI || captured.Document.Scope != record.Scope {
		t.Fatalf("provider document = %#v", captured.Document)
	}
	if capturedClaim.ProviderStoreID != fakeProviderStoreID || capturedClaim.Lease != writerLease || captured.WriterLease != writerLease {
		t.Fatalf("provider writer claim/mutation leases = %+v / %+v, want %+v", capturedClaim, captured.WriterLease, writerLease)
	}

	got, err := store.Get(context.Background(), ContentGetRequest{TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID, UpsertKey: record.UpsertKey})
	if err != nil || got == nil || got.Text != record.Text {
		t.Fatalf("Get() = %#v, %v", got, err)
	}
	scope := authorityScopeForBinding(binding)
	snapshot, err := store.StartSearch(context.Background(), ContentSearchRequest{
		TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID, Scope: scope, Mode: protocol.SearchModeAuto,
		Query: testDurableQuery, MaxSnapshotRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ActualMode != protocol.SearchModeKeyword || len(snapshot.Entries) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	page, err := store.ReadSearchPage(context.Background(), ContentSearchPageRequest{
		TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID, Scope: scope, SnapshotID: snapshot.SnapshotID,
		Entries: snapshot.Entries,
	})
	if err != nil || len(page) != 1 || page[0].Text != record.Text {
		t.Fatalf("page = %#v, %v", page, err)
	}
}

func TestHTTPSContentStoreWriterLeaseFencesEqualEpochCloneAndStaleMutation(t *testing.T) {
	provider := newFakeKD6(t, testProviderToken)
	server := httptest.NewTLSServer(provider.handler())
	defer server.Close()
	store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: server.URL, BearerToken: testProviderToken, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := protocol.Binding{
		ClusterID: "cluster-1", NamespaceUID: "namespace-1", BackendUID: "backend-1",
		AuthorityEpoch: 1, RoutingEpoch: 1, TenantID: testTenantID, StoreUUID: "00000000-0000-4000-8000-000000000001",
	}
	stale := claimTestWriter(t, store, binding, 1, "writer-holder-original")
	clone := ContentWriterLease{
		Authority: writerAuthorityForBinding(binding), WriterEpoch: 1, HolderIdentity: "writer-holder-clone",
	}
	_, err = store.ClaimWriter(context.Background(), ContentWriterClaim{
		TenantID: binding.TenantID, ProviderStoreID: fakeProviderStoreID, Lease: clone,
	})
	var storeErr *StoreError
	if !errors.As(err, &storeErr) || !errors.Is(err, ErrProviderWriterFenced) || !storeErr.Definitive || !storeErr.NeverApplied {
		t.Fatalf("equal-epoch clone claim error = %#v", err)
	}
	current := claimTestWriter(t, store, binding, 2, clone.HolderIdentity)
	record := ContentRecord{
		UpsertKey: protocol.CanonicalUpsertKey(binding, "mem-stale-writer"), Text: "content",
		Tags: []string{"writer"}, Attributes: map[string]string{"source": "test"},
		Scope:     scopeForMutation(binding, "mem-stale-writer", 1, protocol.ContentDigest("content")),
		SourceURI: sourceURI(binding, "mem-stale-writer"),
	}
	_, err = store.Mutate(context.Background(), ContentMutation{
		TenantID: binding.TenantID, ProviderStoreID: fakeProviderStoreID, WriterLease: stale,
		OperationID: "mop-stale-writer", MutationDigest: protocol.ContentDigest("stale-writer"),
		Kind: protocol.MutationKindCreate, UpsertKey: record.UpsertKey, Record: &record,
	})
	if !errors.As(err, &storeErr) || !errors.Is(err, ErrProviderWriterFenced) || !storeErr.Definitive || !storeErr.NeverApplied {
		t.Fatalf("stale mutation error = %#v", err)
	}
	provider.mu.Lock()
	mutateCalls := provider.mutateCalls
	provider.mu.Unlock()
	if mutateCalls != 0 {
		t.Fatalf("provider mutation side effects = %d, want 0", mutateCalls)
	}
	result, err := store.Mutate(context.Background(), ContentMutation{
		TenantID: binding.TenantID, ProviderStoreID: fakeProviderStoreID, WriterLease: current,
		OperationID: "mop-current-writer", MutationDigest: protocol.ContentDigest("current-writer"),
		Kind: protocol.MutationKindCreate, UpsertKey: record.UpsertKey, Record: &record,
	})
	if err != nil || result.Outcome != ContentOutcomeApplied {
		t.Fatalf("current writer mutation = %+v, err=%v", result, err)
	}
}

func TestHTTPSContentStoreReloadsKD6BearerToken(t *testing.T) {
	provider := newFakeKD6(t, "old-provider-token")
	server := httptest.NewTLSServer(provider.handler())
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "kd6-token")
	if err := os.WriteFile(tokenPath, []byte("old-provider-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenProvider, err := NewFileBearerTokenProvider(tokenPath, "KD6 bearer token")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: server.URL, BearerTokenProvider: tokenProvider, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := ResolveStoreRequest{
		TenantID: testTenantID, StoreName: testOMSStoreName, ProviderStoreID: fakeProviderStoreID,
	}
	if _, err := store.ResolveStore(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	provider.setToken("new-provider-token")
	if err := os.WriteFile(tokenPath, []byte("new-provider-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveStore(context.Background(), request); err != nil {
		t.Fatalf("ResolveStore() after KD6 token rotation: %v", err)
	}
}

func TestHTTPSContentStoreRejectsInvalidSearchScores(t *testing.T) {
	scope := ContentAuthorityScope{
		ClusterID: "cluster-1", NamespaceUID: "namespace-1", BackendUID: "backend-1",
		AuthorityEpoch: 1, StoreUUID: "00000000-0000-4000-8000-000000000001",
	}
	validDescriptor := kd6Descriptor{
		Key: "orka:cluster-1:namespace-1:1:mem-1", ProviderID: "provider-1", Version: "version-1",
		MemoryID: "mem-1", Generation: 1, Scope: scope, ContentDigest: protocol.ContentDigest("content"),
		UpdatedAt: time.Now().UTC(),
	}
	for _, tc := range []struct {
		name       string
		actualMode string
		score      float64
	}{
		{name: "negative semantic score", actualMode: protocol.SearchModeSemantic, score: -0.1},
		{name: "nonzero keyword score", actualMode: protocol.SearchModeKeyword, score: 0.5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor := validDescriptor
			descriptor.Score = tc.score
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeFakeJSON(w, http.StatusOK, kd6SearchStartResponse{
					SnapshotID: "snapshot-1", ActualMode: tc.actualMode,
					ExpiresAt: time.Now().UTC().Add(time.Minute), Entries: []kd6Descriptor{descriptor},
				})
			}))
			defer server.Close()
			store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
				Endpoint: server.URL, BearerToken: testProviderToken, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.StartSearch(context.Background(), ContentSearchRequest{
				TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID, Scope: scope,
				Mode: tc.actualMode, Query: "query", MaxSnapshotRecords: 10,
			})
			var storeErr *StoreError
			if !errors.As(err, &storeErr) || storeErr.Code != "KD6_INVALID_SEARCH_SCORE" {
				t.Fatalf("StartSearch() error = %#v", err)
			}
		})
	}

	for _, score := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		descriptor := validDescriptor
		descriptor.Score = score
		_, err := decodeKD6Descriptor(descriptor, scope)
		var storeErr *StoreError
		if !errors.As(err, &storeErr) || storeErr.Code != "KD6_INVALID_SEARCH_SCORE" {
			t.Fatalf("decodeKD6Descriptor(%v) error = %#v", score, err)
		}
	}
}

func TestHTTPSContentStoreRejectsUnresolvedAutoSnapshotMode(t *testing.T) {
	provider := newFakeKD6(t, testProviderToken)
	provider.searchActualMode = protocol.SearchModeAuto
	server := httptest.NewTLSServer(provider.handler())
	defer server.Close()
	store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: server.URL, BearerToken: testProviderToken, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := ContentAuthorityScope{
		ClusterID: "cluster-1", NamespaceUID: "namespace-1", BackendUID: "backend-1",
		AuthorityEpoch: 1, StoreUUID: "00000000-0000-4000-8000-000000000001",
	}
	_, err = store.StartSearch(context.Background(), ContentSearchRequest{
		TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID, Scope: scope,
		Mode: protocol.SearchModeAuto, Query: "", MaxSnapshotRecords: 8,
	})
	var storeErr *StoreError
	if !errors.As(err, &storeErr) || storeErr.Code != "KD6_INVALID_SEARCH_MODE" {
		t.Fatalf("StartSearch() error = %#v", err)
	}
	if err := validateSearchSnapshotEntries(protocol.SearchModeAuto, nil); !errors.As(err, &storeErr) || storeErr.Code != "KD6_INVALID_SEARCH_MODE" {
		t.Fatalf("validateSearchSnapshotEntries(auto) error = %#v", err)
	}
}

func TestHTTPSContentStoreRejectsSearchDescriptorOutsideRequestedAuthority(t *testing.T) {
	requestedScope := ContentAuthorityScope{
		ClusterID: "cluster-1", NamespaceUID: "namespace-1", BackendUID: "backend-1",
		AuthorityEpoch: 2, StoreUUID: "00000000-0000-4000-8000-000000000001",
	}
	wrongScope := requestedScope
	wrongScope.AuthorityEpoch--
	descriptor := kd6Descriptor{
		Key: "orka:cluster-1:namespace-1:1:mem-1", ProviderID: "provider-1", Version: "version-1",
		MemoryID: "mem-1", Generation: 1, Scope: wrongScope, ContentDigest: protocol.ContentDigest("content"),
		UpdatedAt: time.Now().UTC(),
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeFakeJSON(w, http.StatusOK, kd6SearchStartResponse{
			SnapshotID: "snapshot-1", ActualMode: protocol.SearchModeKeyword,
			ExpiresAt: time.Now().UTC().Add(time.Minute), Entries: []kd6Descriptor{descriptor},
		})
	}))
	defer server.Close()
	store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: server.URL, BearerToken: testProviderToken, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.StartSearch(context.Background(), ContentSearchRequest{
		TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID, Scope: requestedScope,
		Mode: protocol.SearchModeKeyword, Query: "", MaxSnapshotRecords: 8,
	})
	var storeErr *StoreError
	if !errors.As(err, &storeErr) || storeErr.Code != "KD6_INVALID_SEARCH_DESCRIPTOR" {
		t.Fatalf("StartSearch() error = %#v", err)
	}
}

func TestHTTPSContentStoreOperationLookupStatuses(t *testing.T) {
	completed := kd6MutationResponse{Outcome: ContentOutcomePreconditionFailed}
	for _, tc := range []struct {
		name     string
		response kd6OperationLookupResponse
		status   string
		result   bool
	}{
		{name: "completed", response: kd6OperationLookupResponse{Status: ContentOperationLookupCompleted, Result: &completed}, status: ContentOperationLookupCompleted, result: true},
		{name: "pending", response: kd6OperationLookupResponse{Status: ContentOperationLookupPending}, status: ContentOperationLookupPending},
		{name: "not found", response: kd6OperationLookupResponse{Status: ContentOperationLookupNotFound}, status: ContentOperationLookupNotFound},
		{name: "never applied", response: kd6OperationLookupResponse{Status: ContentOperationLookupNeverApplied}, status: ContentOperationLookupNeverApplied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeFakeJSON(w, http.StatusOK, tc.response)
			}))
			defer server.Close()
			store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
				Endpoint: server.URL, BearerToken: testProviderToken, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			lookup, err := store.LookupMutation(context.Background(), ContentOperationLookup{
				TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID,
				OperationID: "mop-lookup", MutationDigest: protocol.ContentDigest("lookup"),
			})
			if err != nil || lookup.Status != tc.status || (lookup.Result != nil) != tc.result {
				t.Fatalf("LookupMutation() = %#v, err = %v", lookup, err)
			}
		})
	}
}

func TestHTTPSContentStoreRejectsAmbiguousOperationLookupShapes(t *testing.T) {
	result := kd6MutationResponse{Outcome: ContentOutcomePreconditionFailed}
	for _, response := range []kd6OperationLookupResponse{
		{Status: ContentOperationLookupCompleted},
		{Status: ContentOperationLookupPending, Result: &result},
		{Status: "unknown"},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeFakeJSON(w, http.StatusOK, response)
		}))
		store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
			Endpoint: server.URL, BearerToken: testProviderToken, HTTPClient: server.Client(),
		})
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		_, err = store.LookupMutation(context.Background(), ContentOperationLookup{
			TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID,
			OperationID: "mop-invalid-lookup", MutationDigest: protocol.ContentDigest("lookup"),
		})
		server.Close()
		var storeErr *StoreError
		if !errors.As(err, &storeErr) || !errors.Is(storeErr, ErrProviderDiverged) || storeErr.Definitive {
			t.Fatalf("LookupMutation() error = %#v", err)
		}
	}
}

func TestContentDescriptorIdentityEqualIgnoresScoreAndUsesTimeEqual(t *testing.T) {
	instant := time.Date(2026, time.July, 29, 12, 0, 0, 123, time.FixedZone("offset", -7*60*60))
	left := ContentDescriptor{
		UpsertKey: "upsert-1", ProviderID: "provider-1", Version: "version-1",
		MemoryID: "memory-1", Generation: 3, ContentDigest: protocol.ContentDigest("content"),
		UpdatedAt: instant, Score: 0.95,
	}
	right := left
	right.UpdatedAt = instant.UTC()
	right.Score = 0.05
	if !contentDescriptorIdentityEqual(left, right) {
		t.Fatal("descriptor identity treated score or time representation as immutable identity")
	}
	right.Version = "version-2"
	if contentDescriptorIdentityEqual(left, right) {
		t.Fatal("descriptor identity ignored a durable version change")
	}
}

func TestContentMatchesControlRecomputesProviderTextDigest(t *testing.T) {
	binding := protocol.Binding{
		ClusterID: "cluster-1", NamespaceUID: "namespace-1", BackendUID: "backend-1",
		AuthorityEpoch: 1, RoutingEpoch: 1, TenantID: testTenantID,
		StoreUUID: "00000000-0000-4000-8000-000000000001",
	}
	updatedAt := time.Date(2026, time.July, 29, 12, 45, 0, 0, time.UTC)
	expectedText := "expected provider text"
	digest := protocol.ContentDigest(expectedText)
	control := controlRecord{
		UpsertKey: protocol.CanonicalUpsertKey(binding, "memory-1"), MemoryID: "memory-1",
		State: protocol.RecordStateLive, Generation: 3, BackendVersion: "version-3",
		BackendMemoryID: "provider-1", ContentDigest: digest, UpdatedAt: updatedAt,
	}
	content := ContentRecord{
		UpsertKey: control.UpsertKey, ProviderID: control.BackendMemoryID, Version: control.BackendVersion,
		Text: "tampered provider text", Scope: scopeForMutation(binding, control.MemoryID, control.Generation, digest),
		SourceURI: sourceURI(binding, control.MemoryID), UpdatedAt: updatedAt,
	}
	if contentMatchesControl(content, control, binding) {
		t.Fatal("provider text with only a copied scope digest matched control state")
	}
	content.Text = expectedText
	if !contentMatchesControl(content, control, binding) {
		t.Fatal("provider text matching the recomputed control digest was rejected")
	}
}

func TestHTTPSContentStoreRejectsMutationRecordIdentityMismatch(t *testing.T) {
	provider := newFakeKD6(t, testProviderToken)
	provider.mutationRecordIdentityMismatch = true
	server := httptest.NewTLSServer(provider.handler())
	defer server.Close()
	store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: server.URL, BearerToken: testProviderToken, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := protocol.Binding{
		ClusterID: "cluster-1", NamespaceUID: "namespace-1", BackendUID: "backend-1",
		AuthorityEpoch: 1, RoutingEpoch: 1, TenantID: testTenantID, StoreUUID: "00000000-0000-4000-8000-000000000001",
	}
	writerLease := claimTestWriter(t, store, binding, 1, "writer-holder-mismatch")
	record := ContentRecord{
		UpsertKey: protocol.CanonicalUpsertKey(binding, "mem-mismatch"), Text: "durable content",
		Tags: []string{"durable"}, Attributes: map[string]string{"source": "test"},
		Scope:     scopeForMutation(binding, "mem-mismatch", 1, protocol.ContentDigest("durable content")),
		SourceURI: sourceURI(binding, "mem-mismatch"),
	}
	_, err = store.Mutate(context.Background(), ContentMutation{
		TenantID: testTenantID, ProviderStoreID: fakeProviderStoreID, WriterLease: writerLease, OperationID: "mop-mismatch",
		MutationDigest: protocol.ContentDigest("mutation-mismatch"), Kind: protocol.MutationKindCreate,
		UpsertKey: record.UpsertKey, Record: &record,
	})
	var storeErr *StoreError
	if !errors.As(err, &storeErr) || storeErr.Code != "KD6_MUTATION_RECORD_IDENTITY_MISMATCH" || !storeErr.Retryable {
		t.Fatalf("Mutate() error = %#v", err)
	}
}

func claimTestWriter(t *testing.T, store *HTTPSContentStore, binding protocol.Binding, epoch uint64, holder string) ContentWriterLease {
	t.Helper()
	lease := ContentWriterLease{
		Authority: writerAuthorityForBinding(binding), WriterEpoch: epoch, HolderIdentity: holder,
	}
	claimed, err := store.ClaimWriter(context.Background(), ContentWriterClaim{
		TenantID: binding.TenantID, ProviderStoreID: fakeProviderStoreID, Lease: lease,
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimed != lease {
		t.Fatalf("claimed writer lease = %+v, want %+v", claimed, lease)
	}
	return lease
}

func TestHTTPSContentStoreRejectsRedirectsAndOversizedResponses(t *testing.T) {
	var redirected bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"providerStoreId":fakeProviderStoreID,"canonicalId":"kd6-store-1"}`))
	}))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{Endpoint: redirect.URL, BearerToken: testProviderToken, HTTPClient: redirect.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.ResolveStore(context.Background(), ResolveStoreRequest{TenantID: testTenantID, StoreName: testOMSStoreName, ProviderStoreID: fakeProviderStoreID})
	if err == nil || redirected {
		t.Fatalf("redirect error = %v, redirected = %v", err, redirected)
	}

	oversized := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"providerStoreId":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", protocol.MaxAdapterResponseBytes)))
	}))
	defer oversized.Close()
	store, err = NewHTTPSContentStore(HTTPSContentStoreConfig{Endpoint: oversized.URL, BearerToken: testProviderToken, HTTPClient: oversized.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.ResolveStore(context.Background(), ResolveStoreRequest{TenantID: testTenantID, StoreName: testOMSStoreName, ProviderStoreID: fakeProviderStoreID})
	var storeErr *StoreError
	if !errors.As(err, &storeErr) || storeErr.Code != "KD6_RESPONSE_TOO_LARGE" {
		t.Fatalf("oversized response error = %#v", err)
	}
}

func TestNewHTTPSContentStoreRejectsUnsafeConfiguration(t *testing.T) {
	for _, endpoint := range []string{"http://example.com", "https://user@example.com", "https://example.com?token=x", "relative"} {
		if _, err := NewHTTPSContentStore(HTTPSContentStoreConfig{Endpoint: endpoint, BearerToken: testProviderToken}); err == nil {
			t.Fatalf("endpoint %q was accepted", endpoint)
		}
	}
	if _, err := NewHTTPSContentStore(HTTPSContentStoreConfig{Endpoint: "https://example.com", BearerToken: "secret value"}); err == nil {
		t.Fatal("whitespace-bearing token was accepted")
	}
}

func TestEqualStringMapsRequiresIdenticalKeyPresence(t *testing.T) {
	if equalStringMaps(map[string]string{"left": ""}, map[string]string{"right": ""}) {
		t.Fatal("equalStringMaps() treated different empty-valued keys as equal")
	}
}

func TestDecodeStrictJSONRequiresExactCompleteKD6ResponseShapes(t *testing.T) {
	valid := []byte(`{"snapshotId":"snapshot-1","actualMode":"keyword","expiresAt":"2030-01-02T03:04:05Z","entries":[]}`)
	var response kd6SearchStartResponse
	if err := decodeStrictJSON(valid, &response); err != nil {
		t.Fatalf("decodeStrictJSON(valid): %v", err)
	}

	for name, body := range map[string][]byte{
		"missing required entries": []byte(`{"snapshotId":"snapshot-1","actualMode":"keyword","expiresAt":"2030-01-02T03:04:05Z"}`),
		"null entries":             []byte(`{"snapshotId":"snapshot-1","actualMode":"keyword","expiresAt":"2030-01-02T03:04:05Z","entries":null}`),
		"case-folded alias":        []byte(`{"snapshotId":"snapshot-1","actualMode":"keyword","expiresAt":"2030-01-02T03:04:05Z","entries":[],"Entries":[]}`),
		"invalid UTF-8":            append(append([]byte(nil), valid[:len(valid)-1]...), 0xff, '}'),
	} {
		t.Run(name, func(t *testing.T) {
			var decoded kd6SearchStartResponse
			if err := decodeStrictJSON(body, &decoded); err == nil {
				t.Fatalf("decodeStrictJSON() accepted %s", name)
			}
		})
	}
}

func TestDecodeStrictJSONRejectsNestedCaseFoldedKD6Alias(t *testing.T) {
	wire := []byte(`{
		"revision":"revision-1",
		"expiresAt":"2030-01-02T03:04:05Z",
		"keywordSearch":true,
		"semanticSearch":false,
		"hybridSearch":false,
		"limits":{
			"maxContentBytes":1,
			"MaxContentBytes":1,
			"maxTags":1,
			"maxTagBytes":1,
			"maxMetadataEntries":1,
			"maxMetadataKeyBytes":1,
			"maxMetadataValueBytes":1,
			"maxQueryBytes":1,
			"maxSnapshotRecords":1
		}
	}`)
	var response kd6CapabilitiesResponse
	if err := decodeStrictJSON(wire, &response); err == nil {
		t.Fatal("decodeStrictJSON() accepted a nested case-folded alias")
	}
}

func TestDecodeProviderErrorKeepsHTTP408NonDefinitive(t *testing.T) {
	err := decodeProviderError(http.StatusRequestTimeout, []byte(`{"code":"KD6_TIMEOUT","retryable":false}`))
	var storeErr *StoreError
	if !errors.As(err, &storeErr) {
		t.Fatalf("decodeProviderError() = %T, want StoreError", err)
	}
	if !storeErr.Retryable || storeErr.Definitive {
		t.Fatalf("HTTP 408 classification = %+v, want retryable and non-definitive", storeErr)
	}
}

func TestDecodeProviderUnauthorizedIsDefinitiveNeverApplied(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		err := decodeProviderError(status, []byte(`{"code":"KD6_UNAUTHORIZED","message":"unauthorized","retryable":false}`))
		var storeErr *StoreError
		if !errors.As(err, &storeErr) || storeErr.Retryable || !storeErr.Definitive || !storeErr.NeverApplied {
			t.Fatalf("decodeProviderError(%d) = %#v, want definitive never-applied authentication rejection", status, err)
		}
	}
}

func TestDecodeKD6AppliedMutationRequiresRecordForWrites(t *testing.T) {
	response := kd6MutationResponse{
		Outcome: ContentOutcomeApplied, ProviderID: "provider-id", Version: "version-1", UpdatedAt: time.Now().UTC(),
	}
	if _, err := decodeKD6MutationResponse(response, protocol.MutationKindCreate); err == nil {
		t.Fatal("recordless applied create was accepted")
	}
	if _, err := decodeKD6MutationResponse(response, protocol.MutationKindReplace); err == nil {
		t.Fatal("recordless applied replace was accepted")
	}
	if _, err := decodeKD6MutationResponse(response, protocol.MutationKindDelete); err != nil {
		t.Fatalf("recordless applied delete was rejected: %v", err)
	}
}

func TestStrictProviderTransportRejectsInsecureTLSConfig(t *testing.T) {
	_, err := strictProviderTransport(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}) //nolint:gosec // negative test
	if err == nil || !strings.Contains(err.Error(), "verify server certificates") {
		t.Fatalf("strictProviderTransport() error = %v", err)
	}
}
