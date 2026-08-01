package kd6adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/oms/protocol"
)

type blockingMutationStore struct {
	ContentStore
	entered chan struct{}
	release chan struct{}
}

func (s *blockingMutationStore) Mutate(ctx context.Context, mutation ContentMutation) (ContentMutationResult, error) {
	s.entered <- struct{}{}
	select {
	case <-s.release:
	case <-ctx.Done():
		return ContentMutationResult{}, ctx.Err()
	}
	return s.ContentStore.Mutate(ctx, mutation)
}

type syntheticMutationStore struct {
	ContentStore
	result func(ContentMutation) ContentMutationResult
}

func (s syntheticMutationStore) Mutate(_ context.Context, mutation ContentMutation) (ContentMutationResult, error) {
	return s.result(mutation), nil
}

type neverAppliedOnceStore struct {
	ContentStore
	calls int
}

func (s *neverAppliedOnceStore) Mutate(ctx context.Context, mutation ContentMutation) (ContentMutationResult, error) {
	s.calls++
	if s.calls == 1 {
		return ContentMutationResult{}, &StoreError{
			Code: "KD6_UNAUTHORIZED", Definitive: true, NeverApplied: true,
		}
	}
	return s.ContentStore.Mutate(ctx, mutation)
}

type blockingSnapshotStore struct {
	ContentStore
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int64
	expires time.Time
}

type failingSearchSnapshotStore struct {
	ContentStore
	err error
}

func (s failingSearchSnapshotStore) StartSearch(context.Context, ContentSearchRequest) (ContentSearchSnapshot, error) {
	return ContentSearchSnapshot{}, s.err
}

type blockingTenantGetStore struct {
	ContentStore
	blockedTenant      string
	independentTenant  string
	blockedEntered     chan struct{}
	independentEntered chan struct{}
	release            chan struct{}
	blockedOnce        sync.Once
	independentOnce    sync.Once
}

func (s *blockingTenantGetStore) Get(ctx context.Context, request ContentGetRequest) (*ContentRecord, error) {
	switch request.TenantID {
	case s.blockedTenant:
		s.blockedOnce.Do(func() { close(s.blockedEntered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	case s.independentTenant:
		s.independentOnce.Do(func() { close(s.independentEntered) })
	}
	return s.ContentStore.Get(ctx, request)
}

func (s *blockingSnapshotStore) StartSearch(ctx context.Context, _ ContentSearchRequest) (ContentSearchSnapshot, error) {
	call := s.calls.Add(1)
	s.entered <- struct{}{}
	select {
	case <-s.release:
	case <-ctx.Done():
		return ContentSearchSnapshot{}, ctx.Err()
	}
	return ContentSearchSnapshot{
		SnapshotID: fmt.Sprintf("provider-snapshot-%d", call), ActualMode: protocol.SearchModeKeyword,
		ExpiresAt: s.expires, Entries: []ContentDescriptor{},
	}, nil
}

func openKD6ControlTestServer(t *testing.T, store ContentStore, databasePath string, clock func() time.Time) (*Server, protocol.Binding) {
	t.Helper()
	server, err := Open(context.Background(), Config{
		DatabasePath: databasePath, BearerToken: testInboundToken, ContentStore: store,
		StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID}, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(server.Handler())
	binding := resolveAndClaimKD6Binding(t, endpoint.URL)
	endpoint.Close()
	return server, binding
}

func newKD6ProviderStore(t *testing.T) (ContentStore, *fakeKD6, func()) {
	t.Helper()
	provider := newFakeKD6(t, "provider-token")
	endpoint := httptest.NewTLSServer(provider.handler())
	store, err := NewHTTPSContentStore(HTTPSContentStoreConfig{
		Endpoint: endpoint.URL, BearerToken: "provider-token", HTTPClient: endpoint.Client(),
	})
	if err != nil {
		endpoint.Close()
		t.Fatal(err)
	}
	return store, provider, endpoint.Close
}

func TestRoutingFenceRejectsActiveProviderDispatch(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	blocked := &blockingMutationStore{ContentStore: baseStore, entered: make(chan struct{}, 1), release: make(chan struct{})}
	now := time.Now().UTC()
	adapter, binding := openKD6ControlTestServer(t, blocked, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	mutation := newKD6TestMutation(t, binding, "mop-active-fence", "mem-active-fence", "content")

	result := make(chan error, 1)
	go func() {
		receipt, err := adapter.db.applyMutation(context.Background(), blocked, &mutation, now)
		if err == nil && receipt.Result != protocol.ResultApplied {
			err = fmt.Errorf("mutation result %q", receipt.Result)
		}
		result <- err
	}()
	<-blocked.entered
	fenced := binding
	fenced.RoutingEpoch++
	decision, err := adapter.db.advanceRoutingFence(context.Background(), blocked, fenced, now)
	if !errors.Is(err, errRoutingFenceBlocked) || decision.maxRouting != binding.RoutingEpoch {
		t.Fatalf("active fence decision = %+v, err = %v", decision, err)
	}
	close(blocked.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	decision, err = adapter.db.advanceRoutingFence(context.Background(), blocked, fenced, now.Add(time.Second))
	if err != nil || decision.result != protocol.ResultApplied || decision.maxRouting != fenced.RoutingEpoch {
		t.Fatalf("settled fence decision = %+v, err = %v", decision, err)
	}
}

func TestBlockedGetDoesNotBlockIndependentTenant(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	store := &blockingTenantGetStore{
		ContentStore: baseStore, blockedEntered: make(chan struct{}), independentEntered: make(chan struct{}),
		release: make(chan struct{}),
	}
	adapter, blockedBinding := openKD6ControlTestServer(
		t, store, filepath.Join(t.TempDir(), "control.db"), time.Now,
	)
	defer adapter.Close() //nolint:errcheck
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(store.release) }) }
	defer release()

	independentBinding := blockedBinding
	independentBinding.NamespaceUID = "independent-namespace-uid"
	independentBinding.BackendUID = "independent-backend-uid"
	independentBinding.TenantID = protocol.DeriveTenantID(independentBinding.ClusterID, independentBinding.NamespaceUID)
	independentBinding.StoreUUID = ""
	resolved, err := store.ResolveStore(context.Background(), ResolveStoreRequest{
		TenantID: independentBinding.TenantID, StoreName: testOMSStoreName, ProviderStoreID: fakeProviderStoreID,
	})
	if err != nil {
		t.Fatal(err)
	}
	storeUUID, err := adapter.db.resolveStore(context.Background(), protocol.StoreResolutionBinding{
		ClusterID: independentBinding.ClusterID, NamespaceUID: independentBinding.NamespaceUID,
		BackendUID: independentBinding.BackendUID, TenantID: independentBinding.TenantID,
	}, testOMSStoreName, resolved, adapter.now())
	if err != nil {
		t.Fatal(err)
	}
	independentBinding.StoreUUID = storeUUID
	decision, err := adapter.db.claimOwnership(context.Background(), store, independentBinding, adapter.now())
	if err != nil || decision.result != protocol.ResultApplied {
		t.Fatalf("independent ownership claim = %+v, err = %v", decision, err)
	}
	store.blockedTenant = blockedBinding.TenantID
	store.independentTenant = independentBinding.TenantID

	for index, binding := range []protocol.Binding{blockedBinding, independentBinding} {
		mutation := newKD6TestMutation(t, binding, fmt.Sprintf("mop-get-concurrency-%d", index),
			fmt.Sprintf("mem-get-concurrency-%d", index), fmt.Sprintf("content-%d", index))
		receipt, applyErr := adapter.db.applyMutation(context.Background(), store, &mutation, adapter.now())
		if applyErr != nil || receipt.Result != protocol.ResultApplied {
			t.Fatalf("seed mutation %d receipt = %+v, err = %v", index, receipt, applyErr)
		}
	}

	type handlerResponse struct {
		body   []byte
		status int
	}
	handler := http.HandlerFunc(adapter.handleGet)
	startGet := func(binding protocol.Binding, memoryID string) <-chan handlerResponse {
		t.Helper()
		body, marshalErr := json.Marshal(protocol.GetRequest{
			ProtocolVersion: protocol.Version, Binding: binding,
			UpsertKey: protocol.CanonicalUpsertKey(binding, memoryID),
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		request := httptest.NewRequest(http.MethodPost, protocol.PathRecordsGet, bytes.NewReader(body))
		request.Header.Set("Content-Type", kd6TestJSONMediaType)
		result := make(chan handlerResponse, 1)
		go func() {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			result <- handlerResponse{body: append([]byte(nil), recorder.Body.Bytes()...), status: recorder.Code}
		}()
		return result
	}

	blockedResult := startGet(blockedBinding, "mem-get-concurrency-0")
	select {
	case <-store.blockedEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked tenant get did not reach the provider")
	}
	independentResult := startGet(independentBinding, "mem-get-concurrency-1")
	select {
	case <-store.independentEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("independent tenant get was blocked behind another tenant's provider request")
	}
	select {
	case response := <-independentResult:
		if response.status != http.StatusOK {
			t.Fatalf("independent tenant get status = %d: %s", response.status, response.body)
		}
		decoded, decodeErr := protocol.DecodeGetResponse(response.body)
		if decodeErr != nil || !decoded.Found {
			t.Fatalf("independent tenant get response = %#v, err = %v", decoded, decodeErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("independent tenant get did not complete")
	}

	release()
	select {
	case response := <-blockedResult:
		if response.status != http.StatusOK {
			t.Fatalf("released tenant get status = %d: %s", response.status, response.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("released tenant get did not complete")
	}
}

func TestRoutingFenceRecoversExpiredDispatchAfterRestart(t *testing.T) {
	baseStore, provider, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	path := filepath.Join(t.TempDir(), "control.db")
	now := time.Now().UTC()
	ambiguous := &ambiguousAfterProviderSuccessStore{ContentStore: baseStore}
	first, binding := openKD6ControlTestServer(t, ambiguous, path, func() time.Time { return now })
	mutation := newKD6TestMutation(t, binding, "mop-fence-recovery", "mem-fence-recovery", "content")
	receipt, err := first.db.applyMutation(context.Background(), ambiguous, &mutation, now)
	if err != nil || receipt.Result != protocol.ResultRetryableError {
		t.Fatalf("ambiguous receipt = %+v, err = %v", receipt, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	recoveredAt := now.Add(mutationProviderDispatchTimeout + time.Second)
	second, err := Open(context.Background(), Config{
		DatabasePath: path, BearerToken: testInboundToken, ContentStore: baseStore,
		StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID}, Clock: func() time.Time { return recoveredAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close() //nolint:errcheck
	fenced := binding
	fenced.RoutingEpoch++
	decision, err := second.db.advanceRoutingFence(context.Background(), baseStore, fenced, recoveredAt)
	if err != nil || decision.result != protocol.ResultApplied {
		t.Fatalf("recovery fence decision = %+v, err = %v", decision, err)
	}
	stored, found, err := second.db.lookupOperation(context.Background(), fenced, mutation.OperationID)
	if err != nil || !found || stored.Result != protocol.ResultApplied {
		t.Fatalf("recovered operation = %+v, found=%v, err=%v", stored, found, err)
	}
	provider.mu.Lock()
	calls := provider.mutateCalls
	provider.mu.Unlock()
	if calls != 1 {
		t.Fatalf("provider mutate calls = %d, want 1", calls)
	}
}

func TestRoutingFenceRecoversProviderIdempotencyConflictWithOriginalEpoch(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	path := filepath.Join(t.TempDir(), "control.db")
	now := time.Now().UTC()
	ambiguous := &ambiguousAfterProviderSuccessStore{ContentStore: baseStore}
	first, binding := openKD6ControlTestServer(t, ambiguous, path, func() time.Time { return now })
	mutation := newKD6TestMutation(t, binding, "mop-fence-conflict-recovery", "mem-fence-conflict-recovery", "content")
	receipt, err := first.db.applyMutation(context.Background(), ambiguous, &mutation, now)
	if err != nil || receipt.Result != protocol.ResultRetryableError {
		t.Fatalf("ambiguous receipt = %+v, err = %v", receipt, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	recoveredAt := now.Add(mutationProviderDispatchTimeout + time.Second)
	conflictStore := lookupErrorStore{ContentStore: baseStore, err: &StoreError{
		Code: "KD6_OPERATION_CONFLICT", Definitive: true, Kind: ErrProviderIdempotencyConflict,
	}}
	second, err := Open(context.Background(), Config{
		DatabasePath: path, BearerToken: testInboundToken, ContentStore: conflictStore,
		StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID}, Clock: func() time.Time { return recoveredAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close() //nolint:errcheck
	fenced := binding
	fenced.RoutingEpoch++
	decision, err := second.db.advanceRoutingFence(context.Background(), conflictStore, fenced, recoveredAt)
	if err != nil || decision.result != protocol.ResultApplied || decision.maxRouting != fenced.RoutingEpoch {
		t.Fatalf("recovery fence decision = %+v, err = %v", decision, err)
	}
	stored, found, err := second.db.lookupOperation(context.Background(), fenced, mutation.OperationID)
	if err != nil || !found || stored.Result != protocol.ResultIdempotencyConflict {
		t.Fatalf("recovered operation = %+v, found=%v, err=%v", stored, found, err)
	}
	if stored.Binding.RoutingEpoch != binding.RoutingEpoch {
		t.Fatalf("recovered receipt routing epoch = %d, want %d", stored.Binding.RoutingEpoch, binding.RoutingEpoch)
	}
	if stored.BindingDigest != protocol.BindingDigest(binding) {
		t.Fatalf("recovered receipt binding digest = %q, want %q", stored.BindingDigest, protocol.BindingDigest(binding))
	}
	var intents int
	if err := second.db.db.QueryRow(`SELECT COUNT(*) FROM mutation_intents`).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if intents != 0 {
		t.Fatalf("remaining mutation intents = %d, want 0", intents)
	}
}

func TestMutationRetriesAfterDefinitivePreEffectAuthenticationFailure(t *testing.T) {
	baseStore, provider, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	store := &neverAppliedOnceStore{ContentStore: baseStore}
	now := time.Now().UTC()
	adapter, binding := openKD6ControlTestServer(t, store, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	mutation := newKD6TestMutation(t, binding, "mop-auth-rotation", "mem-auth-rotation", "content")

	first, err := adapter.db.applyMutation(context.Background(), store, &mutation, now)
	if err != nil || first.Result != protocol.ResultRetryableError {
		t.Fatalf("first mutation receipt = %+v, err=%v", first, err)
	}
	var dispatchState string
	if err := adapter.db.db.QueryRow(`SELECT dispatch_state FROM mutation_intents WHERE operation_id = ?`, mutation.OperationID).Scan(&dispatchState); err != nil {
		t.Fatal(err)
	}
	if dispatchState != mutationIntentPrepared {
		t.Fatalf("dispatch state after pre-effect auth failure = %q, want %q", dispatchState, mutationIntentPrepared)
	}

	second, err := adapter.db.applyMutation(context.Background(), store, &mutation, now.Add(time.Second))
	if err != nil || second.Result != protocol.ResultApplied {
		t.Fatalf("retried mutation receipt = %+v, err=%v", second, err)
	}
	provider.mu.Lock()
	providerCalls := provider.mutateCalls
	provider.mu.Unlock()
	if store.calls != 2 || providerCalls != 1 {
		t.Fatalf("mutation calls wrapper=%d provider=%d, want 2/1", store.calls, providerCalls)
	}
}

func TestFutureRoutingEpochDoesNotConsumeOperationID(t *testing.T) {
	store, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC()
	adapter, binding := openKD6ControlTestServer(t, store, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	future := binding
	future.RoutingEpoch++
	mutation := newKD6TestMutation(t, future, "mop-future-routing", "mem-future-routing", "content")

	first, err := adapter.db.applyMutation(context.Background(), store, &mutation, now)
	if err != nil || first.Result != protocol.ResultRetryableError {
		t.Fatalf("future routing receipt = %+v, err=%v", first, err)
	}
	if _, found, err := adapter.db.lookupOperation(context.Background(), future, mutation.OperationID); err != nil || found {
		t.Fatalf("future routing lookup found=%v err=%v, want no durable receipt", found, err)
	}
	decision, err := adapter.db.advanceRoutingFence(context.Background(), store, future, now.Add(time.Second))
	if err != nil || decision.result != protocol.ResultApplied || decision.maxRouting != future.RoutingEpoch {
		t.Fatalf("advance future routing fence = %+v, err=%v", decision, err)
	}
	second, err := adapter.db.applyMutation(context.Background(), store, &mutation, now.Add(2*time.Second))
	if err != nil || second.Result != protocol.ResultApplied {
		t.Fatalf("post-fence mutation receipt = %+v, err=%v", second, err)
	}
}

func TestProviderWriterFencePreventsClonedControlDatabaseSplitBrain(t *testing.T) {
	baseStore, provider, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC()
	directory := t.TempDir()
	authoritativePath := filepath.Join(directory, "authoritative.db")
	clonePath := filepath.Join(directory, "clone.db")

	initial, binding := openKD6ControlTestServer(t, baseStore, authoritativePath, func() time.Time { return now })
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(authoritativePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clonePath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	open := func(t *testing.T, path string) (*Server, *httptest.Server) {
		t.Helper()
		server, openErr := Open(context.Background(), Config{
			DatabasePath: path, BearerToken: testInboundToken, ContentStore: baseStore,
			StoreMappings: map[string]string{testOMSStoreName: fakeProviderStoreID}, Clock: func() time.Time { return now },
		})
		if openErr != nil {
			t.Fatal(openErr)
		}
		return server, httptest.NewServer(server.Handler())
	}
	claim := func(t *testing.T, endpoint string) (*protocol.OwnershipClaimResponse, int) {
		t.Helper()
		body, status := postOMSStatus(t, endpoint, protocol.PathOwnershipClaim, protocol.OwnershipClaimRequest{
			ProtocolVersion: protocol.Version, Binding: binding,
		})
		response, decodeErr := protocol.DecodeOwnershipClaimResponse(body)
		if decodeErr != nil {
			t.Fatalf("decode ownership claim status %d: %v: %s", status, decodeErr, body)
		}
		return response, status
	}

	authoritative, authoritativeEndpoint := open(t, authoritativePath)
	defer authoritative.Close() //nolint:errcheck
	defer authoritativeEndpoint.Close()
	clone, cloneEndpoint := open(t, clonePath)
	defer clone.Close() //nolint:errcheck
	defer cloneEndpoint.Close()

	if response, status := claim(t, authoritativeEndpoint.URL); status != http.StatusOK || response.Result != protocol.ResultApplied {
		t.Fatalf("authoritative claim = %+v status=%d", response, status)
	}
	if response, status := claim(t, cloneEndpoint.URL); status != http.StatusConflict || response.Result != protocol.ResultIdentityConflict {
		t.Fatalf("equal-epoch clone claim = %+v status=%d", response, status)
	}
	if response, status := claim(t, cloneEndpoint.URL); status != http.StatusOK || response.Result != protocol.ResultApplied {
		t.Fatalf("higher-epoch clone claim = %+v status=%d", response, status)
	}

	stale := newKD6TestMutation(t, binding, "mop-clone-stale", "mem-clone-stale", "stale writer")
	body, status := postOMSStatus(t, authoritativeEndpoint.URL, protocol.PathMutations, stale)
	receipt, decodeErr := protocol.DecodeMutationReceipt(body)
	if status != http.StatusServiceUnavailable || decodeErr != nil || receipt.Result != protocol.ResultRetryableError {
		t.Fatalf("stale writer mutation = %+v status=%d err=%v", receipt, status, decodeErr)
	}
	winner := newKD6TestMutation(t, binding, "mop-clone-winner", "mem-clone-winner", "winning writer")
	receipt, decodeErr = protocol.DecodeMutationReceipt(postOMS(t, cloneEndpoint.URL, protocol.PathMutations, winner))
	if decodeErr != nil || receipt.Result != protocol.ResultApplied {
		t.Fatalf("winning clone mutation = %+v err=%v", receipt, decodeErr)
	}
	provider.mu.Lock()
	mutateCalls := provider.mutateCalls
	current := provider.writers[fakeWriterSlotKey(binding.TenantID, fakeProviderStoreID, writerAuthorityForBinding(binding))]
	provider.mu.Unlock()
	if mutateCalls != 1 {
		t.Fatalf("provider-applied mutation calls = %d, want 1", mutateCalls)
	}
	if current.lease.WriterEpoch != 3 || current.lease.HolderIdentity != clone.db.holderID {
		t.Fatalf("current provider writer = %+v, want clone epoch 3", current.lease)
	}

	cloneEndpoint.Close()
	if err := clone.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, restartedEndpoint := open(t, clonePath)
	defer restarted.Close() //nolint:errcheck
	defer restartedEndpoint.Close()
	if response, status := claim(t, restartedEndpoint.URL); status != http.StatusOK || response.Result != protocol.ResultApplied {
		t.Fatalf("authoritative restart claim = %+v status=%d", response, status)
	}
	provider.mu.Lock()
	restartedWriter := provider.writers[fakeWriterSlotKey(binding.TenantID, fakeProviderStoreID, writerAuthorityForBinding(binding))]
	provider.mu.Unlock()
	if restartedWriter.lease.WriterEpoch != 4 || restartedWriter.lease.HolderIdentity != restarted.db.holderID ||
		restartedWriter.lease.HolderIdentity == current.lease.HolderIdentity {
		t.Fatalf("restarted provider writer = %+v, prior=%+v", restartedWriter.lease, current.lease)
	}
	restartedMutation := newKD6TestMutation(t, binding, "mop-clone-restarted", "mem-clone-restarted", "restarted writer")
	receipt, decodeErr = protocol.DecodeMutationReceipt(postOMS(t, restartedEndpoint.URL, protocol.PathMutations, restartedMutation))
	if decodeErr != nil || receipt.Result != protocol.ResultApplied {
		t.Fatalf("restarted writer mutation = %+v err=%v", receipt, decodeErr)
	}
}

func TestMutationRejectsReceiptUnsafeProviderIdentity(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	cases := []struct {
		name string
		id   string
		ver  string
		when time.Time
	}{
		{name: "oversized provider id", id: strings.Repeat("p", protocol.MaxIdentityBytes+1), ver: "v1", when: time.Now().UTC()},
		{name: "oversized version", id: "provider-1", ver: strings.Repeat("v", protocol.MaxBackendVersionBytes+1), when: time.Now().UTC()},
		{name: "unencodable timestamp", id: "provider-1", ver: "v1", when: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := syntheticMutationStore{ContentStore: baseStore, result: func(mutation ContentMutation) ContentMutationResult {
				record := *mutation.Record
				record.ProviderID, record.Version, record.UpdatedAt = tc.id, tc.ver, tc.when
				return ContentMutationResult{Outcome: ContentOutcomeApplied, ProviderID: tc.id, Version: tc.ver, UpdatedAt: tc.when, Record: &record}
			}}
			adapter, binding := openKD6ControlTestServer(t, store, filepath.Join(t.TempDir(), "control.db"), time.Now)
			defer adapter.Close() //nolint:errcheck
			mutation := newKD6TestMutation(t, binding, "mop-unsafe-identity", "mem-unsafe-identity", "content")
			receipt, err := adapter.db.applyMutation(context.Background(), store, &mutation, time.Now().UTC())
			if err != nil || receipt.Result != protocol.ResultRetryableError {
				t.Fatalf("unsafe identity receipt = %+v, err = %v", receipt, err)
			}
			if err := protocol.ValidateMutationReceipt(&receipt); err != nil {
				t.Fatalf("persisted terminal receipt is invalid: %v", err)
			}
			var controls, intents, receipts int
			if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM record_controls`).Scan(&controls); err != nil {
				t.Fatal(err)
			}
			if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM mutation_intents`).Scan(&intents); err != nil {
				t.Fatal(err)
			}
			if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM operation_receipts`).Scan(&receipts); err != nil {
				t.Fatal(err)
			}
			if controls != 0 || intents != 1 || receipts != 0 {
				t.Fatalf("control/intents/receipts = %d/%d/%d, want 0/1/0", controls, intents, receipts)
			}
		})
	}
}

func insertSearchSnapshotQuotaRow(
	t *testing.T,
	adapter *Server,
	id, authority, state string,
	snapshotBytes int,
	createdAt, expiresAt time.Time,
) {
	t.Helper()
	_, err := adapter.db.db.Exec(`INSERT INTO pagination_snapshots(
		snapshot_id, authority_digest, request_fingerprint, provider_snapshot_id, provider_store_id,
		requested_mode, actual_mode, page_size, entry_count, created_at, expires_at, state, snapshot_bytes
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, authority, "fingerprint-"+id,
		"provider-"+id, fakeProviderStoreID, protocol.SearchModeKeyword, protocol.SearchModeKeyword,
		1, 1, formatTime(createdAt), formatTime(expiresAt), state, snapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEmptySearchSnapshotsReleaseSlotsImmediately(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Date(2026, 8, 1, 18, 0, 0, 0, time.UTC)
	store := fixedSearchSnapshotStore{ContentStore: baseStore, snapshot: ContentSearchSnapshot{
		SnapshotID: "provider-empty-snapshot", ActualMode: protocol.SearchModeKeyword,
		ExpiresAt: now.Add(time.Hour), Entries: []ContentDescriptor{},
	}}
	adapter, binding := openKD6ControlTestServer(t, store, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	request := &protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, PageSize: 1,
	}
	for i := range maxActiveSearchSnapshotsPerAuthority + 2 {
		page, err := adapter.db.createSnapshot(context.Background(), store, request, now, func() time.Time { return now }, time.Minute, 10)
		if err != nil || !page.exhausted || page.nextToken != "" || len(page.records) != 0 {
			t.Fatalf("empty search %d = %+v, %v", i, page, err)
		}
	}
	var snapshots, entries int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_entries`).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if snapshots != 0 || entries != 0 {
		t.Fatalf("terminal empty snapshots retained snapshots/entries = %d/%d", snapshots, entries)
	}
}

func TestSinglePageSearchSnapshotReleasesSlotImmediately(t *testing.T) {
	store, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC().Truncate(time.Second)
	adapter, binding := openKD6ControlTestServer(t, store, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	mutation := newKD6TestMutation(t, binding, "mop-single-page", "mem-single-page", "single page")
	if receipt, err := adapter.db.applyMutation(context.Background(), store, &mutation, now); err != nil || receipt.Result != protocol.ResultApplied {
		t.Fatalf("apply mutation = %+v, %v", receipt, err)
	}
	request := &protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, PageSize: 2,
	}
	page, err := adapter.db.createSnapshot(context.Background(), store, request, now, func() time.Time { return now }, time.Minute, 10)
	if err != nil || !page.exhausted || page.nextToken != "" || len(page.records) != 1 {
		t.Fatalf("single-page search = %+v, %v", page, err)
	}
	var snapshots int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if snapshots != 0 {
		t.Fatalf("single-page terminal snapshots = %d, want 0", snapshots)
	}
}

func TestTerminalContinuationReleasesSearchSnapshot(t *testing.T) {
	store, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC().Truncate(time.Second)
	adapter, binding := openKD6ControlTestServer(t, store, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	for i := range 2 {
		mutation := newKD6TestMutation(t, binding, fmt.Sprintf("mop-terminal-%d", i), fmt.Sprintf("mem-terminal-%d", i), "terminal page")
		if receipt, err := adapter.db.applyMutation(context.Background(), store, &mutation, now); err != nil || receipt.Result != protocol.ResultApplied {
			t.Fatalf("apply mutation %d = %+v, %v", i, receipt, err)
		}
	}
	request := &protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, PageSize: 1,
	}
	first, err := adapter.db.createSnapshot(context.Background(), store, request, now, func() time.Time { return now }, time.Minute, 10)
	if err != nil || first.exhausted || first.nextToken == "" || len(first.records) != 1 {
		t.Fatalf("first search page = %+v, %v", first, err)
	}
	var snapshots int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 {
		t.Fatalf("continuable snapshots = %d, want 1", snapshots)
	}
	request.PageToken = first.nextToken
	terminal, err := adapter.db.readSnapshotPage(context.Background(), store, request, now)
	if err != nil || !terminal.exhausted || terminal.nextToken != "" || len(terminal.records) != 1 {
		t.Fatalf("terminal search page = %+v, %v", terminal, err)
	}
	var entries, active, retainedBytes int
	var lifecycleState string
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*), MIN(state), COALESCE(SUM(snapshot_bytes), 0)
		FROM pagination_snapshots`).Scan(&snapshots, &lifecycleState, &retainedBytes); err != nil {
		t.Fatal(err)
	}
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_entries`).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots WHERE state IN (?, ?)`,
		snapshotStateReserved, snapshotStateReady).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 || lifecycleState != snapshotStateTerminal || active != 0 || entries != 2 ||
		retainedBytes <= 0 || retainedBytes > maxSearchSnapshotBytes {
		t.Fatalf("terminal continuation snapshots/state/active/entries/bytes = %d/%q/%d/%d/%d",
			snapshots, lifecycleState, active, entries, retainedBytes)
	}
	replayed, err := adapter.db.readSnapshotPage(context.Background(), store, request, now)
	if err != nil || !replayed.exhausted || len(replayed.records) != 1 {
		t.Fatalf("replayed terminal cursor = %+v, %v", replayed, err)
	}
}

func TestTerminalSearchSnapshotReplayQuotaSurvivesRestart(t *testing.T) {
	store, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "control.db")
	adapter, binding := openKD6ControlTestServer(t, store, path, func() time.Time { return now })
	for i := range 2 {
		mutation := newKD6TestMutation(t, binding, fmt.Sprintf("mop-restart-terminal-%d", i),
			fmt.Sprintf("mem-restart-terminal-%d", i), "restart terminal page")
		if receipt, err := adapter.db.applyMutation(context.Background(), store, &mutation, now); err != nil || receipt.Result != protocol.ResultApplied {
			t.Fatalf("apply mutation %d = %+v, %v", i, receipt, err)
		}
	}
	request := &protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, PageSize: 1,
	}
	first, err := adapter.db.createSnapshot(context.Background(), store, request, now, func() time.Time { return now }, time.Hour, 10)
	if err != nil || first.nextToken == "" || first.exhausted {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	request.PageToken = first.nextToken
	if terminal, err := adapter.db.readSnapshotPage(context.Background(), store, request, now); err != nil || !terminal.exhausted {
		t.Fatalf("terminal page = %+v, %v", terminal, err)
	}
	var retainedBytes int
	if err := adapter.db.db.QueryRow(`SELECT snapshot_bytes FROM pagination_snapshots WHERE snapshot_id = ?`, first.snapshotID).Scan(&retainedBytes); err != nil {
		t.Fatal(err)
	}
	if retainedBytes <= 0 || retainedBytes > maxSearchSnapshotBytes {
		t.Fatalf("retained snapshot bytes = %d", retainedBytes)
	}
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, restartedBinding := openKD6ControlTestServer(t, store, path, func() time.Time { return now })
	defer restarted.Close() //nolint:errcheck
	if protocol.AuthorityDigest(restartedBinding) != protocol.AuthorityDigest(binding) {
		t.Fatalf("restarted authority changed: before=%+v after=%+v", binding, restartedBinding)
	}
	request.Binding = restartedBinding
	replayed, err := restarted.db.readSnapshotPage(context.Background(), store, request, now)
	if err != nil || !replayed.exhausted || len(replayed.records) != 1 {
		t.Fatalf("replayed terminal page after restart = %+v, %v", replayed, err)
	}
	var state string
	var active int
	if err := restarted.db.db.QueryRow(`SELECT state, snapshot_bytes FROM pagination_snapshots WHERE snapshot_id = ?`,
		first.snapshotID).Scan(&state, &retainedBytes); err != nil {
		t.Fatal(err)
	}
	if err := restarted.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots WHERE state IN (?, ?)`,
		snapshotStateReserved, snapshotStateReady).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if state != snapshotStateTerminal || active != 0 || retainedBytes <= 0 {
		t.Fatalf("restarted terminal state/active/bytes = %q/%d/%d", state, active, retainedBytes)
	}
}

func TestTerminalSearchSnapshotQuotasFailClosedAndPreserveReadyCursor(t *testing.T) {
	tests := []struct {
		name      string
		seedCount int
		seedBytes int
		authority func(int, string) string
	}{
		{
			name: "per-authority count", seedCount: maxTerminalSearchSnapshotsPerAuthority, seedBytes: 1,
			authority: func(_ int, current string) string { return current },
		},
		{
			name: "global count", seedCount: maxTerminalSearchSnapshotsGlobal, seedBytes: 1,
			authority: func(i int, _ string) string { return fmt.Sprintf("other-authority-%03d", i) },
		},
		{
			name: "per-authority bytes", seedCount: maxTerminalSearchBytesPerAuthority / maxSearchSnapshotBytes,
			seedBytes: maxSearchSnapshotBytes, authority: func(_ int, current string) string { return current },
		},
		{
			name: "global bytes", seedCount: maxTerminalSearchBytesGlobal / maxSearchSnapshotBytes,
			seedBytes: maxSearchSnapshotBytes, authority: func(i int, _ string) string { return fmt.Sprintf("byte-authority-%03d", i) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseStore, _, closeProvider := newKD6ProviderStore(t)
			defer closeProvider()
			now := time.Now().UTC().Truncate(time.Second)
			adapter, binding := openKD6ControlTestServer(
				t, baseStore, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now },
			)
			defer adapter.Close() //nolint:errcheck
			authority := protocol.AuthorityDigest(binding)
			for i := range test.seedCount {
				insertSearchSnapshotQuotaRow(t, adapter, fmt.Sprintf("terminal-%03d", i),
					test.authority(i, authority), snapshotStateTerminal, test.seedBytes, now, now.Add(time.Hour))
			}
			insertSearchSnapshotQuotaRow(t, adapter, "ready-candidate", authority, snapshotStateReady, 1, now, now.Add(time.Hour))
			if err := adapter.db.completeSearchSnapshot(context.Background(), "ready-candidate", now); !errors.Is(err, errSnapshotCapacity) {
				t.Fatalf("completeSearchSnapshot() error = %v, want capacity", err)
			}
			var state string
			if err := adapter.db.db.QueryRow(`SELECT state FROM pagination_snapshots WHERE snapshot_id = 'ready-candidate'`).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state != snapshotStateReady {
				t.Fatalf("capacity failure changed cursor state to %q", state)
			}
			if _, err := adapter.db.db.Exec(`DELETE FROM pagination_snapshots WHERE state = ?`, snapshotStateTerminal); err != nil {
				t.Fatal(err)
			}
			if err := adapter.db.completeSearchSnapshot(context.Background(), "ready-candidate", now); err != nil {
				t.Fatalf("retry after capacity release: %v", err)
			}
		})
	}
}

func TestTerminalSearchSnapshotCapacityErrorKeepsIssuedCursorRetryable(t *testing.T) {
	store, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC().Truncate(time.Second)
	adapter, binding := openKD6ControlTestServer(t, store, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	for i := range 2 {
		mutation := newKD6TestMutation(t, binding, fmt.Sprintf("mop-capacity-retry-%d", i),
			fmt.Sprintf("mem-capacity-retry-%d", i), "capacity retry")
		if receipt, err := adapter.db.applyMutation(context.Background(), store, &mutation, now); err != nil || receipt.Result != protocol.ResultApplied {
			t.Fatalf("apply mutation %d = %+v, %v", i, receipt, err)
		}
	}
	request := &protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, PageSize: 1,
	}
	first, err := adapter.db.createSnapshot(context.Background(), store, request, now, func() time.Time { return now }, time.Hour, 10)
	if err != nil || first.exhausted || first.nextToken == "" {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	authority := protocol.AuthorityDigest(binding)
	for i := range maxTerminalSearchSnapshotsPerAuthority {
		insertSearchSnapshotQuotaRow(t, adapter, fmt.Sprintf("blocking-terminal-%03d", i),
			authority, snapshotStateTerminal, 1, now, now.Add(time.Hour))
	}
	request.PageToken = first.nextToken
	if _, err := adapter.db.readSnapshotPage(context.Background(), store, request, now); !errors.Is(err, errSnapshotCapacity) {
		t.Fatalf("terminal page at capacity error = %v, want capacity", err)
	}
	var state string
	if err := adapter.db.db.QueryRow(`SELECT state FROM pagination_snapshots WHERE snapshot_id = ?`, first.snapshotID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != snapshotStateReady {
		t.Fatalf("capacity error invalidated issued cursor state: %q", state)
	}
	if _, err := adapter.db.db.Exec(`DELETE FROM pagination_snapshots WHERE snapshot_id = 'blocking-terminal-000'`); err != nil {
		t.Fatal(err)
	}
	terminal, err := adapter.db.readSnapshotPage(context.Background(), store, request, now)
	if err != nil || !terminal.exhausted || len(terminal.records) != 1 {
		t.Fatalf("retried terminal page = %+v, %v", terminal, err)
	}
}

func TestTerminalSearchSnapshotCapacityIsAtomicUnderConcurrency(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC().Truncate(time.Second)
	adapter, binding := openKD6ControlTestServer(t, baseStore, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	authority := protocol.AuthorityDigest(binding)
	for i := range maxTerminalSearchSnapshotsPerAuthority - 1 {
		insertSearchSnapshotQuotaRow(t, adapter, fmt.Sprintf("terminal-%03d", i), authority, snapshotStateTerminal, 1, now, now.Add(time.Hour))
	}
	for _, id := range []string{"ready-a", "ready-b"} {
		insertSearchSnapshotQuotaRow(t, adapter, id, authority, snapshotStateReady, 1, now, now.Add(time.Hour))
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var workers sync.WaitGroup
	for _, id := range []string{"ready-a", "ready-b"} {
		workers.Go(func() {
			<-start
			errs <- adapter.db.completeSearchSnapshot(context.Background(), id, now)
		})
	}
	close(start)
	workers.Wait()
	close(errs)
	succeeded, capacity := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, errSnapshotCapacity):
			capacity++
		default:
			t.Fatal(err)
		}
	}
	if succeeded != 1 || capacity != 1 {
		t.Fatalf("concurrent terminal transitions success/capacity = %d/%d, want 1/1", succeeded, capacity)
	}
	var terminal, ready int
	if err := adapter.db.db.QueryRow(`SELECT
		COUNT(CASE WHEN state = ? THEN 1 END), COUNT(CASE WHEN state = ? THEN 1 END)
		FROM pagination_snapshots WHERE authority_digest = ?`, snapshotStateTerminal, snapshotStateReady, authority).
		Scan(&terminal, &ready); err != nil {
		t.Fatal(err)
	}
	if terminal != maxTerminalSearchSnapshotsPerAuthority || ready != 1 {
		t.Fatalf("terminal/ready snapshots = %d/%d", terminal, ready)
	}
}

func TestExpiredTerminalSnapshotsReleaseReplayQuota(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC().Truncate(time.Second)
	adapter, binding := openKD6ControlTestServer(t, baseStore, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	authority := protocol.AuthorityDigest(binding)
	for i := range maxTerminalSearchSnapshotsPerAuthority {
		insertSearchSnapshotQuotaRow(t, adapter, fmt.Sprintf("expired-%03d", i), authority, snapshotStateTerminal, 1,
			now.Add(-2*time.Minute), now.Add(-time.Minute))
	}
	insertSearchSnapshotQuotaRow(t, adapter, "ready-after-expiry", authority, snapshotStateReady, 1, now, now.Add(time.Hour))
	if err := adapter.db.completeSearchSnapshot(context.Background(), "ready-after-expiry", now); err != nil {
		t.Fatalf("complete after terminal expiry: %v", err)
	}
	var snapshots int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 {
		t.Fatalf("snapshots after expiry reclamation = %d, want 1", snapshots)
	}
}

func TestTerminalSearchSnapshotsReleaseSlotsConcurrently(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Date(2026, 8, 1, 18, 45, 0, 0, time.UTC)
	store := fixedSearchSnapshotStore{ContentStore: baseStore, snapshot: ContentSearchSnapshot{
		SnapshotID: "provider-concurrent-empty", ActualMode: protocol.SearchModeKeyword,
		ExpiresAt: now.Add(time.Hour), Entries: []ContentDescriptor{},
	}}
	adapter, binding := openKD6ControlTestServer(t, store, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	request := &protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, PageSize: 1,
	}
	var workers sync.WaitGroup
	errs := make(chan error, maxActiveSearchSnapshotsPerAuthority)
	for range maxActiveSearchSnapshotsPerAuthority {
		workers.Go(func() {
			for range 5 {
				page, err := adapter.db.createSnapshot(context.Background(), store, request, now, func() time.Time { return now }, time.Minute, 10)
				if err != nil {
					errs <- err
					return
				}
				if !page.exhausted || page.nextToken != "" {
					errs <- fmt.Errorf("non-terminal empty page: %+v", page)
					return
				}
			}
		})
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var snapshots int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if snapshots != 0 {
		t.Fatalf("concurrent terminal snapshots = %d, want 0", snapshots)
	}
}

func TestSearchSnapshotQuotaIsReservedBeforeProviderStart(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC()
	store := &blockingSnapshotStore{
		ContentStore: baseStore, entered: make(chan struct{}, maxActiveSearchSnapshotsPerAuthority),
		release: make(chan struct{}), expires: now.Add(time.Hour),
	}
	adapter, binding := openKD6ControlTestServer(t, store, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	request := &protocol.SearchRequest{ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, PageSize: 1}

	var wg sync.WaitGroup
	errs := make(chan error, maxActiveSearchSnapshotsPerAuthority)
	for range maxActiveSearchSnapshotsPerAuthority {
		wg.Go(func() {
			_, err := adapter.db.createSnapshot(context.Background(), store, request, now, func() time.Time { return now }, time.Minute, 1)
			errs <- err
		})
	}
	for range maxActiveSearchSnapshotsPerAuthority {
		<-store.entered
	}
	if _, err := adapter.db.createSnapshot(context.Background(), store, request, now, func() time.Time { return now }, time.Minute, 1); !errors.Is(err, errSnapshotCapacity) {
		t.Fatalf("ninth snapshot error = %v, want capacity", err)
	}
	if calls := store.calls.Load(); calls != maxActiveSearchSnapshotsPerAuthority {
		t.Fatalf("provider StartSearch calls = %d, want %d", calls, maxActiveSearchSnapshotsPerAuthority)
	}
	var reserved int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots WHERE state = ?`, snapshotStateReserved).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if reserved != maxActiveSearchSnapshotsPerAuthority {
		t.Fatalf("reserved snapshots = %d, want %d", reserved, maxActiveSearchSnapshotsPerAuthority)
	}
	close(store.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSearchSnapshotReservationReleasedAfterProviderError(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC()
	store := failingSearchSnapshotStore{ContentStore: baseStore, err: errors.New("provider unavailable")}
	adapter, binding := openKD6ControlTestServer(t, store, filepath.Join(t.TempDir(), "control.db"), func() time.Time { return now })
	defer adapter.Close() //nolint:errcheck
	request := &protocol.SearchRequest{ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, PageSize: 1}
	if _, err := adapter.db.createSnapshot(context.Background(), store, request, now, func() time.Time { return now }, time.Minute, 1); err == nil {
		t.Fatal("createSnapshot succeeded despite provider error")
	}
	var snapshots int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if snapshots != 0 {
		t.Fatalf("snapshots after provider error = %d, want 0", snapshots)
	}
}

func TestSearchSnapshotReservationReleasedAfterFinalizeError(t *testing.T) {
	baseStore, _, closeProvider := newKD6ProviderStore(t)
	defer closeProvider()
	now := time.Now().UTC()
	store := fixedSearchSnapshotStore{ContentStore: baseStore, snapshot: ContentSearchSnapshot{
		SnapshotID: "provider-crash-snapshot", ActualMode: protocol.SearchModeKeyword,
		ExpiresAt: now.Add(time.Hour), Entries: []ContentDescriptor{},
	}}
	path := filepath.Join(t.TempDir(), "control.db")
	adapter, binding := openKD6ControlTestServer(t, store, path, func() time.Time { return now })
	if _, err := adapter.db.db.Exec(`CREATE TRIGGER fail_snapshot_finalize BEFORE UPDATE OF state ON pagination_snapshots
		WHEN NEW.state = 'ready' BEGIN SELECT RAISE(FAIL, 'simulated crash'); END`); err != nil {
		t.Fatal(err)
	}
	request := &protocol.SearchRequest{ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword, PageSize: 1}
	if _, err := adapter.db.createSnapshot(context.Background(), store, request, now, func() time.Time { return now }, time.Minute, 1); err == nil {
		t.Fatal("createSnapshot succeeded despite simulated finalize crash")
	}
	defer adapter.Close() //nolint:errcheck
	var reserved int
	if err := adapter.db.db.QueryRow(`SELECT COUNT(*) FROM pagination_snapshots WHERE state = ?`, snapshotStateReserved).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if reserved != 0 {
		t.Fatalf("reserved snapshots after finalize error = %d, want 0", reserved)
	}
}
