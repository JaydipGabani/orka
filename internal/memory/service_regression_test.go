package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/apierror"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/pkg/oms/protocol"
)

const testRemoteCreateRoute = "createMemory"

type governedSearchStore struct {
	store.GovernedMemoryStore
	entries   []store.RemoteMemoryCatalogEntry
	byID      map[string]store.RemoteMemoryCatalogEntry
	listCalls int
	getErr    error
	auditErr  error
	cursorErr error
	audits    []store.MemoryAuditRecord
	cursors   map[string]store.MemorySearchCursorState
	retired   map[string]bool
}

func newGovernedSearchStore(entries []store.RemoteMemoryCatalogEntry) *governedSearchStore {
	byID := make(map[string]store.RemoteMemoryCatalogEntry, len(entries))
	for _, entry := range entries {
		byID[entry.ID] = entry
	}
	return &governedSearchStore{
		entries: entries, byID: byID, cursors: make(map[string]store.MemorySearchCursorState), retired: make(map[string]bool),
	}
}

func (s *governedSearchStore) GetRemoteMemory(_ context.Context, _, id string) (*store.RemoteMemoryCatalogEntry, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	entry, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	copy := entry
	return &copy, nil
}

func (s *governedSearchStore) ListRemoteMemories(
	_ context.Context,
	filter store.RemoteMemoryCatalogFilter,
) ([]store.RemoteMemoryCatalogEntry, error) {
	s.listCalls++
	limit := filter.Limit
	if limit <= 0 {
		limit = maxRemoteCatalogLimit
	}
	result := make([]store.RemoteMemoryCatalogEntry, 0, limit)
	for _, entry := range s.entries {
		if entry.NamespaceUID != filter.NamespaceUID ||
			!filter.IncludeDisabled && entry.Disabled || !filter.IncludeDeleted && entry.Deleted ||
			len(filter.IDs) > 0 && !slices.Contains(filter.IDs, entry.ID) ||
			len(filter.States) > 0 && !slices.Contains(filter.States, entry.MaterializationState) ||
			len(filter.Trust) > 0 && !slices.Contains(filter.Trust, entry.Trust) {
			continue
		}
		if filter.BeforeUpdatedAt != nil && (entry.UpdatedAt.After(*filter.BeforeUpdatedAt) ||
			entry.UpdatedAt.Equal(*filter.BeforeUpdatedAt) && entry.ID >= filter.BeforeID) {
			continue
		}
		result = append(result, entry)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func (s *governedSearchStore) SaveMemorySearchCursor(_ context.Context, cursor store.MemorySearchCursorState) error {
	s.cursors[cursor.ID] = cursor
	return nil
}

func (s *governedSearchStore) GetMemorySearchCursor(
	_ context.Context,
	namespaceUID, id string,
	now time.Time,
) (*store.MemorySearchCursorState, error) {
	if s.cursorErr != nil {
		return nil, s.cursorErr
	}
	cursor, ok := s.cursors[id]
	if !ok || cursor.NamespaceUID != namespaceUID || !cursor.ExpiresAt.After(now) {
		return nil, store.ErrNotFound
	}
	copy := cursor
	copy.State = append([]byte(nil), cursor.State...)
	return &copy, nil
}

func (s *governedSearchStore) RetireMemorySearchCursor(_ context.Context, namespaceUID, id string, _ time.Time) error {
	stored, ok := s.cursors[id]
	if !ok || stored.NamespaceUID != namespaceUID {
		return store.ErrNotFound
	}
	s.retired[id] = true
	return nil
}

func (s *governedSearchStore) ListMemoryAudit(
	_ context.Context,
	filter store.MemoryAuditFilter,
) ([]store.MemoryAuditRecord, error) {
	if s.auditErr != nil {
		return nil, s.auditErr
	}
	result := make([]store.MemoryAuditRecord, 0, len(s.audits))
	for _, audit := range s.audits {
		if filter.NamespaceUID != "" && audit.NamespaceUID != filter.NamespaceUID ||
			filter.MemoryID != "" && audit.MemoryID != filter.MemoryID {
			continue
		}
		result = append(result, audit)
	}
	return result, nil
}

func (s *governedSearchStore) AppendMemoryAudit(_ context.Context, audit store.MemoryAuditRecord) error {
	if s.auditErr != nil {
		return s.auditErr
	}
	s.audits = append(s.audits, audit)
	return nil
}

func (s *governedSearchStore) MarkRemoteMemoriesRecalled(context.Context, string, []string, time.Time) error {
	return nil
}

type pagedSearchAdapter struct {
	fakeOMSAdapter
	binding           protocol.Binding
	records           []protocol.MemoryRecord
	byUpsertKey       map[string]protocol.MemoryRecord
	searchCalls       int
	getCalls          int
	pageSizes         []int
	queries           []string
	actualModes       []string
	snapshotExpiresAt time.Time

	getMu         sync.Mutex
	activeGets    int
	maxActiveGets int
	getStarted    chan<- struct{}
	releaseGets   <-chan struct{}
}

func newPagedSearchAdapter(binding protocol.Binding, records []protocol.MemoryRecord) *pagedSearchAdapter {
	byUpsertKey := make(map[string]protocol.MemoryRecord, len(records))
	for _, record := range records {
		byUpsertKey[record.UpsertKey] = record
	}
	return &pagedSearchAdapter{
		binding: binding, records: records, byUpsertKey: byUpsertKey,
		snapshotExpiresAt: time.Now().UTC().Add(time.Minute),
	}
}

func (a *pagedSearchAdapter) Search(_ context.Context, request protocol.SearchRequest) (*protocol.SearchResponse, error) {
	call := a.searchCalls
	a.searchCalls++
	a.pageSizes = append(a.pageSizes, request.PageSize)
	a.queries = append(a.queries, request.Query)
	offset := 0
	if request.PageToken != "" {
		parts := strings.Split(request.PageToken, ".")
		if len(parts) != 3 || parts[0] != "oms-page-v1" || parts[1] != "0123456789abcdef0123456789abcdef" {
			return nil, errors.New("invalid test page token")
		}
		parsed, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, err
		}
		offset = parsed
	}
	end := min(offset+request.PageSize, len(a.records))
	records := append([]protocol.MemoryRecord{}, a.records[offset:end]...)
	next := ""
	if end < len(a.records) {
		next = fmt.Sprintf("oms-page-v1.0123456789abcdef0123456789abcdef.%d", end)
	}
	actualMode := request.Mode
	if actualMode == protocol.SearchModeAuto {
		actualMode = protocol.SearchModeKeyword
	}
	if call < len(a.actualModes) {
		actualMode = a.actualModes[call]
	}
	return &protocol.SearchResponse{
		ProtocolVersion: protocol.Version, Binding: request.Binding,
		RequestedMode: request.Mode, ActualMode: actualMode, Records: records,
		NextPageToken: next, Exhausted: next == "", SnapshotExpiresAt: a.snapshotExpiresAt,
	}, nil
}

func (a *pagedSearchAdapter) Get(ctx context.Context, request protocol.GetRequest) (*protocol.GetResponse, error) {
	a.getMu.Lock()
	a.getCalls++
	a.activeGets++
	a.maxActiveGets = max(a.maxActiveGets, a.activeGets)
	record, ok := a.byUpsertKey[request.UpsertKey]
	started := a.getStarted
	release := a.releaseGets
	a.getMu.Unlock()
	defer func() {
		a.getMu.Lock()
		a.activeGets--
		a.getMu.Unlock()
	}()
	if started != nil {
		select {
		case started <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !ok {
		return &protocol.GetResponse{ProtocolVersion: protocol.Version, Binding: request.Binding, Found: false}, nil
	}
	copy := record
	return &protocol.GetResponse{ProtocolVersion: protocol.Version, Binding: request.Binding, Found: true, Record: &copy}, nil
}

func (a *pagedSearchAdapter) getStats() (calls, maxActive int) {
	a.getMu.Lock()
	defer a.getMu.Unlock()
	return a.getCalls, a.maxActiveGets
}

type countingGetAdapter struct {
	fakeOMSAdapter
	getCalls int
}

func (a *countingGetAdapter) Get(ctx context.Context, request protocol.GetRequest) (*protocol.GetResponse, error) {
	a.mu.Lock()
	a.getCalls++
	a.mu.Unlock()
	return a.fakeOMSAdapter.Get(ctx, request)
}

func (a *countingGetAdapter) getCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.getCalls
}

type recordingMaterializationStore struct {
	*governedSearchStore
	mu     sync.Mutex
	issues []store.RemoteMemoryMaterializationIssue
}

func (s *recordingMaterializationStore) MarkRemoteMemoryMaterializationIssue(
	_ context.Context,
	issue store.RemoteMemoryMaterializationIssue,
) (*store.RemoteMemoryCatalogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issues = append(s.issues, issue)
	entry, ok := s.byID[issue.ID]
	if !ok {
		return nil, store.ErrNotFound
	}
	entry.MaterializationState = issue.State
	s.byID[issue.ID] = entry
	copy := entry
	return &copy, nil
}

func (s *recordingMaterializationStore) recordedIssues() []store.RemoteMemoryMaterializationIssue {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.RemoteMemoryMaterializationIssue(nil), s.issues...)
}

func remoteSearchFixture(
	binding store.MemoryBackendBinding,
	id string,
	updatedAt time.Time,
	content string,
	trust store.MemoryTrust,
) (store.RemoteMemoryCatalogEntry, protocol.MemoryRecord) {
	protocolIdentity, err := protocolBinding(&binding)
	if err != nil {
		panic(err)
	}
	digest := protocol.ContentDigest(content)
	entry := store.RemoteMemoryCatalogEntry{
		ID: id, Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID,
		ClusterID: binding.ClusterID, BackendUID: binding.BackendUID, AuthorityEpoch: binding.AuthorityEpoch,
		TenantID: binding.TenantID, StoreUUID: binding.StoreUUID,
		SessionName: "session-a", AgentName: "agent-a", TaskName: "task-a", ParentTask: "parent-a",
		Source: "api", Tags: []string{"storage"}, Trust: trust,
		Generation: 1, DesiredGeneration: 1, GovernanceRevision: 1,
		MaterializationState: store.MemoryMaterializationActive, ContentAvailable: true,
		BackendVersion: "version-" + id, BackendMemoryID: "backend-" + id,
		ContentDigest: digest, CreatedAt: updatedAt, UpdatedAt: updatedAt,
	}
	record := protocol.MemoryRecord{
		MemoryID: id, UpsertKey: protocol.CanonicalUpsertKey(protocolIdentity, id), State: protocol.RecordStateLive,
		Generation: 1, BackendVersion: entry.BackendVersion, BackendMemoryID: entry.BackendMemoryID,
		ContentDigest: digest, Content: content, Tags: append([]string(nil), entry.Tags...),
		Metadata: remoteRecordMetadataFixture(entry, content), UpdatedAt: updatedAt,
	}
	return entry, record
}

func remoteRecordMetadataFixture(entry store.RemoteMemoryCatalogEntry, content string) map[string]string {
	metadata, err := protocol.NormalizeMetadata(memoryMetadataFromStore(remoteEntryToMemory(&entry, content)))
	if err != nil {
		panic(err)
	}
	return metadata
}

func TestRemoteHydrationRejectsCanonicalTagAndMetadataDrift(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	tests := []struct {
		name   string
		mutate func(*protocol.MemoryRecord)
	}{
		{name: "altered tags", mutate: func(record *protocol.MemoryRecord) { record.Tags = []string{"other"} }},
		{name: "dropped tags", mutate: func(record *protocol.MemoryRecord) { record.Tags = []string{} }},
		{name: "null tags", mutate: func(record *protocol.MemoryRecord) { record.Tags = nil }},
		{name: "altered metadata", mutate: func(record *protocol.MemoryRecord) { record.Metadata["source"] = "cli" }},
		{name: "dropped metadata", mutate: func(record *protocol.MemoryRecord) { delete(record.Metadata, "sessionname") }},
		{name: "null metadata", mutate: func(record *protocol.MemoryRecord) { record.Metadata = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry, record := remoteSearchFixture(binding, "mem-hydrate", now, "durable guidance", store.MemoryTrustReviewed)
			test.mutate(&record)
			service, _, activeBinding, governed := remoteSearchService(
				t, []store.RemoteMemoryCatalogEntry{entry}, []protocol.MemoryRecord{record},
			)
			recordingStore := &recordingMaterializationStore{governedSearchStore: governed}
			service.Governed = recordingStore

			memory, err := service.GetMemory(context.Background(), activeBinding.Namespace, entry.ID)
			var structured *apierror.Error
			if memory != nil || !errors.As(err, &structured) || structured.Status != http.StatusConflict ||
				structured.Reason != ReasonDiverged {
				t.Fatalf("GetMemory() = (%#v, %#v), want fail-closed materialization divergence", memory, err)
			}
			issues := recordingStore.recordedIssues()
			if len(issues) != 1 || issues[0].ID != entry.ID || issues[0].State != store.MemoryMaterializationDiverged {
				t.Fatalf("materialization issues = %#v, want one divergence", issues)
			}
		})
	}
}

func TestRemoteSearchRejectsCanonicalTagAndMetadataDrift(t *testing.T) {
	now := time.Date(2026, 8, 2, 9, 30, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	tests := []struct {
		name   string
		mutate func(*protocol.MemoryRecord)
	}{
		{name: "altered tags", mutate: func(record *protocol.MemoryRecord) { record.Tags = []string{"other"} }},
		{name: "dropped tags", mutate: func(record *protocol.MemoryRecord) { record.Tags = []string{} }},
		{name: "null tags", mutate: func(record *protocol.MemoryRecord) { record.Tags = nil }},
		{name: "altered metadata", mutate: func(record *protocol.MemoryRecord) { record.Metadata["source"] = "cli" }},
		{name: "dropped metadata", mutate: func(record *protocol.MemoryRecord) { delete(record.Metadata, "sessionname") }},
		{name: "null metadata", mutate: func(record *protocol.MemoryRecord) { record.Metadata = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry, record := remoteSearchFixture(binding, "mem-search", now, "needle", store.MemoryTrustReviewed)
			test.mutate(&record)
			service, adapter, activeBinding, _ := remoteSearchService(
				t, []store.RemoteMemoryCatalogEntry{entry}, []protocol.MemoryRecord{record},
			)

			response, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
				Query: "needle", Limit: 1,
			}, SearchContext{RemoteAuthorized: true})
			var structured *apierror.Error
			if response != nil || !errors.As(err, &structured) || structured.Status != http.StatusConflict ||
				structured.Reason != ReasonDiverged {
				t.Fatalf("Search() = (%#v, %#v), want fail-closed materialization divergence", response, err)
			}
			if adapter.searchCalls != 1 {
				t.Fatalf("search calls = %d, want one verified provider page", adapter.searchCalls)
			}
		})
	}
}

func remoteSearchService(
	t *testing.T,
	entries []store.RemoteMemoryCatalogEntry,
	records []protocol.MemoryRecord,
) (*Service, *pagedSearchAdapter, store.MemoryBackendBinding, *governedSearchStore) {
	t.Helper()
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", Mode: store.MemoryBackendModeRemote,
		BackendUID: "22222222-2222-4222-8222-222222222222", AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444", State: store.MemoryBackendBindingAccepting,
	}
	for i := range entries {
		entries[i].Namespace = binding.Namespace
		entries[i].NamespaceUID = binding.NamespaceUID
		entries[i].ClusterID = binding.ClusterID
		entries[i].BackendUID = binding.BackendUID
		entries[i].AuthorityEpoch = binding.AuthorityEpoch
		entries[i].TenantID = binding.TenantID
		entries[i].StoreUUID = binding.StoreUUID
	}
	protocolIdentity, err := protocolBinding(&binding)
	if err != nil {
		t.Fatal(err)
	}
	adapter := newPagedSearchAdapter(protocolIdentity, records)
	backend := &corev1alpha1.MemoryBackend{}
	backend.Status.EffectiveLifecycleState = corev1alpha1.MemoryBackendEffectiveLifecycleActive
	backend.Status.Ready = true
	backend.Status.ObservedCapabilities = &corev1alpha1.MemoryBackendObservedCapabilities{
		Effective: []corev1alpha1.MemoryBackendCapability{corev1alpha1.MemoryBackendCapabilityKeywordSearch},
		Limits:    corev1alpha1.MemoryBackendCapabilityLimits{MaxPageSize: protocol.MaxPageSize},
	}
	governed := newGovernedSearchStore(entries)
	authority := &ResolvedAuthority{
		Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID,
		Binding: &binding, Backend: backend, Adapter: adapter,
	}
	service := &Service{Governed: governed, Resolver: staticAuthorityResolver{authority: authority}}
	return service, adapter, binding, governed
}

func TestRemoteUpdateRejectsPendingMaterializationBeforeProviderHydration(t *testing.T) {
	const (
		actor       = "alice"
		createRoute = "createMemory"
		updateRoute = "updateMemory"
	)
	t.Run("create", func(t *testing.T) {
		storeImpl := newMemoryTestStore(t)
		now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
		binding := activateServiceTestBinding(t, storeImpl, now)
		backend := &corev1alpha1.MemoryBackend{}
		backend.Status.EffectiveLifecycleState = corev1alpha1.MemoryBackendEffectiveLifecycleActive
		backend.Status.Ready = true
		adapter := &countingGetAdapter{}
		authority := &ResolvedAuthority{
			Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID, Binding: &binding, Backend: backend, Adapter: adapter,
		}
		service := &Service{
			Governed: storeImpl, Resolver: staticAuthorityResolver{authority: authority}, Now: func() time.Time { return now.Add(time.Minute) },
		}
		created, err := service.CreateMemory(context.Background(), binding.Namespace, CreateRequest{Content: "pending create"}, MutationContext{
			Actor: actor, Principal: actor, Route: createRoute, IdempotencyKey: "create-pending",
		})
		if err != nil || created.Operation == nil {
			t.Fatalf("CreateMemory() = %#v, %v", created, err)
		}
		before, err := storeImpl.GetRemoteMemory(context.Background(), binding.NamespaceUID, created.Operation.MemoryID)
		if err != nil {
			t.Fatal(err)
		}
		content := "replacement"
		_, err = service.UpdateMemory(context.Background(), binding.Namespace, before.ID, UpdateRequest{Content: &content}, MutationContext{
			Actor: actor, Principal: actor, Route: updateRoute, IdempotencyKey: "update-pending-create",
		})
		var structured *apierror.Error
		if !errors.As(err, &structured) || structured.Status != http.StatusConflict || structured.Reason != ReasonOperationInProgress {
			t.Fatalf("UpdateMemory() error = %#v, want operation-in-progress conflict", err)
		}
		after, err := storeImpl.GetRemoteMemory(context.Background(), binding.NamespaceUID, before.ID)
		if err != nil {
			t.Fatal(err)
		}
		if adapter.getCount() != 0 || after.MaterializationState != store.MemoryMaterializationPending ||
			after.PendingOperationID != before.PendingOperationID || after.Generation != before.Generation ||
			after.DesiredGeneration != before.DesiredGeneration {
			t.Fatalf("pending create was hydrated or reclassified: gets=%d before=%#v after=%#v", adapter.getCount(), before, after)
		}
	})

	t.Run("replacement", func(t *testing.T) {
		storeImpl := newMemoryTestStore(t)
		now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
		binding := activateServiceTestBinding(t, storeImpl, now)
		backend := &corev1alpha1.MemoryBackend{}
		backend.Status.EffectiveLifecycleState = corev1alpha1.MemoryBackendEffectiveLifecycleActive
		backend.Status.Ready = true
		adapter := &countingGetAdapter{}
		authority := &ResolvedAuthority{
			Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID, Binding: &binding, Backend: backend, Adapter: adapter,
		}
		resolver := staticAuthorityResolver{authority: authority}
		service := &Service{
			Governed: storeImpl, Resolver: resolver,
			Dispatcher: &Dispatcher{Store: storeImpl, Resolver: resolver, LeaseOwner: "service-test", Now: func() time.Time { return now.Add(time.Minute) }},
			Now:        func() time.Time { return now.Add(time.Minute) },
		}
		created, err := service.CreateMemory(context.Background(), binding.Namespace, CreateRequest{Content: "materialized"}, MutationContext{
			Actor: actor, Principal: actor, Route: createRoute, IdempotencyKey: "create-materialized",
		})
		if err != nil || created.Memory == nil {
			t.Fatalf("CreateMemory() = %#v, %v", created, err)
		}
		service.Dispatcher = nil
		firstReplacement := "replacement one"
		queued, err := service.UpdateMemory(context.Background(), binding.Namespace, created.Memory.ID, UpdateRequest{Content: &firstReplacement}, MutationContext{
			Actor: actor, Principal: actor, Route: updateRoute, IdempotencyKey: "replace-queued",
		})
		if err != nil || queued.Operation == nil {
			t.Fatalf("first UpdateMemory() = %#v, %v", queued, err)
		}
		before, err := storeImpl.GetRemoteMemory(context.Background(), binding.NamespaceUID, created.Memory.ID)
		if err != nil {
			t.Fatal(err)
		}
		getsBefore := adapter.getCount()
		secondReplacement := "replacement two"
		_, err = service.UpdateMemory(context.Background(), binding.Namespace, created.Memory.ID, UpdateRequest{Content: &secondReplacement}, MutationContext{
			Actor: actor, Principal: actor, Route: updateRoute, IdempotencyKey: "replace-while-queued",
		})
		var structured *apierror.Error
		if !errors.As(err, &structured) || structured.Status != http.StatusConflict || structured.Reason != ReasonOperationInProgress {
			t.Fatalf("second UpdateMemory() error = %#v, want operation-in-progress conflict", err)
		}
		after, err := storeImpl.GetRemoteMemory(context.Background(), binding.NamespaceUID, created.Memory.ID)
		if err != nil {
			t.Fatal(err)
		}
		if adapter.getCount() != getsBefore || after.MaterializationState != store.MemoryMaterializationActive ||
			after.PendingOperationID != before.PendingOperationID || after.Generation != before.Generation ||
			after.DesiredGeneration != before.DesiredGeneration {
			t.Fatalf("pending replacement was hydrated or reclassified: gets=%d/%d before=%#v after=%#v",
				adapter.getCount(), getsBefore, before, after)
		}
	})
}

func TestRemoteDisabledMemoryHydratesForExplicitInspection(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entry, record := remoteSearchFixture(binding, "mem-disabled", now, "disabled guidance", store.MemoryTrustReviewed)
	entry.Disabled = true
	service, adapter, activeBinding, _ := remoteSearchService(t, []store.RemoteMemoryCatalogEntry{entry}, []protocol.MemoryRecord{record})

	listed, err := service.ListMemories(context.Background(), store.MemoryFilter{Namespace: activeBinding.Namespace, Limit: 10})
	if err != nil || len(listed) != 0 {
		t.Fatalf("default ListMemories() = %#v, %v; want disabled memory suppressed", listed, err)
	}
	if calls, _ := adapter.getStats(); calls != 0 {
		t.Fatalf("default list hydrated disabled memory with %d Get calls", calls)
	}

	got, err := service.GetMemory(context.Background(), activeBinding.Namespace, entry.ID)
	if err != nil || got == nil || !got.Disabled || got.Content != "" || got.ContentAvailable {
		t.Fatalf("GetMemory() = %#v, %v; want disabled metadata without content", got, err)
	}
	if calls, _ := adapter.getStats(); calls != 0 {
		t.Fatalf("default exact get hydrated disabled memory with %d Get calls", calls)
	}
	got, err = service.GetMemoryWithVisibility(context.Background(), activeBinding.Namespace, entry.ID, true)
	if err != nil || got == nil || !got.Disabled || got.Content != record.Content || !got.ContentAvailable {
		t.Fatalf("GetMemoryWithVisibility() = %#v, %v; want verified disabled content", got, err)
	}
	listed, err = service.ListMemories(context.Background(), store.MemoryFilter{
		Namespace: activeBinding.Namespace, IncludeDisabled: true, Limit: 10,
	})
	if err != nil || len(listed) != 1 || !listed[0].Disabled || listed[0].Content != record.Content || !listed[0].ContentAvailable {
		t.Fatalf("includeDisabled ListMemories() = %#v, %v; want verified disabled content", listed, err)
	}
	if calls, _ := adapter.getStats(); calls != 2 {
		t.Fatalf("explicit disabled inspection Get calls = %d, want 2", calls)
	}
}

func TestRemoteMutationAdmissionHonorsAdvertisedLimits(t *testing.T) {
	const (
		actor            = "alice"
		createRoute      = "createMemory"
		updateRoute      = "updateMemory"
		oversizedContent = "large"
		contentAtLimit   = "four"
		proposalType     = "memory"
		acceptedStatus   = "accepted"
	)
	storeImpl := newMemoryTestStore(t)
	now := time.Date(2026, 8, 1, 10, 15, 0, 0, time.UTC)
	binding := activateServiceTestBinding(t, storeImpl, now)
	backend := &corev1alpha1.MemoryBackend{}
	backend.Status.EffectiveLifecycleState = corev1alpha1.MemoryBackendEffectiveLifecycleActive
	backend.Status.Ready = true
	backend.Status.ObservedCapabilities = &corev1alpha1.MemoryBackendObservedCapabilities{
		Limits: corev1alpha1.MemoryBackendCapabilityLimits{MaxContentBytes: 4},
	}
	adapter := &countingGetAdapter{}
	authority := &ResolvedAuthority{
		Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID, Binding: &binding, Backend: backend, Adapter: adapter,
	}
	resolver := staticAuthorityResolver{authority: authority}
	service := &Service{
		Legacy: storeImpl, Proposals: storeImpl, Governed: storeImpl, Resolver: resolver, ContentLimit: protocol.MaxContentBytes,
		Dispatcher: &Dispatcher{Store: storeImpl, Resolver: resolver, LeaseOwner: "content-limit-test", Now: func() time.Time { return now.Add(time.Minute) }},
		Now:        func() time.Time { return now.Add(time.Minute) },
	}
	assertTooLarge := func(result *MutationResult, err error) {
		t.Helper()
		var structured *apierror.Error
		if result != nil || !errors.As(err, &structured) || structured.Status != http.StatusRequestEntityTooLarge {
			t.Fatalf("mutation = %#v, %v; want advertised-limit rejection", result, err)
		}
	}
	operationCount := func() int {
		t.Helper()
		operations, err := storeImpl.ListMemoryOperations(context.Background(), store.MemoryOperationFilter{
			NamespaceUID: binding.NamespaceUID, Limit: 20,
		})
		if err != nil {
			t.Fatal(err)
		}
		return len(operations)
	}

	rejectCreate := func(key string, request CreateRequest) {
		t.Helper()
		result, err := service.CreateMemory(context.Background(), binding.Namespace, request, MutationContext{
			Actor: actor, Principal: actor, Route: createRoute, IdempotencyKey: key,
		})
		assertTooLarge(result, err)
		if count := operationCount(); count != 0 {
			t.Fatalf("advertised-limit create %q admitted %d operations", key, count)
		}
	}
	limits := &backend.Status.ObservedCapabilities.Limits
	rejectCreate("create-content-too-large", CreateRequest{Content: oversizedContent})

	limits.MaxContentBytes = 100
	limits.MaxTags = 1
	rejectCreate("create-too-many-tags", CreateRequest{Content: contentAtLimit, Tags: []string{"one", "two"}})
	limits.MaxTags = 0
	limits.MaxTagBytes = 3
	rejectCreate("create-tag-too-large", CreateRequest{Content: contentAtLimit, Tags: []string{"four"}})
	limits.MaxTagBytes = 0
	limits.MaxMetadataEntries = 1
	rejectCreate("create-too-much-metadata", CreateRequest{Content: contentAtLimit, SessionName: "session"})
	limits.MaxMetadataEntries = 0
	limits.MaxMetadataKeyBytes = 5
	rejectCreate("create-metadata-key-too-large", CreateRequest{Content: contentAtLimit})
	limits.MaxMetadataKeyBytes = 0
	limits.MaxMetadataValueBytes = 2
	rejectCreate("create-metadata-value-too-large", CreateRequest{Content: contentAtLimit})
	limits.MaxMetadataValueBytes = 0
	limits.MaxRequestBytes = 1
	rejectCreate("create-request-too-large", CreateRequest{Content: contentAtLimit})
	limits.MaxRequestBytes = 0
	limits.MaxContentBytes = 4

	created, err := service.CreateMemory(context.Background(), binding.Namespace, CreateRequest{Content: contentAtLimit}, MutationContext{
		Actor: actor, Principal: actor, Route: createRoute, IdempotencyKey: "create-within-limit",
	})
	if err != nil || created.Memory == nil {
		t.Fatalf("within-limit CreateMemory() = %#v, %v", created, err)
	}
	baselineOperations := operationCount()
	tooLargeUpdate := oversizedContent
	result, err := service.UpdateMemory(context.Background(), binding.Namespace, created.Memory.ID, UpdateRequest{Content: &tooLargeUpdate}, MutationContext{
		Actor: actor, Principal: actor, Route: updateRoute, IdempotencyKey: "update-too-large",
	})
	assertTooLarge(result, err)
	if count := operationCount(); count != baselineOperations {
		t.Fatalf("oversized update changed operation count from %d to %d", baselineOperations, count)
	}

	proposal := &store.MemoryProposal{
		Namespace: binding.Namespace, Type: proposalType, Title: "oversized proposal", Content: oversizedContent,
	}
	if err := storeImpl.CreateMemoryProposal(context.Background(), proposal); err != nil {
		t.Fatal(err)
	}
	if err := storeImpl.ReviewMemoryProposal(context.Background(), store.MemoryProposalReview{
		Namespace: binding.Namespace, ID: proposal.ID, Status: acceptedStatus, Reviewer: actor,
	}); err != nil {
		t.Fatal(err)
	}
	result, err = service.ApplyMemoryProposal(context.Background(), binding.Namespace, proposal.ID, actor, MutationContext{
		Actor: actor, Principal: actor, Route: "applyMemoryProposal", IdempotencyKey: "proposal-too-large",
	})
	assertTooLarge(result, err)
	if count := operationCount(); count != baselineOperations {
		t.Fatalf("oversized proposal changed operation count from %d to %d", baselineOperations, count)
	}
	persisted, err := storeImpl.GetMemoryProposal(context.Background(), binding.Namespace, proposal.ID)
	if err != nil || persisted.Status != acceptedStatus || persisted.ApplyOperationID != "" {
		t.Fatalf("oversized proposal state = %#v, %v; want unchanged accepted proposal", persisted, err)
	}
}

func TestRemoteDeleteAdmissionRejectsAdvertisedRequestLimitBeforeAdmissionAndEgress(t *testing.T) {
	storeImpl := newMemoryTestStore(t)
	now := time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC)
	binding := activateServiceTestBinding(t, storeImpl, now)
	backend := &corev1alpha1.MemoryBackend{}
	backend.Status.EffectiveLifecycleState = corev1alpha1.MemoryBackendEffectiveLifecycleActive
	backend.Status.Ready = true
	backend.Status.ObservedCapabilities = &corev1alpha1.MemoryBackendObservedCapabilities{}
	adapter := &countingGetAdapter{}
	authority := &ResolvedAuthority{
		Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID, Binding: &binding, Backend: backend, Adapter: adapter,
	}
	resolver := staticAuthorityResolver{authority: authority}
	service := &Service{
		Legacy: storeImpl, Governed: storeImpl, Resolver: resolver,
		Dispatcher: &Dispatcher{Store: storeImpl, Resolver: resolver, LeaseOwner: "delete-limit-test", Now: func() time.Time {
			return now.Add(time.Minute)
		}},
		Now: func() time.Time { return now.Add(time.Minute) },
	}

	created, err := service.CreateMemory(context.Background(), binding.Namespace, CreateRequest{
		ID: "mem-delete-limit", Content: "delete me", Tags: []string{"storage"}, SessionName: "session-a",
	}, MutationContext{
		Actor: "alice", Principal: "alice", Route: testRemoteCreateRoute, IdempotencyKey: "create-delete-limit",
	})
	if err != nil || created == nil || created.Memory == nil {
		t.Fatalf("CreateMemory() = %#v, %v", created, err)
	}
	entry, err := storeImpl.GetRemoteMemory(context.Background(), binding.NamespaceUID, created.Memory.ID)
	if err != nil {
		t.Fatal(err)
	}
	protocolIdentity, err := protocolBinding(&binding)
	if err != nil {
		t.Fatal(err)
	}
	envelope := protocol.MutationEnvelope{
		ProtocolVersion:        protocol.Version,
		OperationID:            "mop-00000000-0000-4000-8000-000000000000",
		Binding:                protocolIdentity,
		MemoryID:               entry.ID,
		Kind:                   protocol.MutationKindDelete,
		Generation:             uint64(max(entry.Generation, entry.DesiredGeneration) + 1),
		ExpectedGeneration:     uint64(entry.Generation),
		ExpectedBackendVersion: entry.BackendVersion,
		State:                  nil,
	}
	if err := protocol.PrepareMutation(&envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	backend.Status.ObservedCapabilities.Limits.MaxRequestBytes = int64(len(payload) - 1)

	operationCount := func() int {
		t.Helper()
		operations, err := storeImpl.ListMemoryOperations(context.Background(), store.MemoryOperationFilter{
			NamespaceUID: binding.NamespaceUID, Limit: 20,
		})
		if err != nil {
			t.Fatal(err)
		}
		return len(operations)
	}
	mutationCount := func() int {
		t.Helper()
		adapter.mu.Lock()
		defer adapter.mu.Unlock()
		return adapter.mutations
	}
	baselineOperations := operationCount()
	baselineMutations := mutationCount()

	result, err := service.DeleteMemory(context.Background(), binding.Namespace, entry.ID, MutationContext{
		Actor: "alice", Principal: "alice", Route: "deleteMemory", IdempotencyKey: "delete-too-large",
	})
	var structured *apierror.Error
	if result != nil || !errors.As(err, &structured) || structured.Status != http.StatusRequestEntityTooLarge ||
		structured.Reason != "" {
		t.Errorf("DeleteMemory() = (%#v, %#v), want client request-too-large rejection", result, err)
	}
	if got := operationCount(); got != baselineOperations {
		t.Errorf("delete operation count = %d, want unchanged %d", got, baselineOperations)
	}
	if got := mutationCount(); got != baselineMutations {
		t.Errorf("provider mutation count = %d, want unchanged %d", got, baselineMutations)
	}
	after, getErr := storeImpl.GetRemoteMemory(context.Background(), binding.NamespaceUID, entry.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if after.Deleted || after.MaterializationState != entry.MaterializationState ||
		after.DesiredGeneration != entry.DesiredGeneration || after.PendingOperationID != entry.PendingOperationID {
		t.Errorf("catalog after rejected delete = %#v, want unchanged active entry %#v", after, entry)
	}
}

func TestRemoteMutationAdmissionPublicLocationIncludesEncodedNamespace(t *testing.T) {
	binding := &store.MemoryBackendBinding{
		ClusterID: "cluster-a", BackendUID: "backend-a", AuthorityEpoch: 1, RoutingEpoch: 1,
	}
	authority := &ResolvedAuthority{
		Namespace: "team blue/child", NamespaceUID: "namespace-a", Binding: binding,
	}
	admission := (&Service{}).mutationAdmission(
		MutationContext{LocationBase: "/api/v1/memory-operations/"}, authority,
		"memory-a", "operation-a", "", "request-digest", protocol.MutationEnvelope{}, nil, time.Now(),
	)
	const want = "/api/v1/memory-operations/operation-a?namespace=team+blue%2Fchild"
	if admission.Location != want {
		t.Fatalf("mutation location = %q, want %q", admission.Location, want)
	}
}

func TestRemoteSearchRequiresAuthorizationAtEgress(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entry, record := remoteSearchFixture(binding, "mem-1", now, "needle", store.MemoryTrustReviewed)
	service, adapter, activeBinding, _ := remoteSearchService(t, []store.RemoteMemoryCatalogEntry{entry}, []protocol.MemoryRecord{record})
	_, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{Query: "needle", Limit: 1}, SearchContext{})
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Status != http.StatusForbidden || structured.Reason != ReasonSearchRemoteAuth {
		t.Fatalf("Search() error = %#v, want remote-search authorization", err)
	}
	if adapter.searchCalls != 0 {
		t.Fatalf("search calls = %d, want no egress", adapter.searchCalls)
	}
	authorized := false
	response, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{Query: "needle", Limit: 1}, SearchContext{
		AuthorizeRemote: func() error { authorized = true; return nil },
	})
	if err != nil || !authorized || len(response.Items) != 1 {
		t.Fatalf("authorized Search() = %#v, err=%v, authorized=%v", response, err, authorized)
	}
}

func TestRemoteListQueryWithoutEgressAuthorizationFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entry, record := remoteSearchFixture(binding, "mem-1", now, "needle", store.MemoryTrustReviewed)
	service, adapter, activeBinding, _ := remoteSearchService(t, []store.RemoteMemoryCatalogEntry{entry}, []protocol.MemoryRecord{record})
	_, err := service.ListMemories(context.Background(), store.MemoryFilter{Namespace: activeBinding.Namespace, Query: "needle", Limit: 1})
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Reason != ReasonSearchRemoteAuth {
		t.Fatalf("ListMemories() error = %#v, want remote-search authorization", err)
	}
	if adapter.searchCalls != 0 {
		t.Fatalf("search calls = %d, want no egress", adapter.searchCalls)
	}
}

func TestRemoteListQueryPreservesEveryFilterBeforeLimit(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	firstEntry, firstRecord := remoteSearchFixture(binding, "mem-first", now, "needle", store.MemoryTrustReviewed)
	firstEntry.SessionName = "other-session"
	firstRecord.Metadata = remoteRecordMetadataFixture(firstEntry, firstRecord.Content)
	secondEntry, secondRecord := remoteSearchFixture(binding, "mem-match", now.Add(-time.Second), "needle", store.MemoryTrustUntrusted)
	service, _, activeBinding, _ := remoteSearchService(t,
		[]store.RemoteMemoryCatalogEntry{firstEntry, secondEntry}, []protocol.MemoryRecord{firstRecord, secondRecord})
	memories, err := service.ListMemoriesWithSearchContext(context.Background(), store.MemoryFilter{
		Namespace: activeBinding.Namespace, Query: "needle", IDs: []string{"mem-match"},
		SessionName: "session-a", AgentName: "agent-a", TaskName: "task-a", ParentTask: "parent-a",
		Source: "api", Tags: []string{"storage"}, Limit: 1,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || len(memories) != 1 || memories[0].ID != "mem-match" {
		t.Fatalf("ListMemoriesWithSearchContext() = %#v, err=%v", memories, err)
	}
}

func TestRemoteCatalogFiltersBeforeLimitAcrossPages(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entries := make([]store.RemoteMemoryCatalogEntry, 0, maxRemoteCatalogLimit+1)
	records := make([]protocol.MemoryRecord, 0, maxRemoteCatalogLimit+1)
	for i := 0; i <= maxRemoteCatalogLimit; i++ {
		entry, record := remoteSearchFixture(binding, fmt.Sprintf("mem-%04d", maxRemoteCatalogLimit-i), now.Add(-time.Duration(i)*time.Second), "content", store.MemoryTrustReviewed)
		entry.AgentName = "other"
		if i == maxRemoteCatalogLimit {
			entry.AgentName = "wanted"
		}
		record.Metadata = remoteRecordMetadataFixture(entry, record.Content)
		entries = append(entries, entry)
		records = append(records, record)
	}
	service, _, activeBinding, governed := remoteSearchService(t, entries, records)
	memories, err := service.ListMemories(context.Background(), store.MemoryFilter{
		Namespace: activeBinding.Namespace, AgentName: "wanted", Limit: 1,
	})
	if err != nil || len(memories) != 1 || memories[0].AgentName != "wanted" {
		t.Fatalf("ListMemories() = %#v, err=%v", memories, err)
	}
	if governed.listCalls < 2 {
		t.Fatalf("list calls = %d, want pagination before applying output limit", governed.listCalls)
	}
}

func TestRemoteCatalogHydratesConcurrentlyWithinFixedBoundAndPreservesOrder(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	count := maxRemoteListHydrationConcurrency + 3
	entries := make([]store.RemoteMemoryCatalogEntry, 0, count)
	records := make([]protocol.MemoryRecord, 0, count)
	for i := range count {
		entry, record := remoteSearchFixture(binding, fmt.Sprintf("mem-%02d", i), now.Add(-time.Duration(i)*time.Second), "content", store.MemoryTrustReviewed)
		entries = append(entries, entry)
		records = append(records, record)
	}
	service, adapter, activeBinding, _ := remoteSearchService(t, entries, records)
	started := make(chan struct{}, count)
	release := make(chan struct{})
	adapter.getStarted = started
	adapter.releaseGets = release
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()

	type listResult struct {
		memories []store.Memory
		err      error
	}
	done := make(chan listResult, 1)
	go func() {
		memories, err := service.ListMemories(context.Background(), store.MemoryFilter{
			Namespace: activeBinding.Namespace, Limit: count,
		})
		done <- listResult{memories: memories, err: err}
	}()
	for range maxRemoteListHydrationConcurrency {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("remote list hydration did not reach the fixed concurrency bound")
		}
	}
	releaseAll()
	var listed listResult
	select {
	case listed = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("remote list hydration did not complete")
	}
	if listed.err != nil || len(listed.memories) != count {
		t.Fatalf("ListMemories() = %#v, err=%v", listed.memories, listed.err)
	}
	for i := range listed.memories {
		if listed.memories[i].ID != entries[i].ID {
			t.Fatalf("memory[%d] = %q, want deterministic %q", i, listed.memories[i].ID, entries[i].ID)
		}
	}
	getCalls, maxActive := adapter.getStats()
	if getCalls != count || maxActive != maxRemoteListHydrationConcurrency {
		t.Fatalf("Get calls=%d max active=%d, want %d and %d", getCalls, maxActive, count, maxRemoteListHydrationConcurrency)
	}
}

func TestRemoteCatalogHTTP1HydrationRespectsTransportConnectionCap(t *testing.T) {
	now := time.Date(2026, 8, 1, 16, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	count := omsHTTPMaxConnsPerHost * 2
	entries := make([]store.RemoteMemoryCatalogEntry, 0, count)
	records := make([]protocol.MemoryRecord, 0, count)
	byUpsertKey := make(map[string]protocol.MemoryRecord, count)
	for i := range count {
		entry, record := remoteSearchFixture(
			binding, fmt.Sprintf("mem-http1-%02d", i), now.Add(-time.Duration(i)*time.Second), "slow content", store.MemoryTrustReviewed,
		)
		entries = append(entries, entry)
		records = append(records, record)
		byUpsertKey[record.UpsertKey] = record
	}

	const requestDelay = 300 * time.Millisecond
	var concurrencyMu sync.Mutex
	active, maxActive := 0, 0
	protocolMajor := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, "invalid body", http.StatusBadRequest)
			return
		}
		decoded, err := protocol.DecodeGetRequest(body)
		if err != nil || request.URL.Path != protocol.PathRecordsGet {
			http.Error(writer, "invalid request", http.StatusBadRequest)
			return
		}
		concurrencyMu.Lock()
		active++
		maxActive = max(maxActive, active)
		protocolMajor = request.ProtoMajor
		concurrencyMu.Unlock()
		defer func() {
			concurrencyMu.Lock()
			active--
			concurrencyMu.Unlock()
		}()
		time.Sleep(requestDelay)
		record, found := byUpsertKey[decoded.UpsertKey]
		response := protocol.GetResponse{
			ProtocolVersion: protocol.Version, Binding: decoded.Binding, Found: found,
		}
		if found {
			copy := record
			response.Record = &copy
		}
		encoded, err := protocol.EncodeJSON(response)
		if err != nil {
			http.Error(writer, "encode response", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(encoded)
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()

	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = omsHTTPMaxConnsPerHost
	client := &OMSClient{
		baseURL: server.URL, token: "test-token",
		client: &http.Client{Transport: transport, Timeout: 500 * time.Millisecond},
	}
	service, _, activeBinding, _ := remoteSearchService(t, entries, records)
	authority := service.Resolver.(staticAuthorityResolver).authority
	authority.Adapter = client

	listed, err := service.ListMemories(context.Background(), store.MemoryFilter{
		Namespace: activeBinding.Namespace, Limit: count,
	})
	if err != nil || len(listed) != count {
		t.Fatalf("ListMemories() = %d items, %v; want all slow HTTP/1.1 records", len(listed), err)
	}
	concurrencyMu.Lock()
	gotMaxActive, gotProtocolMajor := maxActive, protocolMajor
	concurrencyMu.Unlock()
	if gotProtocolMajor != 1 || gotMaxActive != omsHTTPMaxConnsPerHost {
		t.Fatalf("HTTP protocol=%d max active=%d, want HTTP/1.1 and %d",
			gotProtocolMajor, gotMaxActive, omsHTTPMaxConnsPerHost)
	}
}

func TestRemoteCatalogConcurrentHydrationStillRejectsDivergence(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	firstEntry, firstRecord := remoteSearchFixture(binding, "mem-1", now, "first", store.MemoryTrustReviewed)
	secondEntry, secondRecord := remoteSearchFixture(binding, "mem-2", now.Add(-time.Second), "second", store.MemoryTrustReviewed)
	secondRecord.Content = "tampered"
	service, _, activeBinding, governed := remoteSearchService(t,
		[]store.RemoteMemoryCatalogEntry{firstEntry, secondEntry}, []protocol.MemoryRecord{firstRecord, secondRecord})
	recordingStore := &recordingMaterializationStore{governedSearchStore: governed}
	service.Governed = recordingStore

	memories, err := service.ListMemories(context.Background(), store.MemoryFilter{
		Namespace: activeBinding.Namespace, Limit: 2,
	})
	var structured *apierror.Error
	if memories != nil || !errors.As(err, &structured) || structured.Status != http.StatusConflict || structured.Reason != ReasonDiverged {
		t.Fatalf("ListMemories() = (%#v, %#v), want fail-closed divergence", memories, err)
	}
	issues := recordingStore.recordedIssues()
	if len(issues) != 1 || issues[0].ID != secondEntry.ID || issues[0].State != store.MemoryMaterializationDiverged {
		t.Fatalf("materialization issues = %#v", issues)
	}
}

func TestRemoteSearchPersistsAdvertisedMaximumPageSize(t *testing.T) {
	now := time.Date(2026, 8, 1, 16, 15, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entries := make([]store.RemoteMemoryCatalogEntry, 0, 4)
	records := make([]protocol.MemoryRecord, 0, 4)
	for i := 1; i <= 4; i++ {
		entry, record := remoteSearchFixture(
			binding, fmt.Sprintf("mem-page-%d", i), now.Add(-time.Duration(i)*time.Second), "needle", store.MemoryTrustReviewed,
		)
		entries = append(entries, entry)
		records = append(records, record)
	}
	service, adapter, activeBinding, governed := remoteSearchService(t, entries, records)
	authority := service.Resolver.(staticAuthorityResolver).authority
	authority.Backend.Status.ObservedCapabilities.Limits.MaxPageSize = 1

	first, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 2,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || first == nil || len(first.Items) != 2 || first.Cursor == "" || first.Exhausted {
		t.Fatalf("first Search() = %#v, %v", first, err)
	}
	stored := governed.cursors[first.Cursor]
	var cursor persistedRemoteSearchCursor
	if err := json.Unmarshal(stored.State, &cursor); err != nil || cursor.PageSize != 1 {
		t.Fatalf("persisted cursor = %#v, %v; want page size 1", cursor, err)
	}
	second, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 2, Cursor: first.Cursor,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || second == nil || len(second.Items) != 2 || !second.Exhausted {
		t.Fatalf("second Search() = %#v, %v", second, err)
	}
	if !governed.retired[first.Cursor] {
		t.Fatal("consumed remote cursor was not retired")
	}
	replayed, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 2, Cursor: first.Cursor,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || replayed == nil || len(replayed.Items) != len(second.Items) || !replayed.Exhausted {
		t.Fatalf("retired cursor replay = %#v, %v", replayed, err)
	}
	if adapter.searchCalls != 6 || len(adapter.pageSizes) != 6 {
		t.Fatalf("provider calls=%d page sizes=%v, want six single-record pages including replay", adapter.searchCalls, adapter.pageSizes)
	}
	for i, pageSize := range adapter.pageSizes {
		if pageSize != 1 {
			t.Fatalf("provider page size[%d] = %d, want 1", i, pageSize)
		}
	}
}

func TestRemoteSearchCursorPreservesUnconsumedProviderRecords(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entries := make([]store.RemoteMemoryCatalogEntry, 0, 5)
	records := make([]protocol.MemoryRecord, 0, 5)
	for i := 1; i <= 5; i++ {
		trust := store.MemoryTrustReviewed
		if i == 1 {
			trust = store.MemoryTrustUntrusted
		}
		entry, record := remoteSearchFixture(binding, fmt.Sprintf("mem-%d", i), now.Add(-time.Duration(i)*time.Second), "needle", trust)
		entries = append(entries, entry)
		records = append(records, record)
	}
	service, adapter, activeBinding, _ := remoteSearchService(t, entries, records)
	first, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 3, AllowIncomplete: true,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || len(first.Items) != 3 || first.Cursor == "" || !first.Complete || first.Exhausted {
		t.Fatalf("first Search() = %#v, err=%v", first, err)
	}
	if first.Items[2].Memory.ID != "mem-4" {
		t.Fatalf("first page last item = %q, want mem-4", first.Items[2].Memory.ID)
	}
	protocolIdentity, err := protocolBinding(&activeBinding)
	if err != nil {
		t.Fatal(err)
	}
	adapter.getMu.Lock()
	delete(adapter.byUpsertKey, protocol.CanonicalUpsertKey(protocolIdentity, "mem-5"))
	adapter.getMu.Unlock()

	second, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1, Cursor: first.Cursor,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || len(second.Items) != 1 || second.Items[0].Memory.ID != "mem-5" ||
		second.Items[0].Memory.Content != "needle" || !second.Complete {
		t.Fatalf("second Search() = %#v, err=%v", second, err)
	}
	if adapter.searchCalls != 3 || adapter.getCalls != 0 {
		t.Fatalf("search calls=%d get calls=%d, want immutable snapshot replay 3/0", adapter.searchCalls, adapter.getCalls)
	}
	if len(adapter.pageSizes) != 3 || adapter.pageSizes[0] != adapter.pageSizes[1] ||
		adapter.pageSizes[1] != adapter.pageSizes[2] {
		t.Fatalf("provider page sizes = %#v, want stable snapshot page size", adapter.pageSizes)
	}
}

func TestRemoteSearchContinuationRemainsBoundToQueryAndAuthority(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 30, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entries := make([]store.RemoteMemoryCatalogEntry, 0, 5)
	records := make([]protocol.MemoryRecord, 0, 5)
	for i := 1; i <= 5; i++ {
		trust := store.MemoryTrustReviewed
		if i == 1 {
			trust = store.MemoryTrustUntrusted
		}
		entry, record := remoteSearchFixture(binding, fmt.Sprintf("mem-%d", i), now.Add(-time.Duration(i)*time.Second), "needle", trust)
		entries = append(entries, entry)
		records = append(records, record)
	}
	service, adapter, activeBinding, _ := remoteSearchService(t, entries, records)
	first, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 3, AllowIncomplete: true,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || first.Cursor == "" {
		t.Fatalf("first Search() = %#v, err=%v", first, err)
	}
	searchCalls := adapter.searchCalls
	_, err = service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "different", Limit: 1, Cursor: first.Cursor,
	}, SearchContext{RemoteAuthorized: true})
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Status != http.StatusBadRequest {
		t.Fatalf("query-mismatched cursor error = %#v, want bad request", err)
	}
	if adapter.searchCalls != searchCalls {
		t.Fatalf("query-mismatched cursor reached provider: calls=%d, want %d", adapter.searchCalls, searchCalls)
	}

	authority := service.Resolver.(staticAuthorityResolver).authority
	authority.Binding.RoutingEpoch++
	_, err = service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1, Cursor: first.Cursor,
	}, SearchContext{RemoteAuthorized: true})
	if !errors.As(err, &structured) || structured.Status != http.StatusBadRequest {
		t.Fatalf("authority-mismatched cursor error = %#v, want bad request", err)
	}
	if adapter.searchCalls != searchCalls {
		t.Fatalf("authority-mismatched cursor reached provider: calls=%d, want %d", adapter.searchCalls, searchCalls)
	}
}

func TestRemoteSearchContinuationRejectsChangedReplayedSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 1, 13, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entries := make([]store.RemoteMemoryCatalogEntry, 0, 5)
	records := make([]protocol.MemoryRecord, 0, 5)
	for i := 1; i <= 5; i++ {
		trust := store.MemoryTrustReviewed
		if i == 1 {
			trust = store.MemoryTrustUntrusted
		}
		entry, record := remoteSearchFixture(binding, fmt.Sprintf("mem-%d", i), now.Add(-time.Duration(i)*time.Second), "needle", trust)
		entries = append(entries, entry)
		records = append(records, record)
	}
	service, adapter, activeBinding, _ := remoteSearchService(t, entries, records)
	first, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 3, AllowIncomplete: true,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || first.Cursor == "" {
		t.Fatalf("first Search() = %#v, err=%v", first, err)
	}
	adapter.records[4].BackendVersion = "changed-version"
	_, err = service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1, Cursor: first.Cursor,
	}, SearchContext{RemoteAuthorized: true})
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Status != http.StatusConflict || structured.Reason != ReasonDiverged {
		t.Fatalf("continued Search() error = %#v, want changed-snapshot conflict", err)
	}
	if adapter.getCalls != 0 {
		t.Fatalf("continuation issued %d live Get calls", adapter.getCalls)
	}
}

func TestRemoteSearchCursorExpiresWithProviderSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 1, 14, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entries := make([]store.RemoteMemoryCatalogEntry, 0, 5)
	records := make([]protocol.MemoryRecord, 0, 5)
	for i := 1; i <= 5; i++ {
		trust := store.MemoryTrustReviewed
		if i == 1 {
			trust = store.MemoryTrustUntrusted
		}
		entry, record := remoteSearchFixture(binding, fmt.Sprintf("mem-%d", i), now.Add(-time.Duration(i)*time.Second), "needle", trust)
		entries = append(entries, entry)
		records = append(records, record)
	}
	service, adapter, activeBinding, governed := remoteSearchService(t, entries, records)
	current := now
	service.Now = func() time.Time { return current }
	adapter.snapshotExpiresAt = now.Add(30 * time.Second)
	first, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 3, AllowIncomplete: true,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || first.Cursor == "" {
		t.Fatalf("first Search() = %#v, err=%v", first, err)
	}
	stored, ok := governed.cursors[first.Cursor]
	if !ok || !stored.ExpiresAt.Equal(adapter.snapshotExpiresAt) {
		t.Fatalf("cursor expiry = %v, want provider snapshot expiry %v", stored.ExpiresAt, adapter.snapshotExpiresAt)
	}
	searchCalls := adapter.searchCalls
	current = adapter.snapshotExpiresAt.Add(time.Nanosecond)
	_, err = service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1, Cursor: first.Cursor,
	}, SearchContext{RemoteAuthorized: true})
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Status != http.StatusBadRequest {
		t.Fatalf("expired cursor error = %#v, want bad request", err)
	}
	if adapter.searchCalls != searchCalls {
		t.Fatalf("expired cursor reached provider: search calls=%d, want %d", adapter.searchCalls, searchCalls)
	}
}

func TestRemoteSearchRejectsAlreadyExpiredContinuationSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 1, 15, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	firstEntry, firstRecord := remoteSearchFixture(binding, "mem-1", now, "needle", store.MemoryTrustReviewed)
	secondEntry, secondRecord := remoteSearchFixture(binding, "mem-2", now.Add(-time.Second), "needle", store.MemoryTrustReviewed)
	service, adapter, activeBinding, _ := remoteSearchService(t,
		[]store.RemoteMemoryCatalogEntry{firstEntry, secondEntry}, []protocol.MemoryRecord{firstRecord, secondRecord})
	service.Now = func() time.Time { return now }
	adapter.snapshotExpiresAt = now
	_, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1,
	}, SearchContext{RemoteAuthorized: true})
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Status != http.StatusServiceUnavailable ||
		structured.Reason != ReasonBackendUnavailable {
		t.Fatalf("Search() error = %#v, want expired-snapshot backend failure", err)
	}
}

func TestRemoteSearchAcceptsExpiredTerminalSnapshotWithoutCursor(t *testing.T) {
	now := time.Date(2026, 8, 1, 15, 30, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entry, record := remoteSearchFixture(binding, "mem-1", now, "needle", store.MemoryTrustReviewed)
	service, adapter, activeBinding, _ := remoteSearchService(t, []store.RemoteMemoryCatalogEntry{entry}, []protocol.MemoryRecord{record})
	service.Now = func() time.Time { return now }
	adapter.snapshotExpiresAt = now.Add(-time.Minute)
	response, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || response == nil || !response.Exhausted || response.Cursor != "" || len(response.Items) != 1 {
		t.Fatalf("Search() = %#v, %v; want complete terminal page without cursor", response, err)
	}
}

func TestRemoteSearchRejectsResolvedModeChangeAcrossPages(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	firstEntry, firstRecord := remoteSearchFixture(binding, "mem-1", now, "needle", store.MemoryTrustReviewed)
	secondEntry, secondRecord := remoteSearchFixture(binding, "mem-2", now.Add(-time.Second), "needle", store.MemoryTrustReviewed)
	service, adapter, activeBinding, _ := remoteSearchService(t,
		[]store.RemoteMemoryCatalogEntry{firstEntry, secondEntry}, []protocol.MemoryRecord{firstRecord, secondRecord})
	adapter.actualModes = []string{protocol.SearchModeKeyword, protocol.SearchModeSemantic}

	first, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Mode: protocol.SearchModeAuto, Limit: 1,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || first.Cursor == "" || first.ActualMode != protocol.SearchModeKeyword {
		t.Fatalf("first Search() = %#v, err=%v", first, err)
	}
	_, err = service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Mode: protocol.SearchModeAuto, Limit: 1, Cursor: first.Cursor,
	}, SearchContext{RemoteAuthorized: true})
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Status != http.StatusServiceUnavailable || structured.Reason != ReasonBackendUnavailable {
		t.Fatalf("second Search() error = %#v, want changed-mode rejection", err)
	}
	if adapter.searchCalls != 2 {
		t.Fatalf("search calls = %d, want 2", adapter.searchCalls)
	}
}

func TestKeywordRecordMatchesContentAndLocalCatalogMetadata(t *testing.T) {
	record := &protocol.MemoryRecord{
		Content: "durable guidance", Tags: []string{"provider-only"},
		Metadata: map[string]string{"providerOwner": "Mallory"},
	}
	entry := &store.RemoteMemoryCatalogEntry{
		ID: "mem-1", SessionName: "session-a", Source: "api", Tags: []string{"storage"},
	}
	for _, query := range []string{"guidance", "storage", "session-a", "api"} {
		if !keywordRecordMatches(record, entry, query) {
			t.Fatalf("keywordRecordMatches(%q) = false", query)
		}
	}
	for _, query := range []string{"provider-only", "providerowner", "mallory", "missing"} {
		if keywordRecordMatches(record, entry, query) {
			t.Fatalf("keywordRecordMatches(%q) trusted provider-owned metadata", query)
		}
	}
}

type failingLegacyMemoryStore struct {
	store.MemoryStore
	err error
}

func (s failingLegacyMemoryStore) SetMemoryDisabled(context.Context, string, string, bool) error {
	return s.err
}

func (s failingLegacyMemoryStore) SetLegacyMemoryDisabledWithAudit(
	context.Context,
	string, string, string,
	bool,
	string, string, string,
	time.Time,
) error {
	return s.err
}

func TestLegacyDisableErrorsUseMemoryServiceMapping(t *testing.T) {
	authority := &ResolvedAuthority{Namespace: "team-a", NamespaceUID: "namespace-a"}
	service := &Service{
		Legacy: failingLegacyMemoryStore{err: store.ErrNotFound}, Governed: newGovernedSearchStore(nil),
		Resolver: staticAuthorityResolver{authority: authority},
	}
	err := service.SetMemoryDisabled(context.Background(), "team-a", "missing", true, "actor", "request")
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Status != http.StatusNotFound {
		t.Fatalf("SetMemoryDisabled() error = %#v, want mapped 404", err)
	}
}

type failingLegacyAuditReadStore struct {
	store.GovernedMemoryStore
	err error
}

func (s failingLegacyAuditReadStore) ListMemoryAudit(context.Context, store.MemoryAuditFilter) ([]store.MemoryAuditRecord, error) {
	return nil, s.err
}

func TestLegacyUpdateDoesNotCommitBeforeGovernanceOverlayLoads(t *testing.T) {
	storeImpl := newMemoryTestStore(t)
	authority := &ResolvedAuthority{Namespace: "team-a", NamespaceUID: "namespace-a"}
	service := &Service{
		Legacy: storeImpl, Governed: failingLegacyAuditReadStore{err: errors.New("audit unavailable")},
		Resolver: staticAuthorityResolver{authority: authority},
	}
	created, err := service.CreateMemory(context.Background(), authority.Namespace, CreateRequest{
		Content: "legacy guidance", Tags: []string{"original"},
	}, MutationContext{})
	if err != nil {
		t.Fatal(err)
	}
	tags := []string{"changed"}
	if _, err := service.UpdateMemory(context.Background(), authority.Namespace, created.Memory.ID, UpdateRequest{Tags: &tags}, MutationContext{}); err == nil {
		t.Fatal("UpdateMemory() succeeded with unavailable governance overlay")
	}
	unchanged, err := storeImpl.GetMemory(context.Background(), authority.Namespace, created.Memory.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(unchanged.Tags, []string{"original"}) {
		t.Fatalf("memory changed before governance overlay loaded: %#v", unchanged)
	}
}

func TestLegacyProposalApplyDoesNotReadGovernanceAfterCommit(t *testing.T) {
	storeImpl := newMemoryTestStore(t)
	authority := &ResolvedAuthority{Namespace: "team-a", NamespaceUID: "namespace-a"}
	service := &Service{
		Legacy: storeImpl, Proposals: storeImpl,
		Governed: failingLegacyAuditReadStore{err: errors.New("audit unavailable")},
		Resolver: staticAuthorityResolver{authority: authority},
	}
	proposal := &store.MemoryProposal{
		Namespace: authority.Namespace, Type: "memory", Title: "reviewed guidance",
		Content: "Keep durable memory governance explicit.",
	}
	if err := storeImpl.CreateMemoryProposal(context.Background(), proposal); err != nil {
		t.Fatal(err)
	}
	if err := storeImpl.ReviewMemoryProposal(context.Background(), store.MemoryProposalReview{
		Namespace: authority.Namespace, ID: proposal.ID, Status: "accepted", Reviewer: "alice",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := service.ApplyMemoryProposal(context.Background(), authority.Namespace, proposal.ID, "alice", MutationContext{})
	if err != nil {
		t.Fatalf("ApplyMemoryProposal() error = %v", err)
	}
	if result.Memory == nil || result.Memory.Trust != store.MemoryTrustReviewed || result.Memory.GovernanceRevision != 1 {
		t.Fatalf("applied proposal memory = %#v", result.Memory)
	}
	persisted, err := storeImpl.GetMemoryProposal(context.Background(), authority.Namespace, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Status != "applied" || persisted.AppliedMemoryID != result.Memory.ID {
		t.Fatalf("persisted proposal = %#v", persisted)
	}
}

func TestRemoteSearchRedactsQueryAndRequiresDurableAuditBeforeEgress(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entry, record := remoteSearchFixture(binding, "mem-1", now, "token is [REDACTED]", store.MemoryTrustReviewed)
	service, adapter, activeBinding, governed := remoteSearchService(t, []store.RemoteMemoryCatalogEntry{entry}, []protocol.MemoryRecord{record})
	governed.auditErr = errors.New("audit unavailable")
	_, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "token is supersecret", Limit: 1,
	}, SearchContext{RemoteAuthorized: true})
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Status != http.StatusServiceUnavailable || adapter.searchCalls != 0 {
		t.Fatalf("Search() error=%#v calls=%d, want audit failure before egress", err, adapter.searchCalls)
	}

	governed.auditErr = nil
	response, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "token is supersecret", Limit: 1,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || len(response.Items) != 1 {
		t.Fatalf("Search() response=%#v err=%v", response, err)
	}
	if len(adapter.queries) != 1 || adapter.queries[0] != "token is [REDACTED]" ||
		strings.Contains(adapter.queries[0], "supersecret") {
		t.Fatalf("provider queries = %#v, want redacted query", adapter.queries)
	}
	if len(governed.audits) != 1 || governed.audits[0].RequestDigest == "" {
		t.Fatalf("audits = %#v, want one digest-only audit", governed.audits)
	}
}

func TestRemoteSearchRejectsAdvertisedInputLimitsBeforeAuditAndEgress(t *testing.T) {
	t.Run("query bytes", func(t *testing.T) {
		service, adapter, activeBinding, governed := remoteSearchService(t, nil, nil)
		service.Resolver.(staticAuthorityResolver).authority.Backend.Status.ObservedCapabilities.Limits.MaxQueryBytes = 8
		query := "ééééa"
		if got := len([]byte(query)); got != 9 {
			t.Fatalf("query bytes = %d, want 9", got)
		}

		_, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
			Query: query, Limit: 1,
		}, SearchContext{RemoteAuthorized: true})
		assertRemoteSearchAdmissionTooLarge(t, err, adapter, governed)
	})

	t.Run("request envelope bytes", func(t *testing.T) {
		service, adapter, activeBinding, governed := remoteSearchService(t, nil, nil)
		binding, err := protocolBinding(&activeBinding)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(protocol.SearchRequest{
			ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword,
			Query: "q", PageSize: 1, PageToken: "",
		})
		if err != nil {
			t.Fatal(err)
		}
		limits := &service.Resolver.(staticAuthorityResolver).authority.Backend.Status.ObservedCapabilities.Limits
		limits.MaxQueryBytes = protocol.MaxQueryBytes
		limits.MaxRequestBytes = int64(len(payload) - 1)

		_, err = service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
			Query: "q", Limit: 1,
		}, SearchContext{RemoteAuthorized: true})
		assertRemoteSearchAdmissionTooLarge(t, err, adapter, governed)
	})
}

func assertRemoteSearchAdmissionTooLarge(
	t *testing.T,
	err error,
	adapter *pagedSearchAdapter,
	governed *governedSearchStore,
) {
	t.Helper()
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Status != http.StatusRequestEntityTooLarge ||
		structured.Reason != "" {
		t.Fatalf("Search() error = %#v, want client request-too-large classification", err)
	}
	if adapter.searchCalls != 0 || len(governed.audits) != 0 {
		t.Fatalf("rejected search side effects: provider calls=%d audits=%d, want zero", adapter.searchCalls, len(governed.audits))
	}
}

func TestRemoteSearchNormalPageBoundaryIsCompleteAndBudgetExhaustionReturnsCursor(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entries := make([]store.RemoteMemoryCatalogEntry, 0, maxRemoteSearchPages+2)
	records := make([]protocol.MemoryRecord, 0, maxRemoteSearchPages+2)
	for i := range maxRemoteSearchPages + 2 {
		entry, record := remoteSearchFixture(binding, fmt.Sprintf("mem-%02d", i), now.Add(-time.Duration(i)*time.Second), "needle", store.MemoryTrustUntrusted)
		entries = append(entries, entry)
		records = append(records, record)
	}
	service, adapter, activeBinding, _ := remoteSearchService(t, entries, records)
	_, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1,
	}, SearchContext{RemoteAuthorized: true})
	var incomplete *IncompleteSearchError
	if !errors.As(err, &incomplete) || incomplete.Cursor == "" {
		t.Fatalf("Search() error = %#v, want strict incomplete error with cursor", err)
	}
	if adapter.searchCalls != maxRemoteSearchPages {
		t.Fatalf("search calls = %d, want bounded %d", adapter.searchCalls, maxRemoteSearchPages)
	}
}

type cappedLegacyMemoryStore struct {
	store.MemoryStore
	memories []store.Memory
}

func (s cappedLegacyMemoryStore) GetMemory(_ context.Context, namespace, id string) (*store.Memory, error) {
	for _, memory := range s.memories {
		if memory.Namespace == namespace && memory.ID == id {
			copy := memory
			return &copy, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s cappedLegacyMemoryStore) ListMemories(_ context.Context, filter store.MemoryFilter) ([]store.Memory, error) {
	limit := filter.Limit
	if limit <= 0 || limit > len(s.memories) {
		limit = len(s.memories)
	}
	result := make([]store.Memory, 0, limit)
	for _, memory := range s.memories {
		if filter.BeforeUpdatedAt != nil && (memory.UpdatedAt.After(*filter.BeforeUpdatedAt) ||
			memory.UpdatedAt.Equal(*filter.BeforeUpdatedAt) && memory.ID >= filter.BeforeID) {
			continue
		}
		result = append(result, memory)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func TestLegacySearchReportsPreFilterCapAsIncomplete(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	memories := make([]store.Memory, maxRemoteCatalogLimit+1)
	for i := range memories {
		trust := store.MemoryTrustUntrusted
		if i == maxRemoteCatalogLimit {
			trust = store.MemoryTrustReviewed
		}
		memories[i] = store.Memory{
			ID: fmt.Sprintf("mem-%03d", maxRemoteCatalogLimit-i), Namespace: "team-a", Content: "needle", Trust: trust,
			UpdatedAt: now.Add(-time.Duration(i) * time.Second),
		}
	}
	service := &Service{Legacy: cappedLegacyMemoryStore{memories: memories}}
	request := SearchRequest{Query: "needle", Limit: 1, Trust: []store.MemoryTrust{store.MemoryTrustReviewed}}
	_, err := service.Search(context.Background(), "team-a", request, SearchContext{})
	var incomplete *IncompleteSearchError
	if !errors.As(err, &incomplete) || incomplete.Cursor == "" {
		t.Fatalf("Search() error = %#v, want explicit incomplete result with cursor", err)
	}
	request.Cursor = incomplete.Cursor
	continued, err := service.Search(context.Background(), "team-a", request, SearchContext{})
	if err != nil || len(continued.Items) != 1 || continued.Items[0].Memory.Trust != store.MemoryTrustReviewed ||
		!continued.Exhausted || !continued.Complete {
		t.Fatalf("continued response=%#v err=%v", continued, err)
	}
	request.Cursor = ""
	request.AllowIncomplete = true
	response, err := service.Search(context.Background(), "team-a", request, SearchContext{})
	if err != nil || response.Complete || response.Exhausted || len(response.Items) != 0 || response.Cursor == "" {
		t.Fatalf("allow-incomplete response=%#v err=%v", response, err)
	}
}

func TestLegacySearchStrictContinuationPreservesPartialMatches(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	memories := make([]store.Memory, maxRemoteCatalogLimit+1)
	for i := range memories {
		trust := store.MemoryTrustUntrusted
		if i == 0 || i == maxRemoteCatalogLimit {
			trust = store.MemoryTrustReviewed
		}
		memories[i] = store.Memory{
			ID: fmt.Sprintf("mem-partial-%03d", maxRemoteCatalogLimit-i), Namespace: "team-a",
			Content: "needle", Trust: trust, UpdatedAt: now.Add(-time.Duration(i) * time.Second),
		}
	}
	service := &Service{Legacy: cappedLegacyMemoryStore{memories: memories}}
	request := SearchRequest{Query: "needle", Limit: 2, Trust: []store.MemoryTrust{store.MemoryTrustReviewed}}
	_, err := service.Search(t.Context(), "team-a", request, SearchContext{})
	var incomplete *IncompleteSearchError
	if !errors.As(err, &incomplete) || incomplete.Cursor == "" {
		t.Fatalf("first Search() error = %#v, want partial-match continuation", err)
	}
	request.Cursor = incomplete.Cursor
	continued, err := service.Search(t.Context(), "team-a", request, SearchContext{})
	if err != nil || len(continued.Items) != 2 || !continued.Complete || !continued.Exhausted {
		t.Fatalf("continued response=%#v err=%v", continued, err)
	}
	want := []string{memories[0].ID, memories[len(memories)-1].ID}
	got := []string{continued.Items[0].Memory.ID, continued.Items[1].Memory.ID}
	if !slices.Equal(got, want) {
		t.Fatalf("continued ids = %v, want %v", got, want)
	}
}

type generationWatermarkAdmissionStore struct {
	store.GovernedMemoryStore
	watermark int64
	admission *store.RemoteMemoryCreateAdmission
}

func (s *generationWatermarkAdmissionStore) GetMemoryIdempotency(
	context.Context, string, string, string, string,
) (*store.MemoryIdempotencyRecord, error) {
	return nil, store.ErrNotFound
}

func (s *generationWatermarkAdmissionStore) GetRemoteMemoryGenerationWatermark(
	context.Context, string, string, string, int64, string,
) (int64, error) {
	return s.watermark, nil
}

func (s *generationWatermarkAdmissionStore) AdmitRemoteMemoryCreate(
	_ context.Context,
	admission store.RemoteMemoryCreateAdmission,
) (*store.MemoryMutationAdmissionResult, error) {
	copy := admission
	s.admission = &copy
	envelope, err := protocol.DecodeMutationEnvelope(admission.Mutation.Payload)
	if err != nil {
		return nil, err
	}
	return &store.MemoryMutationAdmissionResult{
		Memory: admission.Memory,
		Operation: store.MemoryOperation{
			ID: admission.Mutation.OperationID, Namespace: admission.Mutation.Namespace,
			NamespaceUID: admission.Mutation.NamespaceUID, BackendUID: admission.Mutation.BackendUID,
			AuthorityEpoch: admission.Mutation.AuthorityEpoch, RoutingEpoch: admission.Mutation.RoutingEpoch,
			MemoryID: admission.Mutation.MemoryID, Kind: store.MemoryOperationCreate,
			DesiredGeneration: int64(envelope.Generation), ExpectedMaterializedGeneration: int64(envelope.ExpectedGeneration),
			State: store.MemoryOperationQueued,
		},
		Idempotency: store.MemoryIdempotencyRecord{
			OriginalStatus: admission.Mutation.OriginalStatus, Location: admission.Mutation.Location,
			RetryAfterSeconds: admission.Mutation.RetryAfterSeconds,
		},
	}, nil
}

type replayBeforeFreshStore struct {
	store.GovernedMemoryStore
	record    store.MemoryIdempotencyRecord
	operation store.MemoryOperation
}

func (s *replayBeforeFreshStore) GetMemoryIdempotency(context.Context, string, string, string, string) (*store.MemoryIdempotencyRecord, error) {
	copy := s.record
	return &copy, nil
}

func (s *replayBeforeFreshStore) GetMemoryOperation(context.Context, string, string) (*store.MemoryOperation, error) {
	copy := s.operation
	return &copy, nil
}

type replayBeforeFreshResolver struct {
	local      *ResolvedAuthority
	freshCalls int
}

func (r *replayBeforeFreshResolver) ResolveLocal(context.Context, string) (*ResolvedAuthority, error) {
	return r.local, nil
}

func (r *replayBeforeFreshResolver) Resolve(context.Context, string) (*ResolvedAuthority, error) {
	r.freshCalls++
	return nil, errors.New("fresh backend unavailable")
}

func TestRemoteCreateUsesRetainedGenerationWatermark(t *testing.T) {
	const watermark int64 = 2
	binding := &store.MemoryBackendBinding{
		Namespace: "team-a", NamespaceUID: "11111111-1111-4111-8111-111111111111", Mode: store.MemoryBackendModeRemote,
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222", AuthorityEpoch: 1, RoutingEpoch: 3,
		TenantID: protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"), StoreUUID: "44444444-4444-4444-8444-444444444444",
		State: store.MemoryBackendBindingAccepting,
	}
	backend := &corev1alpha1.MemoryBackend{}
	backend.Status.EffectiveLifecycleState = corev1alpha1.MemoryBackendEffectiveLifecycleActive
	backend.Status.Ready = true
	authority := &ResolvedAuthority{
		Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID, Binding: binding, Backend: backend,
	}
	governed := &generationWatermarkAdmissionStore{watermark: watermark}
	service := &Service{Governed: governed, Resolver: staticAuthorityResolver{authority: authority}}
	result, err := service.CreateMemory(context.Background(), binding.Namespace, CreateRequest{
		ID: "mem-recreated", Content: "recreated content",
	}, MutationContext{
		Actor: "alice", Principal: "alice", Route: testRemoteCreateRoute, IdempotencyKey: "recreate-key",
	})
	if err != nil || result == nil || result.Operation == nil {
		t.Fatalf("CreateMemory() = %#v, %v", result, err)
	}
	if governed.admission == nil {
		t.Fatal("CreateMemory() did not reach durable admission")
	}
	envelope, err := protocol.DecodeMutationEnvelope(governed.admission.Mutation.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Generation != uint64(watermark+1) || envelope.ExpectedGeneration != uint64(watermark) ||
		governed.admission.Memory.Generation != watermark || governed.admission.Memory.DesiredGeneration != watermark+1 ||
		result.Operation.DesiredGeneration != watermark+1 {
		t.Fatalf("recreate generations = envelope %+v admission %+v operation %+v",
			envelope, governed.admission.Memory, result.Operation)
	}
}

func TestMutationIdempotencyReplayPrecedesFreshBackendResolution(t *testing.T) {
	request := CreateRequest{Content: "remember this"}
	binding := &store.MemoryBackendBinding{
		Namespace: "team-a", NamespaceUID: "namespace-a", Mode: store.MemoryBackendModeRemote,
		BackendUID: "backend-a", AuthorityEpoch: 1, RoutingEpoch: 1,
	}
	resolver := &replayBeforeFreshResolver{local: &ResolvedAuthority{
		Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID, Binding: binding,
	}}
	governed := &replayBeforeFreshStore{
		record: store.MemoryIdempotencyRecord{
			NamespaceUID: binding.NamespaceUID, Principal: "alice", Route: "createMemory", CallerKey: "key-1",
			RequestDigest: digestJSON(request), OriginalStatus: http.StatusAccepted,
			AuthorityEpoch: binding.AuthorityEpoch, RoutingEpoch: binding.RoutingEpoch,
			ResponseType: store.MemoryIdempotencyOperation, OperationID: "mop-1",
			Location: "/api/v1/memory-operations/mop-1", RetryAfterSeconds: 2,
		},
		operation: store.MemoryOperation{ID: "mop-1", NamespaceUID: binding.NamespaceUID, State: store.MemoryOperationAmbiguous},
	}
	service := &Service{Governed: governed, Resolver: resolver}
	result, err := service.CreateMemory(context.Background(), binding.Namespace, request, MutationContext{
		Actor: "alice", Principal: "alice", Route: "createMemory", IdempotencyKey: "key-1",
	})
	if err != nil || result.Operation == nil || result.Operation.ID != "mop-1" || !result.Replayed {
		t.Fatalf("CreateMemory() result=%#v err=%v", result, err)
	}
	if resolver.freshCalls != 0 {
		t.Fatalf("fresh resolver calls = %d, want replay before fresh resolution", resolver.freshCalls)
	}
}

func TestSuccessfulMemoryIdempotencyReplayUsesImmutableBodyWithoutProvider(t *testing.T) {
	request := CreateRequest{Content: "original content"}
	binding := &store.MemoryBackendBinding{
		Namespace: "team-a", NamespaceUID: "namespace-a", Mode: store.MemoryBackendModeRemote,
		BackendUID: "backend-a", AuthorityEpoch: 1, RoutingEpoch: 1,
	}
	entry := store.RemoteMemoryCatalogEntry{
		ID: "mem-1", Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID,
		BackendUID: binding.BackendUID, AuthorityEpoch: binding.AuthorityEpoch, RoutingEpoch: binding.RoutingEpoch,
		Generation: 1, DesiredGeneration: 1, GovernanceRevision: 1,
		MaterializationState: store.MemoryMaterializationActive, Trust: store.MemoryTrustReviewed,
		ContentDigest: protocol.ContentDigest(request.Content), ContentAvailable: true,
	}
	operation := store.MemoryOperation{
		ID: "mop-1", Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID,
		BackendUID: binding.BackendUID, AuthorityEpoch: binding.AuthorityEpoch, RoutingEpoch: binding.RoutingEpoch,
		MemoryID: entry.ID, Kind: store.MemoryOperationCreate, DesiredGeneration: 1,
		State: store.MemoryOperationSucceeded,
	}
	snapshot, err := json.Marshal(struct {
		Memory    store.RemoteMemoryCatalogEntry `json:"memory"`
		Operation store.MemoryOperation          `json:"operation"`
		Content   []byte                         `json:"content"`
	}{Memory: entry, Operation: operation, Content: []byte(request.Content)})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &replayBeforeFreshResolver{local: &ResolvedAuthority{
		Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID, Binding: binding,
	}}
	governed := &replayBeforeFreshStore{record: store.MemoryIdempotencyRecord{
		NamespaceUID: binding.NamespaceUID, Principal: "alice", Route: "createMemory", CallerKey: "key-1",
		RequestDigest: digestJSON(request), OriginalStatus: http.StatusCreated,
		AuthorityEpoch: binding.AuthorityEpoch, RoutingEpoch: binding.RoutingEpoch,
		ResponseType: store.MemoryIdempotencyMemory, MemoryID: entry.ID, OperationID: operation.ID,
		ResponseSnapshot: snapshot,
	}}
	service := &Service{Governed: governed, Resolver: resolver}
	result, err := service.CreateMemory(context.Background(), binding.Namespace, request, MutationContext{
		Actor: "alice", Principal: "alice", Route: "createMemory", IdempotencyKey: "key-1",
	})
	if err != nil || result.Memory == nil || result.Memory.Content != request.Content || !result.Replayed {
		t.Fatalf("CreateMemory() result=%#v err=%v", result, err)
	}
	if resolver.freshCalls != 0 {
		t.Fatalf("fresh resolver calls = %d, want immutable replay without provider", resolver.freshCalls)
	}
}

func TestRemoteListIncludeDeletedSkipsLiveDisabledBeforeLimitAcrossPages(t *testing.T) {
	now := time.Date(2026, 8, 1, 17, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entries := make([]store.RemoteMemoryCatalogEntry, 0, maxRemoteCatalogLimit+1)
	for i := range maxRemoteCatalogLimit {
		entry, _ := remoteSearchFixture(
			binding, fmt.Sprintf("mem-disabled-%03d", i), now.Add(-time.Duration(i)*time.Second),
			"disabled live content", store.MemoryTrustReviewed,
		)
		entry.Disabled = true
		entries = append(entries, entry)
	}
	tombstone, _ := remoteSearchFixture(
		binding, "mem-deleted", now.Add(-time.Duration(maxRemoteCatalogLimit)*time.Second),
		"deleted content", store.MemoryTrustReviewed,
	)
	tombstone.Disabled = true
	tombstone.Deleted = true
	tombstone.MaterializationState = store.MemoryMaterializationDeleted
	tombstone.ContentAvailable = false
	entries = append(entries, tombstone)

	service, adapter, activeBinding, governed := remoteSearchService(t, entries, nil)
	page, err := service.ListMemoriesPageWithSearchContext(context.Background(), store.MemoryFilter{
		Namespace: activeBinding.Namespace, IncludeDeleted: true, Limit: 1,
	}, SearchContext{})
	if err != nil || page == nil || len(page.Items) != 1 || page.Items[0].ID != tombstone.ID ||
		!page.Items[0].Deleted || !page.Items[0].Disabled || page.Items[0].ContentAvailable ||
		!page.Complete || !page.Exhausted || page.Cursor != "" {
		t.Fatalf("includeDeleted page = %#v, %v; want only completed tombstone", page, err)
	}
	if governed.listCalls < 2 {
		t.Fatalf("catalog list calls = %d, want pagination past disabled live records", governed.listCalls)
	}
	if adapter.getCalls != 0 {
		t.Fatalf("provider Get calls = %d, want no hydration for filtered live disabled records or tombstone", adapter.getCalls)
	}
}

func TestRemoteListIncludeDeletedIncludesDisabledTombstone(t *testing.T) {
	now := time.Date(2026, 8, 1, 5, 20, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entry, record := remoteSearchFixture(binding, "mem-deleted", now, "deleted content", store.MemoryTrustReviewed)
	entry.Disabled = true
	entry.Deleted = true
	entry.MaterializationState = store.MemoryMaterializationDeleted
	entry.ContentAvailable = false
	service, _, activeBinding, _ := remoteSearchService(t, []store.RemoteMemoryCatalogEntry{entry}, []protocol.MemoryRecord{record})

	memories, err := service.ListMemories(context.Background(), store.MemoryFilter{
		Namespace: activeBinding.Namespace, IncludeDeleted: true,
	})
	if err != nil || len(memories) != 1 || memories[0].ID != entry.ID || !memories[0].Deleted {
		t.Fatalf("ListMemories(includeDeleted) = %#v, err=%v; want tombstone %q", memories, err, entry.ID)
	}
}

func TestRemoteSearchIncludeDeletedMergesCompletedTombstonesWithoutHydration(t *testing.T) {
	const liveMemoryID = "mem-live"
	now := time.Date(2026, 8, 1, 8, 45, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	liveEntry, liveRecord := remoteSearchFixture(binding, liveMemoryID, now, "needle live", store.MemoryTrustReviewed)
	disabledEntry, disabledRecord := remoteSearchFixture(binding, "mem-disabled", now.Add(-time.Second), "needle disabled", store.MemoryTrustReviewed)
	disabledEntry.Disabled = true
	deletedEntry, deletedRecord := remoteSearchFixture(binding, "mem-deleted", now.Add(-2*time.Second), "stale provider content", store.MemoryTrustReviewed)
	deletedEntry.Disabled = true
	deletedEntry.Deleted = true
	deletedEntry.MaterializationState = store.MemoryMaterializationDeleted
	deletedEntry.ContentAvailable = false
	deletedEntry.Tags = []string{"needle"}
	foreignEntry, foreignRecord := remoteSearchFixture(binding, "mem-foreign-deleted", now.Add(time.Second), "stale foreign content", store.MemoryTrustReviewed)
	foreignEntry.Disabled = true
	foreignEntry.Deleted = true
	foreignEntry.MaterializationState = store.MemoryMaterializationDeleted
	foreignEntry.ContentAvailable = false
	foreignEntry.Tags = []string{"needle"}

	for _, test := range []struct {
		name            string
		includeDisabled bool
		wantIDs         []string
	}{
		{name: "deleted does not imply disabled live", wantIDs: []string{liveMemoryID, "mem-deleted"}},
		{name: "disabled live remains independently selectable", includeDisabled: true, wantIDs: []string{liveMemoryID, "mem-disabled", "mem-deleted"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, adapter, activeBinding, governed := remoteSearchService(t,
				[]store.RemoteMemoryCatalogEntry{foreignEntry, liveEntry, disabledEntry, deletedEntry},
				[]protocol.MemoryRecord{foreignRecord, deletedRecord, liveRecord, disabledRecord})
			governed.entries[0].ClusterID = "foreign-cluster"
			governed.byID[foreignEntry.ID] = governed.entries[0]

			response, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
				Query: "needle", Limit: 4, IncludeDeleted: true, IncludeDisabled: test.includeDisabled,
			}, SearchContext{RemoteAuthorized: true})
			if err != nil || response == nil || !response.Complete || !response.Exhausted || response.Cursor != "" {
				t.Fatalf("Search() = %#v, err=%v", response, err)
			}
			gotIDs := make([]string, 0, len(response.Items))
			seen := make(map[string]struct{}, len(response.Items))
			for _, item := range response.Items {
				if _, duplicate := seen[item.Memory.ID]; duplicate {
					t.Fatalf("Search() returned duplicate %q: %#v", item.Memory.ID, response.Items)
				}
				seen[item.Memory.ID] = struct{}{}
				gotIDs = append(gotIDs, item.Memory.ID)
			}
			if !slices.Equal(gotIDs, test.wantIDs) {
				t.Fatalf("Search() ids = %#v, want %#v", gotIDs, test.wantIDs)
			}
			deleted := response.Items[len(response.Items)-1].Memory
			if !deleted.Deleted || !deleted.Disabled || deleted.Content != "" || deleted.ContentAvailable {
				t.Fatalf("completed tombstone = %#v", deleted)
			}
			if adapter.searchCalls != 1 || adapter.getCalls != 0 {
				t.Fatalf("provider calls search=%d get=%d, want 1/0", adapter.searchCalls, adapter.getCalls)
			}
		})
	}
}

func TestRemoteQueriedListIncludeDeletedReturnsCompletedTombstone(t *testing.T) {
	now := time.Date(2026, 8, 1, 8, 50, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entry, _ := remoteSearchFixture(binding, "mem-deleted", now, "unavailable content", store.MemoryTrustReviewed)
	entry.Disabled = true
	entry.Deleted = true
	entry.MaterializationState = store.MemoryMaterializationDeleted
	entry.ContentAvailable = false
	entry.Tags = []string{"needle"}
	service, adapter, activeBinding, _ := remoteSearchService(t, []store.RemoteMemoryCatalogEntry{entry}, nil)

	page, err := service.ListMemoriesPageWithSearchContext(context.Background(), store.MemoryFilter{
		Namespace: activeBinding.Namespace, Query: "needle", IncludeDeleted: true, Limit: 1,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || page == nil || len(page.Items) != 1 || page.Items[0].ID != entry.ID ||
		!page.Items[0].Deleted || !page.Exhausted || !page.Complete || !page.Paginated {
		t.Fatalf("queried ListMemories() = %#v, err=%v", page, err)
	}
	if adapter.searchCalls != 1 || adapter.getCalls != 0 {
		t.Fatalf("provider calls search=%d get=%d, want 1/0", adapter.searchCalls, adapter.getCalls)
	}
}

func TestRemoteSearchIncludeDeletedContinuationKeepsStableTombstoneOrder(t *testing.T) {
	now := time.Date(2026, 8, 1, 8, 55, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	liveEntry, liveRecord := remoteSearchFixture(binding, "mem-live", now.Add(time.Second), "needle live", store.MemoryTrustReviewed)
	tombstoneB, _ := remoteSearchFixture(binding, "mem-tomb-b", now, "unavailable", store.MemoryTrustReviewed)
	tombstoneA, _ := remoteSearchFixture(binding, "mem-tomb-a", now, "unavailable", store.MemoryTrustReviewed)
	for _, entry := range []*store.RemoteMemoryCatalogEntry{&tombstoneB, &tombstoneA} {
		entry.Disabled = true
		entry.Deleted = true
		entry.MaterializationState = store.MemoryMaterializationDeleted
		entry.ContentAvailable = false
		entry.Tags = []string{"needle"}
	}
	service, adapter, activeBinding, governed := remoteSearchService(t,
		[]store.RemoteMemoryCatalogEntry{liveEntry, tombstoneB, tombstoneA}, []protocol.MemoryRecord{liveRecord})

	cursor := ""
	wantIDs := []string{"mem-live", "mem-tomb-b", "mem-tomb-a"}
	pageCursors := make([]string, 0, len(wantIDs)-1)
	for i, wantID := range wantIDs {
		response, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
			Query: "needle", Limit: 1, Cursor: cursor, IncludeDeleted: true,
		}, SearchContext{RemoteAuthorized: true})
		if err != nil || response == nil || len(response.Items) != 1 || response.Items[0].Memory.ID != wantID || !response.Complete {
			t.Fatalf("page %d Search() = %#v, err=%v; want %q", i+1, response, err, wantID)
		}
		if i < len(wantIDs)-1 {
			if response.Exhausted || response.Cursor == "" {
				t.Fatalf("page %d continuation = %#v", i+1, response)
			}
			stored := governed.cursors[response.Cursor]
			if len(stored.State) == 0 || len(stored.State) > maxRemoteSearchCursorBytes {
				t.Fatalf("page %d cursor state bytes = %d", i+1, len(stored.State))
			}
			pageCursors = append(pageCursors, response.Cursor)
		} else if !response.Exhausted || response.Cursor != "" {
			t.Fatalf("final continuation = %#v", response)
		}
		cursor = response.Cursor
	}
	replayed, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1, Cursor: pageCursors[0], IncludeDeleted: true,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || replayed == nil || len(replayed.Items) != 1 || replayed.Items[0].Memory.ID != wantIDs[1] ||
		replayed.Cursor != pageCursors[1] {
		t.Fatalf("replayed successor = %#v, err=%v; want cursor %q", replayed, err, pageCursors[1])
	}
	if adapter.searchCalls != 1 || adapter.getCalls != 0 {
		t.Fatalf("provider calls search=%d get=%d, want 1/0", adapter.searchCalls, adapter.getCalls)
	}
}

func TestRemoteSearchIncludeDeletedPreservesCompletenessAcrossCatalogBudget(t *testing.T) {
	now := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	binding := store.MemoryBackendBinding{
		Namespace: "team-remote", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		ClusterID: "cluster-a", BackendUID: "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 1,
		TenantID:  protocol.DeriveTenantID("cluster-a", "11111111-1111-4111-8111-111111111111"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	entries := make([]store.RemoteMemoryCatalogEntry, 0, maxRemoteSearchCandidates+1)
	for i := 0; i <= maxRemoteSearchCandidates; i++ {
		entry, _ := remoteSearchFixture(binding, fmt.Sprintf("mem-%04d", i), now.Add(-time.Duration(i)*time.Second), "unavailable", store.MemoryTrustReviewed)
		entry.Disabled = true
		entry.Deleted = true
		entry.MaterializationState = store.MemoryMaterializationDeleted
		entry.ContentAvailable = false
		entry.Tags = []string{"other"}
		if i == maxRemoteSearchCandidates {
			entry.Tags = []string{"needle"}
		}
		entries = append(entries, entry)
	}
	service, adapter, activeBinding, governed := remoteSearchService(t, entries, nil)
	service.Now = func() time.Time { return now }

	_, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1, IncludeDeleted: true,
	}, SearchContext{RemoteAuthorized: true})
	var incomplete *IncompleteSearchError
	if !errors.As(err, &incomplete) || incomplete.Cursor == "" {
		t.Fatalf("first Search() error = %#v, want incomplete cursor", err)
	}
	stored := governed.cursors[incomplete.Cursor]
	if len(stored.State) == 0 || len(stored.State) > maxRemoteSearchCursorBytes ||
		!stored.ExpiresAt.Equal(now.Add(remoteSearchCursorTTL)) {
		t.Fatalf("stored continuation = %#v", stored)
	}
	response, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1, Cursor: incomplete.Cursor, IncludeDeleted: true,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || response == nil || len(response.Items) != 1 ||
		response.Items[0].Memory.ID != entries[len(entries)-1].ID || !response.Exhausted || !response.Complete {
		t.Fatalf("continued Search() = %#v, err=%v", response, err)
	}
	if adapter.searchCalls != 1 || adapter.getCalls != 0 {
		t.Fatalf("provider calls search=%d get=%d, want 1/0", adapter.searchCalls, adapter.getCalls)
	}
}

func TestLegacySearchSatisfiedPageIsCompleteAtScanCap(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	memories := make([]store.Memory, maxRemoteCatalogLimit)
	for i := range memories {
		memories[i] = store.Memory{
			ID: fmt.Sprintf("mem-%03d", i), Namespace: "team-a", Content: "needle", Trust: store.MemoryTrustReviewed,
			UpdatedAt: now.Add(-time.Duration(i) * time.Second),
		}
	}
	service := &Service{Legacy: cappedLegacyMemoryStore{memories: memories}}
	response, err := service.Search(context.Background(), "team-a", SearchRequest{
		Query: "needle", Limit: 100,
	}, SearchContext{})
	if err != nil || len(response.Items) != 100 || !response.Complete || response.Exhausted {
		t.Fatalf("Search() response=%#v err=%v, want complete requested page with more legacy rows", response, err)
	}
}

func TestLegacySearchCursorStoreFailureIsServerError(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	memories := []store.Memory{
		{ID: "mem-2", Namespace: "team-a", Content: "needle", Trust: store.MemoryTrustReviewed, UpdatedAt: now.Add(2 * time.Second)},
		{ID: "mem-1", Namespace: "team-a", Content: "needle", Trust: store.MemoryTrustReviewed, UpdatedAt: now.Add(time.Second)},
	}
	governed := newGovernedSearchStore(nil)
	authority := &ResolvedAuthority{Namespace: "team-a", NamespaceUID: "namespace-a"}
	service := &Service{
		Legacy: cappedLegacyMemoryStore{memories: memories}, Governed: governed,
		Resolver: staticAuthorityResolver{authority: authority}, Now: func() time.Time { return now },
	}
	request := SearchRequest{Query: "needle", Limit: 1}
	first, err := service.Search(t.Context(), authority.Namespace, request, SearchContext{})
	if err != nil || first.Cursor == "" {
		t.Fatalf("first Search() = %#v, %v", first, err)
	}
	governed.cursorErr = errors.New("cursor store unavailable")
	request.Cursor = first.Cursor
	_, err = service.Search(t.Context(), authority.Namespace, request, SearchContext{})
	var structured *apierror.Error
	if !errors.As(err, &structured) || structured.Status != http.StatusServiceUnavailable {
		t.Fatalf("cursor store error = %#v, want HTTP 503", err)
	}
}
