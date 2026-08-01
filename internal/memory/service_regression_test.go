package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/apierror"
	"github.com/orka-agents/orka/internal/oms/protocol"
	"github.com/orka-agents/orka/internal/store"
)

type governedSearchStore struct {
	store.GovernedMemoryStore
	entries   []store.RemoteMemoryCatalogEntry
	byID      map[string]store.RemoteMemoryCatalogEntry
	listCalls int
	getErr    error
	auditErr  error
	audits    []store.MemoryAuditRecord
	cursors   map[string]store.MemorySearchCursorState
}

func newGovernedSearchStore(entries []store.RemoteMemoryCatalogEntry) *governedSearchStore {
	byID := make(map[string]store.RemoteMemoryCatalogEntry, len(entries))
	for _, entry := range entries {
		byID[entry.ID] = entry
	}
	return &governedSearchStore{entries: entries, byID: byID, cursors: make(map[string]store.MemorySearchCursorState)}
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
	cursor, ok := s.cursors[id]
	if !ok || cursor.NamespaceUID != namespaceUID || !cursor.ExpiresAt.After(now) {
		return nil, store.ErrNotFound
	}
	copy := cursor
	copy.State = append([]byte(nil), cursor.State...)
	return &copy, nil
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
	binding     protocol.Binding
	records     []protocol.MemoryRecord
	byUpsertKey map[string]protocol.MemoryRecord
	searchCalls int
	getCalls    int
	pageSizes   []int
	queries     []string
	actualModes []string

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
	return &pagedSearchAdapter{binding: binding, records: records, byUpsertKey: byUpsertKey}
}

func (a *pagedSearchAdapter) Search(_ context.Context, request protocol.SearchRequest) (*protocol.SearchResponse, error) {
	call := a.searchCalls
	a.searchCalls++
	a.pageSizes = append(a.pageSizes, request.PageSize)
	a.queries = append(a.queries, request.Query)
	offset := 0
	if request.PageToken != "" {
		parsed, err := strconv.Atoi(strings.TrimPrefix(request.PageToken, "page-"))
		if err != nil {
			return nil, err
		}
		offset = parsed
	}
	end := min(offset+request.PageSize, len(a.records))
	records := append([]protocol.MemoryRecord(nil), a.records[offset:end]...)
	next := ""
	if end < len(a.records) {
		next = fmt.Sprintf("page-%d", end)
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
		NextPageToken: next, Exhausted: next == "", SnapshotExpiresAt: time.Now().Add(time.Minute),
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
		Metadata: map[string]string{"source": entry.Source}, UpdatedAt: updatedAt,
	}
	return entry, record
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
	}
	governed := newGovernedSearchStore(entries)
	authority := &ResolvedAuthority{
		Namespace: binding.Namespace, NamespaceUID: binding.NamespaceUID,
		Binding: &binding, Backend: backend, Adapter: adapter,
	}
	service := &Service{Governed: governed, Resolver: staticAuthorityResolver{authority: authority}}
	return service, adapter, binding, governed
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
	second, err := service.Search(context.Background(), activeBinding.Namespace, SearchRequest{
		Query: "needle", Limit: 1, Cursor: first.Cursor,
	}, SearchContext{RemoteAuthorized: true})
	if err != nil || len(second.Items) != 1 || second.Items[0].Memory.ID != "mem-5" || !second.Complete {
		t.Fatalf("second Search() = %#v, err=%v", second, err)
	}
	if adapter.searchCalls != 2 || adapter.getCalls != 1 {
		t.Fatalf("search calls=%d get calls=%d, want 2/1", adapter.searchCalls, adapter.getCalls)
	}
	if len(adapter.pageSizes) != 2 || adapter.pageSizes[0] != adapter.pageSizes[1] {
		t.Fatalf("provider page sizes = %#v, want stable snapshot page size", adapter.pageSizes)
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

func (s cappedLegacyMemoryStore) ListMemories(_ context.Context, filter store.MemoryFilter) ([]store.Memory, error) {
	limit := filter.Limit
	if limit <= 0 || limit > len(s.memories) {
		limit = len(s.memories)
	}
	return append([]store.Memory(nil), s.memories[:limit]...), nil
}

func TestLegacySearchReportsPreFilterCapAsIncomplete(t *testing.T) {
	memories := make([]store.Memory, maxRemoteCatalogLimit)
	for i := range memories {
		memories[i] = store.Memory{
			ID: fmt.Sprintf("mem-%03d", i), Namespace: "team-a", Content: "needle", Trust: store.MemoryTrustReviewed,
		}
	}
	service := &Service{Legacy: cappedLegacyMemoryStore{memories: memories}}
	_, err := service.Search(context.Background(), "team-a", SearchRequest{Query: "needle", Limit: 1}, SearchContext{})
	var incomplete *IncompleteSearchError
	if !errors.As(err, &incomplete) {
		t.Fatalf("Search() error = %#v, want explicit incomplete result", err)
	}
	response, err := service.Search(context.Background(), "team-a", SearchRequest{
		Query: "needle", Limit: 1, AllowIncomplete: true,
	}, SearchContext{})
	if err != nil || response.Complete || response.Exhausted || len(response.Items) != 1 {
		t.Fatalf("allow-incomplete response=%#v err=%v", response, err)
	}
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
