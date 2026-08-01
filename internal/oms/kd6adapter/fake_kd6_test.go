package kd6adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/oms/protocol"
)

const (
	fakeProviderStoreID     = "provider-store-1"
	fakeSnapshotInvalidCode = "KD6_SNAPSHOT_INVALID"
	testInboundToken        = "inbound-token"
	testOMSStoreName        = "memory"
	testDurableQuery        = "durable"
	conformanceStoreName    = "conformance-store"
)

var testTenantID = protocol.DeriveTenantID("cluster-1", "namespace-1")

type fakeKD6 struct {
	t                              *testing.T
	token                          string
	mu                             sync.Mutex
	clock                          time.Time
	sequence                       int
	semantic                       bool
	hybrid                         bool
	records                        map[string]kd6Document
	writers                        map[string]fakeWriterClaim
	operations                     map[string]fakeOperation
	snapshots                      map[string]fakeSearchSnapshot
	lastMutation                   *kd6MutationRequest
	lastWriterClaim                *kd6WriterClaimRequest
	lastTenant                     string
	lastAgent                      string
	mutateCalls                    int
	writerClaimCalls               int
	operationLookupCalls           int
	mutationRecordIdentityMismatch bool
	searchScores                   map[string]float64
	searchActualMode               string
}

type fakeSearchSnapshot struct {
	scope   ContentAuthorityScope
	records map[string]kd6Document
}

type fakeOperation struct {
	digest   string
	response kd6MutationResponse
}

type fakeWriterClaim struct {
	lease     ContentWriterLease
	claimedAt time.Time
}

func newFakeKD6(t *testing.T, token string) *fakeKD6 {
	t.Helper()
	return &fakeKD6{
		t: t, token: token, clock: time.Now().UTC().Truncate(time.Second),
		records: map[string]kd6Document{}, writers: map[string]fakeWriterClaim{}, operations: map[string]fakeOperation{},
		snapshots: map[string]fakeSearchSnapshot{}, searchScores: map[string]float64{},
	}
}

func (f *fakeKD6) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+kd6PathResolveStore, f.handleResolveStore)
	mux.HandleFunc("POST "+kd6PathCapabilities, f.handleCapabilities)
	mux.HandleFunc("POST "+kd6PathWriterClaim, f.handleWriterClaim)
	mux.HandleFunc("POST "+kd6PathMutate, f.handleMutate)
	mux.HandleFunc("POST "+kd6PathOperationGet, f.handleOperationLookup)
	mux.HandleFunc("POST "+kd6PathGet, f.handleGet)
	mux.HandleFunc("POST "+kd6PathSearchStart, f.handleSearchStart)
	mux.HandleFunc("POST "+kd6PathSearchPage, f.handleSearchPage)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		token := f.token
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+token {
			writeFakeJSON(w, http.StatusUnauthorized, kd6ErrorResponse{Code: "KD6_UNAUTHORIZED", Message: "unauthorized", Retryable: false})
			return
		}
		if strings.TrimSpace(r.Header.Get("X-Tenant-Id")) == "" {
			writeFakeJSON(w, http.StatusBadRequest, kd6ErrorResponse{Code: "KD6_TENANT_REQUIRED", Message: "tenant required", Retryable: false})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (f *fakeKD6) handleWriterClaim(w http.ResponseWriter, r *http.Request) {
	var request kd6WriterClaimRequest
	decodeFakeRequest(f.t, r, &request)
	tenantID := r.Header.Get("X-Tenant-Id")
	if request.ProviderStoreID != fakeProviderStoreID || validateContentWriterLease(tenantID, request.Lease) != nil {
		writeFakeJSON(w, http.StatusBadRequest, kd6ErrorResponse{Code: "KD6_INVALID_WRITER_CLAIM", Message: "invalid writer claim", Retryable: false})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writerClaimCalls++
	f.lastWriterClaim = &request
	key := fakeWriterSlotKey(tenantID, request.ProviderStoreID, request.Lease.Authority)
	if current, found := f.writers[key]; found {
		if current.lease.Authority != request.Lease.Authority || request.Lease.WriterEpoch < current.lease.WriterEpoch ||
			request.Lease.WriterEpoch == current.lease.WriterEpoch && request.Lease.HolderIdentity != current.lease.HolderIdentity {
			writeFakeJSON(w, http.StatusConflict, kd6ErrorResponse{Code: "KD6_WRITER_FENCED", Message: "writer fenced", Retryable: false})
			return
		}
		if current.lease == request.Lease {
			writeFakeJSON(w, http.StatusOK, kd6WriterClaimResponse{Lease: current.lease, ClaimedAt: current.claimedAt})
			return
		}
	}
	claim := fakeWriterClaim{lease: request.Lease, claimedAt: f.clock}
	f.writers[key] = claim
	writeFakeJSON(w, http.StatusOK, kd6WriterClaimResponse{Lease: claim.lease, ClaimedAt: claim.claimedAt})
}

func (f *fakeKD6) setToken(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = token
}

func (f *fakeKD6) handleResolveStore(w http.ResponseWriter, r *http.Request) {
	var request kd6ResolveStoreRequest
	decodeFakeRequest(f.t, r, &request)
	if request.ProviderStoreID != fakeProviderStoreID {
		writeFakeJSON(w, http.StatusNotFound, kd6ErrorResponse{Code: "KD6_NOT_FOUND", Message: "store not found", Retryable: false})
		return
	}
	writeFakeJSON(w, http.StatusOK, kd6ResolveStoreResponse{ProviderStoreID: request.ProviderStoreID, CanonicalID: "kd6-store-1"})
}

func (f *fakeKD6) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	var request kd6StoreRequest
	decodeFakeRequest(f.t, r, &request)
	writeFakeJSON(w, http.StatusOK, kd6CapabilitiesResponse{
		Revision: "fake-kd6-1", ExpiresAt: f.clock.Add(time.Hour), KeywordSearch: true,
		SemanticSearch: f.semantic, HybridSearch: f.hybrid,
		Limits: kd6Limits{
			MaxContentBytes: 256 << 10, MaxTags: 64, MaxTagBytes: 128,
			MaxMetadataEntries: 32, MaxMetadataKeyBytes: 64, MaxMetadataValueBytes: 1024,
			MaxQueryBytes: 1024, MaxSnapshotRecords: 1024,
		},
	})
}

func (f *fakeKD6) handleMutate(w http.ResponseWriter, r *http.Request) {
	var request kd6MutationRequest
	decodeFakeRequest(f.t, r, &request)
	f.mu.Lock()
	defer f.mu.Unlock()
	writerKey := fakeWriterSlotKey(r.Header.Get("X-Tenant-Id"), request.ProviderStoreID, request.WriterLease.Authority)
	writer, found := f.writers[writerKey]
	if !found || writer.lease != request.WriterLease {
		writeFakeJSON(w, http.StatusConflict, kd6ErrorResponse{Code: "KD6_WRITER_FENCED", Message: "writer fenced", Retryable: false})
		return
	}
	f.lastMutation = &request
	f.lastTenant = r.Header.Get("X-Tenant-Id")
	f.lastAgent = r.Header.Get("X-Agent-Id")
	f.mutateCalls++
	operationKey := f.lastTenant + "\x00" + request.ProviderStoreID + "\x00" + request.OperationID
	if existing, ok := f.operations[operationKey]; ok {
		if existing.digest != request.MutationDigest {
			writeFakeJSON(w, http.StatusConflict, kd6ErrorResponse{Code: "KD6_OPERATION_CONFLICT", Message: "operation conflict", Retryable: false})
			return
		}
		writeFakeJSON(w, http.StatusOK, existing.response)
		return
	}
	recordKey := f.lastTenant + "\x00" + request.ProviderStoreID + "\x00" + request.Key
	existing, found := f.records[recordKey]
	response := kd6MutationResponse{}
	switch request.Kind {
	case "create":
		if found {
			response.Outcome = ContentOutcomePreconditionFailed
			break
		}
		if request.Document == nil {
			f.t.Error("create document was nil")
			response.Outcome = ContentOutcomePreconditionFailed
			break
		}
		document := cloneKD6Document(*request.Document)
		f.sequence++
		document.ProviderID = fakeProviderID(request.Key)
		document.Version = fmt.Sprintf("kd6-v%d", f.sequence)
		document.UpdatedAt = f.clock.Add(time.Duration(f.sequence) * time.Second)
		f.records[recordKey] = document
		response = kd6MutationResponse{Outcome: ContentOutcomeApplied, ProviderID: document.ProviderID, Version: document.Version, UpdatedAt: document.UpdatedAt, Record: &document}
	case "replace":
		if !found || existing.Version != request.ExpectedVersion || request.Document == nil {
			response.Outcome = ContentOutcomePreconditionFailed
			break
		}
		document := cloneKD6Document(*request.Document)
		f.sequence++
		document.ProviderID = existing.ProviderID
		document.Version = fmt.Sprintf("kd6-v%d", f.sequence)
		document.UpdatedAt = f.clock.Add(time.Duration(f.sequence) * time.Second)
		f.records[recordKey] = document
		response = kd6MutationResponse{Outcome: ContentOutcomeApplied, ProviderID: document.ProviderID, Version: document.Version, UpdatedAt: document.UpdatedAt, Record: &document}
	case "delete":
		if found && request.ExpectedVersion != "" && existing.Version != request.ExpectedVersion {
			response.Outcome = ContentOutcomePreconditionFailed
			break
		}
		f.sequence++
		providerID := fakeProviderID(request.Key)
		if found {
			providerID = existing.ProviderID
			delete(f.records, recordKey)
			response.Outcome = ContentOutcomeApplied
		} else {
			response.Outcome = ContentOutcomeNotFound
		}
		response.ProviderID = providerID
		response.Version = fmt.Sprintf("kd6-delete-v%d", f.sequence)
		response.UpdatedAt = f.clock.Add(time.Duration(f.sequence) * time.Second)
	default:
		f.t.Errorf("unsupported fake mutation kind %q", request.Kind)
		response.Outcome = ContentOutcomePreconditionFailed
	}
	if f.mutationRecordIdentityMismatch && response.Record != nil {
		mismatched := cloneKD6Document(*response.Record)
		mismatched.Version += "-record-mismatch"
		response.Record = &mismatched
	}
	f.operations[operationKey] = fakeOperation{digest: request.MutationDigest, response: response}
	writeFakeJSON(w, http.StatusOK, response)
}

func fakeWriterSlotKey(tenantID, providerStoreID string, authority ContentWriterAuthority) string {
	return strings.Join([]string{
		tenantID, providerStoreID, authority.ClusterID, authority.NamespaceUID,
		fmt.Sprint(authority.AuthorityEpoch), authority.StoreUUID,
	}, "\x00")
}

func (f *fakeKD6) handleOperationLookup(w http.ResponseWriter, r *http.Request) {
	var request kd6OperationLookupRequest
	decodeFakeRequest(f.t, r, &request)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.operationLookupCalls++
	operationKey := r.Header.Get("X-Tenant-Id") + "\x00" + request.ProviderStoreID + "\x00" + request.OperationID
	existing, ok := f.operations[operationKey]
	if !ok {
		writeFakeJSON(w, http.StatusOK, kd6OperationLookupResponse{Status: ContentOperationLookupNotFound})
		return
	}
	if existing.digest != request.MutationDigest {
		writeFakeJSON(w, http.StatusConflict, kd6ErrorResponse{
			Code: "KD6_OPERATION_CONFLICT", Message: "operation conflict", Retryable: false,
		})
		return
	}
	response := existing.response
	writeFakeJSON(w, http.StatusOK, kd6OperationLookupResponse{Status: ContentOperationLookupCompleted, Result: &response})
}

func (f *fakeKD6) handleGet(w http.ResponseWriter, r *http.Request) {
	var request kd6GetRequest
	decodeFakeRequest(f.t, r, &request)
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.Header.Get("X-Tenant-Id") + "\x00" + request.ProviderStoreID + "\x00" + request.Key
	record, found := f.records[key]
	if !found {
		writeFakeJSON(w, http.StatusOK, kd6GetResponse{Found: false, Record: nil})
		return
	}
	copy := cloneKD6Document(record)
	writeFakeJSON(w, http.StatusOK, kd6GetResponse{Found: true, Record: &copy})
}

func (f *fakeKD6) handleSearchStart(w http.ResponseWriter, r *http.Request) {
	var request kd6SearchStartRequest
	decodeFakeRequest(f.t, r, &request)
	tenantID := r.Header.Get("X-Tenant-Id")
	if err := validateContentAuthorityScope(request.Scope, tenantID); err != nil || request.MaxSnapshotRecords <= 0 {
		writeFakeJSON(w, http.StatusBadRequest, kd6ErrorResponse{Code: "KD6_SEARCH_SCOPE_INVALID", Message: "invalid scope", Retryable: false})
		return
	}
	actualMode := request.Mode
	if f.searchActualMode != "" {
		actualMode = f.searchActualMode
	} else if actualMode == protocol.SearchModeAuto {
		actualMode = protocol.SearchModeKeyword
	}
	if actualMode == protocol.SearchModeSemantic && !f.semantic || actualMode == protocol.SearchModeHybrid && !f.hybrid {
		writeFakeJSON(w, http.StatusUnprocessableEntity, kd6ErrorResponse{Code: "KD6_SEARCH_MODE_UNSUPPORTED", Message: "unsupported", Retryable: false})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := tenantID + "\x00" + request.ProviderStoreID + "\x00"
	query := strings.ToLower(strings.TrimSpace(request.Query))
	keys := make([]string, 0)
	for key, record := range f.records {
		if !strings.HasPrefix(key, prefix) || !contentScopeMatchesAuthority(record.Scope, request.Scope) ||
			query != "" && !fakeRecordMatches(record, query) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := f.records[keys[i]], f.records[keys[j]]
		if actualMode != protocol.SearchModeKeyword {
			leftScore, rightScore := f.searchScores[left.Scope.MemoryID], f.searchScores[right.Scope.MemoryID]
			if leftScore != rightScore {
				return leftScore > rightScore
			}
		}
		return left.Key < right.Key
	})
	if len(keys) > request.MaxSnapshotRecords {
		writeFakeJSON(w, http.StatusServiceUnavailable, kd6ErrorResponse{Code: "KD6_SNAPSHOT_CAPACITY", Message: "capacity", Retryable: true})
		return
	}
	f.sequence++
	snapshotID := fmt.Sprintf("kd6-snapshot-%d", f.sequence)
	snapshot := make(map[string]kd6Document, len(keys))
	entries := make([]kd6Descriptor, 0, len(keys))
	for _, key := range keys {
		document := cloneKD6Document(f.records[key])
		snapshot[document.Key] = document
		descriptor := descriptorFromFakeDocument(document)
		if actualMode != protocol.SearchModeKeyword {
			descriptor.Score = f.searchScores[document.Scope.MemoryID]
		}
		entries = append(entries, encodeKD6Descriptor(descriptor, authorityScopeForContent(document.Scope)))
	}
	f.snapshots[snapshotID] = fakeSearchSnapshot{scope: request.Scope, records: snapshot}
	writeFakeJSON(w, http.StatusOK, kd6SearchStartResponse{
		SnapshotID: snapshotID, ActualMode: actualMode, ExpiresAt: f.clock.Add(30 * time.Minute), Entries: entries,
	})
}

func (f *fakeKD6) handleSearchPage(w http.ResponseWriter, r *http.Request) {
	var request kd6SearchPageRequest
	decodeFakeRequest(f.t, r, &request)
	f.mu.Lock()
	defer f.mu.Unlock()
	snapshot, ok := f.snapshots[request.SnapshotID]
	if !ok || snapshot.scope != request.Scope {
		writeFakeJSON(w, http.StatusConflict, kd6ErrorResponse{Code: fakeSnapshotInvalidCode, Message: "snapshot invalid", Retryable: false})
		return
	}
	records := make([]kd6Document, len(request.Entries))
	for i, requested := range request.Entries {
		record, found := snapshot.records[requested.Key]
		requestedDescriptor, err := decodeKD6Descriptor(requested, request.Scope)
		if !found || err != nil || !contentScopeMatchesAuthority(record.Scope, request.Scope) ||
			!contentDescriptorIdentityEqual(descriptorFromFakeDocument(record), requestedDescriptor) {
			writeFakeJSON(w, http.StatusConflict, kd6ErrorResponse{Code: fakeSnapshotInvalidCode, Message: "entry invalid", Retryable: false})
			return
		}
		records[i] = cloneKD6Document(record)
	}
	writeFakeJSON(w, http.StatusOK, kd6SearchPageResponse{Records: records})
}

func fakeRecordMatches(record kd6Document, query string) bool {
	if strings.Contains(strings.ToLower(record.SemanticLayer.Text), query) || strings.Contains(strings.ToLower(record.SourceURI), query) {
		return true
	}
	for _, tag := range record.Tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}
	for key, value := range record.Attributes {
		if strings.Contains(strings.ToLower(key), query) || strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func descriptorFromFakeDocument(document kd6Document) ContentDescriptor {
	return ContentDescriptor{
		UpsertKey: document.Key, ProviderID: document.ProviderID, Version: document.Version,
		MemoryID: document.Scope.MemoryID, Generation: document.Scope.Generation,
		ContentDigest: document.Scope.ContentDigest, UpdatedAt: document.UpdatedAt,
	}
}

func cloneKD6Document(input kd6Document) kd6Document {
	input.Tags = append([]string(nil), input.Tags...)
	input.Attributes = cloneStringMap(input.Attributes)
	return input
}

func fakeProviderID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "kd6-" + hex.EncodeToString(sum[:16])
}

func decodeFakeRequest(t *testing.T, r *http.Request, destination any) {
	t.Helper()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode fake KD6 request: %v", err)
	}
}

func writeFakeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
