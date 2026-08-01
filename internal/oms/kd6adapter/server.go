/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package kd6adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/orka-agents/orka/internal/oms/protocol"
)

const (
	defaultCapabilityTTL         = 5 * time.Minute
	defaultSnapshotTTL           = 15 * time.Minute
	defaultMaxSnapshotRecords    = 256
	adapterName                  = "orka-oms-kd6-adapter"
	adapterVersion               = "v0alpha1-kd6-proxy-2"
	adapterRevisionPrefix        = "orka.oms.v0alpha1.kd6.2"
	conformanceFailpointHeader   = "X-Orka-OMS-Conformance-Failpoint"
	conformanceProviderCommitGap = "provider-commit-before-receipt-v1"
)

// Config configures one durable single-active KD6 OMS adapter.
type Config struct {
	DatabasePath                string
	BearerToken                 string
	BearerTokenProvider         BearerTokenProvider
	ContentStore                ContentStore
	StoreMappings               map[string]string
	CapabilityTTL               time.Duration
	SnapshotTTL                 time.Duration
	MaxSnapshotRecords          int
	Clock                       func() time.Time
	EnableConformanceFailpoints bool
}

// Server owns the process lock and control-state database. It never stores
// acknowledged content, tags, metadata, or raw mutation payloads.
type Server struct {
	authProvider                BearerTokenProvider
	db                          *controlDatabase
	content                     ContentStore
	storeMappings               map[string]string
	capabilityTTL               time.Duration
	snapshotTTL                 time.Duration
	maxSnapshotRecords          int
	clock                       func() time.Time
	enableConformanceFailpoints bool
	stateMu                     sync.Mutex
	closeOnce                   sync.Once
	closeErr                    error
}

// Open opens and migrates the control database and acquires the single-active
// process lock.
func Open(ctx context.Context, config Config) (*Server, error) {
	authProvider, err := resolveBearerTokenProvider(
		"inbound OMS bearer token", config.BearerToken, config.BearerTokenProvider,
	)
	if err != nil {
		return nil, err
	}
	if config.ContentStore == nil {
		return nil, errors.New("KD6 ContentStore is required")
	}
	mappings := make(map[string]string, len(config.StoreMappings))
	for rawName, rawProviderID := range config.StoreMappings {
		name := strings.TrimSpace(rawName)
		providerID := strings.TrimSpace(rawProviderID)
		if name == "" || len(name) > protocol.MaxIdentityBytes || !safeProviderIdentity(name) || !safeProviderIdentity(providerID) {
			return nil, errors.New("store mappings must use safe non-empty names and provider IDs")
		}
		if _, exists := mappings[name]; exists {
			return nil, fmt.Errorf("store mapping name %q is duplicated after normalization", name)
		}
		mappings[name] = providerID
	}
	if len(mappings) == 0 {
		return nil, errors.New("at least one store mapping is required")
	}
	capabilityTTL := config.CapabilityTTL
	if capabilityTTL <= 0 {
		capabilityTTL = defaultCapabilityTTL
	}
	snapshotTTL := config.SnapshotTTL
	if snapshotTTL <= 0 {
		snapshotTTL = defaultSnapshotTTL
	}
	if snapshotTTL < time.Second || snapshotTTL > 24*time.Hour || snapshotTTL%time.Second != 0 {
		return nil, errors.New("snapshot TTL must be a whole number of seconds between 1 second and 24 hours")
	}
	maxSnapshotRecords := config.MaxSnapshotRecords
	if maxSnapshotRecords <= 0 {
		maxSnapshotRecords = defaultMaxSnapshotRecords
	}
	if maxSnapshotRecords > protocol.MaxSnapshotRecords {
		return nil, fmt.Errorf("max snapshot records exceeds %d", protocol.MaxSnapshotRecords)
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	db, err := openControlDatabase(ctx, config.DatabasePath)
	if err != nil {
		return nil, err
	}
	return &Server{
		authProvider: authProvider, db: db, content: config.ContentStore, storeMappings: mappings,
		capabilityTTL: capabilityTTL, snapshotTTL: snapshotTTL,
		maxSnapshotRecords: maxSnapshotRecords, clock: clock,
		enableConformanceFailpoints: config.EnableConformanceFailpoints,
	}, nil
}

// Close releases the SQLite connection and process lock.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() { s.closeErr = s.db.close() })
	return s.closeErr
}

// Handler returns the authenticated OMS HTTP contract. Callers provide the TLS
// serving layer.
type serverRoute struct {
	method  string
	handler http.HandlerFunc
}

func (s *Server) Handler() http.Handler {
	routes := map[string]serverRoute{
		protocol.PathHealth:         {method: http.MethodGet, handler: s.handleHealth},
		protocol.PathStoreResolve:   {method: http.MethodPost, handler: s.handleStoreResolve},
		protocol.PathCapabilities:   {method: http.MethodPost, handler: s.handleCapabilities},
		protocol.PathOwnershipClaim: {method: http.MethodPost, handler: s.handleOwnershipClaim},
		protocol.PathRoutingFence:   {method: http.MethodPost, handler: s.handleRoutingFence},
		protocol.PathMutations:      {method: http.MethodPost, handler: s.handleMutation},
		protocol.PathRecordsGet:     {method: http.MethodPost, handler: s.handleGet},
		protocol.PathOperationsGet:  {method: http.MethodPost, handler: s.handleOperationLookup},
		protocol.PathSearch:         {method: http.MethodPost, handler: s.handleSearch},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticate(w, r) {
			return
		}
		route, found := routes[r.URL.Path]
		if !found {
			s.writeError(w, http.StatusNotFound, nil, protocol.ErrorCodeNotFound, "endpoint not found", false, 0)
			return
		}
		if r.Method != route.method {
			w.Header().Set("Allow", route.method)
			s.writeError(w, http.StatusMethodNotAllowed, nil, protocol.ErrorCodeMethodNotAllowed, "method not allowed", false, 0)
			return
		}
		route.handler(w, r)
	})
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) bool {
	expected, err := bearerTokenFromProvider("inbound OMS bearer token", s.authProvider)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, nil, protocol.ErrorCodeInternal, "authentication unavailable", true, 1)
		return false
	}
	got := protocol.BearerToken(r.Header.Get("Authorization"))
	if !protocol.ConstantTimeBearerEqual(got, expected) {
		s.writeError(w, http.StatusUnauthorized, nil, protocol.ErrorCodeUnauthorized, "unauthorized", false, 0)
		return false
	}
	return true
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, protocol.HealthResponse{ProtocolVersion: protocol.Version, Status: "ok"})
}

func (s *Server) handleStoreResolve(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readJSONBody(w, r)
	if !ok {
		return
	}
	request, err := protocol.DecodeStoreResolveRequest(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, nil, protocol.ErrorCodeInvalidRequest, "invalid store resolve request", false, 0)
		return
	}
	providerStoreID, exists := s.storeMappings[request.StoreName]
	if !exists {
		s.writeError(w, http.StatusConflict, nil, protocol.ErrorCodeIdentityConflict, "store name is not mapped by this adapter", false, 0)
		return
	}
	resolved, err := s.content.ResolveStore(r.Context(), ResolveStoreRequest{
		TenantID: request.Binding.TenantID, StoreName: request.StoreName, ProviderStoreID: providerStoreID,
	})
	if err != nil {
		s.writeProviderError(w, nil, err, "store resolution unavailable")
		return
	}
	s.stateMu.Lock()
	storeUUID, err := s.db.resolveStore(r.Context(), request.Binding, request.StoreName, resolved, s.now())
	s.stateMu.Unlock()
	if err != nil {
		if errors.Is(err, errIdentityConflict) {
			s.writeError(w, http.StatusConflict, nil, protocol.ErrorCodeIdentityConflict, "store mapping identity changed", false, 0)
			return
		}
		s.writeError(w, http.StatusServiceUnavailable, nil, protocol.ErrorCodeInternal, "store resolution unavailable", true, 1)
		return
	}
	s.writeJSON(w, http.StatusOK, protocol.StoreResolveResponse{
		ProtocolVersion: protocol.Version, Binding: request.Binding,
		StoreName: request.StoreName, StoreUUID: storeUUID,
	})
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readJSONBody(w, r)
	if !ok {
		return
	}
	request, err := protocol.DecodeCapabilitiesRequest(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, nil, protocol.ErrorCodeInvalidRequest, "invalid capabilities request", false, 0)
		return
	}
	providerStoreID, err := s.db.providerStore(r.Context(), request.Binding)
	if err != nil {
		s.writeAccessError(w, request.Binding, err)
		return
	}
	provider, err := s.content.Capabilities(r.Context(), StoreRequest{
		TenantID: request.Binding.TenantID, ProviderStoreID: providerStoreID,
	})
	if err != nil {
		s.writeProviderError(w, &request.Binding, err, "provider capabilities unavailable")
		return
	}
	expiresAt := provider.ExpiresAt.UTC()
	if localExpiry := s.now().Add(s.capabilityTTL); expiresAt.After(localExpiry) {
		expiresAt = localExpiry
	}
	if !expiresAt.After(s.now()) {
		s.writeError(w, http.StatusServiceUnavailable, &request.Binding, protocol.ErrorCodeInternal, "provider capabilities are expired", true, 1)
		return
	}
	limits := protocol.CapabilityLimits{
		MaxRequestBytes: protocol.MaxHTTPBodyBytes, MaxResponseBytes: protocol.MaxAdapterResponseBytes,
		MaxContentBytes: minPositive(provider.MaxContentBytes, protocol.MaxContentBytes),
		MaxTags:         minPositive(provider.MaxTags, protocol.MaxTags), MaxTagBytes: minPositive(provider.MaxTagBytes, protocol.MaxTagBytes),
		MaxMetadataEntries:    minPositive(provider.MaxMetadataEntries, protocol.MaxMetadataEntries),
		MaxMetadataKeyBytes:   minPositive(provider.MaxMetadataKeyBytes, protocol.MaxMetadataKeyBytes),
		MaxMetadataValueBytes: minPositive(provider.MaxMetadataValueBytes, protocol.MaxMetadataValueBytes),
		MaxQueryBytes:         minPositive(provider.MaxQueryBytes, protocol.MaxQueryBytes), MaxPageSize: protocol.MaxPageSize,
		MaxSnapshotRecords: minPositive(minPositive(provider.MaxSnapshotRecords, s.maxSnapshotRecords), protocol.MaxSnapshotRecords),
		SnapshotTTLSeconds: int(s.snapshotTTL.Seconds()),
	}
	response := protocol.CapabilitiesResponse{
		ProtocolVersion: protocol.Version, Binding: request.Binding,
		AdapterName: adapterName, AdapterVersion: adapterVersion,
		Revision: adapterRevisionPrefix + "." + provider.Revision, ExpiresAt: expiresAt,
		Capabilities: protocol.Capabilities{
			DurableIdempotency: true, IdempotencyDigestConflicts: true, CreateIfAbsent: true,
			ConditionalMutation: true, MonotonicGenerations: true, DeleteHighWatermark: true,
			DurableRoutingFence: true, OperationLookup: true, ExactGet: true, StablePagination: true,
			ExclusiveOwnership: true, KeywordSearch: provider.KeywordSearch,
			AuditVersionVisibility: true, SemanticSearch: provider.SemanticSearch, HybridSearch: provider.HybridSearch,
		},
		Limits: limits,
	}
	if err := protocol.ValidateCapabilitiesResponse(&response, s.now()); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, &request.Binding, protocol.ErrorCodeInternal, "provider capabilities are incompatible", true, 1)
		return
	}
	s.writeJSON(w, http.StatusOK, response)
}

func minPositive(left, right int) int {
	if left <= 0 {
		return right
	}
	if right <= 0 || left < right {
		return left
	}
	return right
}

func (s *Server) handleOwnershipClaim(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readJSONBody(w, r)
	if !ok {
		return
	}
	request, err := protocol.DecodeOwnershipClaimRequest(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, nil, protocol.ErrorCodeInvalidRequest, "invalid ownership claim", false, 0)
		return
	}
	s.stateMu.Lock()
	decision, err := s.db.claimOwnership(r.Context(), s.content, request.Binding, s.now())
	s.stateMu.Unlock()
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, &request.Binding, protocol.ErrorCodeInternal, "ownership state unavailable", true, 1)
		return
	}
	response := protocol.OwnershipClaimResponse{
		ProtocolVersion: protocol.Version, Binding: request.Binding, Result: decision.result,
		BindingDigest: protocol.BindingDigest(request.Binding), ClaimIdentity: decision.claimIdentity,
		MaximumRoutingEpoch: decision.maxRouting, ClaimedAt: decision.claimedAt,
	}
	status := http.StatusOK
	if decision.result != protocol.ResultApplied {
		status = http.StatusConflict
	}
	s.writeJSON(w, status, response)
}

func (s *Server) handleRoutingFence(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readJSONBody(w, r)
	if !ok {
		return
	}
	request, err := protocol.DecodeRoutingFenceRequest(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, nil, protocol.ErrorCodeInvalidRequest, "invalid routing fence request", false, 0)
		return
	}
	s.stateMu.Lock()
	decision, err := s.db.advanceRoutingFence(r.Context(), s.content, request.Binding, s.now())
	s.stateMu.Unlock()
	if err != nil {
		if errors.Is(err, errRoutingFenceBlocked) {
			s.writeError(w, http.StatusServiceUnavailable, &request.Binding, protocol.ErrorCodeInternal,
				"routing fence is waiting for prior mutation recovery", true, 1)
			return
		}
		s.writeError(w, http.StatusServiceUnavailable, &request.Binding, protocol.ErrorCodeInternal, "routing fence unavailable", true, 1)
		return
	}
	response := protocol.RoutingFenceResponse{
		ProtocolVersion: protocol.Version, Binding: request.Binding, Result: decision.result,
		BindingDigest: protocol.BindingDigest(request.Binding), MaximumRoutingEpoch: decision.maxRouting,
		CompletedAt: s.now(),
	}
	status := http.StatusOK
	if decision.result != protocol.ResultApplied {
		status = http.StatusConflict
	}
	s.writeJSON(w, status, response)
}

func (s *Server) handleMutation(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readJSONBody(w, r)
	if !ok {
		return
	}
	request, err := protocol.DecodeMutationEnvelope(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, nil, protocol.ErrorCodeInvalidRequest, "invalid mutation envelope", false, 0)
		return
	}
	failpoint := r.Header.Get(conformanceFailpointHeader)
	if failpoint != "" && (failpoint != conformanceProviderCommitGap || !s.enableConformanceFailpoints) {
		s.writeError(w, http.StatusBadRequest, &request.Binding, protocol.ErrorCodeInvalidRequest, "conformance failpoint is not enabled", false, 0)
		return
	}
	s.stateMu.Lock()
	receipt, err := s.db.applyMutationWithFailpoint(
		r.Context(), s.content, request, s.now(), failpoint == conformanceProviderCommitGap,
	)
	s.stateMu.Unlock()
	if errors.Is(err, errConformanceProviderCommitGap) {
		w.Header().Set(conformanceFailpointHeader, conformanceProviderCommitGap)
		s.writeError(w, http.StatusServiceUnavailable, &request.Binding, protocol.ErrorCodeInternal,
			"conformance failpoint injected after provider commit", true, 1)
		return
	}
	if err != nil {
		s.writeProviderError(w, &request.Binding, err, "mutation unavailable")
		return
	}
	s.writeJSON(w, mutationHTTPStatus(receipt.Result), receipt)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readJSONBody(w, r)
	if !ok {
		return
	}
	request, err := protocol.DecodeGetRequest(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, nil, protocol.ErrorCodeInvalidRequest, "invalid exact-get request", false, 0)
		return
	}
	s.stateMu.Lock()
	record, found, err := s.db.lookupRecord(r.Context(), s.content, request.Binding, request.UpsertKey)
	s.stateMu.Unlock()
	if err != nil {
		s.writeProviderError(w, &request.Binding, err, "exact get unavailable")
		return
	}
	response := protocol.GetResponse{ProtocolVersion: protocol.Version, Binding: request.Binding, Found: found}
	if found {
		response.Record = &record
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleOperationLookup(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readJSONBody(w, r)
	if !ok {
		return
	}
	request, err := protocol.DecodeOperationLookupRequest(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, nil, protocol.ErrorCodeInvalidRequest, "invalid operation lookup request", false, 0)
		return
	}
	receipt, found, err := s.db.lookupOperation(r.Context(), request.Binding, request.OperationID)
	if err != nil {
		s.writeAccessError(w, request.Binding, err)
		return
	}
	response := protocol.OperationLookupResponse{ProtocolVersion: protocol.Version, Binding: request.Binding, Found: found}
	if found {
		response.Receipt = &receipt
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readJSONBody(w, r)
	if !ok {
		return
	}
	request, err := protocol.DecodeSearchRequest(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, nil, protocol.ErrorCodeInvalidRequest, "invalid search request", false, 0)
		return
	}
	var page searchPage
	s.stateMu.Lock()
	if request.PageToken == "" {
		page, err = s.db.createSnapshot(r.Context(), s.content, request, s.now(), s.now, s.snapshotTTL, s.maxSnapshotRecords)
	} else {
		page, err = s.db.readSnapshotPage(r.Context(), s.content, request, s.now())
	}
	s.stateMu.Unlock()
	if err != nil {
		s.writeSearchError(w, request.Binding, err)
		return
	}
	response, err := boundedSearchResponse(request, page)
	if err != nil {
		s.writeSearchError(w, request.Binding, err)
		return
	}
	s.writeJSON(w, http.StatusOK, response)
}

var errSearchResponseTooLarge = errors.New("search response exceeds adapter response limit")

func boundedSearchResponse(request *protocol.SearchRequest, page searchPage) (protocol.SearchResponse, error) {
	if request == nil || len(page.records) == 0 && page.start < page.total {
		return protocol.SearchResponse{}, errSearchResponseTooLarge
	}
	minimum := 0
	if len(page.records) > 0 {
		minimum = 1
	}
	for count := len(page.records); count >= minimum; count-- {
		nextToken, exhausted := page.nextToken, page.exhausted
		if count != len(page.records) {
			nextOffset := page.start + count
			exhausted = nextOffset >= page.total
			nextToken = ""
			if !exhausted {
				nextToken = formatPageToken(page.snapshotID, nextOffset)
			}
		}
		response := protocol.SearchResponse{
			ProtocolVersion: protocol.Version, Binding: request.Binding,
			RequestedMode: request.Mode, ActualMode: page.actualMode, Records: page.records[:count],
			NextPageToken: nextToken, Exhausted: exhausted, SnapshotExpiresAt: page.expiresAt,
		}
		body, err := json.Marshal(response)
		if err != nil {
			return protocol.SearchResponse{}, err
		}
		if len(body) <= protocol.MaxAdapterResponseBytes {
			return response, nil
		}
	}
	return protocol.SearchResponse{}, errSearchResponseTooLarge
}

func (s *Server) writeSearchError(w http.ResponseWriter, binding protocol.Binding, err error) {
	switch {
	case errors.Is(err, errIdentityConflict):
		s.writeError(w, http.StatusConflict, &binding, protocol.ErrorCodeIdentityConflict, "binding is not the claimed owner", false, 0)
	case errors.Is(err, errRoutingFenced):
		s.writeError(w, http.StatusConflict, &binding, protocol.ErrorCodeRoutingFenced, "routing epoch is fenced", false, 0)
	case errors.Is(err, errSnapshotInvalid):
		s.writeError(w, http.StatusConflict, &binding, protocol.ErrorCodePageTokenInvalid, "page token is invalid for this request", false, 0)
	case errors.Is(err, errSnapshotExpired), errors.Is(err, ErrProviderSnapshot):
		s.writeError(w, http.StatusConflict, &binding, protocol.ErrorCodePageTokenExpired, "page token has expired", false, 0)
	case errors.Is(err, errSnapshotCapacity):
		s.writeError(w, http.StatusServiceUnavailable, &binding, protocol.ErrorCodeSnapshotCapacity, "snapshot capacity exceeded", true, 1)
	case errors.Is(err, errSearchResponseTooLarge):
		s.writeError(w, http.StatusInternalServerError, &binding, protocol.ErrorCodeResponseTooLarge, "search record exceeds the response limit", false, 0)
	case errors.Is(err, ErrProviderUnsupported):
		s.writeError(w, http.StatusUnprocessableEntity, &binding, protocol.ErrorCodeSearchModeUnsupported, "requested search mode is unsupported", false, 0)
	default:
		s.writeProviderError(w, &binding, err, "search unavailable")
	}
}

func (s *Server) writeAccessError(w http.ResponseWriter, binding protocol.Binding, err error) {
	switch {
	case errors.Is(err, errIdentityConflict):
		s.writeError(w, http.StatusConflict, &binding, protocol.ErrorCodeIdentityConflict, "binding is not the claimed owner", false, 0)
	case errors.Is(err, errRoutingFenced):
		s.writeError(w, http.StatusConflict, &binding, protocol.ErrorCodeRoutingFenced, "routing epoch is fenced", false, 0)
	default:
		s.writeError(w, http.StatusServiceUnavailable, &binding, protocol.ErrorCodeInternal, "adapter state unavailable", true, 1)
	}
}

func (s *Server) writeProviderError(w http.ResponseWriter, binding *protocol.Binding, err error, message string) {
	if binding != nil && (errors.Is(err, errIdentityConflict) || errors.Is(err, errRoutingFenced)) {
		s.writeAccessError(w, *binding, err)
		return
	}
	var storeErr *StoreError
	if errors.As(err, &storeErr) && errors.Is(storeErr, ErrProviderUnsupported) {
		s.writeError(w, http.StatusUnprocessableEntity, binding, protocol.ErrorCodeSearchModeUnsupported, "requested search mode is unsupported", false, 0)
		return
	}
	retryable := true
	status := http.StatusServiceUnavailable
	if errors.As(err, &storeErr) && !storeErr.Retryable && !errors.Is(storeErr, ErrProviderDiverged) {
		retryable = false
		status = http.StatusUnprocessableEntity
	}
	retryAfter := 0
	if retryable {
		retryAfter = 1
	}
	s.writeError(w, status, binding, protocol.ErrorCodeInternal, message, retryable, retryAfter)
}

func (s *Server) readJSONBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		s.writeError(w, http.StatusUnsupportedMediaType, nil, protocol.ErrorCodeInvalidRequest, "content type must be application/json", false, 0)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, protocol.MaxHTTPBodyBytes+1))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, nil, protocol.ErrorCodeInvalidRequest, "request body could not be read", false, 0)
		return nil, false
	}
	if len(body) > protocol.MaxHTTPBodyBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, nil, protocol.ErrorCodeInvalidRequest, "request body exceeds the profile limit", false, 0)
		return nil, false
	}
	return body, true
}

func (s *Server) writeError(w http.ResponseWriter, status int, binding *protocol.Binding, code, message string, retryable bool, retryAfter int) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	}
	s.writeJSON(w, status, protocol.ErrorResponse{
		ProtocolVersion: protocol.Version, Binding: binding, Code: code,
		Message:   protocol.SanitizeMessage(message, protocol.MaxErrorMessageBytes),
		Retryable: retryable, RetryAfterSeconds: retryAfter,
	})
}

func responseBinding(value any) *protocol.Binding {
	var binding protocol.Binding
	switch response := value.(type) {
	case protocol.CapabilitiesResponse:
		binding = response.Binding
	case protocol.OwnershipClaimResponse:
		binding = response.Binding
	case protocol.RoutingFenceResponse:
		binding = response.Binding
	case protocol.MutationReceipt:
		binding = response.Binding
	case protocol.GetResponse:
		binding = response.Binding
	case protocol.OperationLookupResponse:
		binding = response.Binding
	case protocol.SearchResponse:
		binding = response.Binding
	case protocol.ErrorResponse:
		return response.Binding
	default:
		return nil
	}
	return &binding
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := protocol.EncodeJSON(value)
	if err != nil || len(body) > protocol.MaxAdapterResponseBytes {
		body, _ = protocol.EncodeJSON(protocol.ErrorResponse{
			ProtocolVersion: protocol.Version, Binding: responseBinding(value), Code: protocol.ErrorCodeResponseTooLarge,
			Message: "response could not be encoded within the profile limit", Retryable: false, RetryAfterSeconds: 0,
		})
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) now() time.Time { return s.clock().UTC() }

func mutationHTTPStatus(result string) int {
	switch result {
	case protocol.ResultApplied, protocol.ResultNotFound:
		return http.StatusOK
	case protocol.ResultPreconditionFailed, protocol.ResultIdempotencyConflict, protocol.ResultIdentityConflict:
		return http.StatusConflict
	case protocol.ResultRetryableError:
		return http.StatusServiceUnavailable
	case protocol.ResultNonRetryableError:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}
