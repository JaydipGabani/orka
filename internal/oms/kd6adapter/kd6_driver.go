/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package kd6adapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/orka-agents/orka/internal/oms/protocol"
)

const (
	kd6PathResolveStore = "/v1/stores/resolve"
	kd6PathCapabilities = "/v1/stores/capabilities"
	kd6PathWriterClaim  = "/v1/content/writers/claim"
	kd6PathMutate       = "/v1/content/mutate"
	kd6PathOperationGet = "/v1/content/operations/get"
	kd6PathGet          = "/v1/content/get"
	kd6PathSearchStart  = "/v1/content/search/start"
	kd6PathSearchPage   = "/v1/content/search/page"

	defaultProviderTimeout = 30 * time.Second
	maxProviderErrorBytes  = 16 << 10
	kd6CodeSnapshotInvalid = "KD6_SNAPSHOT_INVALID"
	kd6CodeSnapshotExpired = "KD6_SNAPSHOT_EXPIRED"
)

// HTTPSContentStoreConfig configures the strict KD6/proxy transport. Endpoint
// is an HTTPS origin or HTTPS base path; redirects and environment proxies are
// always disabled.
type HTTPSContentStoreConfig struct {
	Endpoint            string
	BearerToken         string
	BearerTokenProvider BearerTokenProvider
	Timeout             time.Duration
	HTTPClient          *http.Client
}

// HTTPSContentStore implements ContentStore against the versioned KD6/proxy
// JSON contract in this file. Native KD6-specific translation stays behind
// that proxy boundary and never leaks into OMS control-state code.
type HTTPSContentStore struct {
	baseURL      *url.URL
	authProvider BearerTokenProvider
	client       *http.Client
}

// NewHTTPSContentStore validates and constructs a strict provider client.
func NewHTTPSContentStore(config HTTPSContentStoreConfig) (*HTTPSContentStore, error) {
	endpoint, err := validateProviderEndpoint(config.Endpoint)
	if err != nil {
		return nil, err
	}
	authProvider, err := resolveBearerTokenProvider(
		"KD6 bearer token", config.BearerToken, config.BearerTokenProvider,
	)
	if err != nil {
		return nil, err
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultProviderTimeout
	}
	client := &http.Client{Timeout: timeout}
	if config.HTTPClient != nil {
		copy := *config.HTTPClient
		client = &copy
		if client.Timeout <= 0 {
			client.Timeout = timeout
		}
	}
	transport, err := strictProviderTransport(client.Transport)
	if err != nil {
		return nil, err
	}
	client.Transport = transport
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPSContentStore{baseURL: endpoint, authProvider: authProvider, client: client}, nil
}

func validateProviderEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("KD6 endpoint must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return nil, errors.New("KD6 endpoint contains forbidden URL components")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

func strictProviderTransport(roundTripper http.RoundTripper) (*http.Transport, error) {
	var transport *http.Transport
	if roundTripper == nil {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("default HTTP transport is not configurable")
		}
		transport = base.Clone()
	} else {
		base, ok := roundTripper.(*http.Transport)
		if !ok {
			return nil, errors.New("custom KD6 HTTP transport must be *http.Transport")
		}
		transport = base.Clone()
	}
	transport.Proxy = nil
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		if transport.TLSClientConfig.InsecureSkipVerify {
			return nil, errors.New("custom KD6 HTTP transport must verify server certificates")
		}
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	return transport, nil
}

func validateSecretValue(name, value string) error {
	if value == "" || len(value) > 4096 || strings.ContainsFunc(value, unicode.IsSpace) || strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("%s is required and must not contain whitespace or controls", name)
	}
	return nil
}

func (c *HTTPSContentStore) ResolveStore(ctx context.Context, request ResolveStoreRequest) (ResolvedStore, error) {
	wireRequest := kd6ResolveStoreRequest{ProviderStoreID: request.ProviderStoreID, StoreName: request.StoreName}
	var response kd6ResolveStoreResponse
	if err := c.doJSON(ctx, request.TenantID, "", kd6PathResolveStore, wireRequest, &response); err != nil {
		return ResolvedStore{}, err
	}
	if response.ProviderStoreID != request.ProviderStoreID || !safeProviderIdentity(response.ProviderStoreID) || !safeProviderIdentity(response.CanonicalID) {
		return ResolvedStore{}, &StoreError{Code: "KD6_INVALID_STORE_IDENTITY", Kind: ErrProviderDiverged}
	}
	return ResolvedStore(response), nil
}

func (c *HTTPSContentStore) Capabilities(ctx context.Context, request StoreRequest) (ProviderCapabilities, error) {
	var response kd6CapabilitiesResponse
	if err := c.doJSON(ctx, request.TenantID, "", kd6PathCapabilities,
		kd6StoreRequest{ProviderStoreID: request.ProviderStoreID}, &response); err != nil {
		return ProviderCapabilities{}, err
	}
	if !safeProviderIdentity(response.Revision) || response.ExpiresAt.IsZero() || !response.ExpiresAt.After(time.Now().Add(-time.Minute)) {
		return ProviderCapabilities{}, &StoreError{Code: "KD6_INVALID_CAPABILITIES", Kind: ErrProviderDiverged}
	}
	limits := response.Limits
	if !response.KeywordSearch || limits.MaxContentBytes <= 0 || limits.MaxTags <= 0 || limits.MaxTagBytes <= 0 ||
		limits.MaxMetadataEntries <= 0 || limits.MaxMetadataKeyBytes <= 0 || limits.MaxMetadataValueBytes <= 0 ||
		limits.MaxQueryBytes <= 0 || limits.MaxSnapshotRecords <= 0 {
		return ProviderCapabilities{}, &StoreError{Code: "KD6_INCOMPATIBLE_CAPABILITIES", Kind: ErrProviderUnsupported}
	}
	return ProviderCapabilities{
		Revision: response.Revision, ExpiresAt: response.ExpiresAt, KeywordSearch: response.KeywordSearch,
		SemanticSearch: response.SemanticSearch, HybridSearch: response.HybridSearch,
		MaxContentBytes: limits.MaxContentBytes, MaxTags: limits.MaxTags, MaxTagBytes: limits.MaxTagBytes,
		MaxMetadataEntries: limits.MaxMetadataEntries, MaxMetadataKeyBytes: limits.MaxMetadataKeyBytes,
		MaxMetadataValueBytes: limits.MaxMetadataValueBytes, MaxQueryBytes: limits.MaxQueryBytes,
		MaxSnapshotRecords: limits.MaxSnapshotRecords,
	}, nil
}

func (c *HTTPSContentStore) ClaimWriter(ctx context.Context, claim ContentWriterClaim) (ContentWriterLease, error) {
	if err := validateContentWriterLease(claim.TenantID, claim.Lease); err != nil {
		return ContentWriterLease{}, err
	}
	var response kd6WriterClaimResponse
	if err := c.doJSON(ctx, claim.TenantID, "", kd6PathWriterClaim, kd6WriterClaimRequest{
		ProviderStoreID: claim.ProviderStoreID, Lease: claim.Lease,
	}, &response); err != nil {
		return ContentWriterLease{}, err
	}
	if response.Lease != claim.Lease || response.ClaimedAt.IsZero() {
		return ContentWriterLease{}, &StoreError{Code: "KD6_INVALID_WRITER_CLAIM", Kind: ErrProviderDiverged}
	}
	return response.Lease, nil
}

func (c *HTTPSContentStore) LookupMutation(ctx context.Context, lookup ContentOperationLookup) (ContentOperationLookupResult, error) {
	var response kd6OperationLookupResponse
	if err := c.doJSON(ctx, lookup.TenantID, "", kd6PathOperationGet, kd6OperationLookupRequest{
		ProviderStoreID: lookup.ProviderStoreID,
		OperationID:     lookup.OperationID,
		MutationDigest:  lookup.MutationDigest,
	}, &response); err != nil {
		return ContentOperationLookupResult{}, err
	}
	result := ContentOperationLookupResult{Status: response.Status}
	switch response.Status {
	case ContentOperationLookupCompleted:
		if response.Result == nil {
			return ContentOperationLookupResult{}, invalidOperationLookupError()
		}
		decoded, err := decodeKD6MutationResponse(*response.Result, lookup.Kind)
		if err != nil {
			return ContentOperationLookupResult{}, err
		}
		result.Result = &decoded
	case ContentOperationLookupPending, ContentOperationLookupNotFound, ContentOperationLookupNeverApplied:
		if response.Result != nil {
			return ContentOperationLookupResult{}, invalidOperationLookupError()
		}
	default:
		return ContentOperationLookupResult{}, invalidOperationLookupError()
	}
	return result, nil
}

func invalidOperationLookupError() error {
	return &StoreError{Code: "KD6_INVALID_OPERATION_LOOKUP", Kind: ErrProviderDiverged}
}

func (c *HTTPSContentStore) Mutate(ctx context.Context, mutation ContentMutation) (ContentMutationResult, error) {
	if err := validateContentWriterLease(mutation.TenantID, mutation.WriterLease); err != nil {
		return ContentMutationResult{}, err
	}
	if mutation.Record != nil && writerAuthorityForContent(mutation.Record.Scope) != mutation.WriterLease.Authority {
		return ContentMutationResult{}, &StoreError{Code: "KD6_MUTATION_WRITER_AUTHORITY_MISMATCH"}
	}
	request := kd6MutationRequest{
		ProviderStoreID: mutation.ProviderStoreID, OperationID: mutation.OperationID,
		MutationDigest: mutation.MutationDigest, Kind: mutation.Kind, Key: mutation.UpsertKey,
		ExpectedVersion: mutation.ExpectedVersion, WriterLease: mutation.WriterLease,
	}
	agentID := ""
	if mutation.Record != nil {
		request.Document = encodeKD6Document(*mutation.Record)
		agentID = deriveTrustedAgentID(mutation.Record.Attributes)
	}
	var response kd6MutationResponse
	if err := c.doJSON(ctx, mutation.TenantID, agentID, kd6PathMutate, request, &response); err != nil {
		return ContentMutationResult{}, err
	}
	return decodeKD6MutationResponse(response, mutation.Kind)
}

func validateContentWriterLease(tenantID string, lease ContentWriterLease) error {
	binding := protocol.Binding{
		ClusterID: lease.Authority.ClusterID, NamespaceUID: lease.Authority.NamespaceUID,
		BackendUID: lease.Authority.BackendUID, AuthorityEpoch: lease.Authority.AuthorityEpoch,
		RoutingEpoch: 1, TenantID: tenantID, StoreUUID: lease.Authority.StoreUUID,
	}
	if err := protocol.ValidateBinding(binding); err != nil || lease.WriterEpoch == 0 || !safeProviderIdentity(lease.HolderIdentity) {
		return &StoreError{Code: "KD6_INVALID_WRITER_LEASE"}
	}
	return nil
}

func decodeKD6MutationResponse(response kd6MutationResponse, kind string) (ContentMutationResult, error) {
	result := ContentMutationResult{
		Outcome: response.Outcome, ProviderID: response.ProviderID,
		Version: response.Version, UpdatedAt: response.UpdatedAt,
	}
	switch response.Outcome {
	case ContentOutcomeApplied:
		if !safeProviderIdentity(response.ProviderID) || !safeProviderIdentity(response.Version) || response.UpdatedAt.IsZero() ||
			(kind != protocol.MutationKindDelete && response.Record == nil) ||
			(kind == protocol.MutationKindDelete && response.Record != nil) {
			return ContentMutationResult{}, &StoreError{Code: "KD6_INVALID_MUTATION_RECEIPT", Kind: ErrProviderDiverged}
		}
		if response.Record != nil {
			record, err := decodeKD6Document(*response.Record)
			if err != nil {
				return ContentMutationResult{}, err
			}
			result.Record = &record
			bound, err := bindMutationResultRecord(result)
			if err != nil {
				return ContentMutationResult{}, &StoreError{Code: "KD6_MUTATION_RECORD_IDENTITY_MISMATCH", Retryable: true, Kind: ErrProviderDiverged}
			}
			result.Record = bound
		}
	case ContentOutcomeNotFound:
		if !safeProviderIdentity(response.ProviderID) || !safeProviderIdentity(response.Version) || response.UpdatedAt.IsZero() {
			return ContentMutationResult{}, &StoreError{Code: "KD6_INVALID_DELETE_RECEIPT", Kind: ErrProviderDiverged}
		}
	case ContentOutcomePreconditionFailed:
		return result, nil
	default:
		return ContentMutationResult{}, &StoreError{Code: "KD6_INVALID_MUTATION_OUTCOME", Kind: ErrProviderDiverged}
	}
	return result, nil
}

func (c *HTTPSContentStore) Get(ctx context.Context, request ContentGetRequest) (*ContentRecord, error) {
	var response kd6GetResponse
	if err := c.doJSON(ctx, request.TenantID, "", kd6PathGet, kd6GetRequest{
		ProviderStoreID: request.ProviderStoreID, Key: request.UpsertKey,
	}, &response); err != nil {
		return nil, err
	}
	if response.Found != (response.Record != nil) {
		return nil, &StoreError{Code: "KD6_INVALID_GET_RESPONSE", Kind: ErrProviderDiverged}
	}
	if response.Record == nil {
		return nil, nil
	}
	record, err := decodeKD6Document(*response.Record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (c *HTTPSContentStore) StartSearch(ctx context.Context, request ContentSearchRequest) (ContentSearchSnapshot, error) {
	if err := validateContentSearchRequest(request); err != nil {
		return ContentSearchSnapshot{}, err
	}
	var response kd6SearchStartResponse
	if err := c.doJSON(ctx, request.TenantID, "", kd6PathSearchStart, kd6SearchStartRequest{
		ProviderStoreID: request.ProviderStoreID, Scope: request.Scope, Mode: request.Mode, Query: request.Query,
		MaxSnapshotRecords: request.MaxSnapshotRecords,
	}, &response); err != nil {
		return ContentSearchSnapshot{}, err
	}
	if !safeProviderIdentity(response.SnapshotID) || response.ExpiresAt.IsZero() || len(response.Entries) > request.MaxSnapshotRecords {
		return ContentSearchSnapshot{}, &StoreError{Code: "KD6_INVALID_SEARCH_SNAPSHOT", Kind: ErrProviderDiverged}
	}
	if !isResolvedSearchMode(response.ActualMode) ||
		request.Mode != protocol.SearchModeAuto && request.Mode != response.ActualMode {
		return ContentSearchSnapshot{}, &StoreError{Code: "KD6_INVALID_SEARCH_MODE", Kind: ErrProviderDiverged}
	}
	entries := make([]ContentDescriptor, len(response.Entries))
	for i := range response.Entries {
		entry, err := decodeKD6Descriptor(response.Entries[i], request.Scope)
		if err != nil {
			return ContentSearchSnapshot{}, err
		}
		entries[i] = entry
	}
	if err := validateSearchSnapshotEntries(response.ActualMode, entries); err != nil {
		return ContentSearchSnapshot{}, err
	}
	return ContentSearchSnapshot{SnapshotID: response.SnapshotID, ActualMode: response.ActualMode, ExpiresAt: response.ExpiresAt, Entries: entries}, nil
}

func (c *HTTPSContentStore) ReadSearchPage(ctx context.Context, request ContentSearchPageRequest) ([]ContentRecord, error) {
	if err := validateContentAuthorityScope(request.Scope, request.TenantID); err != nil {
		return nil, &StoreError{Code: "KD6_INVALID_SEARCH_SCOPE", Kind: err}
	}
	wireEntries := make([]kd6Descriptor, len(request.Entries))
	for i := range request.Entries {
		wireEntries[i] = encodeKD6Descriptor(request.Entries[i], request.Scope)
	}
	var response kd6SearchPageResponse
	if err := c.doJSON(ctx, request.TenantID, "", kd6PathSearchPage, kd6SearchPageRequest{
		ProviderStoreID: request.ProviderStoreID, Scope: request.Scope,
		SnapshotID: request.SnapshotID, Entries: wireEntries,
	}, &response); err != nil {
		return nil, err
	}
	if len(response.Records) != len(request.Entries) {
		return nil, &StoreError{Code: "KD6_INCOMPLETE_SEARCH_PAGE", Kind: ErrProviderDiverged}
	}
	records := make([]ContentRecord, len(response.Records))
	for i := range response.Records {
		record, err := decodeKD6Document(response.Records[i])
		if err != nil {
			return nil, err
		}
		if !contentScopeMatchesAuthority(record.Scope, request.Scope) ||
			!contentDescriptorIdentityEqual(descriptorFromRecord(record), request.Entries[i]) {
			return nil, &StoreError{Code: "KD6_SEARCH_SNAPSHOT_CHANGED", Kind: ErrProviderDiverged}
		}
		record.Score = request.Entries[i].Score
		records[i] = record
	}
	return records, nil
}

func validateContentSearchRequest(request ContentSearchRequest) error {
	if err := validateContentAuthorityScope(request.Scope, request.TenantID); err != nil {
		return &StoreError{Code: "KD6_INVALID_SEARCH_SCOPE", Kind: err}
	}
	if !safeProviderIdentity(request.ProviderStoreID) || request.MaxSnapshotRecords <= 0 ||
		request.MaxSnapshotRecords > protocol.MaxSnapshotRecords {
		return &StoreError{Code: "KD6_INVALID_SEARCH_REQUEST"}
	}
	if request.Mode != protocol.SearchModeAuto && !isResolvedSearchMode(request.Mode) {
		return &StoreError{Code: "KD6_INVALID_SEARCH_MODE"}
	}
	if len(request.Query) > protocol.MaxQueryBytes {
		return &StoreError{Code: "KD6_INVALID_SEARCH_REQUEST"}
	}
	return nil
}

func (c *HTTPSContentStore) doJSON(ctx context.Context, tenantID, agentID, path string, requestValue, responseValue any) error {
	token, err := bearerTokenFromProvider("KD6 bearer token", c.authProvider)
	if err != nil {
		return &StoreError{Code: "KD6_AUTH_UNAVAILABLE", Retryable: true, Kind: err}
	}
	body, err := protocol.EncodeJSON(requestValue)
	if err != nil {
		return &StoreError{Code: "KD6_REQUEST_ENCODE_FAILED", Kind: err}
	}
	if len(body) > protocol.MaxHTTPBodyBytes {
		return &StoreError{Code: "KD6_REQUEST_TOO_LARGE"}
	}
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return &StoreError{Code: "KD6_REQUEST_BUILD_FAILED", Kind: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Tenant-Id", tenantID)
	if agentID != "" {
		req.Header.Set("X-Agent-Id", agentID)
	}
	response, err := c.client.Do(req)
	if err != nil {
		return &StoreError{Code: "KD6_TRANSPORT_ERROR", Retryable: true, Kind: err}
	}
	defer response.Body.Close() //nolint:errcheck
	limit := int64(protocol.MaxAdapterResponseBytes + 1)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		limit = maxProviderErrorBytes + 1
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil {
		return &StoreError{Code: "KD6_RESPONSE_READ_FAILED", Retryable: true, Kind: err}
	}
	if len(responseBody) >= int(limit) {
		return &StoreError{Code: "KD6_RESPONSE_TOO_LARGE", Retryable: response.StatusCode >= 500}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decodeProviderError(response.StatusCode, responseBody)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return &StoreError{Code: "KD6_INVALID_CONTENT_TYPE", Kind: ErrProviderDiverged}
	}
	if err := decodeStrictJSON(responseBody, responseValue); err != nil {
		return &StoreError{Code: "KD6_INVALID_RESPONSE", Kind: err}
	}
	return nil
}

func decodeProviderError(status int, body []byte) error {
	response := kd6ErrorResponse{}
	if len(body) > 0 && decodeStrictJSON(body, &response) == nil && safeProviderIdentity(response.Code) {
		retryable := response.Retryable || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
		kind := error(nil)
		switch response.Code {
		case "KD6_SEARCH_MODE_UNSUPPORTED":
			kind = ErrProviderUnsupported
		case kd6CodeSnapshotInvalid, kd6CodeSnapshotExpired:
			kind = ErrProviderSnapshot
		case "KD6_PRECONDITION_FAILED":
			kind = ErrProviderPrecondition
		case "KD6_OPERATION_CONFLICT":
			kind = ErrProviderIdempotencyConflict
		case "KD6_NOT_FOUND":
			kind = ErrProviderNotFound
		case "KD6_WRITER_FENCED":
			if status == http.StatusConflict && !retryable {
				kind = ErrProviderWriterFenced
			}
		}
		return &StoreError{
			Code: response.Code, Retryable: retryable, Definitive: !retryable,
			NeverApplied: status == http.StatusUnauthorized || status == http.StatusForbidden || errors.Is(kind, ErrProviderWriterFenced), Kind: kind,
		}
	}
	return &StoreError{Code: fmt.Sprintf("KD6_HTTP_%d", status), Retryable: status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= http.StatusInternalServerError}
}

func deriveTrustedAgentID(attributes map[string]string) string {
	if attributes == nil {
		return ""
	}
	agent := strings.TrimSpace(attributes["agentname"])
	if agent == "" {
		return ""
	}
	task := strings.TrimSpace(attributes["taskname"])
	digest := sha256.Sum256([]byte("orka-agent-provenance-v1\x00" + agent + "\x00" + task))
	return "orka-agent-" + hex.EncodeToString(digest[:16])
}

func safeProviderIdentity(value string) bool {
	if value == "" || len(value) > protocol.MaxIdentityBytes {
		return false
	}
	for index, r := range value {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
		if index == 0 && !isASCIIAlphaNumeric(byte(r)) {
			return false
		}
		if index > 0 && !isASCIIAlphaNumeric(byte(r)) && !strings.ContainsRune("._:-", r) {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func encodeKD6Document(record ContentRecord) *kd6Document {
	return &kd6Document{
		Key: record.UpsertKey, ProviderID: record.ProviderID, Version: record.Version,
		SemanticLayer: kd6SemanticLayer{Text: record.Text}, Tags: append([]string(nil), record.Tags...),
		Attributes: cloneStringMap(record.Attributes), Scope: record.Scope, SourceURI: record.SourceURI,
		UpdatedAt: record.UpdatedAt,
	}
}

func decodeKD6Document(document kd6Document) (ContentRecord, error) {
	if document.Key == "" || !safeProviderIdentity(document.ProviderID) || !safeProviderIdentity(document.Version) || document.UpdatedAt.IsZero() {
		return ContentRecord{}, &StoreError{Code: "KD6_INVALID_DOCUMENT_IDENTITY", Kind: ErrProviderDiverged}
	}
	tags, err := protocol.NormalizeTags(document.Tags)
	if err != nil || !slices.Equal(tags, document.Tags) {
		return ContentRecord{}, &StoreError{Code: "KD6_INVALID_DOCUMENT_TAGS", Kind: ErrProviderDiverged}
	}
	metadata, err := protocol.NormalizeMetadata(document.Attributes)
	if err != nil || !equalStringMaps(metadata, document.Attributes) {
		return ContentRecord{}, &StoreError{Code: "KD6_INVALID_DOCUMENT_ATTRIBUTES", Kind: ErrProviderDiverged}
	}
	if protocol.ContentDigest(document.SemanticLayer.Text) != document.Scope.ContentDigest {
		return ContentRecord{}, &StoreError{Code: "KD6_DOCUMENT_DIGEST_MISMATCH", Kind: ErrProviderDiverged}
	}
	return ContentRecord{
		UpsertKey: document.Key, ProviderID: document.ProviderID, Version: document.Version,
		Text: document.SemanticLayer.Text, Tags: tags, Attributes: metadata,
		Scope: document.Scope, SourceURI: document.SourceURI, UpdatedAt: document.UpdatedAt,
	}, nil
}

func encodeKD6Descriptor(entry ContentDescriptor, scope ContentAuthorityScope) kd6Descriptor {
	return kd6Descriptor{
		Key: entry.UpsertKey, ProviderID: entry.ProviderID, Version: entry.Version,
		MemoryID: entry.MemoryID, Generation: entry.Generation, Scope: scope,
		ContentDigest: entry.ContentDigest, UpdatedAt: entry.UpdatedAt, Score: entry.Score,
	}
}

func decodeKD6Descriptor(entry kd6Descriptor, expectedScope ContentAuthorityScope) (ContentDescriptor, error) {
	if entry.Scope != expectedScope || entry.Key == "" || !safeProviderIdentity(entry.ProviderID) || !safeProviderIdentity(entry.Version) ||
		entry.MemoryID == "" || entry.Generation == 0 || entry.ContentDigest == "" || entry.UpdatedAt.IsZero() {
		return ContentDescriptor{}, &StoreError{Code: "KD6_INVALID_SEARCH_DESCRIPTOR", Kind: ErrProviderDiverged}
	}
	descriptor := ContentDescriptor{
		UpsertKey: entry.Key, ProviderID: entry.ProviderID, Version: entry.Version,
		MemoryID: entry.MemoryID, Generation: entry.Generation,
		ContentDigest: entry.ContentDigest, UpdatedAt: entry.UpdatedAt, Score: entry.Score,
	}
	if err := validateSearchScore(descriptor.Score); err != nil {
		return ContentDescriptor{}, err
	}
	return descriptor, nil
}

func cloneStringMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	maps.Copy(result, input)
	return result
}

func equalStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		rightValue, ok := right[key]
		if !ok || rightValue != value {
			return false
		}
	}
	return true
}

func decodeStrictJSON(body []byte, destination any) error {
	if len(body) == 0 || len(body) > protocol.MaxAdapterResponseBytes {
		return errors.New("JSON body size is invalid")
	}
	if !utf8.Valid(body) {
		return errors.New("JSON body must be valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return err
	}
	targetType := reflect.TypeOf(destination)
	if targetType == nil || targetType.Kind() != reflect.Pointer || reflect.ValueOf(destination).IsNil() {
		return errors.New("JSON destination must be a non-nil pointer")
	}
	if err := validateExactJSONShape(body, targetType.Elem(), "value"); err != nil {
		return err
	}
	if err := protocol.ValidateJSONNullability(body, destination); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("JSON body contains trailing data")
		}
		return err
	}
	return nil
}

var jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()

func validateExactJSONShape(raw []byte, targetType reflect.Type, path string) error {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		if targetType.Kind() == reflect.Pointer || targetType.Kind() == reflect.Interface {
			return nil
		}
		return fmt.Errorf("%s must not be null", path)
	}
	for targetType.Kind() == reflect.Pointer {
		targetType = targetType.Elem()
	}
	if reflect.PointerTo(targetType).Implements(jsonUnmarshalerType) {
		return nil
	}
	switch targetType.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return err
		}
		if object == nil {
			return fmt.Errorf("%s must be an object", path)
		}
		fields := make(map[string]reflect.Type, targetType.NumField())
		for field := range targetType.Fields() {
			if field.PkgPath != "" {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for name, fieldType := range fields {
			value, found := object[name]
			if !found {
				return fmt.Errorf("%s.%s is required", path, name)
			}
			if err := validateExactJSONShape(value, fieldType, path+"."+name); err != nil {
				return err
			}
		}
		for name := range object {
			if _, allowed := fields[name]; !allowed {
				return fmt.Errorf("%s contains unknown field %q", path, name)
			}
		}
	case reflect.Slice, reflect.Array:
		var elements []json.RawMessage
		if err := json.Unmarshal(trimmed, &elements); err != nil {
			return err
		}
		if elements == nil {
			return fmt.Errorf("%s must not be null", path)
		}
		for index, element := range elements {
			if err := validateExactJSONShape(element, targetType.Elem(), fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return err
		}
		if object == nil {
			return fmt.Errorf("%s must not be null", path)
		}
		for key, value := range object {
			if err := validateExactJSONShape(value, targetType.Elem(), fmt.Sprintf("%s[%q]", path, key)); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is invalid")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("JSON body contains trailing data")
		}
		return err
	}
	return nil
}

type kd6ResolveStoreRequest struct {
	ProviderStoreID string `json:"providerStoreId"`
	StoreName       string `json:"storeName"`
}

type kd6ResolveStoreResponse struct {
	ProviderStoreID string `json:"providerStoreId"`
	CanonicalID     string `json:"canonicalId"`
}

type kd6StoreRequest struct {
	ProviderStoreID string `json:"providerStoreId"`
}

type kd6CapabilitiesResponse struct {
	Revision       string    `json:"revision"`
	ExpiresAt      time.Time `json:"expiresAt"`
	KeywordSearch  bool      `json:"keywordSearch"`
	SemanticSearch bool      `json:"semanticSearch"`
	HybridSearch   bool      `json:"hybridSearch"`
	Limits         kd6Limits `json:"limits"`
}

type kd6WriterClaimRequest struct {
	ProviderStoreID string             `json:"providerStoreId"`
	Lease           ContentWriterLease `json:"lease"`
}

type kd6WriterClaimResponse struct {
	Lease     ContentWriterLease `json:"lease"`
	ClaimedAt time.Time          `json:"claimedAt"`
}

type kd6Limits struct {
	MaxContentBytes       int `json:"maxContentBytes"`
	MaxTags               int `json:"maxTags"`
	MaxTagBytes           int `json:"maxTagBytes"`
	MaxMetadataEntries    int `json:"maxMetadataEntries"`
	MaxMetadataKeyBytes   int `json:"maxMetadataKeyBytes"`
	MaxMetadataValueBytes int `json:"maxMetadataValueBytes"`
	MaxQueryBytes         int `json:"maxQueryBytes"`
	MaxSnapshotRecords    int `json:"maxSnapshotRecords"`
}

type kd6SemanticLayer struct {
	Text string `json:"text"`
}

type kd6Document struct {
	Key           string            `json:"key"`
	ProviderID    string            `json:"providerId"`
	Version       string            `json:"version"`
	SemanticLayer kd6SemanticLayer  `json:"semanticLayer"`
	Tags          []string          `json:"tags"`
	Attributes    map[string]string `json:"attributes"`
	Scope         ContentScope      `json:"scope"`
	SourceURI     string            `json:"sourceUri"`
	UpdatedAt     time.Time         `json:"updatedAt"`
}

type kd6MutationRequest struct {
	ProviderStoreID string             `json:"providerStoreId"`
	WriterLease     ContentWriterLease `json:"writerLease"`
	OperationID     string             `json:"operationId"`
	MutationDigest  string             `json:"mutationDigest"`
	Kind            string             `json:"kind"`
	Key             string             `json:"key"`
	ExpectedVersion string             `json:"expectedVersion"`
	Document        *kd6Document       `json:"document"`
}

type kd6MutationResponse struct {
	Outcome    string       `json:"outcome"`
	ProviderID string       `json:"providerId"`
	Version    string       `json:"version"`
	UpdatedAt  time.Time    `json:"updatedAt"`
	Record     *kd6Document `json:"record"`
}

type kd6OperationLookupRequest struct {
	ProviderStoreID string `json:"providerStoreId"`
	OperationID     string `json:"operationId"`
	MutationDigest  string `json:"mutationDigest"`
}

type kd6OperationLookupResponse struct {
	Status string               `json:"status"`
	Result *kd6MutationResponse `json:"result"`
}

type kd6GetRequest struct {
	ProviderStoreID string `json:"providerStoreId"`
	Key             string `json:"key"`
}

type kd6GetResponse struct {
	Found  bool         `json:"found"`
	Record *kd6Document `json:"record"`
}

type kd6SearchStartRequest struct {
	ProviderStoreID    string                `json:"providerStoreId"`
	Scope              ContentAuthorityScope `json:"scope"`
	Mode               string                `json:"mode"`
	Query              string                `json:"query"`
	MaxSnapshotRecords int                   `json:"maxSnapshotRecords"`
}

type kd6Descriptor struct {
	Key           string                `json:"key"`
	ProviderID    string                `json:"providerId"`
	Version       string                `json:"version"`
	MemoryID      string                `json:"memoryId"`
	Generation    uint64                `json:"generation"`
	Scope         ContentAuthorityScope `json:"scope"`
	ContentDigest string                `json:"contentDigest"`
	UpdatedAt     time.Time             `json:"updatedAt"`
	Score         float64               `json:"score"`
}

type kd6SearchStartResponse struct {
	SnapshotID string          `json:"snapshotId"`
	ActualMode string          `json:"actualMode"`
	ExpiresAt  time.Time       `json:"expiresAt"`
	Entries    []kd6Descriptor `json:"entries"`
}

type kd6SearchPageRequest struct {
	ProviderStoreID string                `json:"providerStoreId"`
	Scope           ContentAuthorityScope `json:"scope"`
	SnapshotID      string                `json:"snapshotId"`
	Entries         []kd6Descriptor       `json:"entries"`
}

type kd6SearchPageResponse struct {
	Records []kd6Document `json:"records"`
}

type kd6ErrorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
