/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

// Package kd6adapter implements the durable single-active OMS bridge whose
// content authority is a KD6-compatible ContentStore.
package kd6adapter

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/orka-agents/orka/internal/oms/protocol"
)

// ContentStore deliberately isolates provider wire details from the OMS
// server. Implementations own acknowledged content and immutable search
// snapshots; the adapter SQLite database stores control metadata only.
type ContentStore interface {
	ResolveStore(context.Context, ResolveStoreRequest) (ResolvedStore, error)
	Capabilities(context.Context, StoreRequest) (ProviderCapabilities, error)
	ClaimWriter(context.Context, ContentWriterClaim) (ContentWriterLease, error)
	LookupMutation(context.Context, ContentOperationLookup) (ContentOperationLookupResult, error)
	Mutate(context.Context, ContentMutation) (ContentMutationResult, error)
	Get(context.Context, ContentGetRequest) (*ContentRecord, error)
	StartSearch(context.Context, ContentSearchRequest) (ContentSearchSnapshot, error)
	ReadSearchPage(context.Context, ContentSearchPageRequest) ([]ContentRecord, error)
}

// ResolveStoreRequest binds one operator-visible OMS store name to a
// preconfigured provider store identity for a tenant.
type ResolveStoreRequest struct {
	TenantID        string
	StoreName       string
	ProviderStoreID string
}

// ResolvedStore is the provider's canonical store identity.
type ResolvedStore struct {
	ProviderStoreID string
	CanonicalID     string
}

// StoreRequest identifies one tenant-isolated provider store.
type StoreRequest struct {
	TenantID        string
	ProviderStoreID string
}

// ContentWriterAuthority identifies one exclusive provider writer slot. The
// provider keys the slot by tenant, provider store, cluster, namespace,
// authority epoch, and store UUID. BackendUID remains part of the accepted
// lease so a second backend cannot replace the writer within the same slot.
type ContentWriterAuthority struct {
	ClusterID      string `json:"clusterId"`
	NamespaceUID   string `json:"namespaceUid"`
	BackendUID     string `json:"backendUid"`
	AuthorityEpoch uint64 `json:"authorityEpoch"`
	StoreUUID      string `json:"storeUuid"`
}

// ContentWriterLease is the provider-backed fencing token carried by every
// mutation. WriterEpoch is monotonically reserved by one durable control DB;
// HolderIdentity changes for every independently opened adapter process.
type ContentWriterLease struct {
	Authority      ContentWriterAuthority `json:"authority"`
	WriterEpoch    uint64                 `json:"writerEpoch"`
	HolderIdentity string                 `json:"holderIdentity"`
}

// ContentWriterClaim asks the shared provider authority to atomically install
// Lease as the current writer. Providers may accept a higher writer epoch or an
// exact idempotent replay, and must reject every stale or equal-epoch claim from
// a different holder.
type ContentWriterClaim struct {
	TenantID        string
	ProviderStoreID string
	Lease           ContentWriterLease
}

// ProviderCapabilities are the native capabilities and limits reported by the
// KD6/proxy layer. The OMS adapter supplies fencing, CAS, deduplication, and
// stable pagination around these content operations.
type ProviderCapabilities struct {
	Revision              string
	ExpiresAt             time.Time
	KeywordSearch         bool
	SemanticSearch        bool
	HybridSearch          bool
	MaxContentBytes       int
	MaxTags               int
	MaxTagBytes           int
	MaxMetadataEntries    int
	MaxMetadataKeyBytes   int
	MaxMetadataValueBytes int
	MaxQueryBytes         int
	MaxSnapshotRecords    int
}

// ContentScope is the safe Orka identity embedded in provider documents. It
// contains no credentials, raw Kubernetes objects, or mutable routing data.
type ContentScope struct {
	ClusterID      string `json:"clusterId"`
	NamespaceUID   string `json:"namespaceUid"`
	BackendUID     string `json:"backendUid"`
	AuthorityEpoch uint64 `json:"authorityEpoch"`
	StoreUUID      string `json:"storeUuid"`
	MemoryID       string `json:"memoryId"`
	Generation     uint64 `json:"generation"`
	ContentDigest  string `json:"contentDigest"`
}

// ContentAuthorityScope identifies the exact authority whose provider content
// may participate in a search snapshot. Providers must apply this isolation
// before enforcing MaxSnapshotRecords.
type ContentAuthorityScope struct {
	ClusterID      string `json:"clusterId"`
	NamespaceUID   string `json:"namespaceUid"`
	BackendUID     string `json:"backendUid"`
	AuthorityEpoch uint64 `json:"authorityEpoch"`
	StoreUUID      string `json:"storeUuid"`
}

// ContentRecord is one provider-owned materialization. Text, tags, and
// attributes are never written to the adapter control database.
type ContentRecord struct {
	UpsertKey  string
	ProviderID string
	Version    string
	Text       string
	Tags       []string
	Attributes map[string]string
	Scope      ContentScope
	SourceURI  string
	UpdatedAt  time.Time
	Score      float64
}

// ContentDescriptor contains safe immutable pagination identity plus the search
// score returned for that snapshot. It is the only per-record snapshot data
// persisted by the adapter; Score is result metadata, not control identity.
type ContentDescriptor struct {
	UpsertKey     string
	ProviderID    string
	Version       string
	MemoryID      string
	Generation    uint64
	ContentDigest string
	UpdatedAt     time.Time
	Score         float64
}

// ContentMutation is a provider-neutral conditional content mutation.
type ContentMutation struct {
	TenantID        string
	ProviderStoreID string
	WriterLease     ContentWriterLease
	OperationID     string
	MutationDigest  string
	Kind            string
	UpsertKey       string
	ExpectedVersion string
	Record          *ContentRecord
}

// ContentOperationLookup retrieves a provider's durable terminal decision for
// an operation ID bound to the exact canonical mutation digest. Providers must
// return a conflict rather than a result when the operation ID exists with a
// different digest.
type ContentOperationLookup struct {
	TenantID        string
	ProviderStoreID string
	OperationID     string
	MutationDigest  string
	Kind            string
}

const (
	ContentOperationLookupCompleted    = "completed"
	ContentOperationLookupPending      = "pending"
	ContentOperationLookupNotFound     = "notFound"
	ContentOperationLookupNeverApplied = "neverApplied"
)

// ContentOperationLookupResult reports the provider's durable knowledge of an
// operation. Pending and notFound are both ambiguous after dispatch: neither
// proves that a delayed provider mutation was never applied. NeverApplied is
// the only absence result that permits safe redispatch or fence recovery.
type ContentOperationLookupResult struct {
	Status string
	Result *ContentMutationResult
}

const (
	ContentOutcomeApplied            = "applied"
	ContentOutcomeNotFound           = "notFound"
	ContentOutcomePreconditionFailed = "preconditionFailed"
)

// ContentMutationResult is the provider's terminal content decision.
type ContentMutationResult struct {
	Outcome    string
	ProviderID string
	Version    string
	UpdatedAt  time.Time
	Record     *ContentRecord
}

// ContentGetRequest performs exact provider lookup by canonical upsert key.
type ContentGetRequest struct {
	TenantID        string
	ProviderStoreID string
	UpsertKey       string
}

// ContentSearchRequest starts an immutable provider snapshot and returns a
// complete bounded descriptor manifest without returning content.
type ContentSearchRequest struct {
	TenantID           string
	ProviderStoreID    string
	Scope              ContentAuthorityScope
	Mode               string
	Query              string
	MaxSnapshotRecords int
}

// ContentSearchSnapshot identifies an immutable provider snapshot.
type ContentSearchSnapshot struct {
	SnapshotID string
	ActualMode string
	ExpiresAt  time.Time
	Entries    []ContentDescriptor
}

// ContentSearchPageRequest retrieves exact content for a bounded ordered slice
// of the immutable descriptor manifest.
type ContentSearchPageRequest struct {
	TenantID        string
	ProviderStoreID string
	Scope           ContentAuthorityScope
	SnapshotID      string
	Entries         []ContentDescriptor
}

// StoreError is a sanitized provider failure. Provider response bodies and
// credentials are intentionally not retained or surfaced.
type StoreError struct {
	Code      string
	Retryable bool
	// Definitive means the provider explicitly rejected the mutation before
	// applying it. Transport, context, malformed-response, and generic local
	// errors must leave this false because the operation outcome is ambiguous.
	Definitive bool
	// NeverApplied means the provider proved that no mutation side effect
	// occurred, for example because authentication failed before decoding or an
	// atomically checked writer lease was fenced before the write. The durable
	// intent may be reset to prepared and retried after the dependency is repaired.
	NeverApplied bool
	Kind         error
}

func (e *StoreError) Error() string {
	if e == nil {
		return "content store error"
	}
	if e.Code == "" {
		return "content store request failed"
	}
	return fmt.Sprintf("content store request failed (%s)", e.Code)
}

func (e *StoreError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Kind
}

var (
	ErrProviderPrecondition        = errors.New("provider precondition failed")
	ErrProviderIdempotencyConflict = errors.New("provider operation idempotency conflict")
	ErrProviderNotFound            = errors.New("provider content not found")
	ErrProviderSnapshot            = errors.New("provider snapshot is invalid or expired")
	ErrProviderUnsupported         = errors.New("provider search mode is unsupported")
	ErrProviderDiverged            = errors.New("provider content diverged from OMS control state")
	ErrProviderWriterFenced        = errors.New("provider writer lease is stale or held by another adapter")
)

func descriptorFromRecord(record ContentRecord) ContentDescriptor {
	return ContentDescriptor{
		UpsertKey: record.UpsertKey, ProviderID: record.ProviderID, Version: record.Version,
		MemoryID: record.Scope.MemoryID, Generation: record.Scope.Generation,
		ContentDigest: record.Scope.ContentDigest, UpdatedAt: record.UpdatedAt, Score: record.Score,
	}
}

func validateSearchScore(score float64) error {
	if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 {
		return &StoreError{Code: "KD6_INVALID_SEARCH_SCORE", Kind: ErrProviderDiverged}
	}
	return nil
}

func validateSearchSnapshotEntries(mode string, entries []ContentDescriptor) error {
	if !isResolvedSearchMode(mode) {
		return &StoreError{Code: "KD6_INVALID_SEARCH_MODE", Kind: ErrProviderDiverged}
	}
	seen := make(map[string]struct{}, len(entries))
	for i := range entries {
		if err := validateSearchScore(entries[i].Score); err != nil {
			return err
		}
		if mode == protocol.SearchModeKeyword && entries[i].Score != 0 {
			return &StoreError{Code: "KD6_INVALID_SEARCH_SCORE", Kind: ErrProviderDiverged}
		}
		if _, duplicate := seen[entries[i].UpsertKey]; duplicate {
			return &StoreError{Code: "KD6_INVALID_SEARCH_SNAPSHOT", Kind: ErrProviderDiverged}
		}
		seen[entries[i].UpsertKey] = struct{}{}
	}
	return nil
}

func isResolvedSearchMode(mode string) bool {
	return mode == protocol.SearchModeKeyword || mode == protocol.SearchModeSemantic || mode == protocol.SearchModeHybrid
}

func authorityScopeForBinding(binding protocol.Binding) ContentAuthorityScope {
	return ContentAuthorityScope{
		ClusterID: binding.ClusterID, NamespaceUID: binding.NamespaceUID, BackendUID: binding.BackendUID,
		AuthorityEpoch: binding.AuthorityEpoch, StoreUUID: binding.StoreUUID,
	}
}

func writerAuthorityForBinding(binding protocol.Binding) ContentWriterAuthority {
	return ContentWriterAuthority{
		ClusterID: binding.ClusterID, NamespaceUID: binding.NamespaceUID, BackendUID: binding.BackendUID,
		AuthorityEpoch: binding.AuthorityEpoch, StoreUUID: binding.StoreUUID,
	}
}

func writerAuthorityForContent(scope ContentScope) ContentWriterAuthority {
	return ContentWriterAuthority{
		ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, BackendUID: scope.BackendUID,
		AuthorityEpoch: scope.AuthorityEpoch, StoreUUID: scope.StoreUUID,
	}
}

func authorityScopeForContent(scope ContentScope) ContentAuthorityScope {
	return ContentAuthorityScope{
		ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, BackendUID: scope.BackendUID,
		AuthorityEpoch: scope.AuthorityEpoch, StoreUUID: scope.StoreUUID,
	}
}

func validateContentAuthorityScope(scope ContentAuthorityScope, tenantID string) error {
	return protocol.ValidateBinding(protocol.Binding{
		ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, BackendUID: scope.BackendUID,
		AuthorityEpoch: scope.AuthorityEpoch, RoutingEpoch: 1, TenantID: tenantID, StoreUUID: scope.StoreUUID,
	})
}

func contentScopeMatchesAuthority(scope ContentScope, authority ContentAuthorityScope) bool {
	return authorityScopeForContent(scope) == authority
}

func contentDescriptorIdentityEqual(left, right ContentDescriptor) bool {
	return left.UpsertKey == right.UpsertKey && left.ProviderID == right.ProviderID &&
		left.Version == right.Version && left.MemoryID == right.MemoryID &&
		left.Generation == right.Generation && left.ContentDigest == right.ContentDigest &&
		left.UpdatedAt.Equal(right.UpdatedAt)
}

func bindMutationResultRecord(result ContentMutationResult) (*ContentRecord, error) {
	if result.Record == nil {
		return nil, nil
	}
	if result.ProviderID == "" || result.Version == "" || result.UpdatedAt.IsZero() {
		return nil, errors.New("mutation result omitted durable provider identity")
	}
	record := *result.Record
	if record.ProviderID != "" && record.ProviderID != result.ProviderID {
		return nil, errors.New("mutation record provider identity conflicts with mutation result")
	}
	if record.Version != "" && record.Version != result.Version {
		return nil, errors.New("mutation record version conflicts with mutation result")
	}
	if !record.UpdatedAt.IsZero() && !record.UpdatedAt.Equal(result.UpdatedAt) {
		return nil, errors.New("mutation record update time conflicts with mutation result")
	}
	record.ProviderID = result.ProviderID
	record.Version = result.Version
	record.UpdatedAt = result.UpdatedAt
	return &record, nil
}

func scopeForMutation(binding protocol.Binding, memoryID string, generation uint64, digest string) ContentScope {
	return ContentScope{
		ClusterID: binding.ClusterID, NamespaceUID: binding.NamespaceUID, BackendUID: binding.BackendUID,
		AuthorityEpoch: binding.AuthorityEpoch, StoreUUID: binding.StoreUUID,
		MemoryID: memoryID, Generation: generation, ContentDigest: digest,
	}
}
