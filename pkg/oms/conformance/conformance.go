/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

// Package conformance probes the closed orka.oms.v0alpha1 contract. Prepare and
// VerifyAfterRestart are deliberately separate so release automation can prove
// durable receipts, fences, records, tombstones, ownership, and snapshots.
package conformance

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/orka-agents/orka/pkg/oms/protocol"
)

const (
	checkpointVersion                 = "orka.oms.conformance.checkpoint.v2"
	conformanceFailpointHeader        = "X-Orka-OMS-Conformance-Failpoint"
	conformanceProviderCommitGapValue = "provider-commit-before-receipt-v1"
	conformanceTag                    = "conformance"
)

// Checkpoint contains no credentials. It is safe to persist between prepare
// and post-restart verification phases.
type Checkpoint struct {
	CheckpointVersion         string                     `json:"checkpointVersion"`
	ProtocolVersion           string                     `json:"protocolVersion"`
	RunID                     string                     `json:"runId"`
	StoreName                 string                     `json:"storeName"`
	Binding                   protocol.Binding           `json:"binding"`
	CapabilitiesRevision      string                     `json:"capabilitiesRevision"`
	ReplayMutation            protocol.MutationEnvelope  `json:"replayMutation"`
	ReplayReceipt             protocol.MutationReceipt   `json:"replayReceipt"`
	LiveRecord                protocol.MemoryRecord      `json:"liveRecord"`
	TombstoneRecord           protocol.MemoryRecord      `json:"tombstoneRecord"`
	PaginationRequest         protocol.SearchRequest     `json:"paginationRequest"`
	PaginationExpectedKeys    []string                   `json:"paginationExpectedKeys"`
	PaginationExpectedDigests []string                   `json:"paginationExpectedDigests"`
	PaginationActualMode      string                     `json:"paginationActualMode"`
	PaginationSnapshotExpiry  time.Time                  `json:"paginationSnapshotExpiry"`
	SnapshotExcludedKey       string                     `json:"snapshotExcludedKey"`
	StaleMutation             protocol.MutationEnvelope  `json:"staleMutation"`
	StaleReceipt              protocol.MutationReceipt   `json:"staleReceipt"`
	ProviderCommitGapMutation *protocol.MutationEnvelope `json:"providerCommitGapMutation,omitempty"`
}

// CheckResult is the sanitized outcome of one conformance phase.
type CheckResult struct {
	Passed       bool                           `json:"passed"`
	Phase        string                         `json:"phase"`
	Message      string                         `json:"message"`
	Capabilities *protocol.CapabilitiesResponse `json:"capabilities,omitempty"`
}

// Check runs prepare plus verification in one process. Release gates that need
// a restart proof must call Prepare, restart the adapter, and then call
// VerifyAfterRestart with the returned checkpoint.
func Check(ctx context.Context, target Target) (result CheckResult) {
	checkpoint, prepared := Prepare(ctx, target)
	if !prepared.Passed {
		return prepared
	}
	verified := VerifyAfterRestart(ctx, target, checkpoint)
	if !verified.Passed {
		return verified
	}
	verified.Phase = "check"
	verified.Message = "adapter conforms to orka.oms.v0alpha1 (restart durability not independently exercised)"
	return SanitizeCheckResult(verified, target.AuthorizationValue)
}

// Prepare performs the mutating contract phase and returns durable state that
// must remain valid after the adapter is restarted.
//
//nolint:gocyclo // Conformance intentionally exercises the complete closed profile in one ordered phase.
func Prepare(ctx context.Context, target Target) (checkpoint Checkpoint, result CheckResult) {
	result.Phase = "prepare"
	defer func() { result = SanitizeCheckResult(result, target.AuthorizationValue) }()

	client, err := newContractClient(target)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	binding := target.Binding
	if binding == (protocol.Binding{}) {
		binding = DefaultBinding()
	}
	storeName := strings.TrimSpace(target.StoreName)
	if storeName == "" {
		storeName = "conformance-store"
	}
	storeBinding := protocol.StoreResolutionBinding{
		ClusterID: binding.ClusterID, NamespaceUID: binding.NamespaceUID,
		BackendUID: binding.BackendUID, TenantID: binding.TenantID,
	}
	resolved, err := resolveStore(ctx, client, storeBinding, storeName)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	replayedResolution, err := resolveStore(ctx, client, storeBinding, storeName)
	if err != nil || replayedResolution.StoreUUID != resolved.StoreUUID {
		result.Message = "store resolution was not stable and idempotent"
		return checkpoint, result
	}
	binding.StoreUUID = resolved.StoreUUID
	if err := protocol.ValidateBinding(binding); err != nil {
		result.Message = safeError("resolved conformance binding is invalid", err)
		return checkpoint, result
	}
	runID := strings.TrimSpace(target.RunID)
	if runID == "" {
		runID, err = randomRunID()
		if err != nil {
			result.Message = "could not generate conformance run ID"
			return checkpoint, result
		}
	}
	if !isSafeRunID(runID) {
		result.Message = "conformance run ID must contain only lowercase ASCII letters, digits, and hyphens"
		return checkpoint, result
	}

	if err := verifyStrictStoreCodec(ctx, client, storeBinding, storeName); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	caps, err := probe(ctx, client, binding)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	result.Capabilities = caps
	if err := verifyAuthentication(ctx, client, storeBinding, storeName, binding); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if err := verifyStrictCapabilityCodec(ctx, client, binding); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}

	claim, err := claimOwnership(ctx, client, binding)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if claim.Result != protocol.ResultApplied {
		result.Message = "ownership claim was not applied"
		return checkpoint, result
	}
	if claim.MaximumRoutingEpoch > binding.RoutingEpoch {
		binding.RoutingEpoch = claim.MaximumRoutingEpoch
	}
	if err := verifyExclusiveOwnership(ctx, client, binding, runID); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if err := verifyStrictMutationCodec(ctx, client, binding, runID); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if err := verifyConcurrentCAS(ctx, client, binding, runID); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}

	marker := "oms-conformance-" + runID
	mainMutation, err := makeMutation(binding, "mop-"+runID+"-create-main", "mem-"+runID+"-main",
		protocol.MutationKindCreate, 1, 0, "", &protocol.MutationState{
			Content: "durable " + marker + " initial", Tags: []string{"Conformance", marker},
			Metadata: map[string]string{"Suite": "OMS Conformance", "Run": runID},
		})
	if err != nil {
		result.Message = safeError("could not construct create mutation", err)
		return checkpoint, result
	}
	createReceipt, createBody, err := mutation(ctx, client, mainMutation, protocol.ResultApplied)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	replayReceipt, replayBody, err := mutation(ctx, client, mainMutation, protocol.ResultApplied)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if !reflect.DeepEqual(createReceipt, replayReceipt) || !bytes.Equal(createBody, replayBody) {
		result.Message = "exact operation replay did not return the original byte-equivalent receipt"
		return checkpoint, result
	}

	conflicting := mainMutation
	conflicting.State = &protocol.MutationState{
		Content: mainMutation.State.Content + " changed", Tags: append([]string(nil), mainMutation.State.Tags...),
		Metadata: cloneMap(mainMutation.State.Metadata),
	}
	conflicting.MutationDigest = ""
	if err := protocol.PrepareMutation(&conflicting); err != nil {
		result.Message = safeError("could not construct idempotency conflict", err)
		return checkpoint, result
	}
	if _, _, err := mutation(ctx, client, conflicting, protocol.ResultIdempotencyConflict); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}

	duplicateCreate, err := makeMutation(binding, "mop-"+runID+"-duplicate-create", mainMutation.MemoryID,
		protocol.MutationKindCreate, 1, 0, "", cloneState(mainMutation.State))
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if _, _, err := mutation(ctx, client, duplicateCreate, protocol.ResultPreconditionFailed); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}

	got, err := getRecord(ctx, client, binding, mainMutation.UpsertKey)
	if err != nil || got == nil || got.Generation != 1 || got.Content != mainMutation.State.Content {
		result.Message = "exact get did not return the created materialization"
		return checkpoint, result
	}
	lookedUp, err := lookupOperation(ctx, client, binding, mainMutation.OperationID)
	if err != nil || lookedUp == nil || !reflect.DeepEqual(*lookedUp, createReceipt) {
		result.Message = "operation lookup did not return the original receipt"
		return checkpoint, result
	}

	wrongReplace, err := makeMutation(binding, "mop-"+runID+"-replace-wrong-cas", mainMutation.MemoryID,
		protocol.MutationKindReplace, 3, 2, "", &protocol.MutationState{
			Content: "wrong CAS " + marker, Tags: []string{marker}, Metadata: map[string]string{"run": runID},
		})
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if _, _, err := mutation(ctx, client, wrongReplace, protocol.ResultPreconditionFailed); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}

	replaceMutation, err := makeMutation(binding, "mop-"+runID+"-replace-main", mainMutation.MemoryID,
		protocol.MutationKindReplace, 2, 1, createReceipt.BackendVersion, &protocol.MutationState{
			Content: "durable " + marker + " replaced", Tags: []string{marker, "Conformance"},
			Metadata: map[string]string{"run": runID, "suite": "OMS Conformance"},
		})
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if _, _, err := mutation(ctx, client, replaceMutation, protocol.ResultApplied); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	liveRecord, err := getRecord(ctx, client, binding, mainMutation.UpsertKey)
	if err != nil ||
		liveRecord == nil ||
		liveRecord.Generation != 2 ||
		liveRecord.Content != replaceMutation.State.Content {
		result.Message = "conditional replace did not materialize generation 2"
		return checkpoint, result
	}
	expectedSnapshotRecords := []protocol.MemoryRecord{*liveRecord}

	for _, suffix := range []string{"a", "b", "c", "d"} {
		created, createErr := makeMutation(binding, "mop-"+runID+"-search-"+suffix, "mem-"+runID+"-search-"+suffix,
			protocol.MutationKindCreate, 1, 0, "", &protocol.MutationState{
				Content: marker + " searchable " + suffix, Tags: []string{marker, suffix},
				Metadata: map[string]string{"run": runID},
			})
		if createErr != nil {
			result.Message = createErr.Error()
			return checkpoint, result
		}
		if _, _, err := mutation(ctx, client, created, protocol.ResultApplied); err != nil {
			result.Message = err.Error()
			return checkpoint, result
		}
		record, getErr := getRecord(ctx, client, binding, created.UpsertKey)
		if getErr != nil || record == nil {
			result.Message = "search fixture was not readable through exact get"
			return checkpoint, result
		}
		expectedSnapshotRecords = append(expectedSnapshotRecords, *record)
	}
	expectedSnapshotDigests, err := recordDigestByKey(binding, expectedSnapshotRecords)
	if err != nil {
		result.Message = safeError("could not digest exact search fixtures", err)
		return checkpoint, result
	}
	if err := verifySearchModeCapabilities(
		ctx, client, binding, marker, caps.Capabilities, caps.Limits.MaxPageSize,
	); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}

	searchRequest := protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeKeyword,
		Query: marker, PageSize: 2, PageToken: "",
	}
	firstPage, err := search(ctx, client, searchRequest)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if firstPage.ActualMode != protocol.SearchModeKeyword || firstPage.Exhausted || firstPage.NextPageToken == "" {
		result.Message = "explicit keyword search did not produce the required pagination fixture"
		return checkpoint, result
	}
	allSnapshotRecords, err := collectSnapshot(ctx, client, searchRequest, firstPage)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if err := verifySnapshotFixture(binding, allSnapshotRecords, expectedSnapshotDigests); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	remainingRecords := allSnapshotRecords[len(firstPage.Records):]
	remainingKeys, remainingDigests, err := recordProofs(binding, remainingRecords)
	if err != nil {
		result.Message = safeError("could not record pagination proof", err)
		return checkpoint, result
	}
	if len(remainingKeys) == 0 {
		result.Message = "pagination fixture did not produce a continuation page"
		return checkpoint, result
	}

	postSnapshot, err := makeMutation(binding, "mop-"+runID+"-post-snapshot", "mem-"+runID+"-search-z",
		protocol.MutationKindCreate, 1, 0, "", &protocol.MutationState{
			Content: marker + " created after snapshot", Tags: []string{marker}, Metadata: map[string]string{"run": runID},
		})
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if _, _, err := mutation(ctx, client, postSnapshot, protocol.ResultApplied); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}

	snapshotTombstoneKey := remainingKeys[len(remainingKeys)-1]
	toDelete, err := getRecord(ctx, client, binding, snapshotTombstoneKey)
	if err != nil || toDelete == nil {
		result.Message = "could not load snapshot record selected for deletion"
		return checkpoint, result
	}
	deleteSnapshotRecord, err := makeMutation(binding, "mop-"+runID+"-delete-snapshot-record", toDelete.MemoryID,
		protocol.MutationKindDelete, toDelete.Generation+1, toDelete.Generation, toDelete.BackendVersion, nil)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if _, _, err := mutation(ctx, client, deleteSnapshotRecord, protocol.ResultApplied); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}

	absentDelete, err := makeMutation(binding, "mop-"+runID+"-delete-absent", "mem-"+runID+"-absent",
		protocol.MutationKindDelete, 1, 0, "", nil)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if _, _, err := mutation(ctx, client, absentDelete, protocol.ResultNotFound); err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	tombstoneRecord, err := getRecord(ctx, client, binding, absentDelete.UpsertKey)
	if err != nil ||
		tombstoneRecord == nil ||
		tombstoneRecord.State != protocol.RecordStateTombstone ||
		tombstoneRecord.Generation != 1 {
		result.Message = "delete-if-absent did not persist a generation high-watermark tombstone"
		return checkpoint, result
	}
	if binding.RoutingEpoch == math.MaxInt64 {
		result.Message = "routing epoch cannot be advanced for conformance"
		return checkpoint, result
	}
	staleBinding := binding
	binding.RoutingEpoch++
	fence, err := advanceFence(ctx, client, binding)
	if err != nil || fence.Result != protocol.ResultApplied || fence.MaximumRoutingEpoch != binding.RoutingEpoch {
		result.Message = "routing fence did not advance durably"
		return checkpoint, result
	}
	staleMutation, err := makeMutation(staleBinding, "mop-"+runID+"-stale-routing", "mem-"+runID+"-stale-routing",
		protocol.MutationKindCreate, 1, 0, "", &protocol.MutationState{
			Content: marker + " stale routing", Tags: []string{marker}, Metadata: map[string]string{"run": runID},
		})
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	staleReceipt, _, err := mutation(ctx, client, staleMutation, protocol.ResultIdentityConflict)
	if err != nil {
		result.Message = err.Error()
		return checkpoint, result
	}
	if staleRecord, getErr := getRecord(
		ctx, client, binding, staleMutation.UpsertKey,
	); getErr != nil || staleRecord != nil {
		result.Message = "stale routing mutation changed provider content"
		return checkpoint, result
	}

	currentLive, err := getRecord(ctx, client, binding, liveRecord.UpsertKey)
	if err != nil || currentLive == nil {
		result.Message = "live record was not readable after routing-fence advancement"
		return checkpoint, result
	}
	searchRequest.Binding = binding
	searchRequest.PageToken = firstPage.NextPageToken

	var providerCommitGapMutation *protocol.MutationEnvelope
	if target.ProviderCommitGapProof {
		gapMutation, gapErr := makeMutation(
			binding, "mop-"+runID+"-provider-commit-gap", "mem-"+runID+"-provider-commit-gap",
			protocol.MutationKindCreate, 1, 0, "", &protocol.MutationState{
				Content: "provider commit gap " + runID, Tags: []string{conformanceTag, "recovery"},
				Metadata: map[string]string{"run": runID},
			},
		)
		if gapErr != nil {
			result.Message = gapErr.Error()
			return checkpoint, result
		}
		if gapErr = induceProviderCommitGap(ctx, client, gapMutation); gapErr != nil {
			result.Message = gapErr.Error()
			return checkpoint, result
		}
		providerCommitGapMutation = &gapMutation
	}

	checkpoint = Checkpoint{
		CheckpointVersion: checkpointVersion, ProtocolVersion: protocol.Version, RunID: runID,
		StoreName: storeName, Binding: binding, CapabilitiesRevision: caps.Revision,
		ReplayMutation: mainMutation, ReplayReceipt: createReceipt, LiveRecord: *currentLive,
		TombstoneRecord: *tombstoneRecord, PaginationRequest: searchRequest,
		PaginationExpectedKeys: remainingKeys, PaginationExpectedDigests: remainingDigests,
		PaginationActualMode: firstPage.ActualMode, PaginationSnapshotExpiry: firstPage.SnapshotExpiresAt,
		SnapshotExcludedKey: postSnapshot.UpsertKey,
		StaleMutation:       staleMutation, StaleReceipt: staleReceipt,
		ProviderCommitGapMutation: providerCommitGapMutation,
	}
	if err := ValidateCheckpoint(checkpoint); err != nil {
		result.Message = safeError("generated checkpoint is invalid", err)
		return Checkpoint{}, result
	}
	result.Passed = true
	result.Message = "OMS conformance prepare phase passed; restart the adapter before verify"
	return checkpoint, result
}

// VerifyAfterRestart proves that the state created by Prepare remained durable.
//
//nolint:gocyclo // Restart verification checks every persisted OMS safety property.
func VerifyAfterRestart(ctx context.Context, target Target, checkpoint Checkpoint) (result CheckResult) {
	result.Phase = "verify"
	defer func() { result = SanitizeCheckResult(result, target.AuthorizationValue) }()
	if err := ValidateCheckpoint(checkpoint); err != nil {
		result.Message = safeError("checkpoint is invalid", err)
		return result
	}
	client, err := newContractClient(target)
	if err != nil {
		result.Message = err.Error()
		return result
	}
	storeBinding := protocol.StoreResolutionBinding{
		ClusterID: checkpoint.Binding.ClusterID, NamespaceUID: checkpoint.Binding.NamespaceUID,
		BackendUID: checkpoint.Binding.BackendUID, TenantID: checkpoint.Binding.TenantID,
	}
	resolved, err := resolveStore(ctx, client, storeBinding, checkpoint.StoreName)
	if err != nil || resolved.StoreUUID != checkpoint.Binding.StoreUUID {
		result.Message = "stable store resolution did not survive restart"
		return result
	}
	caps, err := probe(ctx, client, checkpoint.Binding)
	if err != nil {
		result.Message = err.Error()
		return result
	}
	result.Capabilities = caps
	if caps.Revision != checkpoint.CapabilitiesRevision {
		result.Message = "capability revision changed between prepare and verify"
		return result
	}
	claim, err := claimOwnership(ctx, client, checkpoint.Binding)
	if err != nil ||
		claim.Result != protocol.ResultApplied ||
		claim.MaximumRoutingEpoch < checkpoint.Binding.RoutingEpoch {
		result.Message = "exclusive ownership claim or routing fence did not survive restart"
		return result
	}
	if err := verifyExclusiveOwnership(ctx, client, checkpoint.Binding, checkpoint.RunID+"-restart"); err != nil {
		result.Message = err.Error()
		return result
	}
	if checkpoint.ProviderCommitGapMutation != nil {
		gapReceipt, _, gapErr := mutation(ctx, client, *checkpoint.ProviderCommitGapMutation, protocol.ResultApplied)
		if gapErr != nil {
			result.Message = "provider-commit gap did not recover through operation lookup after restart"
			return result
		}
		gapLookup, lookupErr := lookupOperation(
			ctx,
			client,
			checkpoint.Binding,
			checkpoint.ProviderCommitGapMutation.OperationID,
		)
		if lookupErr != nil || gapLookup == nil || !reflect.DeepEqual(*gapLookup, gapReceipt) {
			result.Message = "recovered provider-commit gap receipt was not durable after restart"
			return result
		}
		gapRecord, getErr := getRecord(ctx, client, checkpoint.Binding, checkpoint.ProviderCommitGapMutation.UpsertKey)
		if getErr != nil ||
			gapRecord == nil ||
			gapRecord.Generation != checkpoint.ProviderCommitGapMutation.Generation ||
			checkpoint.ProviderCommitGapMutation.State == nil ||
			gapRecord.Content != checkpoint.ProviderCommitGapMutation.State.Content {
			result.Message = "recovered provider-commit gap record is missing or divergent"
			return result
		}
	}
	lookedUp, err := lookupOperation(ctx, client, checkpoint.Binding, checkpoint.ReplayMutation.OperationID)
	if err != nil || lookedUp == nil || !reflect.DeepEqual(*lookedUp, checkpoint.ReplayReceipt) {
		result.Message = "durable operation lookup failed after restart"
		return result
	}
	replayed, _, err := mutation(ctx, client, checkpoint.ReplayMutation, checkpoint.ReplayReceipt.Result)
	if err != nil || !reflect.DeepEqual(replayed, checkpoint.ReplayReceipt) {
		result.Message = "exact stale-routing replay did not return the original receipt after restart"
		return result
	}
	live, err := getRecord(ctx, client, checkpoint.Binding, checkpoint.LiveRecord.UpsertKey)
	if err != nil || live == nil || !reflect.DeepEqual(*live, checkpoint.LiveRecord) {
		result.Message = "live generation did not survive restart"
		return result
	}
	tombstone, err := getRecord(ctx, client, checkpoint.Binding, checkpoint.TombstoneRecord.UpsertKey)
	if err != nil || tombstone == nil || !reflect.DeepEqual(*tombstone, checkpoint.TombstoneRecord) {
		result.Message = "delete high-watermark tombstone did not survive restart"
		return result
	}

	staleCreate, err := makeMutation(checkpoint.Binding, "mop-"+checkpoint.RunID+"-stale-resurrection-verify",
		checkpoint.TombstoneRecord.MemoryID, protocol.MutationKindCreate, checkpoint.TombstoneRecord.Generation,
		0, "", &protocol.MutationState{
			Content: "stale resurrection", Tags: []string{conformanceTag}, Metadata: map[string]string{"run": checkpoint.RunID},
		})
	if err != nil {
		result.Message = err.Error()
		return result
	}
	if _, _, err := mutation(ctx, client, staleCreate, protocol.ResultPreconditionFailed); err != nil {
		result.Message = "delete high-watermark did not reject stale resurrection after restart"
		return result
	}

	continuation, err := collectContinuation(ctx, client, checkpoint.PaginationRequest)
	if err != nil {
		result.Message = err.Error()
		return result
	}
	if err := verifyContinuationProof(checkpoint.Binding, continuation, checkpoint); err != nil {
		result.Message = err.Error()
		return result
	}
	if slices.Contains(checkpoint.PaginationExpectedKeys, checkpoint.SnapshotExcludedKey) {
		result.Message = "stable snapshot included a record created after the snapshot"
		return result
	}

	staleReplay, _, err := mutation(ctx, client, checkpoint.StaleMutation, protocol.ResultIdentityConflict)
	if err != nil || !reflect.DeepEqual(staleReplay, checkpoint.StaleReceipt) {
		result.Message = "stale routing-fence receipt did not survive restart"
		return result
	}
	secondStale := checkpoint.StaleMutation
	secondStale.OperationID = "mop-" + checkpoint.RunID + "-stale-routing-verify"
	secondStale.MemoryID = "mem-" + checkpoint.RunID + "-stale-routing-verify"
	secondStale.UpsertKey = ""
	secondStale.MutationDigest = ""
	if err := protocol.PrepareMutation(&secondStale); err != nil {
		result.Message = err.Error()
		return result
	}
	if _, _, err := mutation(ctx, client, secondStale, protocol.ResultIdentityConflict); err != nil {
		result.Message = "durable routing fence accepted a new stale mutation after restart"
		return result
	}
	if record, getErr := getRecord(
		ctx, client, checkpoint.Binding, secondStale.UpsertKey,
	); getErr != nil || record != nil {
		result.Message = "new stale routing mutation changed content after restart"
		return result
	}

	result.Passed = true
	result.Message = "adapter conforms to orka.oms.v0alpha1 including restart durability"
	return result
}

// ValidateCheckpoint rejects malformed or cross-profile checkpoint files.
func ValidateCheckpoint(checkpoint Checkpoint) error {
	if checkpoint.CheckpointVersion != checkpointVersion || checkpoint.ProtocolVersion != protocol.Version {
		return errors.New("checkpoint version is unsupported")
	}
	if !isSafeRunID(checkpoint.RunID) {
		return errors.New("checkpoint runId is invalid")
	}
	if err := protocol.ValidateBinding(checkpoint.Binding); err != nil {
		return err
	}
	storeBinding := protocol.StoreResolutionBinding{
		ClusterID: checkpoint.Binding.ClusterID, NamespaceUID: checkpoint.Binding.NamespaceUID,
		BackendUID: checkpoint.Binding.BackendUID, TenantID: checkpoint.Binding.TenantID,
	}
	if err := protocol.ValidateStoreResolveRequest(&protocol.StoreResolveRequest{
		ProtocolVersion: protocol.Version, Binding: storeBinding, StoreName: checkpoint.StoreName,
	}); err != nil {
		return err
	}
	if checkpoint.CapabilitiesRevision == "" {
		return errors.New("capabilitiesRevision is required")
	}
	if err := protocol.ValidateMutationEnvelope(&checkpoint.ReplayMutation); err != nil {
		return err
	}
	if err := protocol.ValidateMutationReceipt(&checkpoint.ReplayReceipt); err != nil {
		return err
	}
	if !protocol.AuthorityEqual(checkpoint.Binding, checkpoint.ReplayMutation.Binding) ||
		!protocol.AuthorityEqual(checkpoint.Binding, checkpoint.ReplayReceipt.Binding) {
		return errors.New("replay authority does not match checkpoint binding")
	}
	if err := protocol.ValidateMemoryRecord(&checkpoint.LiveRecord, checkpoint.Binding); err != nil {
		return err
	}
	if checkpoint.LiveRecord.State != protocol.RecordStateLive {
		return errors.New("liveRecord is not live")
	}
	if err := protocol.ValidateMemoryRecord(&checkpoint.TombstoneRecord, checkpoint.Binding); err != nil {
		return err
	}
	if checkpoint.TombstoneRecord.State != protocol.RecordStateTombstone {
		return errors.New("tombstoneRecord is not a tombstone")
	}
	if err := validateCheckpointPagination(checkpoint); err != nil {
		return err
	}
	if checkpoint.SnapshotExcludedKey == "" {
		return errors.New("snapshotExcludedKey is required")
	}
	if err := protocol.ValidateMutationEnvelope(&checkpoint.StaleMutation); err != nil {
		return err
	}
	if err := protocol.ValidateMutationReceipt(&checkpoint.StaleReceipt); err != nil {
		return err
	}
	if checkpoint.StaleMutation.Binding.RoutingEpoch >= checkpoint.Binding.RoutingEpoch {
		return errors.New("stale mutation is not below the checkpoint routing fence")
	}
	if checkpoint.ProviderCommitGapMutation != nil {
		if err := protocol.ValidateMutationEnvelope(checkpoint.ProviderCommitGapMutation); err != nil {
			return err
		}
		if !protocol.BindingEqual(checkpoint.ProviderCommitGapMutation.Binding, checkpoint.Binding) {
			return errors.New("provider-commit gap mutation binding does not match checkpoint binding")
		}
	}
	return nil
}

func validateCheckpointPagination(checkpoint Checkpoint) error {
	if err := protocol.ValidateSearchRequest(&checkpoint.PaginationRequest); err != nil {
		return err
	}
	if checkpoint.PaginationRequest.PageToken == "" ||
		!protocol.BindingEqual(checkpoint.PaginationRequest.Binding, checkpoint.Binding) {
		return errors.New("pagination continuation is not bound to the checkpoint")
	}
	if checkpoint.PaginationRequest.Mode != protocol.SearchModeKeyword ||
		checkpoint.PaginationActualMode != protocol.SearchModeKeyword {
		return errors.New("pagination proof must use explicit keyword mode")
	}
	if checkpoint.PaginationSnapshotExpiry.IsZero() {
		return errors.New("paginationSnapshotExpiry is required")
	}
	if len(checkpoint.PaginationExpectedKeys) == 0 ||
		len(checkpoint.PaginationExpectedKeys) != len(checkpoint.PaginationExpectedDigests) ||
		len(checkpoint.PaginationExpectedKeys) > protocol.MaxSnapshotRecords {
		return errors.New("pagination record proofs are missing or inconsistent")
	}
	seenKeys := make(map[string]struct{}, len(checkpoint.PaginationExpectedKeys))
	for index, key := range checkpoint.PaginationExpectedKeys {
		request := protocol.GetRequest{ProtocolVersion: protocol.Version, Binding: checkpoint.Binding, UpsertKey: key}
		if err := protocol.ValidateGetRequest(&request); err != nil {
			return err
		}
		if _, duplicate := seenKeys[key]; duplicate {
			return errors.New("paginationExpectedKeys contains a duplicate")
		}
		seenKeys[key] = struct{}{}
		if !isCanonicalDigest(checkpoint.PaginationExpectedDigests[index]) {
			return errors.New("paginationExpectedDigests contains an invalid digest")
		}
	}
	return nil
}

func probe(
	ctx context.Context,
	client *contractClient,
	binding protocol.Binding,
) (*protocol.CapabilitiesResponse, error) {
	healthBody, status, err := client.do(ctx, http.MethodGet, protocol.PathHealth, client.authorizationValue, nil)
	if err != nil {
		return nil, fmt.Errorf("health probe failed: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("health probe returned HTTP %d", status)
	}
	if containsCredential(healthBody, client.authorizationValue) {
		return nil, errors.New("health response contained the bearer token")
	}
	if _, err := protocol.DecodeHealthResponse(healthBody); err != nil {
		return nil, err
	}
	body, status, err := client.postJSON(
		ctx,
		protocol.PathCapabilities,
		protocol.CapabilitiesRequest{ProtocolVersion: protocol.Version, Binding: binding},
	)
	if err != nil {
		return nil, fmt.Errorf("capability probe failed: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("capability probe returned HTTP %d", status)
	}
	if containsCredential(body, client.authorizationValue) {
		return nil, errors.New("capability response contained the bearer token")
	}
	caps, err := protocol.DecodeCapabilitiesResponse(body)
	if err != nil {
		return nil, err
	}
	if !protocol.BindingEqual(caps.Binding, binding) {
		return nil, errors.New("capability response did not echo the exact binding")
	}
	return caps, nil
}

type errorExpectation struct {
	status            int
	code              string
	binding           *protocol.Binding
	retryable         bool
	retryAfterSeconds int
}

func validateErrorVariant(response contractResponse, expected errorExpectation) error {
	if response.StatusCode != expected.status {
		return fmt.Errorf("HTTP status = %d, want %d", response.StatusCode, expected.status)
	}
	decoded, err := protocol.DecodeErrorResponse(response.Body)
	if err != nil {
		return fmt.Errorf("response is not a closed bounded error: %w", err)
	}
	if decoded.Code != expected.code || decoded.Retryable != expected.retryable ||
		decoded.RetryAfterSeconds != expected.retryAfterSeconds {
		return errors.New("response returned the wrong error code or retry semantics")
	}
	if expected.binding == nil {
		if decoded.Binding != nil {
			return errors.New("response unexpectedly included a binding")
		}
	} else if decoded.Binding == nil || !protocol.BindingEqual(*decoded.Binding, *expected.binding) {
		return errors.New("response did not echo the expected binding")
	}
	if _, present := response.Header[http.CanonicalHeaderKey("Retry-After")]; !expected.retryable && present {
		return errors.New("non-retryable response included Retry-After")
	}
	return nil
}

func verifyAuthentication(
	ctx context.Context,
	client *contractClient,
	storeBinding protocol.StoreResolutionBinding,
	storeName string,
	binding protocol.Binding,
) error {
	mutationRequest, err := makeMutation(
		binding, "mop-auth-probe", "mem-auth-probe", protocol.MutationKindCreate, 1, 0, "",
		&protocol.MutationState{Content: "authentication probe", Tags: []string{}, Metadata: map[string]string{}},
	)
	if err != nil {
		return err
	}
	marshal := func(value any) []byte {
		body, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			panic(marshalErr)
		}
		return body
	}
	probes := []struct {
		name, method, path string
		body               []byte
	}{
		{name: "health", method: http.MethodGet, path: protocol.PathHealth},
		{
			name: "store resolution", method: http.MethodPost, path: protocol.PathStoreResolve,
			body: marshal(protocol.StoreResolveRequest{
				ProtocolVersion: protocol.Version,
				Binding:         storeBinding,
				StoreName:       storeName,
			}),
		},
		{
			name: "capabilities", method: http.MethodPost, path: protocol.PathCapabilities,
			body: marshal(protocol.CapabilitiesRequest{
				ProtocolVersion: protocol.Version,
				Binding:         binding,
			}),
		},
		{
			name: "ownership claim", method: http.MethodPost, path: protocol.PathOwnershipClaim,
			body: marshal(protocol.OwnershipClaimRequest{
				ProtocolVersion: protocol.Version,
				Binding:         binding,
			}),
		},
		{
			name: "routing fence", method: http.MethodPost, path: protocol.PathRoutingFence,
			body: marshal(protocol.RoutingFenceRequest{
				ProtocolVersion: protocol.Version,
				Binding:         binding,
			}),
		},
		{name: "mutation", method: http.MethodPost, path: protocol.PathMutations, body: marshal(mutationRequest)},
		{
			name: "exact get", method: http.MethodPost, path: protocol.PathRecordsGet,
			body: marshal(protocol.GetRequest{
				ProtocolVersion: protocol.Version,
				Binding:         binding,
				UpsertKey:       mutationRequest.UpsertKey,
			}),
		},
		{
			name: "operation lookup", method: http.MethodPost, path: protocol.PathOperationsGet,
			body: marshal(protocol.OperationLookupRequest{
				ProtocolVersion: protocol.Version,
				Binding:         binding,
				OperationID:     mutationRequest.OperationID,
			}),
		},
		{
			name: "search", method: http.MethodPost, path: protocol.PathSearch,
			body: marshal(protocol.SearchRequest{
				ProtocolVersion: protocol.Version,
				Binding:         binding,
				Mode:            protocol.SearchModeKeyword,
				Query:           "",
				PageSize:        1,
				PageToken:       "",
			}),
		},
	}
	for _, probe := range probes {
		for _, token := range []string{"", client.authorizationValue + "-invalid"} {
			response, requestErr := client.doResponse(ctx, probe.method, probe.path, token, probe.body, nil)
			if requestErr != nil {
				return fmt.Errorf("%s authentication probe failed: %w", probe.name, requestErr)
			}
			if containsCredential(response.Body, client.authorizationValue) {
				return fmt.Errorf("%s authentication response contained the bearer token", probe.name)
			}
			if err := validateErrorVariant(response, errorExpectation{
				status: http.StatusUnauthorized, code: protocol.ErrorCodeUnauthorized,
				retryable: false, retryAfterSeconds: 0,
			}); err != nil {
				return fmt.Errorf("%s authentication error response is not the exact unauthorized variant: %w", probe.name, err)
			}
		}
	}
	return nil
}

func verifyStrictCapabilityCodec(ctx context.Context, client *contractClient, binding protocol.Binding) error {
	valid, _ := json.Marshal(protocol.CapabilitiesRequest{ProtocolVersion: protocol.Version, Binding: binding})
	unknown := append([]byte(`{"unknown":true,`), valid[1:]...)
	duplicate := append([]byte(`{"protocolVersion":"orka.oms.v0alpha1",`), valid[1:]...)
	trailing := append(append([]byte(nil), valid...), []byte(` {}`)...)
	unsafeRequest := protocol.CapabilitiesRequest{ProtocolVersion: protocol.Version, Binding: binding}
	unsafeRequest.Binding.ClusterID = "unsafe\ncluster"
	unsafeBody, _ := json.Marshal(unsafeRequest)
	oversized := append(
		append([]byte(nil), valid...),
		bytes.Repeat([]byte(" "), protocol.MaxHTTPBodyBytes+1-len(valid))...,
	)
	probes := []struct {
		name   string
		status int
		body   []byte
	}{
		{name: "unknown field", status: http.StatusBadRequest, body: unknown},
		{name: "duplicate field", status: http.StatusBadRequest, body: duplicate},
		{name: "trailing JSON", status: http.StatusBadRequest, body: trailing},
		{name: "unsafe identity", status: http.StatusBadRequest, body: unsafeBody},
		{name: "oversized body", status: http.StatusRequestEntityTooLarge, body: oversized},
	}
	for _, probe := range probes {
		if err := expectCodecRejection(
			ctx, client, protocol.PathCapabilities, probe.name, probe.status, probe.body,
		); err != nil {
			return err
		}
	}
	return nil
}

func verifyStrictMutationCodec(
	ctx context.Context,
	client *contractClient,
	binding protocol.Binding,
	runID string,
) error {
	request, err := makeMutation(binding, "mop-"+runID+"-strict-codec", "mem-"+runID+"-strict-codec",
		protocol.MutationKindCreate, 1, 0, "", &protocol.MutationState{
			Content: "strict codec", Tags: []string{"strict"}, Metadata: map[string]string{"run": runID},
		})
	if err != nil {
		return err
	}
	valid, _ := json.Marshal(request)
	unknown := append([]byte(`{"unknown":true,`), valid[1:]...)
	trailing := append(append([]byte(nil), valid...), []byte(` []`)...)
	for name, body := range map[string][]byte{"mutation unknown field": unknown, "mutation trailing JSON": trailing} {
		if err := expectCodecRejection(ctx, client, protocol.PathMutations, name, http.StatusBadRequest, body); err != nil {
			return err
		}
	}
	if record, err := getRecord(ctx, client, binding, request.UpsertKey); err != nil || record != nil {
		return errors.New("malformed mutation changed provider content")
	}
	return nil
}

func expectCodecRejection(
	ctx context.Context,
	client *contractClient,
	path string,
	name string,
	expectedStatus int,
	body []byte,
) error {
	response, err := client.doResponse(ctx, http.MethodPost, path, client.authorizationValue, body, nil)
	if err != nil {
		return fmt.Errorf("%s probe failed: %w", name, err)
	}
	if containsCredential(response.Body, client.authorizationValue) {
		return fmt.Errorf("%s response contained the bearer token", name)
	}
	if err := validateErrorVariant(response, errorExpectation{
		status: expectedStatus, code: protocol.ErrorCodeInvalidRequest,
		retryable: false, retryAfterSeconds: 0,
	}); err != nil {
		return fmt.Errorf("%s response is not the exact invalid-request variant: %w", name, err)
	}
	return nil
}

func resolveStore(
	ctx context.Context,
	client *contractClient,
	binding protocol.StoreResolutionBinding,
	storeName string,
) (*protocol.StoreResolveResponse, error) {
	body, status, err := client.postJSON(ctx, protocol.PathStoreResolve, protocol.StoreResolveRequest{
		ProtocolVersion: protocol.Version, Binding: binding, StoreName: storeName,
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("store resolution returned HTTP %d", status)
	}
	response, err := protocol.DecodeStoreResolveResponse(body)
	if err != nil {
		return nil, err
	}
	if !protocol.StoreResolutionBindingEqual(response.Binding, binding) || response.StoreName != storeName {
		return nil, errors.New("store resolution did not echo the exact pre-authority identity and store name")
	}
	return response, nil
}

func verifyStrictStoreCodec(
	ctx context.Context,
	client *contractClient,
	binding protocol.StoreResolutionBinding,
	storeName string,
) error {
	valid, _ := json.Marshal(protocol.StoreResolveRequest{
		ProtocolVersion: protocol.Version,
		Binding:         binding,
		StoreName:       storeName,
	})
	unknown := append([]byte(`{"unknown":true,`), valid[1:]...)
	trailing := append(append([]byte(nil), valid...), []byte(` {}`)...)
	for name, body := range map[string][]byte{"store unknown field": unknown, "store trailing JSON": trailing} {
		if err := expectCodecRejection(
			ctx, client, protocol.PathStoreResolve, name, http.StatusBadRequest, body,
		); err != nil {
			return err
		}
	}
	return nil
}

func claimOwnership(
	ctx context.Context,
	client *contractClient,
	binding protocol.Binding,
) (*protocol.OwnershipClaimResponse, error) {
	body, status, err := client.postJSON(
		ctx,
		protocol.PathOwnershipClaim,
		protocol.OwnershipClaimRequest{ProtocolVersion: protocol.Version, Binding: binding},
	)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK && status != http.StatusConflict {
		return nil, fmt.Errorf("ownership claim returned HTTP %d", status)
	}
	response, err := protocol.DecodeOwnershipClaimResponse(body)
	if err != nil {
		return nil, err
	}
	if !protocol.BindingEqual(response.Binding, binding) {
		return nil, errors.New("ownership response did not echo the exact binding")
	}
	return response, nil
}

func verifyExclusiveOwnership(
	ctx context.Context,
	client *contractClient,
	binding protocol.Binding,
	runID string,
) error {
	conflict := binding
	conflict.BackendUID = "conflict-" + strings.TrimSuffix(runID, "-restart")
	if conflict.BackendUID == binding.BackendUID {
		conflict.BackendUID = "conflict-owner"
	}
	response, err := claimOwnership(ctx, client, conflict)
	if err != nil {
		return err
	}
	if response.Result != protocol.ResultIdentityConflict {
		return errors.New("adapter allowed a second writer claim for the same authority scope")
	}
	return nil
}

func induceProviderCommitGap(ctx context.Context, client *contractClient, request protocol.MutationEnvelope) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	response, err := client.doResponse(
		ctx, http.MethodPost, protocol.PathMutations, client.authorizationValue, body,
		http.Header{conformanceFailpointHeader: []string{conformanceProviderCommitGapValue}},
	)
	if err != nil {
		return fmt.Errorf("provider-commit gap failpoint request failed: %w", err)
	}
	if response.StatusCode != http.StatusServiceUnavailable ||
		response.Header.Get(conformanceFailpointHeader) != conformanceProviderCommitGapValue {
		return errors.New("adapter did not acknowledge the opt-in provider-commit gap failpoint")
	}
	failure, err := protocol.DecodeErrorResponse(response.Body)
	if err != nil || failure.Code != protocol.ErrorCodeInternal || !failure.Retryable || failure.Binding == nil ||
		!protocol.BindingEqual(*failure.Binding, request.Binding) {
		return errors.New("provider-commit gap failpoint did not return the closed retryable error variant")
	}
	record, err := getRecord(ctx, client, request.Binding, request.UpsertKey)
	if err != nil {
		return err
	}
	if record != nil {
		return errors.New("provider-commit gap was materialized locally before restart recovery")
	}
	return nil
}

func verifyConcurrentCAS(ctx context.Context, client *contractClient, binding protocol.Binding, runID string) error {
	base, err := makeMutation(
		binding, "mop-"+runID+"-cas-base", "mem-"+runID+"-cas", protocol.MutationKindCreate, 1, 0, "",
		&protocol.MutationState{
			Content:  "concurrent CAS base",
			Tags:     []string{"cas"},
			Metadata: map[string]string{"run": runID},
		},
	)
	if err != nil {
		return err
	}
	baseReceipt, _, err := mutation(ctx, client, base, protocol.ResultApplied)
	if err != nil {
		return err
	}
	replacements := make([]protocol.MutationEnvelope, 2)
	for index, side := range []string{"left", "right"} {
		replacements[index], err = makeMutation(
			binding, "mop-"+runID+"-cas-"+side, base.MemoryID, protocol.MutationKindReplace, 2, 1, baseReceipt.BackendVersion,
			&protocol.MutationState{
				Content:  "concurrent CAS " + side,
				Tags:     []string{"cas", side},
				Metadata: map[string]string{"run": runID},
			},
		)
		if err != nil {
			return err
		}
	}
	type response struct {
		receipt protocol.MutationReceipt
		err     error
	}
	start := make(chan struct{})
	results := make(chan response, len(replacements))
	for _, replacement := range replacements {
		go func() {
			<-start
			body, status, requestErr := client.postJSON(ctx, protocol.PathMutations, replacement)
			if requestErr != nil {
				results <- response{err: requestErr}
				return
			}
			receipt, decodeErr := protocol.DecodeMutationReceipt(body)
			if decodeErr != nil {
				results <- response{err: decodeErr}
				return
			}
			if !protocol.BindingEqual(receipt.Binding, replacement.Binding) || receipt.OperationID != replacement.OperationID ||
				receipt.MutationDigest != replacement.MutationDigest || status != resultHTTPStatus(receipt.Result) {
				results <- response{err: errors.New("concurrent CAS receipt did not match its request")}
				return
			}
			results <- response{receipt: *receipt}
		}()
	}
	close(start)
	counts := map[string]int{}
	for range replacements {
		result := <-results
		if result.err != nil {
			return fmt.Errorf("concurrent CAS request failed: %w", result.err)
		}
		counts[result.receipt.Result]++
	}
	if counts[protocol.ResultApplied] != 1 || counts[protocol.ResultPreconditionFailed] != 1 || len(counts) != 2 {
		return fmt.Errorf(
			"concurrent same-generation replacements produced results %#v, want one applied and one preconditionFailed",
			counts,
		)
	}
	record, err := getRecord(ctx, client, binding, base.UpsertKey)
	if err != nil || record == nil || record.Generation != 2 ||
		(record.Content != replacements[0].State.Content && record.Content != replacements[1].State.Content) {
		return errors.New("concurrent CAS did not materialize exactly one generation-2 replacement")
	}
	return nil
}

func advanceFence(
	ctx context.Context,
	client *contractClient,
	binding protocol.Binding,
) (*protocol.RoutingFenceResponse, error) {
	body, status, err := client.postJSON(
		ctx,
		protocol.PathRoutingFence,
		protocol.RoutingFenceRequest{ProtocolVersion: protocol.Version, Binding: binding},
	)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK && status != http.StatusConflict {
		return nil, fmt.Errorf("routing fence returned HTTP %d", status)
	}
	response, err := protocol.DecodeRoutingFenceResponse(body)
	if err != nil {
		return nil, err
	}
	if !protocol.BindingEqual(response.Binding, binding) {
		return nil, errors.New("routing fence response did not echo the exact binding")
	}
	return response, nil
}

func mutation(
	ctx context.Context,
	client *contractClient,
	request protocol.MutationEnvelope,
	expectedResult string,
) (protocol.MutationReceipt, []byte, error) {
	body, status, err := client.postJSON(ctx, protocol.PathMutations, request)
	if err != nil {
		return protocol.MutationReceipt{}, nil, err
	}
	if containsCredential(body, client.authorizationValue) {
		return protocol.MutationReceipt{}, nil, errors.New("mutation response contained the bearer token")
	}
	receipt, err := protocol.DecodeMutationReceipt(body)
	if err != nil {
		return protocol.MutationReceipt{}, nil, err
	}
	if receipt.Result != expectedResult {
		return protocol.MutationReceipt{}, nil, fmt.Errorf(
			"mutation %s result = %s, want %s",
			request.OperationID,
			receipt.Result,
			expectedResult,
		)
	}
	if !protocol.BindingEqual(receipt.Binding, request.Binding) ||
		receipt.OperationID != request.OperationID ||
		receipt.MutationDigest != request.MutationDigest {
		return protocol.MutationReceipt{}, nil, errors.New("mutation receipt did not echo the request identity")
	}
	wantStatus := resultHTTPStatus(expectedResult)
	if status != wantStatus {
		return protocol.MutationReceipt{}, nil, fmt.Errorf(
			"mutation result %s returned HTTP %d, want %d",
			expectedResult,
			status,
			wantStatus,
		)
	}
	return *receipt, body, nil
}

func getRecord(
	ctx context.Context,
	client *contractClient,
	binding protocol.Binding,
	upsertKey string,
) (*protocol.MemoryRecord, error) {
	body, status, err := client.postJSON(
		ctx,
		protocol.PathRecordsGet,
		protocol.GetRequest{
			ProtocolVersion: protocol.Version,
			Binding:         binding,
			UpsertKey:       upsertKey,
		},
	)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("exact get returned HTTP %d", status)
	}
	response, err := protocol.DecodeGetResponse(body)
	if err != nil {
		return nil, err
	}
	if !protocol.BindingEqual(response.Binding, binding) {
		return nil, errors.New("exact get did not echo the binding")
	}
	return response.Record, nil
}

func lookupOperation(
	ctx context.Context,
	client *contractClient,
	binding protocol.Binding,
	operationID string,
) (*protocol.MutationReceipt, error) {
	body, status, err := client.postJSON(ctx, protocol.PathOperationsGet, protocol.OperationLookupRequest{
		ProtocolVersion: protocol.Version, Binding: binding, OperationID: operationID,
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("operation lookup returned HTTP %d", status)
	}
	response, err := protocol.DecodeOperationLookupResponse(body)
	if err != nil {
		return nil, err
	}
	if !protocol.BindingEqual(response.Binding, binding) {
		return nil, errors.New("operation lookup did not echo the binding")
	}
	return response.Receipt, nil
}

func search(
	ctx context.Context,
	client *contractClient,
	request protocol.SearchRequest,
) (*protocol.SearchResponse, error) {
	body, status, err := client.postJSON(ctx, protocol.PathSearch, request)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("search returned HTTP %d", status)
	}
	response, err := protocol.DecodeSearchResponse(body)
	if err != nil {
		return nil, err
	}
	if !protocol.BindingEqual(response.Binding, request.Binding) {
		return nil, errors.New("search did not echo the binding")
	}
	if response.RequestedMode != request.Mode {
		return nil, errors.New("search did not echo the requested mode")
	}
	if request.Mode != protocol.SearchModeAuto && response.ActualMode != request.Mode {
		return nil, errors.New("search changed an explicit requested mode")
	}
	if len(response.Records) > request.PageSize {
		return nil, fmt.Errorf(
			"search returned %d records for requested pageSize %d",
			len(response.Records),
			request.PageSize,
		)
	}
	if request.PageToken != "" && !response.Exhausted && !nextPageTokenFollows(request.PageToken, response.NextPageToken) {
		return nil, errors.New("search continuation token did not advance within the same snapshot")
	}
	return response, nil
}

func nextPageTokenFollows(current, next string) bool {
	currentParts := strings.Split(current, ".")
	nextParts := strings.Split(next, ".")
	if len(currentParts) != 3 ||
		len(nextParts) != 3 ||
		currentParts[0] != nextParts[0] ||
		currentParts[1] != nextParts[1] {
		return false
	}
	currentOffset, currentErr := strconv.Atoi(currentParts[2])
	nextOffset, nextErr := strconv.Atoi(nextParts[2])
	return currentErr == nil && nextErr == nil && nextOffset > currentOffset
}

func verifySearchModeCapabilities(
	ctx context.Context,
	client *contractClient,
	binding protocol.Binding,
	query string,
	capabilities protocol.Capabilities,
	pageSize int,
) error {
	autoRequest := protocol.SearchRequest{
		ProtocolVersion: protocol.Version, Binding: binding, Mode: protocol.SearchModeAuto,
		Query: query, PageSize: pageSize, PageToken: "",
	}
	auto, err := consumeSearchProbe(ctx, client, autoRequest)
	if err != nil {
		return fmt.Errorf("auto search failed: %w", err)
	}
	if !searchModeAdvertised(capabilities, auto.ActualMode) {
		return fmt.Errorf("auto search selected unadvertised mode %q", auto.ActualMode)
	}

	for _, probe := range []struct {
		mode       string
		advertised bool
	}{
		{mode: protocol.SearchModeSemantic, advertised: capabilities.SemanticSearch},
		{mode: protocol.SearchModeHybrid, advertised: capabilities.HybridSearch},
	} {
		request := protocol.SearchRequest{
			ProtocolVersion: protocol.Version, Binding: binding, Mode: probe.mode,
			Query: query, PageSize: pageSize, PageToken: "",
		}
		if probe.advertised {
			if _, err := consumeSearchProbe(ctx, client, request); err != nil {
				return fmt.Errorf("advertised explicit %s search failed: %w", probe.mode, err)
			}
			continue
		}

		body, err := json.Marshal(request)
		if err != nil {
			return err
		}
		response, err := client.doResponse(ctx, http.MethodPost, protocol.PathSearch, client.authorizationValue, body, nil)
		if err != nil {
			return err
		}
		if err := validateErrorVariant(response, errorExpectation{
			status: http.StatusUnprocessableEntity, code: protocol.ErrorCodeSearchModeUnsupported,
			binding: &binding, retryable: false, retryAfterSeconds: 0,
		}); err != nil {
			return fmt.Errorf("unadvertised explicit %s search returned the wrong error variant: %w", probe.mode, err)
		}
	}
	return nil
}

func consumeSearchProbe(
	ctx context.Context,
	client *contractClient,
	request protocol.SearchRequest,
) (*protocol.SearchResponse, error) {
	first, err := search(ctx, client, request)
	if err != nil {
		return nil, err
	}
	if first.Exhausted {
		return first, nil
	}
	if _, err := collectSnapshot(ctx, client, request, first); err != nil {
		return nil, err
	}
	return first, nil
}

func searchModeAdvertised(capabilities protocol.Capabilities, mode string) bool {
	switch mode {
	case protocol.SearchModeKeyword:
		return capabilities.KeywordSearch
	case protocol.SearchModeSemantic:
		return capabilities.SemanticSearch
	case protocol.SearchModeHybrid:
		return capabilities.HybridSearch
	default:
		return false
	}
}

func collectSnapshot(
	ctx context.Context,
	client *contractClient,
	request protocol.SearchRequest,
	first *protocol.SearchResponse,
) ([]protocol.MemoryRecord, error) {
	result := make([]protocol.MemoryRecord, 0, len(first.Records))
	seenRecords := make(map[string]struct{}, len(first.Records))
	if err := appendUniqueSnapshotRecords(&result, seenRecords, first.Records); err != nil {
		return nil, err
	}
	response := first
	seenTokens := map[string]struct{}{}
	for pages := 0; !response.Exhausted; pages++ {
		if pages > protocol.MaxSnapshotRecords {
			return nil, errors.New("pagination did not exhaust within the profile bound")
		}
		if _, duplicate := seenTokens[response.NextPageToken]; duplicate {
			return nil, errors.New("pagination repeated a continuation token")
		}
		seenTokens[response.NextPageToken] = struct{}{}
		request.PageToken = response.NextPageToken
		next, err := search(ctx, client, request)
		if err != nil {
			return nil, err
		}
		if next.ActualMode != first.ActualMode || !next.SnapshotExpiresAt.Equal(first.SnapshotExpiresAt) {
			return nil, errors.New("pagination continuation changed snapshot mode or expiry")
		}
		if err := appendUniqueSnapshotRecords(&result, seenRecords, next.Records); err != nil {
			return nil, err
		}
		response = next
	}
	return result, nil
}

type snapshotContinuation struct {
	Records           []protocol.MemoryRecord
	ActualMode        string
	SnapshotExpiresAt time.Time
}

func collectContinuation(
	ctx context.Context,
	client *contractClient,
	request protocol.SearchRequest,
) (snapshotContinuation, error) {
	result := make([]protocol.MemoryRecord, 0)
	seenTokens := map[string]struct{}{request.PageToken: {}}
	seenRecords := make(map[string]struct{})
	var snapshotExpiry time.Time
	var actualMode string
	for pages := 0; ; pages++ {
		if pages > protocol.MaxSnapshotRecords {
			return snapshotContinuation{}, errors.New("pagination continuation did not exhaust")
		}
		response, err := search(ctx, client, request)
		if err != nil {
			return snapshotContinuation{}, err
		}
		if snapshotExpiry.IsZero() {
			snapshotExpiry, actualMode = response.SnapshotExpiresAt, response.ActualMode
		} else if !response.SnapshotExpiresAt.Equal(snapshotExpiry) || response.ActualMode != actualMode {
			return snapshotContinuation{}, errors.New("pagination continuation changed snapshot mode or expiry")
		}
		if err := appendUniqueSnapshotRecords(&result, seenRecords, response.Records); err != nil {
			return snapshotContinuation{}, err
		}
		if response.Exhausted {
			if response.NextPageToken != "" {
				return snapshotContinuation{}, errors.New("exhausted response included a next page token")
			}
			return snapshotContinuation{
				Records: result, ActualMode: actualMode, SnapshotExpiresAt: snapshotExpiry,
			}, nil
		}
		if _, duplicate := seenTokens[response.NextPageToken]; duplicate {
			return snapshotContinuation{}, errors.New("pagination repeated a continuation token")
		}
		seenTokens[response.NextPageToken] = struct{}{}
		request.PageToken = response.NextPageToken
	}
}

func appendUniqueSnapshotRecords(
	destination *[]protocol.MemoryRecord,
	seen map[string]struct{},
	records []protocol.MemoryRecord,
) error {
	for _, record := range records {
		if _, duplicate := seen[record.UpsertKey]; duplicate {
			return errors.New("pagination repeated a memory record")
		}
		seen[record.UpsertKey] = struct{}{}
		*destination = append(*destination, record)
	}
	return nil
}

func makeMutation(
	binding protocol.Binding,
	operationID string,
	memoryID string,
	kind string,
	generation uint64,
	expectedGeneration uint64,
	expectedVersion string,
	state *protocol.MutationState,
) (protocol.MutationEnvelope, error) {
	request := protocol.MutationEnvelope{
		ProtocolVersion: protocol.Version, OperationID: operationID, Binding: binding,
		MemoryID: memoryID, Kind: kind, Generation: generation, ExpectedGeneration: expectedGeneration,
		ExpectedBackendVersion: expectedVersion, State: state,
	}
	if err := protocol.PrepareMutation(&request); err != nil {
		return protocol.MutationEnvelope{}, err
	}
	return request, nil
}

func resultHTTPStatus(result string) int {
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
		return 0
	}
}

func recordProofs(binding protocol.Binding, records []protocol.MemoryRecord) ([]string, []string, error) {
	keys := make([]string, 0, len(records))
	digests := make([]string, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for index := range records {
		record := &records[index]
		if _, duplicate := seen[record.UpsertKey]; duplicate {
			return nil, nil, errors.New("record proof contains a duplicate upsert key")
		}
		digest, err := protocol.MemoryRecordDigest(record, binding)
		if err != nil {
			return nil, nil, err
		}
		seen[record.UpsertKey] = struct{}{}
		keys = append(keys, record.UpsertKey)
		digests = append(digests, digest)
	}
	return keys, digests, nil
}

func recordDigestByKey(binding protocol.Binding, records []protocol.MemoryRecord) (map[string]string, error) {
	keys, digests, err := recordProofs(binding, records)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(keys))
	for index := range keys {
		result[keys[index]] = digests[index]
	}
	return result, nil
}

func verifySnapshotFixture(
	binding protocol.Binding,
	records []protocol.MemoryRecord,
	expectedDigests map[string]string,
) error {
	actualDigests, err := recordDigestByKey(binding, records)
	if err != nil {
		return err
	}
	if len(actualDigests) != len(expectedDigests) {
		return fmt.Errorf("keyword snapshot returned %d unique records, want %d", len(actualDigests), len(expectedDigests))
	}
	for key, expected := range expectedDigests {
		actual, exists := actualDigests[key]
		if !exists {
			return errors.New("keyword snapshot omitted an exact-get fixture")
		}
		if actual != expected {
			return errors.New("keyword snapshot record diverged from exact get")
		}
	}
	return nil
}

func verifyContinuationProof(
	binding protocol.Binding,
	continuation snapshotContinuation,
	checkpoint Checkpoint,
) error {
	if continuation.ActualMode != checkpoint.PaginationActualMode ||
		!continuation.SnapshotExpiresAt.Equal(checkpoint.PaginationSnapshotExpiry) {
		return errors.New("durable snapshot mode or expiry changed across restart")
	}
	keys, digests, err := recordProofs(binding, continuation.Records)
	if err != nil {
		return fmt.Errorf("durable snapshot continuation is invalid: %w", err)
	}
	if !slices.Equal(keys, checkpoint.PaginationExpectedKeys) {
		return fmt.Errorf("durable snapshot continuation keys = %v, want %v", keys, checkpoint.PaginationExpectedKeys)
	}
	if !slices.Equal(digests, checkpoint.PaginationExpectedDigests) {
		return errors.New("durable snapshot continuation records changed across restart")
	}
	return nil
}
func isCanonicalDigest(value string) bool {
	const prefix = "sha256:"
	encoded, ok := strings.CutPrefix(value, prefix)
	if !ok || len(encoded) != 64 || encoded != strings.ToLower(encoded) {
		return false
	}
	decoded, err := hex.DecodeString(encoded)
	return err == nil && len(decoded) == 32
}

func cloneState(state *protocol.MutationState) *protocol.MutationState {
	if state == nil {
		return nil
	}
	return &protocol.MutationState{
		Content:  state.Content,
		Tags:     append([]string(nil), state.Tags...),
		Metadata: cloneMap(state.Metadata),
	}
}

func cloneMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	maps.Copy(result, input)
	return result
}

func randomRunID() (string, error) {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func isSafeRunID(value string) bool {
	if value == "" || len(value) > 48 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// SanitizeCheckResult returns an output-safe result copy.
func SanitizeCheckResult(result CheckResult, authorizationValue string) CheckResult {
	result.Message = sanitizeOutputText(result.Message, authorizationValue, conformanceMessageLimit)
	if result.Capabilities != nil {
		copy := *result.Capabilities
		copy.AdapterName = sanitizeOutputText(copy.AdapterName, authorizationValue, protocol.MaxIdentityBytes)
		copy.AdapterVersion = sanitizeOutputText(copy.AdapterVersion, authorizationValue, protocol.MaxIdentityBytes)
		copy.Revision = sanitizeOutputText(copy.Revision, authorizationValue, protocol.MaxIdentityBytes)
		result.Capabilities = &copy
	}
	return result
}
