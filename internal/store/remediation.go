package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const (
	RemediationPhaseQueued        = "Queued"
	RemediationPhaseRunning       = "Running"
	RemediationPhaseNeedsInput    = "NeedsInput"
	RemediationPhaseNeedsAdapter  = "NeedsAdapter"
	RemediationPhaseNeedsApproval = "NeedsApproval"
	RemediationPhaseCancelling    = "Cancelling"
	RemediationPhaseSucceeded     = "Succeeded"
	RemediationPhaseFailed        = "Failed"
	RemediationPhaseCancelled     = "Cancelled"
	RemediationPhaseTimedOut      = "TimedOut"
)

const RemediationReasonCleanupQuarantined = "cleanup-quarantined"

const (
	RemediationMaxRequestBytes        = 8 << 20
	RemediationMaxPolicyBytes         = 64 << 10
	RemediationMaxStateBytes          = 1 << 20
	RemediationMaxReasonBytes         = 1024
	RemediationMaxRequestIDBytes      = 96
	RemediationMaxActiveRuns          = 1000
	RemediationMaxSubmitterActiveRuns = 10
	RemediationMaxNamespaceBytes      = 512 << 20
	RemediationMaxListLimit           = 100
	RemediationMaxArtifactBytes       = 8 << 20
	RemediationMaxArtifactTotalBytes  = 64 << 20
	RemediationMaxArtifacts           = 128
	RemediationMaxClaimLease          = 5 * time.Minute
	RemediationMaxCleanupAttempts     = 8
	RemediationMaxCleanupDuration     = 5 * time.Minute
)

// ErrRemediationIntegrity means stored artifact bytes no longer match their
// immutable SHA-256 receipt. Callers must not use the returned content.
var ErrRemediationIntegrity = errors.New("remediation artifact integrity check failed")

// RemediationRun freezes namespace-bound submission input and policy. RequestJSON,
// PolicyJSON, and StateJSON contain at most 8 MiB, 64 KiB, and 1 MiB respectively.
// Callers must supply sanitized content, never credentials or raw tokens.
//
// Revision fences content updates; ClaimEpoch independently fences ownership.
// Claim acquisition and renewal do not change Revision. Terminal records cannot
// be mutated. Cancellation is irreversible and prevents subsequent success.
type RemediationRun struct {
	// Intake is write-only acquisition input, encrypted atomically on creation.
	// It is never included in rows, status JSON or artifact enumeration.
	Intake             []byte              `json:"-"`
	SourceOperationKey string              `json:"-"`
	Namespace          string              `json:"namespace"`
	ID                 string              `json:"id"`
	RequestID          string              `json:"requestId"`
	SubmittedBy        string              `json:"submittedBy"`
	Mode               string              `json:"mode"`
	PolicyDigest       string              `json:"policyDigest"`
	InputDigest        string              `json:"inputDigest"`
	RequestJSON        json.RawMessage     `json:"requestJson"`
	PolicyJSON         json.RawMessage     `json:"policyJson"`
	StateJSON          json.RawMessage     `json:"stateJson"`
	Phase              string              `json:"phase"`
	Reason             string              `json:"reason,omitempty"`
	Revision           uint64              `json:"revision"`
	ClaimEpoch         uint64              `json:"claimEpoch"`
	ClaimOwner         string              `json:"claimOwner,omitempty"`
	ClaimUntil         time.Time           `json:"claimUntil"`
	CreatedAt          time.Time           `json:"createdAt"`
	UpdatedAt          time.Time           `json:"updatedAt"`
	Deadline           time.Time           `json:"deadline"`
	CancelRequested    bool                `json:"cancelRequested"`
	ApprovalDigest     string              `json:"approvalDigest,omitempty"`
	ApprovedDigest     string              `json:"approvedDigest,omitempty"`
	ApprovedBy         string              `json:"approvedBy,omitempty"`
	Cleanup            *RemediationCleanup `json:"cleanup,omitempty"`
}

// RemediationCleanup is bounded, controller-owned settlement metadata. It is
// stored separately from payload JSON so quota exhaustion cannot prevent
// recording the cleanup deadline or failure budget.
type RemediationCleanup struct {
	Phase            string    `json:"phase"`
	Reason           string    `json:"reason"`
	Attempts         int       `json:"attempts"`
	StartedAt        time.Time `json:"startedAt"`
	LastAttemptEpoch uint64    `json:"lastAttemptEpoch,omitempty"`
	RecoveryEpoch    uint64    `json:"recoveryEpoch,omitempty"`
}

// RemediationUpdate replaces mutable worker state. Empty StateJSON preserves the
// previous state. Other fields replace their previous values, including empty
// Reason and ApprovalDigest. ApprovalDigest must be nonempty for NeedsApproval
// and empty for every other phase. ApprovedDigest and ApprovedBy can only be
// written by ApproveRemediationRun.
type RemediationUpdate struct {
	Phase          string          `json:"phase"`
	Reason         string          `json:"reason,omitempty"`
	StateJSON      json.RawMessage `json:"stateJson,omitempty"`
	ApprovalDigest string          `json:"approvalDigest,omitempty"`
}

// RemediationArtifact is an immutable per-run receipt. Digest is
// "sha256:" followed by the lowercase hex SHA-256 of its exact bytes.
type RemediationArtifact struct {
	Name      string    `json:"name"`
	Digest    string    `json:"digest"`
	MediaType string    `json:"mediaType"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
}

type RemediationRunCounts struct {
	Active          int64
	Quarantined     int64
	RetainedIntakes int64
}

type RemediationRunPage struct {
	Items    []RemediationRun
	Continue string
}

// RemediationRunStore requires an exact, nonempty namespace on every operation.
// InitializeRemediationStore is explicitly invoked by the opting-in service;
// constructing an ordinary store does not enable this schema.
//
// Contract revision: NeedsInput and NeedsAdapter are terminal non-success
// outcomes, not resumable pauses. NeedsApproval is the only paused phase and
// becomes claimable at its deadline solely for TimedOut settlement. Submission
// replay compares client input, not the current server policy; the original
// policy stays frozen. Lists and explicit metadata reads do not load JSON blobs.
type RemediationRunStore interface {
	InitializeRemediationStore(ctx context.Context) error

	// CreateRemediationRun returns created=true only for a new record. The service
	// supplies a random rm-<32 lowercase hex> ID and a stable DNS-like RequestID.
	// Reusing (Namespace, RequestID) requires identical SubmittedBy, Mode,
	// InputDigest and RequestJSON; otherwise it returns ErrDuplicateMismatch.
	// Replays return the original ID, frozen policy, and current state.
	// New runs start Queued at revision 1. Limits are 1000 nonterminal runs per
	// namespace, 10 per submitter within that namespace, and 512 MiB of persisted
	// request/policy/state/artifact payload bytes per namespace, including terminal
	// records. Exact replays remain available at capacity. Only encrypted raw
	// intake has automatic terminal-only retention; runs and artifacts remain.
	CreateRemediationRun(ctx context.Context, run *RemediationRun) (*RemediationRun, bool, error)
	GetRemediationRun(ctx context.Context, namespace, id string) (*RemediationRun, error)
	// GetRemediationRunByRequestID reads the immutable submission before live
	// admission dependencies are consulted. Callers must still authorize the
	// current actor/policy and compare exact submission fields before replay.
	GetRemediationRunByRequestID(ctx context.Context, namespace, requestID string) (*RemediationRun, error)
	// GetRemediationRunMetadata does not load RequestJSON, PolicyJSON, or
	// StateJSON; these fields are nil in the returned record.
	GetRemediationRunMetadata(ctx context.Context, namespace, id string) (*RemediationRun, error)
	// ListRemediationRuns returns metadata only, newest submissions first, with
	// a limit in [1, 100]. All three JSON fields are nil, without loading blobs.
	ListRemediationRuns(ctx context.Context, namespace string, limit int) ([]RemediationRun, error)
	// ListRemediationRunsPage uses the last returned ID as a namespace-scoped
	// keyset cursor, with the same metadata-only, at-most-100-row contract.
	ListRemediationRunsPage(ctx context.Context, namespace string, limit int, beforeID string) (RemediationRunPage, error)
	// CountRemediationRuns covers the complete namespace without loading private
	// JSON or being limited by the paginated metadata listing.
	CountRemediationRuns(ctx context.Context, namespace string) (RemediationRunCounts, error)

	// ClaimNextRemediationRun claims the oldest eligible run, increments its
	// epoch, and returns ErrNotFound when none is available. NeedsApproval is not
	// eligible until cancellation or its deadline. The service claims expired
	// runs to durably settle them as TimedOut; it cannot bypass pending approval.
	// Leases must be positive and no longer than five minutes.
	ClaimNextRemediationRun(ctx context.Context, namespace, owner string, now time.Time, lease time.Duration) (*RemediationRun, error)
	RenewRemediationClaim(ctx context.Context, namespace, id, owner string, epoch uint64, now time.Time, lease time.Duration) error
	// UpdateRemediationRun requires the unexpired owner/epoch and exact content
	// revision. It increments Revision and preserves all submission fields.
	// Paused and terminal transitions release the claim. Following cancellation,
	// only Cancelling or Cancelled may be committed.
	UpdateRemediationRun(ctx context.Context, namespace, id, owner string, epoch, expectedRevision uint64, update RemediationUpdate, now time.Time) (*RemediationRun, error)
	// CancelRemediationRun sets the durable flag and Cancelling phase without
	// stealing a live claim. Already-cancelled or terminal runs are unchanged.
	CancelRemediationRun(ctx context.Context, namespace, id string, now time.Time) (*RemediationRun, error)
	// UpdateRemediationCleanup changes only bounded settlement metadata and
	// phase/reason. It preserves payloads and requires the current claim/revision.
	// Complete records observed cleanup, never a force-release. Quarantine
	// releases the worker lease, never the active source/effect reservation.
	UpdateRemediationCleanup(ctx context.Context, namespace, id, owner string, epoch, expectedRevision uint64, cleanup RemediationCleanup, complete bool, now time.Time) (*RemediationRun, error)
	// BeginRemediationCleanupAttempt persists the current attempt epoch before
	// any cleanup effects. A new claim may reserve one post-deadline recovery
	// attempt per cleanup window, without resetting StartedAt or failed Attempts.
	// The reservation survives crashes, preventing repeated restart bypasses.
	BeginRemediationCleanupAttempt(ctx context.Context, namespace, id, owner string, epoch, expectedRevision uint64, cleanup RemediationCleanup, now time.Time) (*RemediationRun, error)
	// ReconcileRemediationCleanup is an explicitly audited cleanup-only re-drive.
	// Only an exact quarantined revision without a live claim is eligible.
	// It fences old workers and resets cleanup budgets, never execution state,
	// external resource identities, cancellation, or the active source claim.
	ReconcileRemediationCleanup(ctx context.Context, namespace, id, actor string, expectedRevision uint64, now time.Time) (*RemediationRun, error)
	// PruneRemediationIntake removes at most limit encrypted intake rows for
	// settled terminal runs whose last update precedes cutoff. Active,
	// quarantined, or unknown/orphaned snapshots are never eligible.
	PruneRemediationIntake(ctx context.Context, namespace string, cutoff time.Time, limit int) (int64, error)
	// ApproveRemediationRun only accepts the exact pending plan digest while
	// NeedsApproval and before its deadline. It records ApprovedDigest/ApprovedBy,
	// clears ApprovalDigest, and queues the run with a new revision. Repeating the
	// same actor/digest returns the unchanged Queued, Running, or terminal record
	// if no approval is pending. The service must re-authorize every request.
	// New approval requests clear the previous receipt; workers cannot forge it.
	ApproveRemediationRun(ctx context.Context, namespace, id, planDigest, actor string, now time.Time) (*RemediationRun, error)

	// Artifacts require an active claim to write, and exact name/media-type/byte
	// replay is idempotent. Conflicting replay returns ErrConflict. Bounds are
	// 8 MiB per artifact, 64 MiB total bytes, and 128 names per run. Reads verify
	// stored bytes against their SHA-256 receipt. No removal/reset is supported.
	PutRemediationArtifact(ctx context.Context, namespace, id, owner string, epoch uint64, name, mediaType string, data []byte, now time.Time) (*RemediationArtifact, error)
	GetRemediationArtifact(ctx context.Context, namespace, id, name string) (*RemediationArtifact, []byte, error)
	ListRemediationArtifacts(ctx context.Context, namespace, id string) ([]RemediationArtifact, error)
}

func IsRemediationTerminalPhase(phase string) bool {
	switch phase {
	case RemediationPhaseSucceeded, RemediationPhaseFailed, RemediationPhaseCancelled, RemediationPhaseTimedOut,
		RemediationPhaseNeedsInput, RemediationPhaseNeedsAdapter:
		return true
	default:
		return false
	}
}

// RemediationSourceOperationKey is shared by submission and store migration.
// Preserve this canonical JSON identity across upgrades: changing it would
// permit a different client request ID to bypass an existing source claim.
func RemediationSourceOperationKey(policy, sourceKind, sourceID, inputDigest, mode, patch string) (string, error) {
	if policy == "" || inputDigest == "" || (mode != "generate" && mode != "validate" && mode != "verify") {
		return "", ErrValidation
	}
	source, record := "report", inputDigest
	if sourceID != "" {
		if sourceKind == "" {
			return "", ErrValidation
		}
		source, record = sourceKind, sourceID
	}
	patchDigest := sha256.Sum256([]byte(patch))
	raw, err := json.Marshal(struct{ Policy, Source, Record, Mode, Patch string }{
		policy, source, record, mode, "sha256:" + hex.EncodeToString(patchDigest[:]),
	})
	if err != nil {
		return "", ErrValidation
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
