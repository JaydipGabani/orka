package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/store"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	Version         = 1
	MaxRequestBytes = 8 << 20
	MaxPolicyBytes  = 64 << 10
	MaxPatchBytes   = 256 << 10
)

var (
	ErrDisabled                   = errors.New("remediation service is disabled")
	ErrInvalid                    = errors.New("invalid remediation request")
	ErrPolicy                     = errors.New("remediation policy is unavailable or not permitted")
	ErrApproval                   = errors.New("remediation approval does not match the pending plan")
	ErrClaimLost                  = errors.New("remediation execution ownership was lost")
	ErrNeedsInput                 = errors.New("remediation requires additional input")
	ErrNeedsAdapter               = errors.New("no approved adapter covers the required environment")
	ErrUnknown                    = errors.New("remediation execution outcome requires reconciliation")
	ErrAttemptFailed              = errors.New("candidate did not pass the frozen checks")
	ErrAwaitApproval              = errors.New("remediation is awaiting exact plan approval")
	ErrRetryable                  = errors.New("remediation dependency is temporarily unavailable")
	ErrCleanupPending             = errors.New("remediation cleanup is awaiting observed completion")
	ErrChecksProposal             = errors.New("model did not produce a valid bounded check proposal")
	ErrAuthorizationUnavailable   = errors.Join(ErrRetryable, errors.New("remediation authorization is temporarily unavailable"))
	ErrIntakeConnectorUnavailable = errors.New("server-side incident acquisition is not configured; submit a complete authorized report snapshot")
)

type Mode string

const (
	Generate Mode = "generate"
	Validate Mode = "validate"
	Verify   Mode = "verify"
)

type Request struct {
	RequestID string          `json:"requestID"`
	Policy    string          `json:"policy,omitempty"`
	Mode      Mode            `json:"mode,omitempty"`
	Incident  string          `json:"incident,omitempty"`
	Report    json.RawMessage `json:"report,omitempty"`
	Patch     string          `json:"patch,omitempty"`
}

type Policy struct {
	Version              int                       `json:"version"`
	Name                 string                    `json:"name"`
	Namespace            string                    `json:"namespace"`
	AgentName            string                    `json:"agentName"`
	ProposalBackend      string                    `json:"proposalBackend,omitempty"`
	Copilot              *modelagent.CopilotConfig `json:"copilot,omitempty"`
	AllowRestrictedModel bool                      `json:"allowRestrictedModel"`
	Repositories         []string                  `json:"repositories"`
	Adapters             []AdapterPolicy           `json:"adapters"`
	MaxDurationSeconds   int                       `json:"maxDurationSeconds"`
	MaxCandidates        int                       `json:"maxCandidates"`
	MaxModelCalls        int                       `json:"maxModelCalls"`
	RequirePlanApproval  bool                      `json:"requirePlanApproval"`
	AllowTestChanges     bool                      `json:"allowTestChanges"`
}

type AdapterPolicy struct {
	Name          string          `json:"name"`
	Kind          string          `json:"kind"`
	Repositories  []string        `json:"repositories"`
	Configuration json.RawMessage `json:"configuration"`
}

type StoredRequest struct {
	RequestID       string         `json:"requestID"`
	ClientRequestID string         `json:"clientRequestID,omitempty"`
	Policy          string         `json:"policy"`
	Mode            Mode           `json:"mode"`
	Incident        string         `json:"incident,omitempty"`
	Report          *intake.Report `json:"report,omitempty"`
	Patch           string         `json:"patch,omitempty"`
	Actor           ActorIdentity  `json:"actor"`
}

type Status struct {
	ID              string                      `json:"id"`
	Namespace       string                      `json:"namespace"`
	RequestID       string                      `json:"requestID"`
	Mode            Mode                        `json:"mode"`
	Policy          string                      `json:"policy"`
	Phase           string                      `json:"phase"`
	Stage           string                      `json:"stage,omitempty"`
	Reason          string                      `json:"reason,omitempty"`
	Revision        uint64                      `json:"revision"`
	ApprovalDigest  string                      `json:"approvalDigest,omitempty"`
	CancelRequested bool                        `json:"cancelRequested"`
	CreatedAt       time.Time                   `json:"createdAt"`
	UpdatedAt       time.Time                   `json:"updatedAt"`
	Deadline        time.Time                   `json:"deadline"`
	Artifacts       []store.RemediationArtifact `json:"artifacts,omitempty"`
	Cleanup         *store.RemediationCleanup   `json:"cleanup,omitempty"`
}

// Processor advances durable stages. It must record external-operation intent
// before submitting work and retain exact identities for recovery/cancellation.
type Processor interface {
	Run(context.Context, *Session) error
	Cancel(context.Context, *Session) error
}

type Config struct {
	Namespace               string
	Policies                []Policy
	Store                   store.RemediationRunStore
	Processor               Processor
	Interval                time.Duration
	Lease                   time.Duration
	Workers                 int
	AdmissionDisabled       bool
	DispatchReader          client.Reader
	Authorize               func(context.Context, string, string, ActorIdentity) error
	IntakeRetention         time.Duration
	IntakeRetentionInterval time.Duration
}
