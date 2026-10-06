// Package buildjob runs a trusted, fixed-function BuildKit client in durable
// Kubernetes Jobs. Candidate build instructions execute only in the separately
// approved, isolated BuildKit daemon, never in this client or the controller.
package buildjob

import (
	"errors"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const (
	Version             = 1
	MaxInputBytes       = 768 << 10
	MaxTerminationBytes = 4096
	MaxDiagnostics      = 8
)

var (
	ErrInvalid       = errors.New("invalid build configuration or input")
	ErrIdentity      = errors.New("build identity or ownership changed")
	ErrLost          = errors.New("accepted build is missing; replay forbidden")
	ErrAPI           = errors.New("build API operation unavailable")
	ErrCleanup       = errors.New("build cleanup is incomplete")
	ErrLimit         = errors.New("build operation limit exceeded")
	ErrIndeterminate = errors.New("build submission acknowledgement unavailable")
)

// Config is operator configuration, not a model/tool input. Both clients must
// address the same API server; APIReader must bypass informer caches.
type Config struct {
	Kube               kubernetes.Interface
	APIReader          kubernetes.Interface
	Namespace          string
	WorkerImage        string
	BuildKitAddress    string
	TLS                *TLS
	RegistrySecretName string
	Policies           []Policy
	Limits             Limits
}

// TLS contains operator-owned Secret references, never credential values.
// The CA and client Secrets must be immutable and in the build namespace.
type TLS struct {
	CASecretName     string `json:"caSecretName"`
	ServerName       string `json:"serverName"`
	ClientSecretName string `json:"clientSecretName,omitempty"`
}

type SecretIdentity struct {
	Name            string    `json:"name"`
	UID             types.UID `json:"uid"`
	ResourceVersion string    `json:"resourceVersion"`
}

// TLSSecrets fences authentication material using metadata only. No credential
// bytes or hashes of credential bytes enter a receipt or the input digest.
type TLSSecrets struct {
	CA     SecretIdentity `json:"ca"`
	Client SecretIdentity `json:"client"`
}

// Policy freezes every frontend option. SourcePaths adds operator-approved
// diagnostic paths, not permission to read their contents.
type Policy struct {
	RecipePath       string            `json:"recipePath"`
	Frontend         string            `json:"frontend"`
	Worker           string            `json:"worker"`
	WorkerArg        string            `json:"workerArg,omitempty"`
	WorkerContext    string            `json:"workerContext,omitempty"`
	Target           string            `json:"target"`
	Platform         string            `json:"platform"`
	OutputRepository string            `json:"outputRepository"`
	Args             map[string]string `json:"args,omitempty"`
	SourcePaths      []string          `json:"sourcePaths,omitempty"`
	// BuildOnlyInputs are exact, operator-acquired baseline patch bytes.
	// They may execute only in the private build boundary, never be disclosed.
	BuildOnlyInputs map[string]string `json:"buildOnlyInputs,omitempty"`
}

type Limits struct {
	MaxInputBytes     int           `json:"maxInputBytes"`
	MaxFileBytes      int           `json:"maxFileBytes"`
	MaxFiles          int           `json:"maxFiles"`
	MaxOperations     int           `json:"maxOperations"`
	MaxLogBytes       int           `json:"maxLogBytes"`
	BuildTimeout      time.Duration `json:"buildTimeout"`
	SettlementTimeout time.Duration `json:"settlementTimeout"`
	APITimeout        time.Duration `json:"apiTimeout"`
	CleanupTimeout    time.Duration `json:"cleanupTimeout"`
	PollInterval      time.Duration `json:"pollInterval"`
	CPU               string        `json:"cpu"`
	Memory            string        `json:"memory"`
}

type Input struct {
	RunID            string            `json:"runID"`
	OperationID      string            `json:"operationID"`
	InputDigest      string            `json:"inputDigest,omitempty"`
	Files            map[string][]byte `json:"files"`
	RecipePath       string            `json:"recipePath"`
	Frontend         string            `json:"frontend"`
	Worker           string            `json:"worker"`
	WorkerArg        string            `json:"workerArg,omitempty"`
	WorkerContext    string            `json:"workerContext,omitempty"`
	Target           string            `json:"target"`
	Platform         string            `json:"platform"`
	OutputRepository string            `json:"outputRepository"`
	Args             map[string]string `json:"args,omitempty"`
	BuildOnlyInputs  map[string]string `json:"buildOnlyInputs,omitempty"`
	RequireExisting  bool              `json:"requireExisting,omitempty"`
	ExpectedJobUID   types.UID         `json:"expectedJobUID,omitempty"`
}

// Receipt is the durable workflow handle. Persist it, including on a Start error
// when it has UIDs. RequireExisting and ExpectedJobUID prohibit new submission
// when the caller is recovering an already-accepted operation.
type Receipt struct {
	Version             int            `json:"version"`
	RunID               string         `json:"runID"`
	OperationID         string         `json:"operationID"`
	InputDigest         string         `json:"inputDigest"`
	ConfigurationDigest string         `json:"configurationDigest"`
	Namespace           string         `json:"namespace"`
	NamespaceUID        types.UID      `json:"namespaceUID"`
	LedgerName          string         `json:"ledgerName"`
	LedgerUID           types.UID      `json:"ledgerUID"`
	AnchorName          string         `json:"anchorName"`
	AnchorUID           types.UID      `json:"anchorUID"`
	JobName             string         `json:"jobName"`
	JobUID              types.UID      `json:"jobUID"`
	TLSSecrets          TLSSecrets     `json:"tlsSecrets"`
	RegistrySecret      SecretIdentity `json:"registrySecret,omitzero"`
}

type BuildOutcome string

const (
	Success        BuildOutcome = "success"
	CompileFailure BuildOutcome = "compile-failure"
	TestFailure    BuildOutcome = "test-failure"
	Infrastructure BuildOutcome = "infrastructure"
	Cancelled      BuildOutcome = "cancelled"
)

// Diagnostic is untrusted repair advice, never disclosure or success evidence.
// TestName without Path/Line means that no approved source location was bound.
type Diagnostic struct {
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Column   int    `json:"column,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
	TestName string `json:"testName,omitempty"`
}

// WorkerResult is the only accepted termination-message wire format.
type WorkerResult struct {
	Version      int          `json:"version"`
	InputDigest  string       `json:"inputDigest"`
	BuildOutcome BuildOutcome `json:"buildOutcome"`
	// BuildExitCode is required for TestFailure and preserves the client's
	// actual nonzero exit. Older outcomes retain their existing wire shape.
	BuildExitCode        int          `json:"buildExitCode,omitempty"`
	ImmutableImageDigest string       `json:"immutableImageDigest,omitempty"`
	Diagnostics          []Diagnostic `json:"diagnostics,omitempty"`
	OutputTruncated      bool         `json:"outputTruncated,omitempty"`
	BuildRef             string       `json:"buildRef,omitempty"`
	DaemonSettled        bool         `json:"daemonSettled"`
}

type Result struct {
	Receipt Receipt `json:"receipt"`
	WorkerResult
	Done             bool      `json:"done"`
	PodName          string    `json:"podName,omitempty"`
	PodUID           types.UID `json:"podUID,omitempty"`
	ContainerImageID string    `json:"containerImageID,omitempty"`
	Image            string    `json:"image,omitempty"`
	ResultDigest     string    `json:"resultDigest,omitempty"`
}

// BindingDigest is a consistency checksum, not authentication. Only Observe
// establishes that these fields were measured from the trusted Kubernetes path.
func (r Result) BindingDigest() string {
	r.ResultDigest = ""
	return jsonDigest(struct {
		Domain string
		Result Result
	}{"orka.remediation.buildjob.result.v1", r})
}

// CleanupReceipt is returned only after exact-UID Job/anchor deletion and all
// observed owned Pods have disappeared and trusted workers have reported exact
// receiving-daemon build completion. This does not attest cache garbage collection.
type CleanupReceipt struct {
	Receipt
	PodUIDs           []types.UID `json:"podUIDs,omitempty"`
	SubmissionSettled bool        `json:"submissionSettled"`
	Stopped           bool        `json:"stopped"`
	DaemonSettled     bool        `json:"daemonSettled"`
	CleanupDigest     string      `json:"cleanupDigest"`
}

// BindingDigest checks persisted evidence for consistency; it does not replace
// Cleanup's authoritative API observation.
func (r CleanupReceipt) BindingDigest() string {
	r.CleanupDigest = ""
	return jsonDigest(struct {
		Domain string
		Proof  CleanupReceipt
	}{"orka.remediation.buildjob.cleanup.v1", r})
}

type codedError struct {
	code string
	kind error
}

func (e *codedError) Error() string { return e.code }
func (e *codedError) Unwrap() error { return e.kind }

func failure(kind error, code string) error {
	return &codedError{kind: kind, code: code}
}
