// Package isolation measures NetworkPolicy enforcement using a trusted, pinned
// TCP canary. Its receipts and proofs are private controller state, not model
// inputs or claims that a NetworkPolicy object's presence provides isolation.
package isolation

import (
	"context"
	"reflect"
	"time"

	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const Version = 1

// Config is operator-only. ControlNamespace must be an exclusively reserved,
// empty, parent-owned namespace, distinct from the subject namespace. This
// adapter neither allocates nor deletes namespaces and never loads credentials.
type Config struct {
	ProbeImage       string           `json:"probeImage"`
	ControlNamespace SubjectNamespace `json:"controlNamespace"`
	Timeout          time.Duration    `json:"timeout"`
}

type SubjectNamespace struct {
	Name string    `json:"name"`
	UID  types.UID `json:"uid"`
}

// PolicyIdentity binds the API-server-observed policy, including its revision.
// PolicyDigest hashes the policy spec; UID and ResourceVersion are separate
// fences, so metadata-only changes also invalidate an in-progress proof.
type PolicyIdentity struct {
	Name            string    `json:"name"`
	UID             types.UID `json:"uid"`
	ResourceVersion string    `json:"resourceVersion"`
	Digest          string    `json:"digest"`
}

// ReceiptCallback must durably CAS Revision-1 to Revision before returning.
// Reject an initial Revision=1 for an already-used run/operation, and retain
// terminal tombstones. Calls for the same operation must be serialized by the
// caller. Never feed the receipt (including its synthetic nonce) to a model.
type ReceiptCallback func(context.Context, Receipt) error

type Phase string

const (
	Preparing      Phase = "preparing"
	WaitingCanary  Phase = "waiting-canary"
	PositiveBefore Phase = "positive-before"
	Negative       Phase = "negative"
	PositiveAfter  Phase = "positive-after"
	Cleaning       Phase = "cleaning"
	Complete       Phase = "complete"
	Failed         Phase = "failed"
)

type Outcome string

const (
	Pending   Outcome = "pending"
	Passed    Outcome = "passed"
	Rejected  Outcome = "failed"
	Cancelled Outcome = "cancelled"
)

// Error contains only a fixed classifier, never Kubernetes errors, addresses,
// termination messages, or other potentially private reflected data.
type Error struct {
	Code string
}

func (e *Error) Error() string { return "isolation: needs-adapter: " + e.Code }

type ObjectReceipt struct {
	Role                  string    `json:"role"`
	Kind                  string    `json:"kind"`
	Namespace             string    `json:"namespace"`
	Name                  string    `json:"name"`
	UID                   types.UID `json:"uid,omitempty"`
	ResourceVersion       string    `json:"resourceVersion,omitempty"`
	ActiveDeadlineSeconds int64     `json:"activeDeadlineSeconds,omitempty"`
	CreateAttempted       bool      `json:"createAttempted,omitempty"`
	DeleteRequested       bool      `json:"deleteRequested,omitempty"`
	Deleted               bool      `json:"deleted,omitempty"`
}

type Endpoint struct {
	Pod        ObjectReceipt `json:"pod"`
	Address    string        `json:"address"`
	NodeName   string        `json:"nodeName"`
	ImageID    string        `json:"imageID"`
	ObservedAt time.Time     `json:"observedAt"`
}

type Observation struct {
	Phase       Phase         `json:"phase"`
	Pod         ObjectReceipt `json:"pod"`
	ImageID     string        `json:"imageID"`
	NodeName    string        `json:"nodeName"`
	EndpointUID types.UID     `json:"endpointUID"`
	Target      string        `json:"target"`
	StartedAt   time.Time     `json:"startedAt"`
	FinishedAt  time.Time     `json:"finishedAt"`
	ObservedAt  time.Time     `json:"observedAt"`
	Result      probe.Result  `json:"result"`
}

// Proof is a private, point-in-time measurement of one exact canary path, not a
// universal CNI attestation. The parent must bind the subsequent subject to the
// same namespace, labels, node and frozen policy set, without a policy mutation.
type Proof struct {
	Verified              bool              `json:"verified"`
	ClusterUID            types.UID         `json:"clusterUID"`
	SubjectNamespace      SubjectNamespace  `json:"subjectNamespace"`
	ControlNamespace      SubjectNamespace  `json:"controlNamespace"`
	SubjectSelectorLabels map[string]string `json:"subjectSelectorLabels"`
	Policy                PolicyIdentity    `json:"policy"`
	SubjectPolicies       []PolicyIdentity  `json:"subjectPolicies"`
	ProbeImage            string            `json:"probeImage"`
	Endpoint              Endpoint          `json:"endpoint"`
	Observations          []Observation     `json:"observations"`
	SameNode              bool              `json:"sameNode"`
	CompletedAt           time.Time         `json:"completedAt,omitempty"`
}

// Receipt is the complete restart state. Resume with Observe, never with Start.
// A returned receipt may contain an acknowledged UID whose persistence failed;
// retain it and retry persistence/Cancel. Unknown-UID create windows cannot be
// adopted for proof, only recovered for cleanup under the frozen namespace UID.
type Receipt struct {
	Version         int               `json:"version"`
	Revision        uint64            `json:"revision"`
	RunID           string            `json:"runID"`
	OperationID     string            `json:"operationID"`
	OperationDigest string            `json:"operationDigest"`
	Config          Config            `json:"config"`
	Nonce           string            `json:"nonce"`
	StartedAt       time.Time         `json:"startedAt"`
	Deadline        time.Time         `json:"deadline"`
	SubjectLabels   map[string]string `json:"subjectNamespaceLabels"`
	ControlLabels   map[string]string `json:"controlNamespaceLabels"`
	Phase           Phase             `json:"phase"`
	Outcome         Outcome           `json:"outcome"`
	FailureCode     string            `json:"failureCode,omitempty"`
	Objects         []ObjectReceipt   `json:"objects"`
	Proof           Proof             `json:"proof"`
	CleanupComplete bool              `json:"cleanupComplete"`
}

type Adapter struct {
	kube kubernetes.Interface
	now  func() time.Time
}

// New accepts a dedicated, uncached Kubernetes client from trusted code.
func New(client kubernetes.Interface) (*Adapter, error) {
	if client == nil || (reflect.ValueOf(client).Kind() == reflect.Pointer && reflect.ValueOf(client).IsNil()) {
		return nil, &Error{Code: "kubernetes-client-required"}
	}
	return &Adapter{kube: client, now: time.Now}, nil
}
