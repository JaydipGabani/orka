package controllerlab

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	Version                 = 1
	MaxStepClientOperations = 64
)

type Capability string

const (
	KEDANamespaceEvents Capability = "keda-namespace-events-v1"
	KEDAEventPublishing Capability = "keda-event-publishing-v2"
	KEDARedisAuth       Capability = "keda-redis-auth-v1"
)

type BoundSource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
}

type ActorAccess string

const (
	NamespaceAEventSource ActorAccess = "namespace-a-event-source"
	NamespaceBEventSource ActorAccess = "namespace-b-event-source"
)

type SemanticOutcome string

const (
	NamespacedEventScope              SemanticOutcome = "namespaced-event-scope"
	NamespacedEventCredentialScope    SemanticOutcome = "namespaced-event-credential-scope"
	UndelegatedClusterCredentialScope SemanticOutcome = "undelegated-cluster-credential-scope"
)

// Plan is model-facing. It cannot express Kubernetes objects, images, credentials,
// URLs, commands, RBAC, namespace names, or changes to the trusted runtime recipe.
type Plan struct {
	Version     int               `json:"version"`
	Capability  Capability        `json:"capability"`
	BoundSource BoundSource       `json:"boundSource"`
	RecipeID    string            `json:"recipeID"`
	Actors      []ActorAccess     `json:"actors"`
	Expected    []SemanticOutcome `json:"expected"`
}

type Role string

const (
	Original  Role = "original"
	Control   Role = "rebuilt-control"
	Candidate Role = "candidate"
)

// ImageBinding is installed by the parent after its independent build/provenance
// verification. An image's exit status is never observation evidence.
type ImageBinding struct {
	ID             string      `json:"id"`
	Role           Role        `json:"role"`
	Source         BoundSource `json:"source"`
	RecipeID       string      `json:"recipeID"`
	Image          string      `json:"image"`
	EvidenceDigest string      `json:"evidenceDigest"`
}

// ControllerRuntimeTemplate selects compiled code, not a general manifest recipe.
// The operator preinstalls the exact read-only cluster watcher role. This package
// creates only a run-owned binding to that role, never CRDs or cluster roles.
type ControllerRuntimeTemplate struct {
	RecipeID         string
	Family           string
	Source           BoundSource
	ClusterWatchRole ObjectRef
	Resources        corev1.ResourceRequirements
}

type EgressEndpoint struct {
	CIDR string
	Port int32
}

// Config is operator-only and is frozen by the constructor. The dedicated cluster
// must have no other KEDA instance or cluster event/auth sources. APIServer is an
// explicit operator-reviewed literal address; DNS egress is unsupported.
type Config struct {
	DedicatedClusterApproved bool
	ClusterIdentity          string
	NamespacePrefix          string
	Template                 ControllerRuntimeTemplate
	Bindings                 []ImageBinding
	ObserverImage            string
	ObserverResources        corev1.ResourceRequirements
	APIServer                EgressEndpoint
	// Opts into the pinned HTTP/HTTPS event-scope and undelegated-credential
	// contract. Cluster HTTP broadcasts remain normal controls; no endpoint is configurable.
	EnableEventPublishing bool `json:"enableEventPublishing,omitempty"`
	// DNS is retained only to reject older DNS-permitting operator configs.
	// The compiled fixture never grants DNS egress.
	DNS               EgressEndpoint
	StartupTimeout    time.Duration
	ObservationWindow time.Duration
	TailWindow        time.Duration
	OperationTimeout  time.Duration
}

type Clients struct {
	Kubernetes      kubernetes.Interface
	CustomResources dynamic.Interface
	Observer        Observer
}

// Hooks must be backed by the parent's private durable store. PersistState must
// atomically compare Revision, retain terminal tombstones, and reject CAS(0) for
// an already-used run/operation. Acceptance must recheck authorization before
// each mutation, including recovery and cleanup. Neither receives secret bytes.
type Hooks struct {
	Acceptance   func(context.Context, Mutation) error
	PersistState func(context.Context, uint64, State) error
}

type Mutation struct {
	RunID           string            `json:"runID"`
	OperationID     string            `json:"operationID"`
	OperationDigest string            `json:"operationDigest"`
	Action          string            `json:"action"`
	Object          ObjectRef         `json:"object"`
	Placement       *SubjectPlacement `json:"placement,omitempty"`
}

// SubjectPlacement is supplied ONLY by the trusted parent after it validates a
// completed/cleaned isolation proof. It is not part of model-facing Plan.
// ProofDigest identifies the parent's retained evidence, not a proof this
// package can independently validate.
type SubjectPlacement struct {
	OperationDigest string `json:"operationDigest"`
	NodeName        string `json:"nodeName"`
	ProofDigest     string `json:"proofDigest"`
}

type Request struct {
	RunID       string            `json:"runID"`
	OperationID string            `json:"operationID"`
	Plan        Plan              `json:"plan"`
	BindingID   string            `json:"bindingID"`
	Cancel      bool              `json:"cancel,omitempty"`
	Placement   *SubjectPlacement `json:"placement,omitempty"`
}

type Phase string

const (
	Preflight            Phase = "preflight"
	Preparing            Phase = "preparing"
	WaitingObserver      Phase = "waiting-observer"
	InstallingController Phase = "installing-controller"
	WaitingPlacement     Phase = "waiting-placement"
	WaitingRuntime       Phase = "waiting-runtime"
	InstallingSources    Phase = "installing-sources"
	WaitingSources       Phase = "waiting-sources"
	InstallingInitial    Phase = "installing-initial"
	ObservingInitial     Phase = "observing-initial"
	ObservingWindow      Phase = "observing-window"
	InstallingFinal      Phase = "installing-final"
	ObservingFinal       Phase = "observing-final"
	Settling             Phase = "settling"
	Cleaning             Phase = "cleaning"
	Complete             Phase = "complete"
	Quarantined          Phase = "quarantined"
)

type Outcome string

const (
	Reproduced    Outcome = "reproduced"
	Protected     Outcome = "protected"
	StillExposed  Outcome = "still-exposed"
	NotReproduced Outcome = "not-reproduced"
	Inconclusive  Outcome = "inconclusive"
	Cancelled     Outcome = "cancelled"
)

type ObjectRef struct {
	Resource  schema.GroupVersionResource `json:"resource"`
	Namespace string                      `json:"namespace,omitempty"`
	Name      string                      `json:"name"`
	UID       types.UID                   `json:"uid,omitempty"`
}

type Receipt struct {
	Object           ObjectRef         `json:"object"`
	IntentDigest     string            `json:"intentDigest"`
	DeleteRequested  bool              `json:"deleteRequested,omitempty"`
	Deleted          bool              `json:"deleted,omitempty"`
	BindingDigest    string            `json:"bindingDigest,omitempty"`
	FinalizerRemoval *FinalizerRemoval `json:"finalizerRemoval,omitempty"`
}

type FinalizerRemoval struct {
	ResourceVersion string `json:"resourceVersion"`
	Completed       bool   `json:"completed,omitempty"`
}

type Intent struct {
	Object ObjectRef `json:"object"`
	Digest string    `json:"digest"`
}

type EvidenceSummary struct {
	Generation     uint64              `json:"generation"`
	HTTPCount      int                 `json:"httpCount"`
	RESPCount      int                 `json:"respCount"`
	HTTPDigest     string              `json:"httpDigest"`
	RESPDigest     string              `json:"respDigest"`
	StateDigest    string              `json:"stateDigest"`
	InitialNormal  [2]bool             `json:"initialNormal"`
	FinalNormal    [2]bool             `json:"finalNormal"`
	CrossObserved  bool                `json:"crossObserved"`
	Publishing     *PublishingEvidence `json:"publishing,omitempty"`
	DuplicateHTTP  uint64              `json:"duplicateHTTP,omitempty"`
	BindingsDigest string              `json:"bindingsDigest,omitempty"`
}

// PublishingEvidence concerns request emission to synthetic infrastructure, not
// acceptance or authorization by Azure. HTTPS controls require both actual TLS
// data ingress and the exact channel's synthetic aeg-sas-key.
type PublishingEvidence struct {
	InitialHTTPS       [2]bool                  `json:"initialHTTPS"`
	FinalHTTPS         [2]bool                  `json:"finalHTTPS"`
	InitialClusterHTTP [2]bool                  `json:"initialClusterHTTP"`
	FinalClusterHTTP   [2]bool                  `json:"finalClusterHTTP"`
	HTTPCrossObserved  bool                     `json:"httpCrossObserved"`
	HTTPSCrossObserved bool                     `json:"httpsCrossObserved"`
	CredentialAttack   CredentialAttackEvidence `json:"credentialAttack"`
}

// CredentialAttackEvidence is independent of event namespace isolation.
// Referencing cluster authentication does not delegate its credential to a
// namespaced source's receiver. Initial/final observations require B events.
type CredentialAttackEvidence struct {
	Observed        bool `json:"observed"`
	InitialObserved bool `json:"initialObserved"`
	FinalObserved   bool `json:"finalObserved"`
}

type State struct {
	Version         int    `json:"version"`
	Revision        uint64 `json:"revision"`
	RunID           string `json:"runID"`
	OperationID     string `json:"operationID"`
	OperationDigest string `json:"operationDigest"`
	ConfigDigest    string `json:"configDigest"`
	PlanDigest      string `json:"planDigest"`
	// Omitted for the original HTTP-only contract to preserve its durable shape.
	Capability Capability `json:"capability,omitempty"`
	// A non-credential challenge seed, retained by the trusted journal only.
	// Observer configuration contains subject hashes, never this seed.
	FinalMarkerNonce    string            `json:"finalMarkerNonce,omitempty"`
	Role                Role              `json:"role"`
	ImageDigest         string            `json:"imageDigest"`
	Phase               Phase             `json:"phase"`
	Cursor              int               `json:"cursor"`
	Namespaces          [2]string         `json:"namespaces"`
	ObserverNamespace   string            `json:"observerNamespace"`
	ObserverPodIP       string            `json:"observerPodIP,omitempty"`
	ObserverImageDigest string            `json:"observerImageDigest,omitempty"`
	RuntimePod          *ObjectRef        `json:"runtimePod,omitempty"`
	Placement           *SubjectPlacement `json:"placement,omitempty"`
	SubjectStartedAt    time.Time         `json:"subjectStartedAt,omitempty"`
	StartedAt           time.Time         `json:"startedAt"`
	Deadline            time.Time         `json:"deadline"`
	WindowStartedAt     time.Time         `json:"windowStartedAt,omitempty"`
	TailStartedAt       time.Time         `json:"tailStartedAt,omitempty"`
	Outcome             Outcome           `json:"outcome,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	Intent              *Intent           `json:"intent,omitempty"`
	Receipts            []Receipt         `json:"receipts"`
	Evidence            EvidenceSummary   `json:"evidence"`
	ControllerStopped   bool              `json:"controllerStopped,omitempty"`
}

func (s State) Terminal() bool { return s.Phase == Complete || s.Phase == Quarantined }

type ErrorKind string

const (
	NeedsAdapter   ErrorKind = "needs-adapter"
	OutsideScope   ErrorKind = "outside-scope"
	Infrastructure ErrorKind = "infrastructure"
	OwnershipLost  ErrorKind = "ownership-lost"
	StoreRejected  ErrorKind = "store-rejected"
	InvalidState   ErrorKind = "invalid-state"
	TerminalRun    ErrorKind = "terminal-run"
)

// Error deliberately drops underlying Kubernetes, TLS and HTTP errors, which can
// contain reflected credentials or subject-controlled messages.
type Error struct {
	Kind ErrorKind
	Code string
}

func (e *Error) Error() string { return "controllerlab: " + string(e.Kind) + ": " + e.Code }

func failure(kind ErrorKind, code string) error { return &Error{Kind: kind, Code: code} }
