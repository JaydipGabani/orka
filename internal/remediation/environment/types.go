package environment

import (
	"context"
	"time"

	"github.com/orka-agents/orka/internal/remediation/isolation"
	"github.com/orka-agents/orka/internal/remediation/provenance"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

const Version = 1

type ErrorKind string

const (
	BuildFailed     ErrorKind = "build-failed"
	AssertionFailed ErrorKind = "assertion-failed"
	Infrastructure  ErrorKind = "infrastructure"
	NeedsAdapter    ErrorKind = "needs-adapter"
	Unknown         ErrorKind = "unknown"
)

// Error intentionally excludes underlying process, Kubernetes, and HTTP errors:
// those errors can contain credentials, private names, or reflected request data.
type Error struct {
	Kind      ErrorKind `json:"kind"`
	Code      string    `json:"code"`
	Retryable bool      `json:"retryable,omitempty"`
}

func (e *Error) Error() string { return "environment: " + string(e.Kind) + ": " + e.Code }

func failure(kind ErrorKind, code string) error { return &Error{Kind: kind, Code: code} }

type Config struct {
	Repositories   []RepositoryPolicy
	AllowedGVKs    []schema.GroupVersionKind
	Kubernetes     *KubernetesConfig
	Isolation      *IsolationConfig `json:"Isolation,omitempty"`
	BuildKit       *BuildKitConfig
	BuildJobs      *BuildJobsConfig `json:"BuildJobs,omitempty"`
	ImageBindings  []ImageBinding
	OutputRoot     string
	TemporaryRoot  string
	SyntheticScope string
	Limits         Limits
}

type RepositoryPolicy struct {
	ID  string
	URL string
	// SourceRoot is optional and is never copied or read by the Dalec builder.
	// The approved recipe's pinned Git source supplies the build checkout.
	SourceRoot        string
	RecipeRoot        string
	RecipeRepository  string
	Recipes           []RecipePolicy
	CheckCapabilities []string
	HTTPPorts         []int32
}

// Files are exact, operator-approved recipe inputs, not a glob or a checkout
// copy. Each value is a SHA-256 digest; the recipe itself must be included.
type RecipePolicy struct {
	ID string
	// CatalogDirectory selects a versioned context beneath RecipeRoot. It is
	// operator-only; Path and Files keep their original repository-relative names.
	CatalogDirectory string
	Commit           string
	Path             string
	Files            map[string]string
	UpstreamSource   string
	Target           string
	Platform         string
	FrontendImage    string
	WorkerImage      string
	OriginalImage    string
	ExpectedVersion  string
	ExpectedRevision string
	AttestedInputs   *provenance.AttestedBuildInputs
}

// RecipeChoice is safe discovery data, not executor configuration or a claim of
// runtime readiness. Model proposals select ID; the trusted caller uses
// BindRecipe to fill the exact source/recipe binding without model-supplied paths.
type RecipeChoice struct {
	ID                  string       `json:"id"`
	SourceTarget        SourceTarget `json:"sourceTarget"`
	Version             string       `json:"version"`
	Revision            string       `json:"revision"`
	Target              string       `json:"target"`
	Platform            string       `json:"platform"`
	RecipeDigest        string       `json:"recipeDigest"`
	OriginalImage       string       `json:"originalImage"`
	OrderedPatchDigests []string     `json:"orderedPatchDigests"`
	HTTPPorts           []int32      `json:"httpPorts"`
	SupportedChecks     []string     `json:"supportedChecks"`
	NeedsAdapterChecks  []string     `json:"needsAdapterChecks"`
}

type KubernetesConfig struct {
	Kubeconfig    string
	Context       string
	ObserverCIDRs []string
}

// IsolationConfig is operator-only. Nil is the legacy, manually qualified
// library mode; it is not an assertion of runtime NetworkPolicy enforcement.
// Automatic callers must require non-nil. One namespace from MaxNamespaces is
// reserved for controller-owned probes; it is never selected by a model.
type IsolationConfig struct {
	ProbeImage string
}

// Command is the absolute buildctl executable followed by operator-fixed prefix
// arguments. WorkerImageArgument is the exact build-arg supported by the approved
// frontend to select its build worker. No default is guessed. WorkerEvidenceDigest
// identifies the operator's endpoint/worker-contract verification, not a signature
// verified by this package. Anonymous registry push must be supported by the
// operator's infrastructure; no local registry credentials are forwarded.
type BuildKitConfig struct {
	Command              []string
	ExecutableDigest     string
	Address              string
	WorkerImageArgument  string
	WorkerEvidenceDigest string
	OutputRepository     string
}

type Limits struct {
	MaxNamespaces    int
	MaxResources     int
	MaxChecks        int
	MaxActiveRuns    int
	MaxOperations    int
	MaxPlanBytes     int64
	MaxBodyBytes     int64
	MaxOutputBytes   int64
	OperationTimeout time.Duration
	ProbeTimeout     time.Duration
	BuildTimeout     time.Duration
	PodCPU           string
	PodMemory        string
}

type SourceTarget struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
}

type RecipeIdentity struct {
	ID            string `json:"id"`
	Repository    string `json:"repository"`
	Commit        string `json:"commit"`
	Path          string `json:"path"`
	ContentDigest string `json:"contentDigest"`
	Target        string `json:"target"`
	Platform      string `json:"platform"`
	FrontendImage string `json:"frontendImage"`
	WorkerImage   string `json:"workerImage"`
}

type Bind struct {
	SourceTarget SourceTarget   `json:"sourceTarget"`
	Recipe       RecipeIdentity `json:"recipe"`
	ChecksDigest string         `json:"checksDigest"`
}

type Plan struct {
	Version             int                  `json:"version"`
	Bind                Bind                 `json:"bind"`
	Namespaces          []Namespace          `json:"namespaces"`
	Resources           []Resource           `json:"resources"`
	Checks              []Check              `json:"checks"`
	ExternalObservation *ExternalObservation `json:"externalObservation,omitempty"`
}

// ExternalObservation binds a build to a separately admitted compiled observer.
// It never authorizes this adapter to start an HTTP or controller workload.
type ExternalObservation struct {
	Capability     string `json:"capability"`
	ContractDigest string `json:"contractDigest"`
}

type Namespace struct {
	Alias string `json:"alias"`
}

// Resource is deliberately not a Kubernetes object or RawExtension. There is no
// escape hatch for Pod commands, images, host paths, labels, credentials, or RBAC.
type Resource struct {
	ID        string                  `json:"id"`
	Namespace string                  `json:"namespace"`
	GVK       schema.GroupVersionKind `json:"gvk"`
	HTTP      *HTTPWorkload           `json:"http,omitempty"`
}

type HTTPWorkload struct {
	Port int32 `json:"port"`
}

type CheckClass string

const (
	Reproduction CheckClass = "reproduction"
	Normal       CheckClass = "normal"
)

const (
	HTTPExact = "http-exact-v1"
	EventSink = "event-sink-v1"
)

type Check struct {
	ID         string          `json:"id"`
	Class      CheckClass      `json:"class"`
	Capability string          `json:"capability"`
	HTTP       *HTTPProbe      `json:"http,omitempty"`
	Event      *EventSinkProbe `json:"event,omitempty"`
}

type HTTPProbe struct {
	Resource string           `json:"resource"`
	Protocol string           `json:"protocol"`
	Path     string           `json:"path"`
	Healthy  HTTPExpectation  `json:"healthy"`
	Failure  *HTTPExpectation `json:"failure,omitempty"`
	// Deprecated: single-expectation plans are rejected, never upgraded implicitly.
	ExpectedStatus int    `json:"expectedStatus,omitempty"`
	ExpectedBody   string `json:"expectedBody,omitempty"`
}

type HTTPExpectation struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// EventSinkProbe describes a required primitive without pretending an HTTP
// surrogate implements it. The current adapter returns NeedsAdapter for it.
type EventSinkProbe struct {
	Resource      string `json:"resource"`
	Type          string `json:"type"`
	ExpectedCount int    `json:"expectedCount"`
}

type Role string

const (
	PublishedOriginal Role = "published-original"
	RebuiltControl    Role = "rebuilt-control"
	Candidate         Role = "candidate"
)

// ImageBinding is installed by an external verifier/operator, never copied from
// a model response. EvidenceDigest identifies that verifier's retained evidence.
type ImageBinding struct {
	ID           string         `json:"id"`
	Role         Role           `json:"role"`
	SourceTarget SourceTarget   `json:"sourceTarget"`
	Recipe       RecipeIdentity `json:"recipe"`
	// Deprecated: an image identifies build inputs, not per-case observations.
	ChecksDigest   string `json:"checksDigest,omitempty"`
	PatchDigest    string `json:"patchDigest,omitempty"`
	Image          string `json:"image"`
	EvidenceDigest string `json:"evidenceDigest"`
}

type Subject struct {
	Role              Role   `json:"role"`
	Image             string `json:"image"`
	PatchDigest       string `json:"patchDigest,omitempty"`
	ExternalBindingID string `json:"externalBindingID,omitempty"`
	BuildID           string `json:"buildID,omitempty"`
}

type Request struct {
	// Derive RunID from case identity plus plan revision; a run freezes one Bind.
	RunID           string           `json:"runID"`
	OperationID     string           `json:"operationID"`
	Plan            Plan             `json:"plan"`
	Subject         Subject          `json:"subject"`
	RequireExisting bool             `json:"requireExisting,omitempty"`
	Expected        []ObjectIdentity `json:"expected,omitempty"`
}

type ObjectIdentity struct {
	Kind      string    `json:"kind"`
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name"`
	UID       types.UID `json:"uid,omitempty"`
	Image     string    `json:"image,omitempty"`
}

type Receipt struct {
	Version         int              `json:"version"`
	OperationDigest string           `json:"operationDigest"`
	ConfigDigest    string           `json:"configDigest"`
	Policy          OperationPolicy  `json:"policy"`
	Request         Request          `json:"request"`
	StartedAt       time.Time        `json:"startedAt"`
	Deadline        time.Time        `json:"deadline"`
	Objects         []ObjectIdentity `json:"objects"`
	// Proofs and their synthetic nonces are private restart state, never model
	// context. Creation intents distinguish uncreated resources from lost ACKs.
	Proofs            []isolation.Receipt `json:"proofs,omitempty"`
	CreateIntents     []int               `json:"createIntents,omitempty"`
	IsolationDeadline time.Time           `json:"isolationDeadline,omitempty"`
}

// OperationPolicy freezes only execution settings, not repository roots, builder
// commands, credentials, or the entire mutable operator catalog. ClusterIdentity
// is derived from the approved lab's kube-system namespace UID.
type OperationPolicy struct {
	ClusterIdentity string   `json:"clusterIdentity"`
	Limits          Limits   `json:"limits"`
	ObserverCIDRs   []string `json:"observerCIDRs"`
	SyntheticScope  string   `json:"syntheticScope"`
	ProbeImage      string   `json:"probeImage,omitempty"`
}

type Phase string

const (
	Starting  Phase = "starting"
	Running   Phase = "running"
	Cleaning  Phase = "cleaning"
	Completed Phase = "completed"
	Cancelled Phase = "cancelled"
)

type Outcome string

const (
	OutcomeHealthy Outcome = "healthy"
	OutcomeFailure Outcome = "failure"
	OutcomeOther   Outcome = "other"
)

// HTTPResult is evidence measured outside the subject process. A reproduction
// is the exact declared Failure response, never an arbitrary mismatch/crash/404.
// The coordinator requires failure on original/control, healthy on candidate,
// and healthy on every paired normal check. "Other" never satisfies an arm.
type HTTPResult struct {
	CheckID           string     `json:"checkID"`
	Class             CheckClass `json:"class"`
	PodUID            types.UID  `json:"podUID"`
	Image             string     `json:"image"`
	RuntimeImageID    string     `json:"runtimeImageID"`
	Status            int        `json:"status"`
	BodyDigest        string     `json:"bodyDigest"`
	HealthyStatus     int        `json:"healthyStatus"`
	HealthyBodyDigest string     `json:"healthyBodyDigest"`
	FailureStatus     int        `json:"failureStatus,omitempty"`
	FailureBodyDigest string     `json:"failureBodyDigest,omitempty"`
	Outcome           Outcome    `json:"outcome"`
	ObservedAt        time.Time  `json:"observedAt"`
	// Deprecated: these compatibility fields are never populated or serialized.
	ExpectedStatus     int    `json:"-"`
	ExpectedBodyDigest string `json:"-"`
	Matched            bool   `json:"-"`
}

type Observation struct {
	Receipt         Receipt      `json:"receipt"`
	Phase           Phase        `json:"phase"`
	Checks          []HTTPResult `json:"checks,omitempty"`
	Failure         *Error       `json:"failure,omitempty"`
	CleanupComplete bool         `json:"cleanupComplete"`
}

type Lifecycle interface {
	Start(context.Context, Request) (Receipt, error)
	Observe(context.Context, Receipt) (Observation, error)
	Cancel(context.Context, Receipt) error
}

type BuildRequest struct {
	RunID           string `json:"runID"`
	OperationID     string `json:"operationID"`
	Plan            Plan   `json:"plan"`
	Role            Role   `json:"role"`
	Patch           []byte `json:"patch,omitempty"`
	PatchDigest     string `json:"patchDigest,omitempty"`
	RequireExisting bool   `json:"requireExisting,omitempty"`
}

type Diagnostic struct {
	// Codes contain an allowlisted classification, never raw compiler output.
	Code       string `json:"code"`
	Count      int    `json:"count"`
	Path       string `json:"path,omitempty"`
	Line       int    `json:"line,omitempty"`
	Column     int    `json:"column,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

type BuildResult struct {
	ID                   string            `json:"id"`
	Bind                 Bind              `json:"bind"`
	Subject              Subject           `json:"subject"`
	Baseline             provenance.Recipe `json:"baseline"`
	Built                provenance.Recipe `json:"built"`
	OriginalRecipeDigest string            `json:"originalRecipeDigest"`
	BuildRecipeDigest    string            `json:"buildRecipeDigest"`
	WorkerEvidenceDigest string            `json:"workerEvidenceDigest"`
	CommandDigest        string            `json:"commandDigest"`
	MetadataDigest       string            `json:"metadataDigest"`
	Diagnostics          []Diagnostic      `json:"diagnostics,omitempty"`
	OutputTruncated      bool              `json:"outputTruncated,omitempty"`
}
