package patchverification

import "encoding/json"

const (
	ApplicationProtocolVersion           = 1
	ApplicationRuntimeProfile            = "application-runtime"
	ApplicationBuildGoPackage            = "go-package-v1"
	ApplicationPolicyVersion             = "application-v1"
	ApplicationPolicyKey                 = "orka.application.policy"
	ApplicationObserverImageKey          = "orka.application.observer-image"
	ApplicationObserverImageIDKey        = "orka.application.observer-image-id"
	ApplicationTargetLabel               = "orka.ai/application-target"
	ApplicationRunLabel                  = "applicationexec.orka.ai/run"
	ApplicationWorkerPath                = "/usr/local/bin/orka-application-worker"
	ApplicationBinaryName                = "application"
	ApplicationArtifactName              = "artifact.json"
	ApplicationInputPath                 = "/input/input.json"
	ApplicationSourcePath                = "/source/source.tar"
	ApplicationSourceVolumePath          = "/source"
	ApplicationSourceDirectory           = "archives"
	ApplicationOriginalSourceName        = "original.tar"
	ApplicationPatchedSourceName         = "patched.tar"
	ApplicationOriginalSourceSubPath     = ApplicationSourceDirectory + "/" + ApplicationOriginalSourceName
	ApplicationPatchedSourceSubPath      = ApplicationSourceDirectory + "/" + ApplicationPatchedSourceName
	ApplicationArtifactsPath             = "/artifacts"
	ApplicationWorkPath                  = "/work"
	ApplicationMarkerPath                = "/marker/value"
	ApplicationKubeconfigPath            = "/target/kubeconfig"
	ApplicationSubjectConfigPath         = "/subject-config"
	ApplicationFixtureSecretsPath        = "/fixture-secrets"
	ApplicationRuntimeQualificationPath  = "/input/runtime.json"
	ApplicationRuntimeQualificationKey   = "orka.application.runtime-qualification"
	ApplicationRuntimeGVisorBoundedV1    = "gvisor-bounded-v1"
	MaxApplicationSourceContentBytes     = 256 << 20
	MaxApplicationSourceBytes            = 320 << 20
	MaxApplicationSourceEntries          = 32768
	MaxApplicationBinaryBytes            = 256 << 20
	MaxApplicationInputBytes             = 1 << 20
	MaxApplicationReportBytes            = 64 << 10
	MaxApplicationResources              = 32
	MaxApplicationTCPBytes               = 16 << 10
	MaxApplicationPreparationReportBytes = 2 << 20
)

// ApplicationPlan is run data, not permission to build or deploy. The backend
// must also admit it against its operator-owned image, RBAC and target bounds.
// The complete plan participates in the existing ManifestDigest.
type ApplicationPlan struct {
	Version          int                          `json:"version"`
	Build            ApplicationBuild             `json:"build"`
	Runtime          ApplicationRuntime           `json:"runtime"`
	Resources        []json.RawMessage            `json:"resources,omitempty"`
	Permissions      []ApplicationPermission      `json:"permissions,omitempty"`
	Fixtures         []ApplicationFixture         `json:"fixtures,omitempty"`
	SyntheticSecrets []ApplicationSyntheticSecret `json:"syntheticSecrets,omitempty"`
}

// Environment.Image/ImageID identify the pinned trusted worker/toolchain image.
// No executable build instructions, flags, environment or Dockerfile are input.
type ApplicationBuild struct {
	Profile   string `json:"profile"`
	Package   string `json:"package"`
	GoVersion string `json:"goVersion"`
}

type ApplicationRuntime struct {
	Image   string   `json:"image"`
	ImageID string   `json:"imageID"`
	Args    []string `json:"args,omitempty"`
	Ports   []int    `json:"ports,omitempty"`
}

// Permissions can only become a namespace Role. Wildcards, RBAC mutations,
// credential reads, subresource exec and cluster-scoped access are unsupported.
type ApplicationPermission struct {
	APIGroup      string   `json:"apiGroup"`
	Resources     []string `json:"resources"`
	Verbs         []string `json:"verbs"`
	ResourceNames []string `json:"resourceNames,omitempty"`
}

// Fixtures are trusted TCP marker servers, not arbitrary image entrypoints.
// The backend generates a fresh protected marker; it is never part of a plan.
type ApplicationFixture struct {
	ID      string            `json:"id"`
	Port    int               `json:"port"`
	Kind    string            `json:"kind,omitempty"`
	Profile string            `json:"profile,omitempty"`
	Config  map[string]string `json:"config,omitempty"`
}

type ApplicationCheck struct {
	Version       int                         `json:"version"`
	SettleSeconds int                         `json:"settleSeconds,omitempty"`
	Resources     []json.RawMessage           `json:"resources,omitempty"`
	Kubernetes    *ApplicationKubernetesCheck `json:"kubernetes,omitempty"`
	TCP           *ApplicationTCPCheck        `json:"tcp,omitempty"`
	Actions       []ApplicationAction         `json:"actions,omitempty"`
}

// Kubernetes observations are exact named GETs in the run namespace, never
// arbitrary URLs, list queries, log streams, exec or fixture-written verdicts.
type ApplicationKubernetesCheck struct {
	APIVersion  string          `json:"apiVersion"`
	Resource    string          `json:"resource"`
	Name        string          `json:"name"`
	Pointer     string          `json:"pointer"`
	NormalValue json.RawMessage `json:"normalValue,omitempty"`
}

type ApplicationTCPCheck struct {
	Target        string `json:"target"`
	Port          int    `json:"port"`
	Request       []byte `json:"request,omitempty"`
	MarkerID      string `json:"markerID"`
	MaxBytes      int    `json:"maxBytes"`
	Mode          string `json:"mode,omitempty"`
	WindowSeconds int    `json:"windowSeconds,omitempty"`
	Terminator    []byte `json:"terminator,omitempty"`
	Response      []byte `json:"response,omitempty"`
}

type ApplicationAPIValue struct {
	Exists bool            `json:"exists"`
	Found  bool            `json:"found"`
	Value  json.RawMessage `json:"value,omitempty"`
}

type ApplicationTCPValue struct {
	Connected     bool `json:"connected"`
	MarkerMatched bool `json:"markerMatched"`
}

type ApplicationTarget struct {
	ClusterUID   string `json:"clusterUID"`
	Namespace    string `json:"namespace"`
	NamespaceUID string `json:"namespaceUID"`
}

// Container identities come from a live API read by the trusted backend or
// observer, not from an application log or an untrusted source fixture.
type ApplicationContainerIdentity struct {
	PodName            string `json:"podName"`
	PodUID             string `json:"podUID"`
	ContainerName      string `json:"containerName"`
	ContainerID        string `json:"containerID"`
	ImageID            string `json:"imageID"`
	JobUID             string `json:"jobUID,omitempty"`
	ServiceAccountName string `json:"serviceAccountName"`
	ServiceAccountUID  string `json:"serviceAccountUID"`
	Namespace          string `json:"namespace,omitempty"`
	NamespaceUID       string `json:"namespaceUID,omitempty"`
}

type ApplicationArtifact struct {
	Version        int                          `json:"version"`
	RunID          string                       `json:"runID"`
	AttemptID      string                       `json:"attemptID"`
	TaskID         string                       `json:"taskID"`
	ManifestDigest string                       `json:"manifestDigest"`
	PlanDigest     string                       `json:"planDigest"`
	Side           string                       `json:"side"`
	Source         SourceIdentity               `json:"source"`
	BinaryDigest   string                       `json:"binaryDigest"`
	BinaryBytes    int64                        `json:"binaryBytes"`
	GoVersion      string                       `json:"goVersion"`
	Platform       string                       `json:"platform"`
	Build          ApplicationContainerIdentity `json:"build"`
}

type ApplicationEndpoint struct {
	ID      string                       `json:"id"`
	Address string                       `json:"address"`
	Port    int                          `json:"port"`
	Pod     ApplicationContainerIdentity `json:"pod"`
}

// WorkerInput is mounted read-only by the backend. Build uses SourcePath;
// subject verifies Artifact then execs the read-only binary; observe uses an
// independently scoped target kubeconfig and, for TCP only, a protected marker.
// None of these worker modes accepts a shell command.
type ApplicationWorkerInput struct {
	Version         int                                `json:"version"`
	Manifest        Manifest                           `json:"manifest"`
	Binding         Binding                            `json:"binding"`
	Side            string                             `json:"side"`
	CheckID         string                             `json:"checkID,omitempty"`
	TaskUID         string                             `json:"taskUID"`
	Target          ApplicationTarget                  `json:"target"`
	Worker          ApplicationContainerIdentity       `json:"worker"`
	Artifact        *ApplicationArtifact               `json:"artifact,omitempty"`
	Subject         *ApplicationContainerIdentity      `json:"subject,omitempty"`
	Endpoints       []ApplicationEndpoint              `json:"endpoints,omitempty"`
	MarkerDigest    string                             `json:"markerDigest,omitempty"`
	Actors          []ApplicationActorIdentity         `json:"actors,omitempty"`
	MarkerRef       *ApplicationProtectedMarkerRef     `json:"markerRef,omitempty"`
	FixtureID       string                             `json:"fixtureID,omitempty"`
	ActionTargets   []ApplicationActionTarget          `json:"actionTargets,omitempty"`
	ReceiverService *ApplicationServiceIdentity        `json:"receiverService,omitempty"`
	APIBaseline     *ApplicationAPIIdentity            `json:"apiBaseline,omitempty"`
	SubjectTLS      []ApplicationSubjectTLSIdentity    `json:"subjectTLS,omitempty"`
	FixtureSecrets  []ApplicationFixtureSecretIdentity `json:"fixtureSecrets,omitempty"`
}

type ApplicationBuildReport struct {
	Version  int                 `json:"version"`
	TaskUID  string              `json:"taskUID"`
	PodUID   string              `json:"podUID"`
	Artifact ApplicationArtifact `json:"artifact"`
}

type ApplicationReport struct {
	Version  int               `json:"version"`
	TaskUID  string            `json:"taskUID"`
	PodUID   string            `json:"podUID"`
	Evidence ExecutionEvidence `json:"evidence"`
}

type ApplicationObservation struct {
	Version     int                             `json:"version"`
	Completed   bool                            `json:"completed"`
	PlanDigest  string                          `json:"planDigest"`
	Target      ApplicationTarget               `json:"target"`
	Artifact    ApplicationArtifact             `json:"artifact"`
	Subject     ApplicationContainerIdentity    `json:"subject"`
	Kubernetes  *ApplicationAPIIdentity         `json:"kubernetes,omitempty"`
	APIBaseline *ApplicationAPIIdentity         `json:"apiBaseline,omitempty"`
	TCP         *ApplicationTCPIdentity         `json:"tcp,omitempty"`
	Actions     []ApplicationActionObservation  `json:"actions,omitempty"`
	SubjectTLS  []ApplicationSubjectTLSIdentity `json:"subjectTLS,omitempty"`
	Replica     *ApplicationReplicaObservation  `json:"replica,omitempty"`
}

type ApplicationReplicaObservation struct {
	DeploymentUID   string                         `json:"deploymentUID"`
	ReplicaSetUIDs  []string                       `json:"replicaSetUIDs"`
	Pods            []ApplicationContainerIdentity `json:"pods"`
	DesiredReplicas int32                          `json:"desiredReplicas"`
	ReadyReplicas   int32                          `json:"readyReplicas"`
	InitialReplicas int32                          `json:"initialReplicas"`
	MaxReplicas     int32                          `json:"maxReplicas"`
}

type ApplicationAPIIdentity struct {
	APIVersion      string               `json:"apiVersion"`
	Resource        string               `json:"resource"`
	Name            string               `json:"name"`
	Pointer         string               `json:"pointer,omitempty"`
	UID             string               `json:"uid,omitempty"`
	ResourceVersion string               `json:"resourceVersion,omitempty"`
	Result          ApplicationAPIResult `json:"result"`
}

type ApplicationTCPIdentity struct {
	Endpoint      ApplicationEndpoint            `json:"endpoint"`
	MarkerID      string                         `json:"markerID"`
	MarkerDigest  string                         `json:"markerDigest"`
	MarkerBytes   int                            `json:"markerBytes"`
	Bytes         int                            `json:"bytes"`
	Result        ApplicationTCPValue            `json:"result"`
	Mode          string                         `json:"mode,omitempty"`
	WindowSeconds int                            `json:"windowSeconds,omitempty"`
	Connections   int                            `json:"connections,omitempty"`
	MarkerRef     *ApplicationProtectedMarkerRef `json:"markerRef,omitempty"`
	ReceiverRoute *ApplicationReceiverRoute      `json:"receiverRoute,omitempty"`
}

// API values are reduced to canonical digest/size metadata before transport.
// In particular, a subject cannot exfiltrate credentials through a status field.
type ApplicationAPIResult struct {
	Exists      bool   `json:"exists"`
	Found       bool   `json:"found"`
	ValueDigest string `json:"valueDigest,omitempty"`
	ValueBytes  int    `json:"valueBytes,omitempty"`
}

type ApplicationBoundaryInput struct {
	Version              int                              `json:"version"`
	ID                   string                           `json:"id"`
	TaskUID              string                           `json:"taskUID"`
	Target               ApplicationTarget                `json:"target"`
	CanaryHost           string                           `json:"canaryHost"`
	CanaryPort           int                              `json:"canaryPort"`
	PositiveControl      bool                             `json:"positiveControl"`
	APIAddress           string                           `json:"apiAddress,omitempty"`
	ServiceAccountName   string                           `json:"serviceAccountName,omitempty"`
	SourceHost           string                           `json:"sourceHost,omitempty"`
	RuntimeQualification *ApplicationRuntimeQualification `json:"runtimeQualification,omitempty"`
	RuntimeLimits        *ApplicationRuntimeLimits        `json:"runtimeLimits,omitempty"`
	FileSizeRole         string                           `json:"fileSizeRole,omitempty"`
}

// Boundary reports contain measured controls, not an asserted "sandbox safe".
// The backend must bind the report to the exact admitted probe Pod and compare
// a reachable positive canary control with the denied subject-profile probe.
type ApplicationBoundaryReport struct {
	Version                    int               `json:"version"`
	InputDigest                string            `json:"inputDigest"`
	TaskUID                    string            `json:"taskUID"`
	PodUID                     string            `json:"podUID"`
	UID                        int               `json:"uid"`
	GID                        int               `json:"gid"`
	PID                        int               `json:"pid"`
	Capabilities               map[string]string `json:"capabilities"`
	NoNewPrivileges            bool              `json:"noNewPrivileges"`
	SeccompMode                int               `json:"seccompMode"`
	ReadOnlyRoot               bool              `json:"readOnlyRoot"`
	MemoryMax                  uint64            `json:"memoryMax"`
	PIDsMax                    uint64            `json:"pidsMax"`
	SwapMax                    uint64            `json:"swapMax"`
	CPUQuota                   uint64            `json:"cpuQuota"`
	CPUPeriod                  uint64            `json:"cpuPeriod"`
	CanaryReachable            bool              `json:"canaryReachable"`
	APIStatuses                map[string]int    `json:"apiStatuses,omitempty"`
	APIUserUID                 string            `json:"apiUserUID,omitempty"`
	SourceHTTPSVerified        bool              `json:"sourceHTTPSVerified,omitempty"`
	SourceHTTPStatus           int               `json:"sourceHTTPStatus,omitempty"`
	RuntimeProfile             string            `json:"runtimeProfile,omitempty"`
	RuntimeQualificationDigest string            `json:"runtimeQualificationDigest,omitempty"`
	PIDLimitSource             string            `json:"pidLimitSource,omitempty"`
	SwapLimitSource            string            `json:"swapLimitSource,omitempty"`
	GuestPIDSoft               uint64            `json:"guestPIDSoft,omitempty"`
	GuestPIDHard               uint64            `json:"guestPIDHard,omitempty"`
	FileSizeSoft               uint64            `json:"fileSizeSoft,omitempty"`
	FileSizeHard               uint64            `json:"fileSizeHard,omitempty"`
}
