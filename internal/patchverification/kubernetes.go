package patchverification

import "time"

type SubmissionState string

const (
	SubmissionPreparing  SubmissionState = "preparing"
	SubmissionRunning    SubmissionState = "running"
	SubmissionTerminal   SubmissionState = "terminal"
	SubmissionCancelling SubmissionState = "cancelling"
)

type KubernetesSubmission struct {
	Namespace        string            `json:"namespace"`
	RequestID        string            `json:"requestID"`
	SubmittedBy      string            `json:"submittedBy"`
	AttemptID        string            `json:"attemptID"`
	OriginalTaskName string            `json:"originalTaskName"`
	PatchedTaskName  string            `json:"patchedTaskName,omitempty"`
	OriginalTaskUID  string            `json:"originalTaskUID,omitempty"`
	PatchedTaskUID   string            `json:"patchedTaskUID,omitempty"`
	Manifest         Manifest          `json:"manifest"`
	Provenance       map[string][]byte `json:"-"`
	Binding          *Binding          `json:"binding,omitempty"`
	RunID            string            `json:"runID,omitempty"`
	State            SubmissionState   `json:"state"`
	Failure          string            `json:"failure,omitempty"`
	CreatedAt        time.Time         `json:"createdAt"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	Assessment       *Assessment       `json:"assessment,omitempty"`
	RequiredChecks   int               `json:"requiredChecks"`
	RecordedChecks   int               `json:"recordedChecks"`
}

type DispatchState string

const (
	DispatchPlanned  DispatchState = "planned"
	DispatchCreated  DispatchState = "created"
	DispatchObserved DispatchState = "observed"
	DispatchRecorded DispatchState = "recorded"
	DispatchFailed   DispatchState = "failed"
)

type KubernetesDispatch struct {
	RunID       string        `json:"runID"`
	Side        string        `json:"side"`
	CheckID     string        `json:"checkID"`
	JobName     string        `json:"jobName"`
	SpecDigest  string        `json:"specDigest"`
	JobUID      string        `json:"jobUID,omitempty"`
	PodUID      string        `json:"podUID,omitempty"`
	ContainerID string        `json:"containerID,omitempty"`
	State       DispatchState `json:"state"`
	Failure     string        `json:"failure,omitempty"`
}
