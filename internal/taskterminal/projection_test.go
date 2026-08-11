package taskterminal

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/store"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestValidateRestoredProjectionAcceptsExactSourceEvidence(t *testing.T) {
	task, sourceUID, attempt, projection := restoredProjectionFixture()

	if _, err := ValidateRestoredProjection(marshalProjection(t, projection), task, sourceUID, attempt); err != nil {
		t.Fatalf("ValidateRestoredProjection() error = %v", err)
	}
}

func TestValidateRestoredProjectionAcceptsDocumentedDeliverySettlementRewrite(t *testing.T) {
	task, sourceUID, attempt, projection := restoredProjectionFixture()
	attempt.DeliveryState = store.PromptDeliveryPublicationOutcomeUnknown
	projection.Phase = corev1alpha1.TaskPhaseFailed
	projection.Delivery.State = corev1alpha1.TaskDeliveryStatePublicationOutcomeUnknown
	projection.Delivery.Outcome = corev1alpha1.TaskDeliveryOutcomePublicationOutcomeUnknown
	projection.Delivery.LastTransitionTime = timePtr(time.Date(2026, 8, 11, 12, 5, 0, 0, time.UTC))
	task.Status.Delivery.State = corev1alpha1.TaskDeliveryStatePreparing
	task.Status.Delivery.Outcome = ""
	task.Status.Delivery.LastTransitionTime = timePtr(time.Date(2026, 8, 11, 12, 4, 0, 0, time.UTC))

	if _, err := ValidateRestoredProjection(marshalProjection(t, projection), task, sourceUID, attempt); err != nil {
		t.Fatalf("ValidateRestoredProjection(documented settlement rewrite) error = %v", err)
	}
}

func TestValidateRestoredProjectionAcceptsExactRestoreMarker(t *testing.T) {
	task, sourceUID, attempt, projection := restoredProjectionFixture()
	const message = "Task incarnation changed during restore after source execution reached a durable terminal state; execution was preserved and was not replayed"
	attempt.TerminalReason = string(restoreIdentityChangedReason)
	attempt.OutcomeMarker = message
	projection.Execution.Reason = restoreIdentityChangedReason
	projection.Execution.Message = message
	projection.Message = message

	if _, err := ValidateRestoredProjection(marshalProjection(t, projection), task, sourceUID, attempt); err != nil {
		t.Fatalf("ValidateRestoredProjection(restore marker) error = %v", err)
	}
}

//nolint:gocyclo // One table deliberately covers every security-relevant terminal payload field.
func TestValidateRestoredProjectionRejectsForgedOrIncompletePayload(t *testing.T) {
	const forgedValue = "other"

	tests := []struct {
		name   string
		mutate func(*Projection)
	}{
		{name: "namespace", mutate: func(p *Projection) { p.Namespace = forgedValue }},
		{name: "task name", mutate: func(p *Projection) { p.Task = forgedValue }},
		{name: "source UID", mutate: func(p *Projection) { p.TaskUID = forgedValue }},
		{name: "attempt", mutate: func(p *Projection) { p.Attempt++ }},
		{name: "execution attempt", mutate: func(p *Projection) { p.Execution.Attempt++ }},
		{name: "prompt ID", mutate: func(p *Projection) { p.Execution.PromptID = forgedValue }},
		{name: "request digest", mutate: func(p *Projection) { p.Execution.RequestDigest = digest("other-request") }},
		{name: "binding digest", mutate: func(p *Projection) { p.BindingDigest = digest("other-binding") }},
		{name: "execution state", mutate: func(p *Projection) { p.Execution.State = corev1alpha1.TaskExecutionStateFailed }},
		{name: "execution outcome", mutate: func(p *Projection) { p.Execution.Outcome = corev1alpha1.TaskExecutionOutcomeFailed }},
		{name: "phase", mutate: func(p *Projection) { p.Phase = corev1alpha1.TaskPhaseFailed }},
		{name: "runtime pool", mutate: func(p *Projection) { p.Execution.RuntimePoolName = forgedValue }},
		{name: "runtime pool UID", mutate: func(p *Projection) { p.Execution.RuntimePoolUID = forgedValue }},
		{name: "runtime instance", mutate: func(p *Projection) { p.Execution.RuntimeInstanceID = forgedValue }},
		{name: "runtime Session", mutate: func(p *Projection) { p.Execution.RuntimeSessionUID = forgedValue }},
		{name: "runtime Session generation", mutate: func(p *Projection) { p.Execution.RuntimeSessionGeneration++ }},
		{name: "runtime supervisor boot", mutate: func(p *Projection) { p.Execution.RuntimeSessionSupervisorBootID = forgedValue }},
		{name: "runtime profile digest", mutate: func(p *Projection) { p.Execution.RuntimeSessionProfileDigest = digest("other-profile") }},
		{name: "runtime MCP digest", mutate: func(p *Projection) { p.Execution.RuntimeSessionMCPDigest = digest("other-mcp") }},
		{name: "runtime workspace digest", mutate: func(p *Projection) { p.Execution.RuntimeSessionWorkspaceDigest = digest("other-workspace") }},
		{name: "delivery omitted", mutate: func(p *Projection) { p.Delivery = nil }},
		{name: "delivery state", mutate: func(p *Projection) { p.Delivery.State = corev1alpha1.TaskDeliveryStateDeliveryConflict }},
		{name: "delivery outcome", mutate: func(p *Projection) { p.Delivery.Outcome = corev1alpha1.TaskDeliveryOutcomeDeliveryConflict }},
		{name: "delivery reason", mutate: func(p *Projection) { p.Delivery.Reason = "Other" }},
		{name: "publication ID", mutate: func(p *Projection) { p.Delivery.PublicationID = forgedValue }},
		{name: "source repository", mutate: func(p *Projection) { p.Delivery.SourceRepository.ID = "github.com/other/source" }},
		{name: "publication repository", mutate: func(p *Projection) { p.Delivery.PublicationRepository.ID = "github.com/other/target" }},
		{name: "branch", mutate: func(p *Projection) { p.Delivery.Branch = forgedValue }},
		{name: "starting SHA", mutate: func(p *Projection) { p.Delivery.StartingSHA = strings.Repeat("a", 40) }},
		{name: "remote before SHA", mutate: func(p *Projection) { value := strings.Repeat("b", 40); p.Delivery.RemoteBeforeSHA = &value }},
		{name: "tree SHA", mutate: func(p *Projection) { p.Delivery.TreeSHA = strings.Repeat("c", 40) }},
		{name: "expected commit SHA", mutate: func(p *Projection) { p.Delivery.ExpectedCommitSHA = strings.Repeat("d", 40) }},
		{name: "verified remote SHA", mutate: func(p *Projection) { p.Delivery.VerifiedRemoteSHA = strings.Repeat("e", 40) }},
		{name: "superseding remote SHA", mutate: func(p *Projection) { p.Delivery.SupersedingRemoteSHA = strings.Repeat("f", 40) }},
		{name: "artifact digest", mutate: func(p *Projection) { p.Delivery.ArtifactDigest = digest("other-artifact") }},
		{name: "pull request receipt", mutate: func(p *Projection) { p.Delivery.PRReceipt.ID = forgedValue }},
		{name: "delivery message", mutate: func(p *Projection) { p.Delivery.Message = forgedValue }},
		{name: "harness v1 runtime", mutate: func(p *Projection) { p.HarnessRuntime = &corev1alpha1.HarnessRuntimeStatus{} }},
		{name: "harness v1 result", mutate: func(p *Projection) { p.ResultRef = &corev1alpha1.ResultReference{} }},
		{name: "unproved restore marker", mutate: func(p *Projection) { p.Execution.Reason = restoreIdentityChangedReason }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task, sourceUID, attempt, projection := restoredProjectionFixture()
			tt.mutate(&projection)
			if _, err := ValidateRestoredProjection(marshalProjection(t, projection), task, sourceUID, attempt); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("ValidateRestoredProjection() error = %v, want ErrConflict", err)
			}
		})
	}

	for _, tt := range []struct {
		name    string
		payload []byte
	}{
		{name: "empty object", payload: []byte(`{}`)},
		{name: "legacy phase only", payload: []byte(`{"phase":"Succeeded"}`)},
		{name: "unknown field", payload: []byte(`{"unknown":true}`)},
		{name: "trailing object", payload: []byte(`{} {}`)},
		{name: "not JSON", payload: []byte(`not-json`)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			task, sourceUID, attempt, _ := restoredProjectionFixture()
			if _, err := ValidateRestoredProjection(tt.payload, task, sourceUID, attempt); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("ValidateRestoredProjection() error = %v, want ErrConflict", err)
			}
		})
	}
}

func restoredProjectionFixture() (*corev1alpha1.Task, string, *store.PromptAttempt, Projection) {
	const sourceUID = "11111111-1111-1111-1111-111111111111"
	remoteBefore := strings.Repeat("1", 40)
	transition := metav1.NewTime(time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC))
	delivery := &corev1alpha1.TaskDeliveryStatus{
		State: corev1alpha1.TaskDeliveryStateVerifiedExact, Outcome: corev1alpha1.TaskDeliveryOutcomeVerifiedExact,
		Reason: "Verified", PublicationID: "publication-source", Branch: "restore-proof",
		SourceRepository:      &corev1alpha1.RepositoryIdentity{Provider: "github", ID: "github.com/example/source"},
		PublicationRepository: &corev1alpha1.RepositoryIdentity{Provider: "github", ID: "github.com/example/target"},
		StartingSHA:           strings.Repeat("2", 40), RemoteBeforeSHA: &remoteBefore, TreeSHA: strings.Repeat("3", 40),
		ExpectedCommitSHA: strings.Repeat("4", 40), VerifiedRemoteSHA: strings.Repeat("4", 40),
		SupersedingRemoteSHA: strings.Repeat("5", 40), ArtifactDigest: digest("artifact"),
		PRReceipt: &corev1alpha1.TaskPullRequestReceipt{ID: "pr-1", Number: 1, URL: "https://github.com/example/target/pull/1", State: "open"},
		Message:   "verified exact", LastTransitionTime: &transition,
	}
	execution := &corev1alpha1.TaskExecutionStatus{
		State: corev1alpha1.TaskExecutionStateSucceeded, Outcome: corev1alpha1.TaskExecutionOutcomeSucceeded,
		Reason: restoreIdentityChangedReason, Message: "restored status", Attempt: 2, PromptID: "prompt-final",
		RuntimePoolName: "pool", RuntimePoolUID: "pool-uid", RuntimeInstanceID: "runtime-instance",
		RuntimeSessionUID: "session-uid", RuntimeSessionGeneration: 3, RuntimeSessionSupervisorBootID: "boot-id",
		RuntimeSessionProfileDigest: digest("profile"), RuntimeSessionMCPDigest: digest("mcp"),
		RuntimeSessionWorkspaceDigest: digest("workspace"), RequestDigest: digest("request"), ControllerEpoch: 9,
		LastTransitionTime: &transition,
	}
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "restored-task", UID: types.UID("22222222-2222-2222-2222-222222222222")},
		Status: corev1alpha1.TaskStatus{
			Phase: corev1alpha1.TaskPhaseSucceeded, Message: "restored status", Execution: execution, Delivery: delivery.DeepCopy(),
			AgentExecutionBinding: &corev1alpha1.AgentExecutionBinding{
				SchemaVersion: 1, ContractVersion: corev1alpha1.AgentRuntimeContractHarnessV2,
				BindingDigest: digest("binding"), Task: corev1alpha1.AgentExecutionBindingTaskRef{UID: types.UID(sourceUID)},
				Snapshot: corev1alpha1.AgentExecutionSnapshotRef{ID: sourceUID + "/" + digest("snapshot"), Digest: digest("snapshot"), SchemaVersion: 1},
			},
		},
	}
	attempt := &store.PromptAttempt{
		ID:            "prompt-attempt-final",
		Key:           store.PromptAttemptKey{Namespace: task.Namespace, TaskUID: sourceUID, Attempt: 2, PromptID: execution.PromptID},
		RequestDigest: execution.RequestDigest, BindingDigest: task.Status.AgentExecutionBinding.BindingDigest,
		RuntimeInstanceID: execution.RuntimeInstanceID, SessionUID: execution.RuntimeSessionUID,
		SessionLeaseGeneration: execution.RuntimeSessionGeneration, ExecutionState: store.PromptExecutionSucceeded,
		DeliveryState: store.PromptDeliveryVerifiedExact, ControllerEpoch: 7,
	}
	projectionExecution := *execution.DeepCopy()
	projectionExecution.Reason = "SourceCompleted"
	projectionExecution.Message = "source terminal message"
	projectionExecution.ControllerEpoch = attempt.ControllerEpoch
	projectionExecution.LastTransitionTime = timePtr(time.Date(2026, 8, 11, 11, 59, 0, 0, time.UTC))
	projection := Projection{
		Namespace: task.Namespace, Task: task.Name, TaskUID: sourceUID, Attempt: execution.Attempt,
		Phase: corev1alpha1.TaskPhaseSucceeded, Message: "source completed",
		BindingDigest: task.Status.AgentExecutionBinding.BindingDigest, Execution: projectionExecution,
		Delivery: delivery.DeepCopy(),
	}
	projection.Delivery.LastTransitionTime = timePtr(time.Date(2026, 8, 11, 11, 58, 0, 0, time.UTC))
	return task, sourceUID, attempt, projection
}

func marshalProjection(t *testing.T, projection Projection) []byte {
	t.Helper()
	payload, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	return payload
}

func digest(value string) string {
	if len(value) > 64 {
		value = value[:64]
	}
	return "sha256:" + value + strings.Repeat("0", 64-len(value))
}

func timePtr(value time.Time) *metav1.Time {
	result := metav1.NewTime(value)
	return &result
}
