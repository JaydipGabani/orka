package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRemediationQueueUnavailableOldestDoesNotReserveCapacity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	started := make(chan struct{}, 1)
	fixture := newTaskScopedCreateConflictFixture(t, ctx, "older", types.UID("older-task"),
		func(profile harnessv2.RuntimeProfile, digest harnessv2.ProfileDigest, _ *client.Client) *httptest.Server {
			server := newDispatcherRuntimeServerForPool(t, profile, digest, acpDispatcherTestPoolUID,
				func(harnessv2.CreateRuntimeSessionRequest) { started <- struct{}{} })
			handler := server.Config.Handler
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/prompts/") &&
					!strings.HasSuffix(request.URL.Path, "/cancel") {
					writeRemediationQueuePrompt(t, w, request)
					return
				}
				handler.ServeHTTP(w, request)
			})
			return server
		})
	defer fixture.stop()
	d := fixture.dispatcher
	persistence := d.Store.(*sqlite.Store)
	d.EventStore, d.PlanStore = persistence, persistence
	d.sem, d.active = make(chan struct{}, 1), make(map[types.UID]struct{})

	agent := &corev1alpha1.Agent{}
	if err := fixture.kubeClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "agent"}, agent); err != nil {
		t.Fatal(err)
	}
	ready := fixture.task.DeepCopy()
	ready.Name, ready.UID, ready.ResourceVersion = "ready", "ready-task", ""
	ready.CreationTimestamp = metav1.Now()
	ready.Status.AgentExecutionBinding = nil
	ready.Status.Execution.PromptID = "prompt-ready-task-1"
	if err := fixture.kubeClient.Create(ctx, ready); err != nil {
		t.Fatal(err)
	}
	ready = prepareBoundACPDispatcherTaskForTest(t, ctx, fixture.kubeClient, fixture.kubeClient.Scheme(),
		persistence, ready, agent, ACPRuntimeImages{Codex: "docker.io/example/acp@sha256:" + strings.Repeat("a", 64)})
	fence, err := d.Epochs.CurrentFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreatePromptAttempt(ctx, boundPromptAttemptForTest(&store.PromptAttempt{
		Key:           store.PromptAttemptKey{Namespace: ready.Namespace, TaskUID: string(ready.UID), Attempt: 1, PromptID: ready.Status.Execution.PromptID},
		RequestDigest: ready.Status.Execution.RequestDigest, BindingDigest: ready.Status.AgentExecutionBinding.BindingDigest,
		SnapshotDigest: ready.Status.AgentExecutionBinding.Snapshot.Digest,
	}), fence); err != nil {
		t.Fatal(err)
	}
	pool := &corev1alpha1.RuntimePool{}
	if err := fixture.kubeClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: ready.Status.Execution.RuntimePoolName}, pool); err != nil {
		t.Fatal(err)
	}
	pool.Spec.Capacity = &corev1alpha1.RuntimePoolCapacitySpec{MaxResidentSessions: 1, MaxRunningPrompts: 1}
	if err := fixture.kubeClient.Update(ctx, pool); err != nil {
		t.Fatal(err)
	}
	for _, task := range []*corev1alpha1.Task{fixture.currentTask(t, ctx), ready} {
		task.Labels[labels.LabelCreatedBy] = remediationpolicy.CreatedBy
		if task.Name == "older" {
			task.Annotations = map[string]string{acpRuntimeQueuedAtAnnotation: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)}
		}
		if err := fixture.kubeClient.Update(ctx, task); err != nil {
			t.Fatal(err)
		}
	}
	oldReserved := make(chan struct{}, 1)
	releaseOld := make(chan struct{})
	defer close(releaseOld)
	d.RemediationQueueValidator = func(_ context.Context, task *corev1alpha1.Task) error {
		if task.Name == "older" {
			return apierrors.NewServiceUnavailable("synthetic expired run claim")
		}
		return nil
	}
	d.RemediationDispatchValidator = func(_ context.Context, task *corev1alpha1.Task, _ *corev1alpha1.RuntimePool) error {
		if task.Name == "older" {
			oldReserved <- struct{}{}
			select {
			case <-releaseOld:
			case <-ctx.Done():
			}
			return apierrors.NewServiceUnavailable("synthetic expired run claim")
		}
		return nil
	}
	if err := d.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-oldReserved:
		t.Fatal("ineligible oldest Task acquired the only dispatch/pool slot")
	case <-started:
	case <-ctx.Done():
		t.Fatal("newer authorized Task was starved by unavailable older work")
	}
	if got := fixture.currentTask(t, ctx); got.Status.Execution.State != corev1alpha1.TaskExecutionStateQueued {
		t.Fatal("unavailable Task acquired a durable reservation")
	}
	for {
		d.mu.Lock()
		active := len(d.active)
		d.mu.Unlock()
		if active == 0 {
			break
		}
		select {
		case <-ctx.Done():
			current := &corev1alpha1.Task{}
			readErr := fixture.kubeClient.Get(t.Context(), client.ObjectKeyFromObject(ready), current)
			t.Fatalf("authorized dispatch did not settle: execution=%+v readErr=%v", current.Status.Execution, readErr)
		case <-time.After(10 * time.Millisecond):
		}
	}
	current := &corev1alpha1.Task{}
	if err := fixture.kubeClient.Get(ctx, client.ObjectKeyFromObject(ready), current); err != nil {
		t.Fatal(err)
	}
	if current.Status.Phase != corev1alpha1.TaskPhaseSucceeded {
		t.Fatal("authorized newer Task did not complete", current.Status.Phase)
	}
}

// Queue fairness needs a source-free prompt, not the general fixture's tools
// and diagnostic-history redaction workload.
func writeRemediationQueuePrompt(t *testing.T, w http.ResponseWriter, request *http.Request) {
	t.Helper()
	var prompt harnessv2.StartPromptRequest
	if err := json.NewDecoder(request.Body).Decode(&prompt); err != nil {
		t.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	limits := harnessv2.DefaultProtocolLimits()
	w.Header().Set("Content-Type", harnessv2.NDJSONMediaType)
	encoder, err := harnessv2.NewEventEncoder(w, harnessv2.EventStreamLimits{
		MaxLineBytes: limits.MaxEventLineBytes, MaxTerminalResultBytes: limits.MaxTerminalResultBytes,
		MaxBufferedEvents: limits.MaxBufferedEvents, MaxUpdateEventsPerSecond: limits.MaxUpdateEventsPerSecond,
	}, harnessv2.EventExpectationFromMetadata(prompt.Metadata))
	if err != nil {
		t.Error(err)
		return
	}
	now := time.Now().UTC()
	identity := harnessv2.EventIdentity{
		RuntimeInstanceID: prompt.Metadata.Fence.RuntimeInstanceID, SupervisorBootID: prompt.Metadata.Fence.SupervisorBootID,
		RuntimeSessionUID: prompt.Metadata.Fence.RuntimeSessionUID, RuntimeSessionGeneration: prompt.Metadata.Fence.RuntimeSessionGeneration,
		TaskUID: prompt.Metadata.TaskUID, TaskAttempt: prompt.Metadata.TaskAttempt, PromptID: prompt.Metadata.PromptID,
		Sequence: 1, RequestDigest: prompt.Metadata.RequestDigest, Timestamp: now,
	}
	if err := encoder.Encode(harnessv2.Event{Protocol: harnessv2.ProtocolVersion, Type: harnessv2.EventAccepted, Identity: identity,
		Accepted: &harnessv2.AcceptedEvent{AcceptedAt: now, Lease: prompt.Lease, ACPVersion: harnessv2.ACPProfileV1}}); err != nil {
		t.Error(err)
		return
	}
	identity.Sequence++
	identity.Timestamp = now.Add(time.Millisecond)
	if err := encoder.Encode(harnessv2.Event{Protocol: harnessv2.ProtocolVersion, Type: harnessv2.EventCompleted, Identity: identity,
		Completed: &harnessv2.CompletedEvent{StopReason: harnessv2.ACPStopReasonEndTurn, Result: harnessv2.PromptResult{
			Content: []harnessv2.ContentBlock{{Type: harnessv2.ContentBlockText, Text: "synthetic result"}},
		}}}); err != nil {
		t.Error(err)
		return
	}
	if err := encoder.Close(); err != nil {
		t.Error(err)
	}
}
