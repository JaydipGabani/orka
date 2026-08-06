/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	types "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/harness"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
)

const harnessV1TestBindingDigest = "sha256:" + "abababababababababababababababababababababababababababababababab"

func harnessV1TestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func harnessV1TestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	db, err := sqlite.NewDB(filepath.Join(t.TempDir(), "harness-v1-dispatcher.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlite.NewStore(db, "test")
	cipher, err := sqlite.NewAgentExecutionSnapshotCipher(bytes.Repeat([]byte{0x22}, sqlite.AgentExecutionSnapshotKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	s.SetAgentExecutionSnapshotCipher(cipher)
	return s
}

func harnessV1TestEpochs(t *testing.T, controlStore *sqlite.Store) *ControllerEpochManager {
	t.Helper()
	epochs := NewControllerEpochManager(controlStore, "harness-v1-dispatcher-test")
	epochCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- epochs.Start(epochCtx) }()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	if _, err := epochs.CurrentFence(waitCtx); err != nil {
		t.Fatal(err)
	}
	return epochs
}

func harnessV1PersistSnapshot(t *testing.T, snapshots store.AgentExecutionSnapshotStore, taskUID string, body []byte) string {
	t.Helper()
	digest := store.CanonicalAgentExecutionSnapshotDigest(body)
	if err := snapshots.PersistAgentExecutionSnapshot(context.Background(), store.AgentExecutionSnapshot{
		TaskUID: taskUID, Digest: digest, SchemaVersion: store.AgentExecutionSnapshotSchemaVersion, Body: body,
	}); err != nil {
		t.Fatal(err)
	}
	return digest
}

func harnessV1BoundTask(name, uid, snapshotDigest string, mutate func(*corev1alpha1.Task)) *corev1alpha1.Task {
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID(uid), Generation: 1},
		Spec: corev1alpha1.TaskSpec{
			Type:     corev1alpha1.TaskTypeAgent,
			Prompt:   "say hello",
			AgentRef: &corev1alpha1.AgentReference{Name: "agent"},
		},
		Status: corev1alpha1.TaskStatus{
			Phase: corev1alpha1.TaskPhasePending,
			AgentExecutionBinding: &corev1alpha1.AgentExecutionBinding{
				SchemaVersion:   1,
				Mode:            corev1alpha1.AgentExecutionBindingModeExecute,
				ContractVersion: corev1alpha1.AgentRuntimeContractHarnessV1,
				Backend:         corev1alpha1.AgentExecutionBackendHarnessWrapper,
				Provenance:      corev1alpha1.AgentExecutionProvenanceNewlyBound,
				BindingDigest:   harnessV1TestBindingDigest,
				Task: corev1alpha1.AgentExecutionBindingTaskRef{
					NamespaceUID: types.UID("ns-uid"), UID: types.UID(uid), BoundSpecGeneration: 1,
				},
				Snapshot: corev1alpha1.AgentExecutionSnapshotRef{
					ID: uid + "/" + snapshotDigest, Digest: snapshotDigest, SchemaVersion: 1,
				},
				BoundAt: metav1.Now(),
			},
		},
	}
	if mutate != nil {
		mutate(task)
	}
	return task
}

func harnessV1TestDispatcher(kubeClient client.Client, controlStore *sqlite.Store, epochs *ControllerEpochManager, endpoint string) *HarnessV1Dispatcher {
	return &HarnessV1Dispatcher{
		Client:            kubeClient,
		APIReader:         kubeClient,
		Attempts:          controlStore,
		Snapshots:         controlStore,
		ExecutionEvents:   controlStore,
		Epochs:            epochs,
		WrapperEndpoint:   endpoint,
		StreamPollTimeout: 250 * time.Millisecond,
	}
}

// harnessV1FakeWrapper is a minimal scripted v1 wrapper speaking exactly the
// protocol paths the dispatcher uses, with wire-hit counting and a submission
// observation hook.
type harnessV1FakeWrapper struct {
	server *httptest.Server

	mu         sync.Mutex
	startHits  int
	cancelHits int
	turns      map[harness.HarnessTurnID]harness.StartTurnRequest

	// hangup closes the raw connection on every request, producing ambiguous
	// transport errors for both StartTurn and stream polls.
	hangup bool
	// terminalFrames appends a TurnCompleted frame after the runtime output.
	terminalFrames bool
	// emptyStream serves a well-formed but frameless event stream.
	emptyStream bool
	// truncateStream serves the frames and then drops the connection without
	// the SSE done marker or the terminating chunk.
	truncateStream bool
	// onStart runs while a StartTurn request is being handled.
	onStart func()
}

func newHarnessV1FakeWrapper(t *testing.T) *harnessV1FakeWrapper {
	t.Helper()
	wrapper := &harnessV1FakeWrapper{turns: map[harness.HarnessTurnID]harness.StartTurnRequest{}, terminalFrames: true}
	mux := http.NewServeMux()
	mux.HandleFunc(harness.TurnsPath, wrapper.handleStartTurn)
	mux.HandleFunc(harness.TurnsPath+"/", wrapper.handleTurn)
	wrapper.server = httptest.NewServer(mux)
	t.Cleanup(wrapper.server.Close)
	return wrapper
}

func (f *harnessV1FakeWrapper) URL() string { return f.server.URL }

func (f *harnessV1FakeWrapper) hits() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startHits, f.cancelHits
}

// registerTurn makes the wrapper own a turn without any StartTurn call, as a
// restored wrapper would after adopting historical state.
func (f *harnessV1FakeWrapper) registerTurn(request harness.StartTurnRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.turns[request.TurnID] = request
}

// forgetTurn simulates a wrapper restart that lost the turn state.
func (f *harnessV1FakeWrapper) forgetTurn(turnID harness.HarnessTurnID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.turns, turnID)
}

func (f *harnessV1FakeWrapper) closeConnection(w http.ResponseWriter) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		panic("test server connection is not hijackable")
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	_ = conn.Close()
}

func (f *harnessV1FakeWrapper) handleStartTurn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		harness.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	f.mu.Lock()
	f.startHits++
	onStart := f.onStart
	hangup := f.hangup
	f.mu.Unlock()
	if onStart != nil {
		onStart()
	}
	if hangup {
		f.closeConnection(w)
		return
	}
	var request harness.StartTurnRequest
	if err := decodeHarnessV1TestJSON(r, &request); err != nil {
		harness.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	eventStreamPath, err := harness.EventStreamPath(request.TurnID)
	if err != nil {
		harness.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.mu.Lock()
	f.turns[request.TurnID] = request
	f.mu.Unlock()
	harness.WriteJSON(w, http.StatusAccepted, harness.StartTurnResponse{
		Version:          harness.ProtocolVersion,
		Accepted:         true,
		RuntimeSessionID: request.RuntimeSessionID,
		TurnID:           request.TurnID,
		CorrelationID:    request.CorrelationID,
		EventStreamPath:  eventStreamPath,
	})
}

func (f *harnessV1FakeWrapper) handleTurn(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	hangup := f.hangup
	f.mu.Unlock()
	if hangup {
		f.closeConnection(w)
		return
	}
	turnID, resource, err := harness.ParseTurnResourcePath(r.URL.EscapedPath())
	if err != nil {
		harness.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	f.mu.Lock()
	request, known := f.turns[turnID]
	f.mu.Unlock()
	switch resource {
	case "events":
		if !known {
			harness.WriteError(w, http.StatusNotFound, "turn not found")
			return
		}
		f.writeFrames(w, r, request)
	case "cancel":
		f.mu.Lock()
		f.cancelHits++
		f.mu.Unlock()
		if !known {
			harness.WriteError(w, http.StatusNotFound, "turn not found")
			return
		}
		var cancelRequest harness.CancelTurnRequest
		if err := decodeHarnessV1TestJSON(r, &cancelRequest); err != nil {
			harness.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		harness.WriteJSON(w, http.StatusAccepted, harness.CancelTurnResponse{
			Version:          harness.ProtocolVersion,
			Accepted:         true,
			RuntimeSessionID: cancelRequest.RuntimeSessionID,
			TurnID:           cancelRequest.TurnID,
			CorrelationID:    cancelRequest.CorrelationID,
			Message:          "cancel accepted",
		})
	default:
		harness.WriteError(w, http.StatusNotFound, "not found")
	}
}

func (f *harnessV1FakeWrapper) writeFrames(w http.ResponseWriter, r *http.Request, request harness.StartTurnRequest) {
	afterSeq, _ := strconv.ParseInt(r.URL.Query().Get("afterSeq"), 10, 64)
	f.mu.Lock()
	terminal := f.terminalFrames
	empty := f.emptyStream
	truncate := f.truncateStream
	f.mu.Unlock()
	if empty {
		w.Header().Set("Content-Type", "text/event-stream")
		_ = harness.WriteSSEDone(w)
		return
	}
	frame := func(seq int64, frameType harness.FrameType) harness.HarnessEventFrame {
		return harness.HarnessEventFrame{
			Version:          harness.ProtocolVersion,
			Type:             frameType,
			RuntimeSessionID: request.RuntimeSessionID,
			TurnID:           request.TurnID,
			CorrelationID:    request.CorrelationID,
			Seq:              seq,
			CreatedAt:        time.Now().UTC(),
			Summary:          string(frameType),
		}
	}
	frames := []harness.HarnessEventFrame{frame(1, harness.FrameTurnStarted)}
	if terminal {
		output := frame(2, harness.FrameRuntimeOutput)
		output.ContentText = "echo: " + request.Input.Prompt
		completed := frame(3, harness.FrameTurnCompleted)
		completed.Completed = &harness.TurnCompleted{Result: "ok", FinalEventSeq: 3}
		frames = append(frames, output, completed)
	}
	pending := frames[:0]
	for _, current := range frames {
		if current.Seq > afterSeq {
			pending = append(pending, current)
		}
	}
	if truncate {
		f.writeTruncatedFrames(w, pending)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	for _, current := range pending {
		if err := harness.WriteSSEFrame(w, current); err != nil {
			return
		}
	}
	_ = harness.WriteSSEDone(w)
}

// writeTruncatedFrames writes a chunked SSE response containing the frames and
// then closes the connection without the terminating chunk, so the client
// receives every frame followed by an unexpected-EOF stream error.
func (f *harnessV1FakeWrapper) writeTruncatedFrames(w http.ResponseWriter, frames []harness.HarnessEventFrame) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		panic("test server connection is not hijackable")
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck
	var payload bytes.Buffer
	for _, frame := range frames {
		encoded, err := json.Marshal(frame)
		if err != nil {
			return
		}
		payload.WriteString("data: ")
		payload.Write(encoded)
		payload.WriteString("\n\n")
	}
	fmt.Fprintf(buffered, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
	fmt.Fprintf(buffered, "%x\r\n", payload.Len())
	buffered.Write(payload.Bytes())
	fmt.Fprintf(buffered, "\r\n")
	_ = buffered.Flush()
}

func decodeHarnessV1TestJSON(r *http.Request, out any) error {
	defer r.Body.Close() //nolint:errcheck
	return json.NewDecoder(r.Body).Decode(out)
}

func harnessV1AttemptKey(task *corev1alpha1.Task, attempt int32) store.HarnessV1AttemptKey {
	return store.HarnessV1AttemptKey{Namespace: task.Namespace, TaskUID: string(task.UID), Attempt: attempt}
}

// harnessV1CreateStoredAttempt seeds attempt 1 for a task exactly as the
// dispatcher would create it, so crash-window states can be simulated.
func harnessV1CreateStoredAttempt(t *testing.T, s *sqlite.Store, task *corev1alpha1.Task, snapshotDigest string) *store.HarnessV1Attempt {
	t.Helper()
	ctx := context.Background()
	requestDigest, err := acpDomainDigest("harness-v1-test-request", map[string]any{"taskUID": string(task.UID)})
	if err != nil {
		t.Fatal(err)
	}
	attempt := &store.HarnessV1Attempt{
		Namespace:      task.Namespace,
		TaskName:       task.Name,
		TaskUID:        string(task.UID),
		Attempt:        1,
		BindingDigest:  harnessV1TestBindingDigest,
		SnapshotDigest: snapshotDigest,
		RequestDigest:  requestDigest,
		TurnID:         fmt.Sprintf("%s-a1", task.UID),
		CorrelationID:  string(task.UID),
		Backend:        string(corev1alpha1.AgentExecutionBackendHarnessWrapper),
		State:          store.HarnessV1AttemptPrepared,
		RetryClass:     store.HarnessV1RetryClassNone,
	}
	if err := s.CreateHarnessV1Attempt(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	created, err := s.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	return created
}

// harnessV1ForceTransition applies one store transition directly to simulate a
// crash between dispatcher transitions.
func harnessV1ForceTransition(
	t *testing.T,
	s *sqlite.Store,
	attempt *store.HarnessV1Attempt,
	target store.HarnessV1AttemptState,
	operation string,
	updates store.HarnessV1AttemptUpdates,
) *store.HarnessV1Attempt {
	t.Helper()
	digest, err := acpDomainDigest("harness-v1-test-op", map[string]any{"operation": operation, "target": string(target)})
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.TransitionHarnessV1Attempt(context.Background(), store.HarnessV1AttemptTransition{
		Key:             store.HarnessV1AttemptKey{Namespace: attempt.Namespace, TaskUID: attempt.TaskUID, Attempt: attempt.Attempt},
		ExpectedVersion: attempt.Version,
		ExpectedState:   attempt.State,
		TargetState:     target,
		OperationID:     operation,
		OperationDigest: digest,
		Updates:         updates,
	})
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func harnessV1GetTask(t *testing.T, kubeClient client.Client, task *corev1alpha1.Task) *corev1alpha1.Task {
	t.Helper()
	current := &corev1alpha1.Task{}
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Namespace: task.Namespace, Name: task.Name}, current); err != nil {
		t.Fatal(err)
	}
	return current
}

// (a) Adopted observe path: no persisted frames and the wrapper does not know
// the turn, so the attempt is definitively Rejected and the Task fails with a
// clear message. StartTurn is never called for adoption snapshots.
func TestHarnessV1DispatcherAdoptedTaskWithoutExecutorStateRejects(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t)

	body := []byte(`{"schemaVersion":1,"adoption":true,"inventoryID":"inv-1","taskUID":"uid-adopted","contract":"orka.harness.v1","evidenceDigest":"` + harnessV1TestBindingDigest + `"}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-adopted", body)
	task := harnessV1BoundTask("adopted-task", "uid-adopted", digest, func(task *corev1alpha1.Task) {
		task.Status.AgentExecutionBinding.Provenance = corev1alpha1.AgentExecutionProvenanceLegacyAdopted
	})
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}

	attempt, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptRejected {
		t.Fatalf("attempt state = %s, want Rejected", attempt.State)
	}
	if attempt.TerminalReason != harnessV1ReasonAdoptedTurnMissing {
		t.Fatalf("terminal reason = %q, want %q", attempt.TerminalReason, harnessV1ReasonAdoptedTurnMissing)
	}
	current := harnessV1GetTask(t, kubeClient, task)
	if current.Status.Phase != corev1alpha1.TaskPhaseFailed {
		t.Fatalf("task phase = %s, want Failed", current.Status.Phase)
	}
	if !strings.Contains(current.Status.Message, harnessV1AdoptedNoStateMessage) {
		t.Fatalf("task message = %q, want it to contain %q", current.Status.Message, harnessV1AdoptedNoStateMessage)
	}
	if current.Status.CompletionTime == nil {
		t.Fatal("terminal task is missing a completion time")
	}
	startHits, _ := wrapper.hits()
	if startHits != 0 {
		t.Fatalf("StartTurn hits = %d, want 0 for an adopted turn", startHits)
	}
}

// (b) Full-snapshot dispatch: Submitting is durable before StartTurn reaches
// the wrapper, acceptance yields Accepted, and the terminal completed frame
// settles the attempt and the Task.
func TestHarnessV1DispatcherFullSnapshotDispatchSucceeds(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t)

	body := []byte(`{"schemaVersion":1,"contractVersion":"orka.harness.v1","backend":"harness-wrapper","prompt":"say hello","configuration":{"model":"gpt-test"}}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-full", body)
	task := harnessV1BoundTask("full-task", "uid-full", digest, nil)
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	var observedMu sync.Mutex
	var observedStateAtStart store.HarnessV1AttemptState
	wrapper.onStart = func() {
		attempt, err := controlStore.GetHarnessV1Attempt(context.Background(), harnessV1AttemptKey(task, 1))
		if err == nil {
			observedMu.Lock()
			observedStateAtStart = attempt.State
			observedMu.Unlock()
		}
	}

	for pass := 0; pass < 3; pass++ {
		if err := dispatcher.dispatchOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if harnessV1GetTask(t, kubeClient, task).Status.Phase == corev1alpha1.TaskPhaseSucceeded {
			break
		}
	}

	observedMu.Lock()
	observedAtStart := observedStateAtStart
	observedMu.Unlock()
	if observedAtStart != store.HarnessV1AttemptSubmitting {
		t.Fatalf("attempt state observed at StartTurn = %q, want Submitting persisted before the wire call", observedAtStart)
	}
	attempt, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptSucceeded {
		t.Fatalf("attempt state = %s, want Succeeded", attempt.State)
	}
	if attempt.LastEventSeq != 3 {
		t.Fatalf("attempt last event seq = %d, want 3", attempt.LastEventSeq)
	}
	if attempt.TerminalReceiptDigest == "" || attempt.TerminalReason != harnessV1ReasonCompleted {
		t.Fatalf("terminal receipt = %q reason = %q, want digest plus Completed", attempt.TerminalReceiptDigest, attempt.TerminalReason)
	}
	if attempt.BindingDigest != harnessV1TestBindingDigest || attempt.SnapshotDigest != digest {
		t.Fatalf("attempt digests = %q/%q, want binding and snapshot digests preserved", attempt.BindingDigest, attempt.SnapshotDigest)
	}
	current := harnessV1GetTask(t, kubeClient, task)
	if current.Status.Phase != corev1alpha1.TaskPhaseSucceeded {
		t.Fatalf("task phase = %s, want Succeeded", current.Status.Phase)
	}
	if current.Status.CompletionTime == nil || current.Status.StartTime == nil {
		t.Fatalf("task times = start %v completion %v, want both recorded", current.Status.StartTime, current.Status.CompletionTime)
	}
	if current.Status.HarnessRuntime == nil ||
		current.Status.HarnessRuntime.ContractVersion != harness.ProtocolVersion ||
		current.Status.HarnessRuntime.Endpoint != wrapper.URL() ||
		current.Status.HarnessRuntime.RuntimeName != harnessV1WrapperRuntimeName {
		t.Fatalf("harness runtime status = %#v, want v1 wrapper endpoint metadata", current.Status.HarnessRuntime)
	}
	if current.Status.Execution != nil || current.Status.Delivery != nil {
		t.Fatalf("v1-bound task acquired v2 state: execution=%v delivery=%v", current.Status.Execution, current.Status.Delivery)
	}
	startHits, _ := wrapper.hits()
	if startHits != 1 {
		t.Fatalf("StartTurn hits = %d, want exactly 1", startHits)
	}
}

// (c) An ambiguous submission becomes durable SubmittedUnknown and is NEVER
// resent: the next pass escalates to terminal OutcomeUnknown and fails the
// Task with OutcomeUnknown semantics.
func TestHarnessV1DispatcherAmbiguousSubmitNeverResends(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t)
	wrapper.hangup = true

	body := []byte(`{"schemaVersion":1,"prompt":"say hello","configuration":{"model":"gpt-test"}}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-ambiguous", body)
	task := harnessV1BoundTask("ambiguous-task", "uid-ambiguous", digest, nil)
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	// Pass 1: Prepared -> Submitting -> ambiguous wire failure -> SubmittedUnknown.
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	attempt, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptSubmittedUnknown {
		t.Fatalf("attempt state after pass 1 = %s, want SubmittedUnknown", attempt.State)
	}
	startHits, _ := wrapper.hits()
	if startHits != 1 {
		t.Fatalf("StartTurn hits after pass 1 = %d, want 1", startHits)
	}
	if phase := harnessV1GetTask(t, kubeClient, task).Status.Phase; phase != corev1alpha1.TaskPhasePending {
		t.Fatalf("task phase after pass 1 = %s, want Pending", phase)
	}

	// Pass 2: still unprovable -> terminal OutcomeUnknown, task failed, and the
	// request was not resent.
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	attempt, err = controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptOutcomeUnknown {
		t.Fatalf("attempt state after pass 2 = %s, want OutcomeUnknown", attempt.State)
	}
	if attempt.TerminalReason != harnessV1ReasonSubmissionUnprovable {
		t.Fatalf("terminal reason = %q, want %q", attempt.TerminalReason, harnessV1ReasonSubmissionUnprovable)
	}
	current := harnessV1GetTask(t, kubeClient, task)
	if current.Status.Phase != corev1alpha1.TaskPhaseFailed {
		t.Fatalf("task phase after pass 2 = %s, want Failed", current.Status.Phase)
	}
	if !strings.Contains(current.Status.Message, "OutcomeUnknown") {
		t.Fatalf("task message = %q, want it to mention OutcomeUnknown", current.Status.Message)
	}
	if current.Status.HarnessRuntime == nil {
		t.Fatal("task is missing the v1 harness runtime compatibility status")
	}

	// Pass 3: the terminal task is out of scope; nothing is resent.
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	startHits, _ = wrapper.hits()
	if startHits != 1 {
		t.Fatalf("StartTurn hits after pass 3 = %d, want exactly 1 (ambiguous submissions are never resent)", startHits)
	}
}

// (d) Cancellation intent transitions the attempt to nonterminal
// CancelRequested plus a wrapper CancelTurn; the attempt terminalizes only on
// a terminal frame or the bounded settlement escalation.
func TestHarnessV1DispatcherCancellationRequestIsNonterminal(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t)
	wrapper.terminalFrames = false // long-running turn: TurnStarted only

	body := []byte(`{"schemaVersion":1,"prompt":"run forever","configuration":{"model":"gpt-test"}}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-cancel", body)
	task := harnessV1BoundTask("cancel-task", "uid-cancel", digest, func(task *corev1alpha1.Task) {
		task.Spec.Timeout = &metav1.Duration{Duration: time.Nanosecond}
	})
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	// Pass 1: accept and start streaming; the task starts Running so the
	// timeout clock begins.
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	attempt, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptRunning {
		t.Fatalf("attempt state after pass 1 = %s, want Running", attempt.State)
	}

	// Pass 2: the 1ns timeout is exceeded -> CancelRequested plus wire cancel.
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	attempt, err = controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptCancelRequested {
		t.Fatalf("attempt state after pass 2 = %s, want CancelRequested", attempt.State)
	}
	if attempt.CancelRequestedAt == nil {
		t.Fatal("cancel request timestamp was not persisted")
	}
	if attempt.TerminalReason != harnessV1ReasonTimeout {
		t.Fatalf("cancel cause = %q, want %q", attempt.TerminalReason, harnessV1ReasonTimeout)
	}
	if store.IsTerminalHarnessV1AttemptState(attempt.State) {
		t.Fatal("CancelRequested must be nonterminal")
	}
	_, cancelHits := wrapper.hits()
	if cancelHits < 1 {
		t.Fatalf("CancelTurn hits after pass 2 = %d, want at least 1", cancelHits)
	}
	if phase := harnessV1GetTask(t, kubeClient, task).Status.Phase; phase != corev1alpha1.TaskPhaseRunning {
		t.Fatalf("task phase after pass 2 = %s, want Running (cancellation must not terminalize the task)", phase)
	}

	// Pass 3: no terminal frame and the settlement window is still open, so the
	// attempt stays CancelRequested and nothing terminalizes.
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	attempt, err = controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptCancelRequested {
		t.Fatalf("attempt state after pass 3 = %s, want CancelRequested", attempt.State)
	}
	if phase := harnessV1GetTask(t, kubeClient, task).Status.Phase; taskPhaseTerminal(phase) {
		t.Fatalf("task phase after pass 3 = %s, want nonterminal", phase)
	}
	startHits, _ := wrapper.hits()
	if startHits != 1 {
		t.Fatalf("StartTurn hits = %d, want exactly 1", startHits)
	}
}

// A journaled terminal frame settles the attempt even when the wrapper drops
// the connection right after emitting it; a trailing stream error must not
// outrank the durable terminal outcome.
func TestHarnessV1DispatcherSettlesTerminalFrameDespiteStreamError(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t)
	wrapper.truncateStream = true

	body := []byte(`{"schemaVersion":1,"prompt":"say hello","configuration":{"model":"gpt-test"}}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-truncated", body)
	task := harnessV1BoundTask("truncated-task", "uid-truncated", digest, nil)
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	for pass := 0; pass < 3; pass++ {
		if err := dispatcher.dispatchOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if harnessV1GetTask(t, kubeClient, task).Status.Phase == corev1alpha1.TaskPhaseSucceeded {
			break
		}
	}
	attempt, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptSucceeded {
		t.Fatalf("attempt state = %s, want Succeeded despite the truncated stream", attempt.State)
	}
	if phase := harnessV1GetTask(t, kubeClient, task).Status.Phase; phase != corev1alpha1.TaskPhaseSucceeded {
		t.Fatalf("task phase = %s, want Succeeded", phase)
	}
}

// A Settling attempt carries its durable terminal decision and must finalize
// from it even when the wrapper has lost the turn entirely.
func TestHarnessV1DispatcherSettlingRecoveryFinalizesFromDurableDecision(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t) // knows no turns: any poll would 404

	body := []byte(`{"schemaVersion":1,"prompt":"say hello","configuration":{"model":"gpt-test"}}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-settling", body)
	task := harnessV1BoundTask("settling-task", "uid-settling", digest, nil)
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	reason := harnessV1ReasonCompleted
	receipt := harnessV1TestBindingDigest
	attempt := harnessV1CreateStoredAttempt(t, controlStore, task, digest)
	attempt = harnessV1ForceTransition(t, controlStore, attempt, store.HarnessV1AttemptSubmitting, "t-submit", store.HarnessV1AttemptUpdates{})
	attempt = harnessV1ForceTransition(t, controlStore, attempt, store.HarnessV1AttemptAccepted, "t-accept", store.HarnessV1AttemptUpdates{})
	harnessV1ForceTransition(t, controlStore, attempt, store.HarnessV1AttemptSettling, "t-settle",
		store.HarnessV1AttemptUpdates{TerminalReason: &reason, TerminalReceiptDigest: &receipt})

	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != store.HarnessV1AttemptSucceeded {
		t.Fatalf("attempt state = %s, want Succeeded finalized from the durable Settling decision", recovered.State)
	}
	if phase := harnessV1GetTask(t, kubeClient, task).Status.Phase; phase != corev1alpha1.TaskPhaseSucceeded {
		t.Fatalf("task phase = %s, want Succeeded", phase)
	}
}

// An Accepted turn whose wrapper state is lost before any frame was journaled
// must terminalize as OutcomeUnknown instead of waiting forever.
func TestHarnessV1DispatcherAcceptedTurnStateLostBecomesOutcomeUnknown(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t)
	wrapper.emptyStream = true // accepted turn emits no frames before the loss

	body := []byte(`{"schemaVersion":1,"prompt":"say hello","configuration":{"model":"gpt-test"}}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-lost", body)
	task := harnessV1BoundTask("lost-task", "uid-lost", digest, nil)
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	attempt, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptAccepted {
		t.Fatalf("attempt state after pass 1 = %s, want Accepted", attempt.State)
	}

	wrapper.forgetTurn(harness.HarnessTurnID(attempt.TurnID))
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	attempt, err = controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptOutcomeUnknown || attempt.TerminalReason != harnessV1ReasonTurnStateLost {
		t.Fatalf("attempt = %s/%s, want OutcomeUnknown with TurnStateLost", attempt.State, attempt.TerminalReason)
	}
	current := harnessV1GetTask(t, kubeClient, task)
	if current.Status.Phase != corev1alpha1.TaskPhaseFailed || !strings.Contains(current.Status.Message, "OutcomeUnknown") {
		t.Fatalf("task = %s %q, want Failed mentioning OutcomeUnknown", current.Status.Phase, current.Status.Message)
	}
}

// A CancelRequested attempt whose turn state is lost stays nonterminal until
// the bounded settlement timeout escalates it to OutcomeUnknown with reason
// CancelUnsettled; a 404 alone must not preempt settlement.
func TestHarnessV1DispatcherCancelRequestedTurnLossWaitsForSettlementTimeout(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t)
	wrapper.terminalFrames = false

	body := []byte(`{"schemaVersion":1,"prompt":"run forever","configuration":{"model":"gpt-test"}}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-cancel-lost", body)
	task := harnessV1BoundTask("cancel-lost-task", "uid-cancel-lost", digest, func(task *corev1alpha1.Task) {
		task.Spec.Timeout = &metav1.Duration{Duration: time.Nanosecond}
	})
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	// Pass 1 accepts and runs; pass 2 requests cancellation.
	for pass := 0; pass < 2; pass++ {
		if err := dispatcher.dispatchOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	attempt, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptCancelRequested {
		t.Fatalf("attempt state after pass 2 = %s, want CancelRequested", attempt.State)
	}

	// Turn state loss during cancellation must not terminalize early.
	wrapper.forgetTurn(harness.HarnessTurnID(attempt.TurnID))
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	attempt, err = controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptCancelRequested {
		t.Fatalf("attempt state after turn loss = %s, want CancelRequested until settlement times out", attempt.State)
	}

	// The bounded settlement timeout is the only remaining exit.
	dispatcher.CancelSettlementTimeout = time.Nanosecond
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	attempt, err = controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptOutcomeUnknown || attempt.TerminalReason != harnessV1ReasonCancelUnsettled {
		t.Fatalf("attempt = %s/%s, want OutcomeUnknown with CancelUnsettled", attempt.State, attempt.TerminalReason)
	}
	current := harnessV1GetTask(t, kubeClient, task)
	if current.Status.Phase != corev1alpha1.TaskPhaseFailed || !strings.Contains(current.Status.Message, "OutcomeUnknown") {
		t.Fatalf("task = %s %q, want Failed mentioning OutcomeUnknown", current.Status.Phase, current.Status.Message)
	}
}

// A frameless poll is not ownership proof for an adopted turn: the attempt
// stays Prepared and retries instead of being falsely accepted.
func TestHarnessV1DispatcherAdoptedEmptyStreamStaysPrepared(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t)
	wrapper.emptyStream = true

	body := []byte(`{"schemaVersion":1,"adoption":true,"inventoryID":"inv-2","taskUID":"uid-adopted-empty","contract":"orka.harness.v1"}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-adopted-empty", body)
	task := harnessV1BoundTask("adopted-empty-task", "uid-adopted-empty", digest, func(task *corev1alpha1.Task) {
		task.Status.AgentExecutionBinding.Provenance = corev1alpha1.AgentExecutionProvenanceLegacyAdopted
	})
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	wrapper.registerTurn(harness.StartTurnRequest{
		TurnID:           harness.HarnessTurnID(string(task.UID) + "-a1"),
		RuntimeSessionID: harness.RuntimeSessionID("legacy-rsid"),
		CorrelationID:    "legacy-corr",
	})
	for pass := 0; pass < 2; pass++ {
		if err := dispatcher.dispatchOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	attempt, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != store.HarnessV1AttemptPrepared {
		t.Fatalf("attempt state = %s, want Prepared until positive frame evidence exists", attempt.State)
	}
	if phase := harnessV1GetTask(t, kubeClient, task).Status.Phase; phase != corev1alpha1.TaskPhasePending {
		t.Fatalf("task phase = %s, want Pending", phase)
	}
	startHits, _ := wrapper.hits()
	if startHits != 0 {
		t.Fatalf("StartTurn hits = %d, want 0 for an adopted turn", startHits)
	}
}

// A crash between the adopted Submitting and Accepted transitions recovers
// with adoption semantics: a missing turn is Rejected, never classified as an
// unprovable submission, and StartTurn is never called.
func TestHarnessV1DispatcherAdoptedSubmittingRecoveryUsesAdoptionSemantics(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t) // knows no turns: streams 404

	body := []byte(`{"schemaVersion":1,"adoption":true,"inventoryID":"inv-3","taskUID":"uid-adopted-crash","contract":"orka.harness.v1"}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-adopted-crash", body)
	task := harnessV1BoundTask("adopted-crash-task", "uid-adopted-crash", digest, func(task *corev1alpha1.Task) {
		task.Status.AgentExecutionBinding.Provenance = corev1alpha1.AgentExecutionProvenanceLegacyAdopted
	})
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	attempt := harnessV1CreateStoredAttempt(t, controlStore, task, digest)
	harnessV1ForceTransition(t, controlStore, attempt, store.HarnessV1AttemptSubmitting, "adopt-submit-crash", store.HarnessV1AttemptUpdates{})

	for pass := 0; pass < 2; pass++ {
		if err := dispatcher.dispatchOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	recovered, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != store.HarnessV1AttemptRejected || recovered.TerminalReason != harnessV1ReasonAdoptedTurnMissing {
		t.Fatalf("attempt = %s/%s, want Rejected with AdoptedTurnMissing (never SubmittedUnknown)", recovered.State, recovered.TerminalReason)
	}
	startHits, _ := wrapper.hits()
	if startHits != 0 {
		t.Fatalf("StartTurn hits = %d, want 0 for adopted recovery", startHits)
	}
	current := harnessV1GetTask(t, kubeClient, task)
	if current.Status.Phase != corev1alpha1.TaskPhaseFailed || !strings.Contains(current.Status.Message, harnessV1AdoptedNoStateMessage) {
		t.Fatalf("task = %s %q, want Failed with the adopted-turn message", current.Status.Phase, current.Status.Message)
	}
}

// Cancellation of an adopted Prepared attempt must observe and cancel the
// pre-existing remote turn instead of terminating the attempt locally as
// never-started.
func TestHarnessV1DispatcherAdoptedPreparedCancellationObservesRemoteTurn(t *testing.T) {
	ctx := context.Background()
	controlStore := harnessV1TestStore(t)
	epochs := harnessV1TestEpochs(t, controlStore)
	wrapper := newHarnessV1FakeWrapper(t)
	wrapper.terminalFrames = false // remote turn is still running

	body := []byte(`{"schemaVersion":1,"adoption":true,"inventoryID":"inv-4","taskUID":"uid-adopted-cancel","contract":"orka.harness.v1"}`)
	digest := harnessV1PersistSnapshot(t, controlStore, "uid-adopted-cancel", body)
	task := harnessV1BoundTask("adopted-cancel-task", "uid-adopted-cancel", digest, func(task *corev1alpha1.Task) {
		task.Status.AgentExecutionBinding.Provenance = corev1alpha1.AgentExecutionProvenanceLegacyAdopted
		task.Finalizers = []string{"orka.ai/test-cleanup"}
	})
	kubeClient := fake.NewClientBuilder().WithScheme(harnessV1TestScheme(t)).
		WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(task).Build()
	dispatcher := harnessV1TestDispatcher(kubeClient, controlStore, epochs, wrapper.URL())

	attempt := harnessV1CreateStoredAttempt(t, controlStore, task, digest)
	wrapper.registerTurn(harness.StartTurnRequest{
		TurnID:           harness.HarnessTurnID(attempt.TurnID),
		RuntimeSessionID: harness.RuntimeSessionID("legacy-rsid"),
		CorrelationID:    "legacy-corr",
	})
	if err := kubeClient.Delete(ctx, task.DeepCopy()); err != nil {
		t.Fatal(err)
	}

	// Pass 1: the deleting task's adopted turn is observed and driven to
	// Accepted/Running, never locally cancelled as unstarted.
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	observed, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if observed.State != store.HarnessV1AttemptAccepted && observed.State != store.HarnessV1AttemptRunning {
		t.Fatalf("attempt state after pass 1 = %s, want Accepted or Running (not locally cancelled)", observed.State)
	}

	// Pass 2: cancellation targets the exact remote turn.
	if err := dispatcher.dispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	cancelled, err := controlStore.GetHarnessV1Attempt(ctx, harnessV1AttemptKey(task, 1))
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.State != store.HarnessV1AttemptCancelRequested || cancelled.TerminalReason != harnessV1ReasonTaskDeleting {
		t.Fatalf("attempt = %s/%s, want CancelRequested with TaskDeleting", cancelled.State, cancelled.TerminalReason)
	}
	_, cancelHits := wrapper.hits()
	if cancelHits < 1 {
		t.Fatalf("CancelTurn hits = %d, want at least 1 against the remote turn", cancelHits)
	}
	startHits, _ := wrapper.hits()
	if startHits != 0 {
		t.Fatalf("StartTurn hits = %d, want 0 for an adopted turn", startHits)
	}
}
