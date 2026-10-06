package supervisor

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/acp"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
)

func TestSupervisorAbandonsOnlyExplicitSettledPrompt(t *testing.T) {
	server, cfg, state, request := newPromptAbandonmentFixture(t)
	drain := harnessv2.DrainRequest{
		Protocol: harnessv2.ProtocolVersion, Reason: "runtime_pool_rollout_restart",
		Metadata: harnessv2.MutationMetadata{
			Fence: cfg.Fence, OperationID: "restart-drain", RequestDigestSchemaVersion: harnessv2.RequestDigestSchemaVersion,
			ExpiresAt: time.Now().UTC().Add(time.Minute),
		},
	}
	sealRequest(t, &drain.Metadata.RequestDigest, drain)
	response := performMutation(t, server.Handler(), http.MethodPut, harnessv2.DrainPath, drain, cfg)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated drain HTTP status = %d", response.Code)
	}
	server.mu.Lock()
	untouched := server.sessions[state.id] == state && state.descriptor.State == harnessv2.RuntimeSessionStateValidating &&
		!state.drainCleanupScheduled
	server.mu.Unlock()
	if !untouched {
		t.Fatal("generic drain discarded an unvalidated prompt without controller abandonment")
	}
	response = performMutation(t, server.Handler(), http.MethodDelete, "/v2/runtime-sessions/session-1", request, cfg)
	if response.Code != http.StatusOK {
		t.Fatalf("explicit prompt abandonment HTTP status = %d", response.Code)
	}
	var deleted harnessv2.DeleteRuntimeSessionResponse
	decodeResponse(t, response, &deleted)
	if err := deleted.ValidateFor(request); err != nil {
		t.Fatalf("abandonment did not produce exact deletion proof: %v", err)
	}
	server.mu.Lock()
	resident := len(server.sessions)
	accepting := server.drain.AcceptingNewSessions
	server.mu.Unlock()
	if resident != 0 || accepting {
		t.Fatal("retirement retained the abandoned session or reopened admission")
	}
	duplicate := performMutation(t, server.Handler(), http.MethodDelete, "/v2/runtime-sessions/session-1", request, cfg)
	if duplicate.Code != http.StatusOK {
		t.Fatalf("duplicate abandonment HTTP status = %d", duplicate.Code)
	}
	decodeResponse(t, duplicate, &deleted)
	if err := deleted.ValidateFor(request); err != nil || deleted.Classification.Class != harnessv2.RequestClassificationDuplicate {
		t.Fatalf("abandonment did not retain its exact tombstone: %v", err)
	}
}

func TestSupervisorPromptAbandonmentFailsClosed(t *testing.T) {
	for _, change := range []string{
		"ordinary delete", "task UID", "attempt", "prompt", "boot", "epoch",
		"missing settlement", "active validation", "prepared publication", "publishing", "finalizing",
	} {
		t.Run(change, func(t *testing.T) {
			server, cfg, state, request := newPromptAbandonmentFixture(t)
			switch change {
			case "ordinary delete":
				request.AbandonUnvalidatedPrompt = false
			case "task UID":
				request.Metadata.TaskUID = "other-task"
			case "attempt":
				request.Metadata.TaskAttempt++
			case "prompt":
				request.Metadata.PromptID = "other-prompt"
			case "boot":
				request.Metadata.Fence.SupervisorBootID = "other-boot"
			case "epoch":
				request.Metadata.Fence.ControllerEpoch++
			case "missing settlement":
				state.prompt.settlement = nil
			case "active validation":
				state.workspaceValidationInProgress = true
			case "prepared publication":
				state.descriptor.State = harnessv2.RuntimeSessionStatePublicationPrepared
			case "publishing":
				state.descriptor.State = harnessv2.RuntimeSessionStatePublishing
			case "finalizing":
				state.descriptor.State = harnessv2.RuntimeSessionStateFinalizing
			}
			originalState := state.descriptor.State
			sealRequest(t, &request.Metadata.RequestDigest, request)
			response := performMutation(t, server.Handler(), http.MethodDelete, "/v2/runtime-sessions/session-1", request, cfg)
			if response.Code != http.StatusConflict && response.Code != http.StatusGone {
				t.Fatalf("unsafe abandonment HTTP status = %d", response.Code)
			}
			server.mu.Lock()
			retained := server.sessions[state.id] == state && state.descriptor.State == originalState
			tombstones := len(server.tombstones)
			server.mu.Unlock()
			if !retained || tombstones != 0 {
				t.Fatal("rejected abandonment changed session state or minted a deletion tombstone")
			}
		})
	}
}

func TestSupervisorAbandonmentWaitsForCancellationSettlement(t *testing.T) {
	server, cfg, state, request := newPromptAbandonmentFixture(t)
	state.descriptor.State = harnessv2.RuntimeSessionStatePromptRunning
	state.prompt.settlement = nil
	mutations := &recordingPromptMutator{}
	state.promptMutations = mutations
	request.AbandonUnvalidatedPrompt = false
	sealRequest(t, &request.Metadata.RequestDigest, request)
	response := performMutation(t, server.Handler(), http.MethodDelete, "/v2/runtime-sessions/session-1", request, cfg)
	if response.Code != http.StatusConflict || mutations.cancelCalls != 1 {
		t.Fatalf("unsettled deletion: HTTP=%d cancellation calls=%d", response.Code, mutations.cancelCalls)
	}
	server.mu.Lock()
	unsettled := server.sessions[state.id] == state && state.prompt.settlement == nil &&
		state.descriptor.State == harnessv2.RuntimeSessionStateCancelling && len(server.tombstones) == 0
	server.mu.Unlock()
	if !unsettled {
		t.Fatal("cancellation request was treated as descendant cleanup proof")
	}
	server.finishPrompt(state, state.prompt, acp.PromptResult{
		Accepted: true, Outcome: acp.PromptOutcomeCompleted, StopReason: acp.StopReasonEndTurn,
	}, time.Now().UTC())
	request.AbandonUnvalidatedPrompt = true
	request.Metadata.OperationID = "abandon-after-settlement"
	sealRequest(t, &request.Metadata.RequestDigest, request)
	response = performMutation(t, server.Handler(), http.MethodDelete, "/v2/runtime-sessions/session-1", request, cfg)
	if response.Code != http.StatusOK {
		t.Fatalf("settled prompt retirement HTTP status = %d", response.Code)
	}
	var proof harnessv2.DeleteRuntimeSessionResponse
	decodeResponse(t, response, &proof)
	if err := proof.ValidateFor(request); err != nil {
		t.Fatalf("settled cancellation lacks exact retirement proof: %v", err)
	}
}

// This handler fixture starts no ACP process. The full child-process variant
// below exercises the same request when the host can enforce UID isolation.
func newPromptAbandonmentFixture(t *testing.T) (*Server, Config, *sessionState, harnessv2.DeleteRuntimeSessionRequest) {
	t.Helper()
	now := time.Now().UTC()
	base := harnessv2.Fence{
		RuntimeInstanceID: "runtime-pod.original-boot", SupervisorBootID: "original-boot", ControllerEpoch: 26,
		RuntimePoolUID: "runtime-pool", RuntimePoolGeneration: 4,
		RuntimeProfileDigest: harnessv2.ProfileDigest(testDigest("profile")), ProfileDigestSchemaVersion: harnessv2.ProfileDigestSchemaVersion,
	}
	cfg := Config{
		Fence: base, ControllerBearerToken: strings.Repeat("t", 32), CapabilitySecret: []byte(strings.Repeat("s", 32)),
		RequireCapabilities: true, Capabilities: harnessv2.CapabilitiesResponse{Limits: harnessv2.DefaultProtocolLimits()},
	}
	fence := base
	fence.RuntimeSessionUID, fence.RuntimeSessionGeneration = "session-uid", 1
	metadata := harnessv2.MutationMetadata{
		Fence: fence, TaskUID: "accepted-task-uid", TaskAttempt: 1, PromptID: "accepted-prompt",
		OperationID: "abandon-prompt", RequestDigestSchemaVersion: harnessv2.RequestDigestSchemaVersion,
		ExpiresAt: now.Add(time.Minute),
	}
	promptMetadata := metadata
	promptMetadata.OperationID = "accepted-operation"
	promptMetadata.RequestDigest = harnessv2.RequestDigest(testDigest("accepted-operation"))
	root := t.TempDir()
	state := &sessionState{
		id: "session-1", runtime: &acp.RuntimeSession{}, paths: acp.SessionPaths{Root: root, Workspace: root},
		descriptor: harnessv2.RuntimeSessionDescriptor{
			RuntimeSessionID: "session-1", RuntimeSessionUID: fence.RuntimeSessionUID, Generation: 1,
			RuntimeInstanceID: base.RuntimeInstanceID, SupervisorBootID: base.SupervisorBootID, RuntimeProfileDigest: base.RuntimeProfileDigest,
			State: harnessv2.RuntimeSessionStateValidating, CreatedAt: now, LastTransitionAt: now,
		},
		prompt: &promptState{
			request: harnessv2.StartPromptRequest{Metadata: promptMetadata}, acceptedAt: now,
			settlement: &harnessv2.PromptSettlement{
				TerminalEvent: harnessv2.EventCompleted, Outcome: harnessv2.PromptOutcomeSucceeded,
				StopReason: harnessv2.ACPStopReasonEndTurn, SettledAt: now,
			},
		},
		operations: map[harnessv2.OperationID]harnessv2.OperationRecord{},
	}
	server := &Server{
		cfg: cfg, mux: http.NewServeMux(), sessions: map[harnessv2.RuntimeSessionID]*sessionState{state.id: state},
		tombstones: map[harnessv2.RuntimeSessionUID]sessionTombstone{}, poolOps: map[harnessv2.OperationID]harnessv2.OperationRecord{},
	}
	server.registerRoutes()
	request := harnessv2.DeleteRuntimeSessionRequest{
		Protocol: harnessv2.ProtocolVersion, Metadata: metadata, Reason: "terminal_recovery", AbandonUnvalidatedPrompt: true,
	}
	sealRequest(t, &request.Metadata.RequestDigest, request)
	return server, cfg, state, request
}

func TestSupervisorAbandonsCompletedChildWithoutPromptReplay(t *testing.T) {
	server, cfg, profile := newTestServer(t, "immediate")
	create := testCreateSessionRequest(t, cfg, profile)
	created := performMutation(t, server.Handler(), http.MethodPut, "/v2/runtime-sessions/session-1", create, cfg)
	if created.Code != http.StatusCreated {
		t.Fatalf("create HTTP status = %d", created.Code)
	}
	prompt := testStartPromptRequest(t, cfg, create.Metadata.Fence)
	completed := performMutation(t, server.Handler(), http.MethodPut, "/v2/runtime-sessions/session-1/prompts/prompt-1", prompt, cfg)
	if completed.Code != http.StatusOK {
		t.Fatalf("prompt HTTP status = %d", completed.Code)
	}
	server.mu.Lock()
	state := server.sessions[create.RuntimeSessionID]
	validating := state != nil && state.descriptor.State == harnessv2.RuntimeSessionStateValidating &&
		state.prompt != nil && state.prompt.settlement != nil
	server.mu.Unlock()
	if !validating {
		t.Fatal("completed ACP child did not leave a settled validation obligation")
	}
	request := harnessv2.DeleteRuntimeSessionRequest{
		Protocol: harnessv2.ProtocolVersion, Metadata: prompt.Metadata, Reason: "terminal_recovery", AbandonUnvalidatedPrompt: true,
	}
	request.Metadata.OperationID = "abandon-completed-child"
	request.Metadata.ExpiresAt = time.Now().UTC().Add(time.Minute)
	sealRequest(t, &request.Metadata.RequestDigest, request)
	deleted := performMutation(t, server.Handler(), http.MethodDelete, "/v2/runtime-sessions/session-1", request, cfg)
	if deleted.Code != http.StatusOK {
		t.Fatalf("child abandonment HTTP status = %d", deleted.Code)
	}
	var proof harnessv2.DeleteRuntimeSessionResponse
	decodeResponse(t, deleted, &proof)
	if err := proof.ValidateFor(request); err != nil {
		t.Fatalf("child retirement lacks deletion proof: %v", err)
	}
}
