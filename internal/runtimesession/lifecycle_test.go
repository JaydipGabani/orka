/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package runtimesession

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRuntimeSessionStateTransitions(t *testing.T) {
	valid := [][2]RuntimeSessionState{
		{RuntimeSessionStatePending, RuntimeSessionStateBooting},
		{RuntimeSessionStateBooting, RuntimeSessionStateReady},
		{RuntimeSessionStateReady, RuntimeSessionStateTurnRunning},
		{RuntimeSessionStateTurnRunning, RuntimeSessionStateIdle},
		{RuntimeSessionStateIdle, RuntimeSessionStateReleasing},
		{RuntimeSessionStateReleasing, RuntimeSessionStateRetained},
		{RuntimeSessionStateRetained, RuntimeSessionStateDeleting},
		{RuntimeSessionStateDeleting, RuntimeSessionStateDeleted},
		{RuntimeSessionStateIdle, RuntimeSessionStateSuspended},
		{RuntimeSessionStateSuspended, RuntimeSessionStateBooting},
	}
	for _, transition := range valid {
		if err := ValidateRuntimeSessionTransition(transition[0], transition[1]); err != nil {
			t.Fatalf("ValidateRuntimeSessionTransition(%s,%s) error = %v", transition[0], transition[1], err)
		}
	}
	invalid := [][2]RuntimeSessionState{
		{RuntimeSessionStateDeleted, RuntimeSessionStateReady},
		{RuntimeSessionStatePending, RuntimeSessionStateTurnRunning},
		{RuntimeSessionStateReady, RuntimeSessionStateSuspended},
	}
	for _, transition := range invalid {
		if err := ValidateRuntimeSessionTransition(transition[0], transition[1]); err == nil {
			t.Fatalf("ValidateRuntimeSessionTransition(%s,%s) error = nil, want error", transition[0], transition[1])
		}
	}
}

func TestRuntimeSessionValidationRequiresOwnership(t *testing.T) {
	session := RuntimeSession{ID: "runtime-a", State: RuntimeSessionStatePending, CleanupPolicy: RuntimeCleanupPolicyDelete}
	if err := session.Validate(); err == nil || !strings.Contains(err.Error(), "namespace is required") {
		t.Fatalf("Validate() = %v, want namespace required", err)
	}
	session.Owner = RuntimeSessionOwner{Namespace: "default", SessionName: "session-a", Provider: ProviderKindKubernetesService}
	if err := session.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestRuntimeSessionTransitionUpdatesTimestamp(t *testing.T) {
	session := RuntimeSession{
		ID:            "runtime-a",
		Owner:         RuntimeSessionOwner{Namespace: "default", SessionName: "session-a", Provider: ProviderKindKubernetesService},
		State:         RuntimeSessionStatePending,
		CleanupPolicy: RuntimeCleanupPolicyDelete,
	}
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	if err := session.Transition(RuntimeSessionStateBooting, now); err != nil {
		t.Fatalf("Transition() error = %v", err)
	}
	if session.State != RuntimeSessionStateBooting || !session.UpdatedAt.Equal(now) {
		t.Fatalf("session = %#v, want booting with timestamp", session)
	}
}

func TestRuntimeSessionJSONRoundTripPreservesShape(t *testing.T) {
	createdAt := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(5 * time.Minute)
	session := RuntimeSession{
		ID: "runtime-a",
		Owner: RuntimeSessionOwner{
			Namespace:   "runtime-ns",
			SessionName: "session-a",
			ActiveTask:  "task-a",
			AgentName:   "agent-a",
			Provider:    ProviderKindSubstrate,
		},
		State:         RuntimeSessionStateIdle,
		CleanupPolicy: RuntimeCleanupPolicySuspend,
		IdleTimeout:   2 * time.Minute,
		MaxLifetime:   time.Hour,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}

	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	const want = `{"id":"runtime-a","owner":{"namespace":"runtime-ns","sessionName":"session-a","activeTask":"task-a","agentName":"agent-a","provider":"substrate"},"state":"Idle","cleanupPolicy":"suspend","idleTimeout":120000000000,"maxLifetime":3600000000000,"createdAt":"2026-06-11T12:00:00Z","updatedAt":"2026-06-11T12:05:00Z"}`
	if string(encoded) != want {
		t.Fatalf("Marshal() = %s, want %s", encoded, want)
	}

	var decoded RuntimeSession
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if decoded != session {
		t.Fatalf("round trip = %#v, want %#v", decoded, session)
	}
}
