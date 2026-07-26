/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/runtimesession"
	"github.com/orka-agents/orka/internal/store"
)

const (
	runtimeSessionTestNamespace = "runtime-ns"
	runtimeSessionTestName      = "runtime-session"
	runtimeSessionTestTask      = "runtime-task"
	runtimeSessionTestAgent     = "runtime-agent"
	runtimeSessionNamespaceA    = "runtime-ns-a"
	runtimeSessionNamespaceB    = "runtime-ns-b"
)

func TestRuntimeSessionStoreCreateGetRoundTrip(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	createdAt := time.Date(2026, 6, 24, 10, 0, 0, 123, time.FixedZone("offset", -7*60*60))
	updatedAt := createdAt.Add(time.Minute)
	session := runtimeSessionFixture("runtime-a")
	session.CreatedAt = createdAt
	session.UpdatedAt = updatedAt
	session.IdleTimeout = 5 * time.Minute
	session.MaxLifetime = 2 * time.Hour

	if err := s.CreateRuntimeSession(ctx, &session); err != nil {
		t.Fatalf("CreateRuntimeSession: %v", err)
	}
	if !session.CreatedAt.Equal(createdAt.UTC()) || !session.UpdatedAt.Equal(updatedAt.UTC()) {
		t.Fatalf("normalized timestamps = %s/%s, want UTC %s/%s", session.CreatedAt, session.UpdatedAt, createdAt.UTC(), updatedAt.UTC())
	}

	got, err := s.GetRuntimeSession(ctx, runtimeSessionTestNamespace, "runtime-a")
	if err != nil {
		t.Fatalf("GetRuntimeSession: %v", err)
	}
	assertRuntimeSessionEqual(t, *got, session)
}

func TestRuntimeSessionStoreCreateDefaults(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	session := runtimeSessionFixture(" runtime-defaults ")
	session.Owner.Namespace = " " + runtimeSessionTestNamespace + " "
	session.Owner.SessionName = " " + runtimeSessionTestName + " "
	session.Owner.ActiveTask = " " + runtimeSessionTestTask + " "
	session.Owner.AgentName = " " + runtimeSessionTestAgent + " "
	session.Owner.Provider = " kubernetes-service "
	session.State = ""
	session.CleanupPolicy = ""

	if err := s.CreateRuntimeSession(ctx, &session); err != nil {
		t.Fatalf("CreateRuntimeSession: %v", err)
	}
	if session.ID != "runtime-defaults" || session.Owner.Namespace != runtimeSessionTestNamespace || session.Owner.SessionName != runtimeSessionTestName {
		t.Fatalf("normalized identity = %#v", session)
	}
	if session.State != runtimesession.RuntimeSessionStatePending {
		t.Fatalf("state = %q, want Pending", session.State)
	}
	if session.CleanupPolicy != runtimesession.RuntimeCleanupPolicyDelete {
		t.Fatalf("cleanup policy = %q, want delete", session.CleanupPolicy)
	}
	if session.CreatedAt.IsZero() || session.UpdatedAt.IsZero() || !session.UpdatedAt.Equal(session.CreatedAt) {
		t.Fatalf("timestamps = %s/%s, want populated equal values", session.CreatedAt, session.UpdatedAt)
	}

	got, err := s.GetRuntimeSession(ctx, runtimeSessionTestNamespace, "runtime-defaults")
	if err != nil {
		t.Fatalf("GetRuntimeSession: %v", err)
	}
	assertRuntimeSessionEqual(t, *got, session)
}

func TestRuntimeSessionStoreNamespaceOwnership(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	nsA := runtimeSessionFixture("runtime-shared")
	nsA.Owner.Namespace = runtimeSessionNamespaceA
	nsA.Owner.SessionName = runtimeSessionTestName
	nsB := runtimeSessionFixture("runtime-shared")
	nsB.Owner.Namespace = runtimeSessionNamespaceB
	nsB.Owner.SessionName = "session-b"

	if err := s.CreateRuntimeSession(ctx, &nsA); err != nil {
		t.Fatalf("CreateRuntimeSession ns-a: %v", err)
	}
	if err := s.CreateRuntimeSession(ctx, &nsB); err != nil {
		t.Fatalf("CreateRuntimeSession ns-b: %v", err)
	}

	gotA, err := s.GetRuntimeSession(ctx, runtimeSessionNamespaceA, "runtime-shared")
	if err != nil {
		t.Fatalf("GetRuntimeSession ns-a: %v", err)
	}
	gotB, err := s.GetRuntimeSession(ctx, runtimeSessionNamespaceB, "runtime-shared")
	if err != nil {
		t.Fatalf("GetRuntimeSession ns-b: %v", err)
	}
	if gotA.Owner.Namespace != runtimeSessionNamespaceA || gotA.Owner.SessionName != runtimeSessionTestName {
		t.Fatalf("ns-a row = %#v", gotA)
	}
	if gotB.Owner.Namespace != runtimeSessionNamespaceB || gotB.Owner.SessionName != "session-b" {
		t.Fatalf("ns-b row = %#v", gotB)
	}
	if _, err := s.GetRuntimeSession(ctx, "ns-c", "runtime-shared"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetRuntimeSession ns-c error = %v, want ErrNotFound", err)
	}
	duplicate := runtimeSessionFixture("runtime-shared")
	duplicate.Owner.Namespace = runtimeSessionNamespaceA
	if err := s.CreateRuntimeSession(ctx, &duplicate); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("CreateRuntimeSession duplicate error = %v, want ErrConflict", err)
	}
}

func TestRuntimeSessionStoreListFiltersAndCursor(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	fixtures := []runtimesession.RuntimeSession{
		runtimeSessionListFixture("runtime-1", "ns-list", "alpha", runtimeSessionTestTask, runtimeSessionTestAgent, runtimesession.ProviderKindKubernetesService, runtimesession.RuntimeSessionStatePending, runtimesession.RuntimeCleanupPolicyDelete, base.Add(5*time.Minute)),
		runtimeSessionListFixture("runtime-2", "ns-list", "alpha", "task-b", "agent-b", runtimesession.ProviderKindKubernetesService, runtimesession.RuntimeSessionStateIdle, runtimesession.RuntimeCleanupPolicyRetain, base.Add(4*time.Minute)),
		runtimeSessionListFixture("runtime-3", "ns-list", "alpha", "", runtimeSessionTestAgent, runtimesession.ProviderKindKubernetesService, runtimesession.RuntimeSessionStateDeleted, runtimesession.RuntimeCleanupPolicyDelete, base.Add(3*time.Minute)),
		runtimeSessionListFixture("runtime-4", "ns-list", "beta", "task-c", runtimeSessionTestAgent, runtimesession.ProviderKindSidecar, runtimesession.RuntimeSessionStateReady, runtimesession.RuntimeCleanupPolicySuspend, base.Add(2*time.Minute)),
		runtimeSessionListFixture("runtime-5", "other-ns", "alpha", runtimeSessionTestTask, runtimeSessionTestAgent, runtimesession.ProviderKindKubernetesService, runtimesession.RuntimeSessionStatePending, runtimesession.RuntimeCleanupPolicyDelete, base.Add(time.Minute)),
	}
	for i := range fixtures {
		if err := s.CreateRuntimeSession(ctx, &fixtures[i]); err != nil {
			t.Fatalf("CreateRuntimeSession %s: %v", fixtures[i].ID, err)
		}
	}

	listed, cursor, err := s.ListRuntimeSessions(ctx, runtimesession.RuntimeSessionFilter{Namespace: "ns-list"})
	if err != nil {
		t.Fatalf("ListRuntimeSessions default: %v", err)
	}
	assertRuntimeSessionIDs(t, listed, []runtimesession.RuntimeSessionID{"runtime-1", "runtime-2", "runtime-4"})
	if cursor != "" {
		t.Fatalf("cursor = %q, want empty", cursor)
	}

	listed, _, err = s.ListRuntimeSessions(ctx, runtimesession.RuntimeSessionFilter{Namespace: "ns-list", IncludeDeleted: true})
	if err != nil {
		t.Fatalf("ListRuntimeSessions include deleted: %v", err)
	}
	assertRuntimeSessionIDs(t, listed, []runtimesession.RuntimeSessionID{"runtime-1", "runtime-2", "runtime-3", "runtime-4"})

	filterAssertions := []struct {
		name   string
		filter runtimesession.RuntimeSessionFilter
		want   []runtimesession.RuntimeSessionID
	}{
		{name: "state", filter: runtimesession.RuntimeSessionFilter{States: []runtimesession.RuntimeSessionState{runtimesession.RuntimeSessionStateDeleted}}, want: []runtimesession.RuntimeSessionID{"runtime-3"}},
		{name: "session", filter: runtimesession.RuntimeSessionFilter{SessionName: "beta"}, want: []runtimesession.RuntimeSessionID{"runtime-4"}},
		{name: "active task", filter: runtimesession.RuntimeSessionFilter{ActiveTask: "task-b"}, want: []runtimesession.RuntimeSessionID{"runtime-2"}},
		{name: "agent", filter: runtimesession.RuntimeSessionFilter{AgentName: runtimeSessionTestAgent}, want: []runtimesession.RuntimeSessionID{"runtime-1", "runtime-4"}},
		{name: "provider", filter: runtimesession.RuntimeSessionFilter{Provider: runtimesession.ProviderKindSidecar}, want: []runtimesession.RuntimeSessionID{"runtime-4"}},
		{name: "cleanup", filter: runtimesession.RuntimeSessionFilter{CleanupPolicies: []runtimesession.RuntimeCleanupPolicy{runtimesession.RuntimeCleanupPolicyRetain}}, want: []runtimesession.RuntimeSessionID{"runtime-2"}},
	}
	for _, tt := range filterAssertions {
		t.Run(tt.name, func(t *testing.T) {
			filter := tt.filter
			filter.Namespace = "ns-list"
			listed, _, err := s.ListRuntimeSessions(ctx, filter)
			if err != nil {
				t.Fatalf("ListRuntimeSessions: %v", err)
			}
			assertRuntimeSessionIDs(t, listed, tt.want)
		})
	}

	page1, cursor, err := s.ListRuntimeSessions(ctx, runtimesession.RuntimeSessionFilter{Namespace: "ns-list", Limit: 2})
	if err != nil {
		t.Fatalf("ListRuntimeSessions page1: %v", err)
	}
	assertRuntimeSessionIDs(t, page1, []runtimesession.RuntimeSessionID{"runtime-1", "runtime-2"})
	if cursor == "" {
		t.Fatal("cursor is empty, want second page cursor")
	}
	page2, next, err := s.ListRuntimeSessions(ctx, runtimesession.RuntimeSessionFilter{Namespace: "ns-list", Limit: 2, Cursor: cursor})
	if err != nil {
		t.Fatalf("ListRuntimeSessions page2: %v", err)
	}
	assertRuntimeSessionIDs(t, page2, []runtimesession.RuntimeSessionID{"runtime-4"})
	if next != "" {
		t.Fatalf("next cursor = %q, want empty", next)
	}
}

func TestRuntimeSessionStoreTransitionValidatesStateMachine(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	session := runtimeSessionFixture("runtime-transition")
	if err := s.CreateRuntimeSession(ctx, &session); err != nil {
		t.Fatalf("CreateRuntimeSession: %v", err)
	}

	transitionAt := time.Date(2026, 6, 24, 11, 0, 0, 0, time.UTC)
	updated, err := s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{
		Namespace: runtimeSessionTestNamespace,
		ID:        session.ID,
		From:      runtimesession.RuntimeSessionStatePending,
		To:        runtimesession.RuntimeSessionStateBooting,
		UpdatedAt: transitionAt,
	})
	if err != nil {
		t.Fatalf("TransitionRuntimeSession: %v", err)
	}
	if updated.State != runtimesession.RuntimeSessionStateBooting || !updated.UpdatedAt.Equal(transitionAt) {
		t.Fatalf("updated session = %#v, want Booting at transition time", updated)
	}

	_, err = s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{
		Namespace: runtimeSessionTestNamespace,
		ID:        session.ID,
		From:      runtimesession.RuntimeSessionStateBooting,
		To:        runtimesession.RuntimeSessionStateTurnRunning,
		UpdatedAt: transitionAt.Add(time.Minute),
	})
	if !errors.Is(err, store.ErrValidation) {
		t.Fatalf("invalid TransitionRuntimeSession error = %v, want ErrValidation", err)
	}
	got, err := s.GetRuntimeSession(ctx, runtimeSessionTestNamespace, session.ID)
	if err != nil {
		t.Fatalf("GetRuntimeSession after invalid transition: %v", err)
	}
	if got.State != runtimesession.RuntimeSessionStateBooting || !got.UpdatedAt.Equal(transitionAt) {
		t.Fatalf("session changed after invalid transition: %#v", got)
	}
}

func TestRuntimeSessionStoreTransitionUsesExpectedFromState(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	session := runtimeSessionFixture("runtime-cas")
	if err := s.CreateRuntimeSession(ctx, &session); err != nil {
		t.Fatalf("CreateRuntimeSession: %v", err)
	}
	if _, err := s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{
		Namespace: runtimeSessionTestNamespace,
		ID:        session.ID,
		From:      runtimesession.RuntimeSessionStatePending,
		To:        runtimesession.RuntimeSessionStateBooting,
	}); err != nil {
		t.Fatalf("initial TransitionRuntimeSession: %v", err)
	}

	_, err := s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{
		Namespace: runtimeSessionTestNamespace,
		ID:        session.ID,
		From:      runtimesession.RuntimeSessionStatePending,
		To:        runtimesession.RuntimeSessionStateFailed,
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale TransitionRuntimeSession error = %v, want ErrConflict", err)
	}
	got, err := s.GetRuntimeSession(ctx, runtimeSessionTestNamespace, session.ID)
	if err != nil {
		t.Fatalf("GetRuntimeSession: %v", err)
	}
	if got.State != runtimesession.RuntimeSessionStateBooting {
		t.Fatalf("state = %q, want Booting after stale transition", got.State)
	}
}

func TestRuntimeSessionStoreTransitionCanSetAndClearActiveTask(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	session := runtimeSessionFixture("runtime-active-task")
	session.State = runtimesession.RuntimeSessionStateReady
	session.Owner.ActiveTask = ""
	if err := s.CreateRuntimeSession(ctx, &session); err != nil {
		t.Fatalf("CreateRuntimeSession: %v", err)
	}

	activeTask := runtimeSessionTestTask
	updated, err := s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{
		Namespace:  runtimeSessionTestNamespace,
		ID:         session.ID,
		From:       runtimesession.RuntimeSessionStateReady,
		To:         runtimesession.RuntimeSessionStateTurnRunning,
		ActiveTask: &activeTask,
	})
	if err != nil {
		t.Fatalf("set active task transition: %v", err)
	}
	if updated.Owner.ActiveTask != runtimeSessionTestTask {
		t.Fatalf("active task = %q, want runtime task", updated.Owner.ActiveTask)
	}

	updated, err = s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{
		Namespace: runtimeSessionTestNamespace,
		ID:        session.ID,
		From:      runtimesession.RuntimeSessionStateTurnRunning,
		To:        runtimesession.RuntimeSessionStateIdle,
	})
	if err != nil {
		t.Fatalf("preserve active task transition: %v", err)
	}
	if updated.Owner.ActiveTask != runtimeSessionTestTask {
		t.Fatalf("active task = %q, want preserved runtime task", updated.Owner.ActiveTask)
	}

	if _, err := s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{
		Namespace: runtimeSessionTestNamespace,
		ID:        session.ID,
		From:      runtimesession.RuntimeSessionStateIdle,
		To:        runtimesession.RuntimeSessionStateTurnRunning,
	}); err != nil {
		t.Fatalf("back to running transition: %v", err)
	}
	clearActiveTask := ""
	updated, err = s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{
		Namespace:  runtimeSessionTestNamespace,
		ID:         session.ID,
		From:       runtimesession.RuntimeSessionStateTurnRunning,
		To:         runtimesession.RuntimeSessionStateIdle,
		ActiveTask: &clearActiveTask,
	})
	if err != nil {
		t.Fatalf("clear active task transition: %v", err)
	}
	if updated.Owner.ActiveTask != "" {
		t.Fatalf("active task = %q, want cleared", updated.Owner.ActiveTask)
	}
}

func TestRuntimeSessionStoreDeleteRequiresDeletedState(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	session := runtimeSessionFixture("runtime-delete")
	if err := s.CreateRuntimeSession(ctx, &session); err != nil {
		t.Fatalf("CreateRuntimeSession: %v", err)
	}
	if err := s.DeleteRuntimeSession(ctx, runtimeSessionTestNamespace, session.ID); !errors.Is(err, store.ErrValidation) {
		t.Fatalf("DeleteRuntimeSession active error = %v, want ErrValidation", err)
	}
	if _, err := s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{Namespace: runtimeSessionTestNamespace, ID: session.ID, From: runtimesession.RuntimeSessionStatePending, To: runtimesession.RuntimeSessionStateDeleting}); err != nil {
		t.Fatalf("transition to deleting: %v", err)
	}
	if _, err := s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{Namespace: runtimeSessionTestNamespace, ID: session.ID, From: runtimesession.RuntimeSessionStateDeleting, To: runtimesession.RuntimeSessionStateDeleted}); err != nil {
		t.Fatalf("transition to deleted: %v", err)
	}
	if err := s.DeleteRuntimeSession(ctx, runtimeSessionTestNamespace, session.ID); err != nil {
		t.Fatalf("DeleteRuntimeSession deleted: %v", err)
	}
	if _, err := s.GetRuntimeSession(ctx, runtimeSessionTestNamespace, session.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetRuntimeSession after delete error = %v, want ErrNotFound", err)
	}
}

func TestRuntimeSessionStoreValidationErrors(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	assertValidationError := func(name string, fn func() error) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if err := fn(); !errors.Is(err, store.ErrValidation) {
				t.Fatalf("error = %v, want ErrValidation", err)
			}
		})
	}

	assertValidationError("nil create", func() error { return s.CreateRuntimeSession(ctx, nil) })
	assertValidationError("empty id", func() error {
		session := runtimeSessionFixture("")
		return s.CreateRuntimeSession(ctx, &session)
	})
	assertValidationError("empty namespace", func() error {
		session := runtimeSessionFixture("runtime-invalid")
		session.Owner.Namespace = ""
		return s.CreateRuntimeSession(ctx, &session)
	})
	assertValidationError("empty session", func() error {
		session := runtimeSessionFixture("runtime-invalid")
		session.Owner.SessionName = ""
		return s.CreateRuntimeSession(ctx, &session)
	})
	assertValidationError("empty provider", func() error {
		session := runtimeSessionFixture("runtime-invalid")
		session.Owner.Provider = ""
		return s.CreateRuntimeSession(ctx, &session)
	})
	assertValidationError("unknown state", func() error {
		session := runtimeSessionFixture("runtime-invalid")
		session.State = "Mystery"
		return s.CreateRuntimeSession(ctx, &session)
	})
	assertValidationError("unknown cleanup policy", func() error {
		session := runtimeSessionFixture("runtime-invalid")
		session.CleanupPolicy = "archive"
		return s.CreateRuntimeSession(ctx, &session)
	})
	assertValidationError("negative idle timeout", func() error {
		session := runtimeSessionFixture("runtime-invalid")
		session.IdleTimeout = -time.Second
		return s.CreateRuntimeSession(ctx, &session)
	})
	assertValidationError("negative max lifetime", func() error {
		session := runtimeSessionFixture("runtime-invalid")
		session.MaxLifetime = -time.Second
		return s.CreateRuntimeSession(ctx, &session)
	})
	assertValidationError("get empty namespace", func() error {
		_, err := s.GetRuntimeSession(ctx, "", "runtime")
		return err
	})
	assertValidationError("get empty id", func() error {
		_, err := s.GetRuntimeSession(ctx, runtimeSessionTestNamespace, "")
		return err
	})
	assertValidationError("list empty namespace", func() error {
		_, _, err := s.ListRuntimeSessions(ctx, runtimesession.RuntimeSessionFilter{})
		return err
	})
	assertValidationError("list invalid state", func() error {
		_, _, err := s.ListRuntimeSessions(ctx, runtimesession.RuntimeSessionFilter{Namespace: runtimeSessionTestNamespace, States: []runtimesession.RuntimeSessionState{"Mystery"}})
		return err
	})
	assertValidationError("list invalid cleanup policy", func() error {
		_, _, err := s.ListRuntimeSessions(ctx, runtimesession.RuntimeSessionFilter{Namespace: runtimeSessionTestNamespace, CleanupPolicies: []runtimesession.RuntimeCleanupPolicy{"archive"}})
		return err
	})
	assertValidationError("list invalid cursor", func() error {
		_, _, err := s.ListRuntimeSessions(ctx, runtimesession.RuntimeSessionFilter{Namespace: runtimeSessionTestNamespace, Cursor: "not-an-offset"})
		return err
	})
	assertValidationError("transition empty namespace", func() error {
		_, err := s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{ID: "runtime", From: runtimesession.RuntimeSessionStatePending, To: runtimesession.RuntimeSessionStateBooting})
		return err
	})
	assertValidationError("transition invalid state", func() error {
		_, err := s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{Namespace: runtimeSessionTestNamespace, ID: "runtime", From: "Mystery", To: runtimesession.RuntimeSessionStateBooting})
		return err
	})
	assertValidationError("delete empty namespace", func() error { return s.DeleteRuntimeSession(ctx, "", "runtime") })

	if _, err := s.GetRuntimeSession(ctx, runtimeSessionTestNamespace, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetRuntimeSession missing error = %v, want ErrNotFound", err)
	}
	if _, err := s.TransitionRuntimeSession(ctx, runtimesession.RuntimeSessionTransition{Namespace: runtimeSessionTestNamespace, ID: "missing", From: runtimesession.RuntimeSessionStatePending, To: runtimesession.RuntimeSessionStateBooting}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("TransitionRuntimeSession missing error = %v, want ErrNotFound", err)
	}
	if err := s.DeleteRuntimeSession(ctx, runtimeSessionTestNamespace, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteRuntimeSession missing error = %v, want ErrNotFound", err)
	}
}

func runtimeSessionFixture(id runtimesession.RuntimeSessionID) runtimesession.RuntimeSession {
	return runtimesession.RuntimeSession{
		ID: id,
		Owner: runtimesession.RuntimeSessionOwner{
			Namespace:   runtimeSessionTestNamespace,
			SessionName: runtimeSessionTestName,
			ActiveTask:  runtimeSessionTestTask,
			AgentName:   runtimeSessionTestAgent,
			Provider:    runtimesession.ProviderKindKubernetesService,
		},
		State:         runtimesession.RuntimeSessionStatePending,
		CleanupPolicy: runtimesession.RuntimeCleanupPolicyDelete,
	}
}

func runtimeSessionListFixture(
	id runtimesession.RuntimeSessionID,
	namespace string,
	sessionName string,
	activeTask string,
	agentName string,
	provider runtimesession.ProviderKind,
	state runtimesession.RuntimeSessionState,
	cleanupPolicy runtimesession.RuntimeCleanupPolicy,
	updatedAt time.Time,
) runtimesession.RuntimeSession {
	session := runtimeSessionFixture(id)
	session.Owner.Namespace = namespace
	session.Owner.SessionName = sessionName
	session.Owner.ActiveTask = activeTask
	session.Owner.AgentName = agentName
	session.Owner.Provider = provider
	session.State = state
	session.CleanupPolicy = cleanupPolicy
	session.CreatedAt = updatedAt.Add(-time.Hour)
	session.UpdatedAt = updatedAt
	return session
}

func assertRuntimeSessionEqual(t *testing.T, got, want runtimesession.RuntimeSession) {
	t.Helper()
	if got.ID != want.ID || got.Owner != want.Owner || got.State != want.State || got.CleanupPolicy != want.CleanupPolicy {
		t.Fatalf("session identity/state = %#v, want %#v", got, want)
	}
	if got.IdleTimeout != want.IdleTimeout || got.MaxLifetime != want.MaxLifetime {
		t.Fatalf("session durations = %s/%s, want %s/%s", got.IdleTimeout, got.MaxLifetime, want.IdleTimeout, want.MaxLifetime)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Fatalf("session times = %s/%s, want %s/%s", got.CreatedAt, got.UpdatedAt, want.CreatedAt, want.UpdatedAt)
	}
}

func assertRuntimeSessionIDs(t *testing.T, got []runtimesession.RuntimeSession, want []runtimesession.RuntimeSessionID) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d sessions (%#v), want %d ids (%#v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("session ids = %#v, want %#v", runtimeSessionIDs(got), want)
		}
	}
}

func runtimeSessionIDs(sessions []runtimesession.RuntimeSession) []runtimesession.RuntimeSessionID {
	ids := make([]runtimesession.RuntimeSessionID, 0, len(sessions))
	for _, session := range sessions {
		ids = append(ids, session.ID)
	}
	return ids
}
