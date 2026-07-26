package harness

import (
	"slices"
	"testing"

	"github.com/orka-agents/orka/internal/runtimesession"
)

var (
	_ runtimesession.RuntimeSessionID    = RuntimeSessionID("runtime-a")
	_ RuntimeSessionID                   = runtimesession.RuntimeSessionID("runtime-a")
	_ runtimesession.ProviderKind        = ProviderKindRemote
	_ ProviderKind                       = runtimesession.ProviderKindRemote
	_ runtimesession.RuntimeSession      = RuntimeSession{}
	_ RuntimeSession                     = runtimesession.RuntimeSession{}
	_ runtimesession.RuntimeSessionStore = RuntimeSessionStore(nil)
	_ RuntimeSessionStore                = runtimesession.RuntimeSessionStore(nil)
)

func TestRuntimeSessionCompatibilityAliases(t *testing.T) {
	input := RuntimeSessionIdentityInput{
		Namespace:   "runtime-ns",
		TaskName:    "task-a",
		TaskUID:     "uid-a",
		RuntimeName: "codex",
		Provider:    ProviderKindKubernetesService,
	}
	got := ResolveRuntimeSessionIdentity(input)
	want := runtimesession.ResolveRuntimeSessionIdentity(input)
	if got != want {
		t.Fatalf("ResolveRuntimeSessionIdentity() = %#v, want %#v", got, want)
	}

	if err := ValidateRuntimeSessionTransition(RuntimeSessionStatePending, RuntimeSessionStateBooting); err != nil {
		t.Fatalf("ValidateRuntimeSessionTransition() error = %v", err)
	}
	if !slices.Equal(RuntimeSessionStates(), runtimesession.RuntimeSessionStates()) {
		t.Fatalf("RuntimeSessionStates() = %#v, want %#v", RuntimeSessionStates(), runtimesession.RuntimeSessionStates())
	}
	if !IsKnownRuntimeCleanupPolicy(RuntimeCleanupPolicySuspend) {
		t.Fatal("IsKnownRuntimeCleanupPolicy(suspend) = false, want true")
	}

	compatSession := RuntimeSession{
		ID:            got.ID,
		Owner:         got.Owner,
		State:         RuntimeSessionStatePending,
		CleanupPolicy: RuntimeCleanupPolicyDelete,
	}
	if err := compatSession.Validate(); err != nil {
		t.Fatalf("compatibility alias Validate() error = %v", err)
	}
}
