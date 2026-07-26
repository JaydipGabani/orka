package harness

import "github.com/orka-agents/orka/internal/runtimesession"

// RuntimeSessionState is retained as a harness compatibility alias. Runtime
// session lifecycle ownership lives in the dependency-neutral runtimesession package.
type RuntimeSessionState = runtimesession.RuntimeSessionState

const (
	RuntimeSessionStatePending     = runtimesession.RuntimeSessionStatePending
	RuntimeSessionStateBooting     = runtimesession.RuntimeSessionStateBooting
	RuntimeSessionStateReady       = runtimesession.RuntimeSessionStateReady
	RuntimeSessionStateTurnRunning = runtimesession.RuntimeSessionStateTurnRunning
	RuntimeSessionStateIdle        = runtimesession.RuntimeSessionStateIdle
	RuntimeSessionStateReleasing   = runtimesession.RuntimeSessionStateReleasing
	RuntimeSessionStateRetained    = runtimesession.RuntimeSessionStateRetained
	RuntimeSessionStateSuspended   = runtimesession.RuntimeSessionStateSuspended
	RuntimeSessionStateDeleting    = runtimesession.RuntimeSessionStateDeleting
	RuntimeSessionStateDeleted     = runtimesession.RuntimeSessionStateDeleted
	RuntimeSessionStateFailed      = runtimesession.RuntimeSessionStateFailed
	RuntimeSessionStateUnhealthy   = runtimesession.RuntimeSessionStateUnhealthy
)

// RuntimeCleanupPolicy is retained as a harness compatibility alias.
type RuntimeCleanupPolicy = runtimesession.RuntimeCleanupPolicy

const (
	RuntimeCleanupPolicyDelete  = runtimesession.RuntimeCleanupPolicyDelete
	RuntimeCleanupPolicyRetain  = runtimesession.RuntimeCleanupPolicyRetain
	RuntimeCleanupPolicySuspend = runtimesession.RuntimeCleanupPolicySuspend
)

// RuntimeSessionOwner is retained as a harness compatibility alias.
type RuntimeSessionOwner = runtimesession.RuntimeSessionOwner

// RuntimeSession is retained as a harness compatibility alias.
type RuntimeSession = runtimesession.RuntimeSession

// RuntimeSessionStates returns all supported runtime session states.
func RuntimeSessionStates() []RuntimeSessionState {
	return runtimesession.RuntimeSessionStates()
}

// IsKnownRuntimeSessionState reports whether state is supported.
func IsKnownRuntimeSessionState(state RuntimeSessionState) bool {
	return runtimesession.IsKnownRuntimeSessionState(state)
}

// RuntimeSessionTransitionAllowed reports whether a state transition is allowed.
func RuntimeSessionTransitionAllowed(from, to RuntimeSessionState) bool {
	return runtimesession.RuntimeSessionTransitionAllowed(from, to)
}

// ValidateRuntimeSessionTransition validates a runtime session state transition.
func ValidateRuntimeSessionTransition(from, to RuntimeSessionState) error {
	return runtimesession.ValidateRuntimeSessionTransition(from, to)
}

// IsKnownRuntimeCleanupPolicy reports whether policy is supported.
func IsKnownRuntimeCleanupPolicy(policy RuntimeCleanupPolicy) bool {
	return runtimesession.IsKnownRuntimeCleanupPolicy(policy)
}
