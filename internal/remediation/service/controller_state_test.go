package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func controllerSessionFixture(t *testing.T) (*controllerTestFixture, *Session, *pipelineState) {
	t.Helper()
	fixture := newControllerFixture(t)
	submitted := fixture.submit(Validate)
	run, err := fixture.store.ClaimNextRemediationRun(t.Context(), submitted.Namespace, "controller-hooks", time.Now(), 10*time.Second)
	require.NoError(t, err)
	require.NotNil(t, run)
	session := &Session{store: fixture.store, run: run, owner: run.ClaimOwner, epoch: run.ClaimEpoch}
	subject := fixture.adapter.selection.Original
	state := &pipelineState{Version: Version, Stage: "controller-hooks", Selection: &fixture.adapter.selection,
		Models: map[string]modelOperation{}, Original: executionOperation{
			ID: "original", Role: subject.Role, Subject: &subject, Intent: true,
			Controller: &controllerOperation{RunID: run.ID, InputDigest: run.InputDigest, OperationID: "original"},
		},
	}
	require.NoError(t, fixture.pipeline.save(t.Context(), session, state, state.Stage))
	return fixture, session, state
}

func TestControllerHooksFenceRevisionRunClaimAndCancellation(t *testing.T) {
	t.Parallel()
	fixture, session, state := controllerSessionFixture(t)
	operation := &state.Original
	hooks := controllerHooks(session, state, operation, false)
	next := controllerlab.State{Version: 1, Revision: 1, RunID: session.run.ID, OperationID: operation.ID,
		OperationDigest: strings.Repeat("a", 64), Phase: controllerlab.Preparing,
	}
	previous := cloneControllerOperation(operation.Controller)
	require.NoError(t, hooks.PersistState(t.Context(), 0, next))
	operation.Controller = &previous
	require.NoError(t, hooks.PersistState(t.Context(), 0, next), "identical committed receipt must acknowledge lost ACK")

	operation.Controller = &previous
	changed := next
	changed.Phase = controllerlab.Cleaning
	require.ErrorIs(t, hooks.PersistState(t.Context(), 0, changed), ErrUnknown)
	operation.Controller.State = next
	changed = next
	changed.Revision, changed.RunID = 2, "other-run"
	require.ErrorIs(t, hooks.PersistState(t.Context(), 1, changed), ErrUnknown)

	_, err := fixture.store.CancelRemediationRun(t.Context(), session.run.Namespace, session.run.ID, time.Now())
	require.NoError(t, err)
	mutation := controllerlab.Mutation{RunID: session.run.ID, OperationID: operation.ID,
		OperationDigest: next.OperationDigest, Action: "create"}
	require.ErrorIs(t, hooks.Acceptance(t.Context(), mutation), context.Canceled)
	next.Revision = 2
	require.ErrorIs(t, hooks.PersistState(t.Context(), 1, next), context.Canceled)
	cleanup := controllerHooks(session, state, operation, true)
	require.ErrorIs(t, cleanup.Acceptance(t.Context(), mutation), ErrInvalid)
	mutation.Action = "delete"
	require.NoError(t, cleanup.Acceptance(t.Context(), mutation))
	next.Phase = controllerlab.Cleaning
	require.NoError(t, cleanup.PersistState(t.Context(), 1, next))

	current, err := session.Current(t.Context())
	require.NoError(t, err)
	reclaimed, err := fixture.store.ClaimNextRemediationRun(t.Context(), current.Namespace, "replacement-worker",
		current.ClaimUntil.Add(time.Millisecond), time.Second)
	require.NoError(t, err)
	require.NotNil(t, reclaimed)
	require.ErrorIs(t, cleanup.Acceptance(t.Context(), mutation), ErrClaimLost)
	next.Revision++
	require.ErrorIs(t, cleanup.PersistState(t.Context(), 2, next), ErrClaimLost)
}

func TestControllerCheckpointPreservesSettlementAndBoundsStateBytes(t *testing.T) {
	t.Parallel()
	_, session, state := controllerSessionFixture(t)
	current, err := session.Current(t.Context())
	require.NoError(t, err)
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(current.StateJSON, &raw))
	raw["settlement"] = json.RawMessage(`{"attempts":2,"phase":"Cancelled"}`)
	content, err := json.Marshal(raw)
	require.NoError(t, err)
	require.NoError(t, session.Checkpoint(t.Context(), store.RemediationPhaseRunning, "", content, ""))
	operation := &state.Original
	hooks := controllerHooks(session, state, operation, true)
	next := controllerlab.State{Version: 1, Revision: 1, RunID: current.ID, OperationID: operation.ID,
		OperationDigest: strings.Repeat("a", 64), Phase: controllerlab.Preparing,
	}
	require.NoError(t, hooks.PersistState(t.Context(), 0, next))
	current, err = session.Current(t.Context())
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(current.StateJSON, &raw))
	require.JSONEq(t, `{"attempts":2,"phase":"Cancelled"}`, string(raw["settlement"]))
	next.Revision++
	next.Reason = strings.Repeat("x", store.RemediationMaxStateBytes)
	require.ErrorIs(t, hooks.PersistState(t.Context(), 1, next), ErrInvalid)
	unchanged, err := session.Current(t.Context())
	require.NoError(t, err)
	require.Equal(t, current.Revision, unchanged.Revision)
}

func TestControllerProofExpiryAndOperatorFloors(t *testing.T) {
	t.Parallel()
	now := time.Now()
	require.True(t, controllerProofFresh(now, now.Add(time.Minute), time.Minute))
	require.False(t, controllerProofFresh(now, now.Add(time.Minute+time.Nanosecond), time.Minute))
	require.False(t, controllerProofFresh(now, now.Add(-time.Nanosecond), time.Minute))
	require.False(t, controllerProofFresh(time.Time{}, now, time.Minute))
	choice := environment.RecipeChoice{
		SupportedChecks: []string{environment.HTTPExact}, NeedsAdapterChecks: []string{environment.EventSink},
	}
	_, _, err := catalogRequirements(AdapterPolicy{Kind: httpAdapterKind}, choice, investigate.Plan{})
	require.NoError(t, err, "optional HTTP catalog primitives must not become newly mandatory")
	config, err := json.Marshal(ControllerAdapterConfig{RequiredRequirements: []string{"external-service"}})
	require.NoError(t, err)
	choice = environment.RecipeChoice{NeedsAdapterChecks: []string{string(controllerlab.KEDANamespaceEvents)}}
	_, _, err = catalogRequirements(AdapterPolicy{Kind: controllerAdapterKind, Configuration: config}, choice, investigate.Plan{})
	require.ErrorIs(t, err, ErrNeedsAdapter, "model omissions cannot waive the operator's external-service floor")
}

func TestControllerRepositoryFloorCannotFallBackToHTTP(t *testing.T) {
	t.Parallel()
	fixture := newControllerFixture(t)
	config := fixture.adapter.config
	config.BuildEnvironment.BuildJobs = &environment.BuildJobsConfig{}
	config.BuildEnvironment.Kubernetes = &environment.KubernetesConfig{}
	config.RequiredCapabilities = []string{string(controllerlab.KEDARedisAuth)}
	raw, err := json.Marshal(config)
	require.NoError(t, err)
	policy := Policy{Adapters: []AdapterPolicy{
		{Name: "controller", Kind: controllerAdapterKind, Repositories: []string{config.Controller.Template.Source.Repository}, Configuration: raw},
		{Name: "unrelated-http", Kind: httpAdapterKind, Repositories: []string{config.Controller.Template.Source.Repository}, Configuration: json.RawMessage(`{}`)},
	}}
	capabilities, requirements, err := catalogSourceFloor(policy, config.Controller.Template.Source.Repository, config.Controller.Template.Source.Commit)
	require.NoError(t, err)
	require.Contains(t, capabilities, string(controllerlab.KEDARedisAuth))
	require.Contains(t, capabilities, string(controllerlab.KEDANamespaceEvents))
	require.Contains(t, requirements, "controller")
	selection := fixture.adapter.selection
	selection.Capabilities = []string{environment.HTTPExact}
	_, err = (Catalog{}).Resume(t.Context(), policy, selection)
	require.ErrorIs(t, err, ErrNeedsAdapter, "resume must enforce the same repository floor before constructing an adapter")
	capabilities, requirements, err = catalogSourceFloor(policy, config.Controller.Template.Source.Repository, strings.Repeat("f", 40))
	require.NoError(t, err)
	require.Empty(t, capabilities, "floors must not infer a different commit")
	require.Empty(t, requirements)
}
