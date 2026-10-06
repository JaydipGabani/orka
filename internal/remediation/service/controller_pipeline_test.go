package service

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktesting "k8s.io/client-go/testing"
)

func TestControllerPipelineUsesCommonRepairAndEvidence(t *testing.T) {
	t.Parallel()
	fixture := newControllerFixture(t)
	run := fixture.submit(Generate)
	require.NoError(t, fixture.service.RunOnce(t.Context()))
	completed, err := fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseSucceeded, completed.Phase, completed.Reason)
	var state pipelineState
	require.NoError(t, json.Unmarshal(completed.StateJSON, &state))
	require.Len(t, state.Attempts, 2)
	require.Contains(t, string(state.Attempts[0].Feedback), "candidate-build-failed")
	require.True(t, fixture.models.sawFeedback)
	require.Equal(t, 5, fixture.models.calls)
	require.Equal(t, 3, fixture.builder.builds)
	require.Zero(t, fixture.builder.starts, "a controller contract must never use HTTP Start")
	require.Less(t, len(completed.StateJSON), store.RemediationMaxStateBytes)
	status, err := fixture.service.Get(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Less(t, len(status.Artifacts), store.RemediationMaxArtifacts)

	var result executionResult
	for _, artifact := range status.Artifacts {
		if strings.HasPrefix(artifact.Name, "verification-") {
			_, raw, err := fixture.store.GetRemediationArtifact(t.Context(), run.Namespace, run.ID, artifact.Name)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &result))
		}
	}
	require.NotNil(t, result.Patched)
	require.NoError(t, controllerlab.Compare(*result.Original.Controller, *result.Control.Controller, *result.Patched.Controller))
	require.Equal(t, controllerlab.Reproduced, result.Original.Controller.Outcome)
	require.Equal(t, controllerlab.Reproduced, result.Control.Controller.Outcome)
	require.Equal(t, controllerlab.Protected, result.Patched.Controller.Outcome)
	require.Equal(t, result.Patched.Controller.ConfigDigest, result.Original.Controller.ConfigDigest)
	require.NotEqual(t, result.Patched.Controller.ImageDigest, result.Original.Controller.ImageDigest)
	require.Equal(t, state.Attempts[1].Patch.Digest, result.PatchDigest)
	for _, operation := range []*executionOperation{&state.Original, &state.Control, &state.Attempts[1].Operation} {
		require.True(t, operation.Cleaned)
		require.True(t, operation.Controller.Isolation.CleanupComplete)
		require.True(t, operation.Controller.Control.Deleted)
		require.NotEmpty(t, operation.Controller.NodeUID)
	}
	namespaces, err := fixture.kube.CoreV1().Namespaces().List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, namespaces.Items, 1)
	require.Equal(t, "kube-system", namespaces.Items[0].Name)

	checks := loadControllerTestPlan(t, fixture, completed, &state)
	t.Run("normal-regression", func(t *testing.T) {
		patched := *result.Patched.Controller
		patched.Outcome = controllerlab.Inconclusive
		patched.Reason = "observation-deadline-exceeded"
		patched.Evidence.FinalNormal[1] = false
		err := validateExecutionObservations(checks, result.Original, result.Control, &ExecutionObservation{Controller: &patched})
		rejected, ok := rejected(err)
		require.True(t, ok)
		require.Equal(t, "candidate-controller-normal-controls-failed", rejected.Code)
		raw, err := json.Marshal(rejected)
		require.NoError(t, err)
		require.NotContains(t, string(raw), patched.ObserverNamespace)
	})
	t.Run("still-exposed", func(t *testing.T) {
		patched := *result.Patched.Controller
		patched.Outcome = controllerlab.StillExposed
		patched.Evidence.CrossObserved = true
		err := validateExecutionObservations(checks, result.Original, result.Control, &ExecutionObservation{Controller: &patched})
		rejected, ok := rejected(err)
		require.True(t, ok)
		require.Equal(t, "candidate-controller-still-exposed", rejected.Code)
	})
	t.Run("infrastructure-not-a-patch-failure", func(t *testing.T) {
		patched := *result.Patched.Controller
		patched.Outcome = controllerlab.Inconclusive
		patched.Reason = "observer-state-unavailable"
		err := validateExecutionObservations(checks, result.Original, result.Control, &ExecutionObservation{Controller: &patched})
		require.ErrorIs(t, err, ErrUnknown)
		_, repairable := rejected(err)
		require.False(t, repairable)
	})
	for _, mutation := range []struct {
		name   string
		change func(*controllerlab.State)
	}{
		{"checks", func(s *controllerlab.State) { s.PlanDigest = strings.Repeat("0", 64) }},
		{"image", func(s *controllerlab.State) { s.ImageDigest = result.Original.Controller.ImageDigest }},
		{"cleanup", func(s *controllerlab.State) { s.Receipts = nil }},
		{"role", func(s *controllerlab.State) { s.Role = controllerlab.Original }},
		{"normal-controls", func(s *controllerlab.State) { s.Evidence.FinalNormal[0] = false }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			patched := *result.Patched.Controller
			mutation.change(&patched)
			require.Error(t, validateExecutionObservations(checks, result.Original, result.Control, &ExecutionObservation{Controller: &patched}))
		})
	}
}

func loadControllerTestPlan(t *testing.T, fixture *controllerTestFixture, run *store.RemediationRun, state *pipelineState) ExecutionPlan {
	t.Helper()
	session := &Session{store: fixture.store, run: run}
	plan, err := loadExecutionPlan(t.Context(), session, state.Checks)
	require.NoError(t, err)
	return plan
}

func TestControllerPipelineResumesDurableStepsWithoutDuplicateCreates(t *testing.T) {
	for _, phase := range []controllerlab.Phase{controllerlab.Preparing, controllerlab.WaitingPlacement, controllerlab.Cleaning} {
		t.Run(string(phase), func(t *testing.T) {
			t.Parallel()
			fixture := newControllerFixture(t)
			run := fixture.submit(Validate)
			paused := make(chan struct{})
			var once atomic.Bool
			fixture.afterState = func(ctx context.Context, next controllerlab.State) error {
				if next.Role == controllerlab.Original && next.Phase == phase &&
					(phase != controllerlab.Preparing || next.Intent != nil) && once.CompareAndSwap(false, true) {
					close(paused)
					<-ctx.Done()
					return ctx.Err()
				}
				return nil
			}
			first, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- fixture.service.RunOnce(first) }()
			select {
			case <-paused:
			case <-time.After(30 * time.Second):
				// The cleanup pause includes original-arm preparation and observation.
				t.Fatal("controller did not reach pause")
			}
			cancel()
			require.NoError(t, <-done)
			time.Sleep(fixture.service.config.Lease + 20*time.Millisecond)
			restarted, err := New(t.Context(), fixture.service.config)
			require.NoError(t, err)
			require.NoError(t, restarted.RunOnce(t.Context()))
			current, err := fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
			require.NoError(t, err)
			require.Equal(t, store.RemediationPhaseSucceeded, current.Phase, current.Reason)
			seenNames := map[string]bool{}
			for _, action := range fixture.kube.Actions() {
				if action.GetVerb() != "create" || action.GetResource().Resource == "subjectaccessreviews" {
					continue
				}
				created := action.(ktesting.CreateAction).GetObject()
				metadata, err := meta.Accessor(created)
				require.NoError(t, err)
				key := action.GetResource().Resource + "/" + action.GetNamespace() + "/" + metadata.GetName()
				require.False(t, seenNames[key], "restart repeated a create")
				seenNames[key] = true
			}
			seen := map[string]bool{}
			for _, state := range fixture.states {
				for _, receipt := range state.Receipts {
					key := string(receipt.Object.UID)
					require.False(t, seen[key], "UID reused across arms")
					seen[key] = true
					require.True(t, receipt.Deleted)
				}
			}
			require.Equal(t, 3, fixture.models.calls, "restart repeated a model proposal")
			require.Equal(t, 1, fixture.builder.builds, "restart repeated the rebuilt control")
		})
	}
}

func TestControllerPlanCannotDowngradeOperatorCapability(t *testing.T) {
	t.Parallel()
	choice := environment.RecipeChoice{NeedsAdapterChecks: []string{string(controllerlab.KEDANamespaceEvents)}}
	capabilities, requirements, err := catalogRequirements(AdapterPolicy{Kind: controllerAdapterKind}, choice, investigate.Plan{})
	require.NoError(t, err)
	require.Equal(t, []string{string(controllerlab.KEDANamespaceEvents)}, capabilities)
	require.Contains(t, requirements, "controller")
	require.Contains(t, requirements, "cluster")
	require.Contains(t, requirements, "test-identity")
	floor, err := json.Marshal(ControllerAdapterConfig{RequiredCapabilities: []string{string(controllerlab.KEDARedisAuth)}})
	require.NoError(t, err)
	_, _, err = catalogRequirements(AdapterPolicy{Kind: controllerAdapterKind, Configuration: floor}, choice, investigate.Plan{})
	require.ErrorIs(t, err, ErrNeedsAdapter)
	choice = environment.RecipeChoice{SupportedChecks: []string{environment.HTTPExact}}
	_, _, err = catalogRequirements(AdapterPolicy{Kind: "dalec-http"}, choice, investigate.Plan{
		Requirements: []pv.EnvironmentRequirement{{Kind: "controller", Name: "namespace-events"}},
	})
	require.ErrorIs(t, err, ErrNeedsAdapter)
}

func TestControllerCancellationWaitsForOwnedRuntimeDeletion(t *testing.T) {
	t.Parallel()
	fixture := newControllerFixture(t)
	run := fixture.submit(Validate)
	active := make(chan struct{})
	var once atomic.Bool
	fixture.afterState = func(ctx context.Context, next controllerlab.State) error {
		if next.Phase == controllerlab.WaitingRuntime && once.CompareAndSwap(false, true) {
			close(active)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- fixture.service.RunOnce(t.Context()) }()
	select {
	case <-active:
	case <-time.After(10 * time.Second):
		t.Fatal("runtime was not active")
	}
	status, err := fixture.service.Cancel(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseCancelling, status.Phase)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("cancellation did not settle")
	}
	current, err := fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseCancelled, current.Phase, current.Reason)
	var state pipelineState
	require.NoError(t, json.Unmarshal(current.StateJSON, &state))
	require.Equal(t, controllerlab.Complete, state.Original.Controller.State.Phase)
	require.Equal(t, controllerlab.Cancelled, state.Original.Controller.State.Outcome)
	require.True(t, state.Original.Controller.Control.Deleted)
	for _, receipt := range state.Original.Controller.State.Receipts {
		require.True(t, receipt.Deleted)
	}
	namespaceList, err := fixture.kube.CoreV1().Namespaces().List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, namespaceList.Items, 1)
}
