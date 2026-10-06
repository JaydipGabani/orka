package service

import (
	"encoding/json"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/stretchr/testify/require"
)

func TestControllerCapabilityRequiresExactOperatorOptIn(t *testing.T) {
	legacy := ControllerAdapterConfig{}
	require.True(t, validControllerCapability(legacy))
	require.Equal(t, controllerlab.KEDANamespaceEvents, selectedControllerCapability(legacy))
	publishing := ControllerAdapterConfig{Capability: controllerlab.KEDAEventPublishing}
	require.False(t, validControllerCapability(publishing))
	publishing.Controller.EnableEventPublishing = true
	require.True(t, validControllerCapability(publishing))
	legacy.Controller.EnableEventPublishing = true
	require.False(t, validControllerCapability(legacy), "the new observer must not be enabled without an explicit selection")
	publishing.Capability = "unapproved"
	require.False(t, validControllerCapability(publishing))
}

func TestControllerPublishingCatalogCannotSelectHTTPOnlyChecks(t *testing.T) {
	config := ControllerAdapterConfig{
		Capability:           controllerlab.KEDAEventPublishing,
		RequiredCapabilities: []string{string(controllerlab.KEDAEventPublishing)},
	}
	config.Controller.EnableEventPublishing = true
	raw, err := json.Marshal(config)
	require.NoError(t, err)
	configured := AdapterPolicy{Kind: controllerAdapterKind, Configuration: raw}
	choice := environment.RecipeChoice{NeedsAdapterChecks: []string{string(controllerlab.KEDANamespaceEvents)}}
	_, _, err = catalogRequirements(configured, choice, investigate.Plan{})
	require.ErrorIs(t, err, ErrNeedsAdapter)
	choice.NeedsAdapterChecks = []string{string(controllerlab.KEDAEventPublishing)}
	capabilities, requirements, err := catalogRequirements(configured, choice, investigate.Plan{})
	require.NoError(t, err)
	require.Equal(t, []string{string(controllerlab.KEDAEventPublishing)}, capabilities)
	require.Contains(t, requirements, "controller")
	require.Contains(t, requirements, "test-identity")
}

func TestControllerPublishingPlanCannotDropHTTPSOrCredentialChecks(t *testing.T) {
	fixture := newControllerFixture(t)
	adapter := fixture.adapter
	adapter.config.Capability = controllerlab.KEDAEventPublishing
	adapter.config.Controller.EnableEventPublishing = true
	adapter.config.Controller.Template.Source.Commit = "e615440f24f6abec8b7c69bd88854cb4324e9eaa"
	adapter.selection.Binding.SourceTarget.Commit = adapter.config.Controller.Template.Source.Commit
	adapter.selection.Capabilities = []string{string(controllerlab.KEDAEventPublishing)}
	plan := controllerlab.Plan{
		Version: controllerlab.Version, Capability: controllerlab.KEDAEventPublishing,
		BoundSource: adapter.config.Controller.Template.Source, RecipeID: adapter.config.Controller.Template.RecipeID,
		Actors:   []controllerlab.ActorAccess{controllerlab.NamespaceAEventSource, controllerlab.NamespaceBEventSource},
		Expected: controllerExpectedOutcomes(controllerlab.KEDAEventPublishing),
	}
	require.NoError(t, controllerlab.ValidatePlan(plan))
	_, err := adapter.freezePlan(plan)
	require.NoError(t, err)
	plan.Expected = []controllerlab.SemanticOutcome{controllerlab.NamespacedEventScope}
	_, err = adapter.freezePlan(plan)
	require.ErrorIs(t, err, ErrNeedsAdapter)
	plan.Capability = controllerlab.KEDANamespaceEvents
	_, err = adapter.freezePlan(plan)
	require.ErrorIs(t, err, ErrNeedsAdapter, "a valid legacy plan is still a downgrade of the operator-selected capability")
}
