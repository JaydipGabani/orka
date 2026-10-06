package service

import "github.com/orka-agents/orka/internal/remediation/controllerlab"

func selectedControllerCapability(config ControllerAdapterConfig) controllerlab.Capability {
	if config.Capability == "" {
		return controllerlab.KEDANamespaceEvents
	}
	return config.Capability
}

func validControllerCapability(config ControllerAdapterConfig) bool {
	switch selectedControllerCapability(config) {
	case controllerlab.KEDANamespaceEvents:
		return !config.Controller.EnableEventPublishing
	case controllerlab.KEDAEventPublishing:
		return config.Controller.EnableEventPublishing
	default:
		return false
	}
}

func controllerExpectedOutcomes(capability controllerlab.Capability) []controllerlab.SemanticOutcome {
	expected := []controllerlab.SemanticOutcome{controllerlab.NamespacedEventScope}
	if capability == controllerlab.KEDAEventPublishing {
		expected = append(expected, controllerlab.NamespacedEventCredentialScope, controllerlab.UndelegatedClusterCredentialScope)
	}
	return expected
}

func controllerNormalControlsComplete(plan controllerlab.Plan, evidence controllerlab.EvidenceSummary) bool {
	both := [2]bool{true, true}
	if evidence.FinalNormal != both {
		return false
	}
	if plan.Capability != controllerlab.KEDAEventPublishing {
		return evidence.Publishing == nil
	}
	publishing := evidence.Publishing
	return publishing != nil && evidence.InitialNormal == both &&
		publishing.InitialHTTPS == both && publishing.FinalHTTPS == both &&
		publishing.InitialClusterHTTP == both && publishing.FinalClusterHTTP == both
}
