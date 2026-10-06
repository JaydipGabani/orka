package service

import (
	"testing"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/stretchr/testify/require"
)

func TestPublishingEvidenceRequiresAllNormalControls(t *testing.T) {
	both := [2]bool{true, true}
	plan := controllerlab.Plan{Capability: controllerlab.KEDAEventPublishing}
	evidence := controllerlab.EvidenceSummary{
		InitialNormal: both, FinalNormal: both,
		Publishing: &controllerlab.PublishingEvidence{
			InitialHTTPS: both, FinalHTTPS: both, InitialClusterHTTP: both, FinalClusterHTTP: both,
		},
	}
	require.True(t, controllerNormalControlsComplete(plan, evidence))
	for _, change := range []func(*controllerlab.EvidenceSummary){
		func(e *controllerlab.EvidenceSummary) { e.Publishing = nil },
		func(e *controllerlab.EvidenceSummary) { e.InitialNormal[0] = false },
		func(e *controllerlab.EvidenceSummary) { e.FinalNormal[1] = false },
		func(e *controllerlab.EvidenceSummary) { e.Publishing.InitialHTTPS[0] = false },
		func(e *controllerlab.EvidenceSummary) { e.Publishing.FinalHTTPS[1] = false },
		func(e *controllerlab.EvidenceSummary) { e.Publishing.InitialClusterHTTP[0] = false },
		func(e *controllerlab.EvidenceSummary) { e.Publishing.FinalClusterHTTP[1] = false },
	} {
		changed := evidence
		publishing := *evidence.Publishing
		changed.Publishing = &publishing
		change(&changed)
		require.False(t, controllerNormalControlsComplete(plan, changed))
	}
	require.True(t, controllerNormalControlsComplete(controllerlab.Plan{Capability: controllerlab.KEDANamespaceEvents},
		controllerlab.EvidenceSummary{FinalNormal: both}), "legacy evidence remains compatible")
	require.False(t, controllerNormalControlsComplete(controllerlab.Plan{Capability: controllerlab.KEDANamespaceEvents}, evidence),
		"publishing evidence cannot be reinterpreted as a weaker legacy result")
}
