package service

import (
	"encoding/json"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

func TestIntegrityReviewRejectionCannotFeedAnotherCandidate(t *testing.T) {
	for _, code := range []string{"fixture-tampering", "test-specific-behavior", "unrelated-network-access", "unrelated-credential-access"} {
		patch := []byte("synthetic patch")
		decision := patchReviewDecision{
			Version: 1, PatchDigest: Digest(patch), Decision: "reject",
			Findings: []patchReviewFinding{{Path: "server.go", Code: code, Detail: "Independent review identified an integrity concern."}},
		}
		raw, err := json.Marshal(decision)
		require.NoError(t, err)
		pipeline, session, state, policy, _, calls := disclosurePipelineFixture(t, string(raw))
		sourcePlan := investigate.Plan{Packet: source.Packet{Files: []source.PacketFile{{Path: "server.go"}}}}
		plan := ExecutionPlan{Controller: &controllerlab.Plan{Capability: controllerlab.KEDAEventPublishing}}
		// A nil adapter must never be reached: the integrity decision happens
		// before any build or execution, and is not a repairable rejection.
		_, review, err := pipeline.executeReviewedCandidate(t.Context(), session, session.run, policy, sourcePlan, plan, nil, state, 0, patch)
		require.ErrorIs(t, err, ErrNeedsInput)
		require.NotNil(t, review, "the private decision stays available for operator inspection")
		_, retry := rejected(err)
		require.False(t, retry, "the repair loop must stop instead of teaching the generator to evade an integrity finding")
		require.Equal(t, 1, *calls)
		require.Empty(t, state.Attempts)
		encoded, err := json.Marshal(state)
		require.NoError(t, err)
		var resumed pipelineState
		require.NoError(t, json.Unmarshal(encoded, &resumed))
		_, _, err = pipeline.executeReviewedCandidate(t.Context(), session, session.run, policy, sourcePlan, plan, nil, &resumed, 0, patch)
		require.ErrorIs(t, err, ErrNeedsInput)
		require.Empty(t, resumed.Attempts)
		require.Equal(t, 1, *calls, "resume must not ask again or generate a new candidate")
	}
}

func TestMixedIntegrityReviewFindingsAreNeverRepairable(t *testing.T) {
	for _, first := range []bool{false, true} {
		findings := []patchReviewFinding{{Code: "behavior-regression"}, {Code: "fixture-tampering"}}
		if first {
			findings[0], findings[1] = findings[1], findings[0]
		}
		require.False(t, repairablePatchReview(patchReviewDecision{Decision: "reject", Findings: findings}))
		require.False(t, repairablePatchReview(patchReviewDecision{Decision: "uncertain", Findings: findings}))
	}
	require.True(t, repairablePatchReview(patchReviewDecision{Decision: "reject",
		Findings: []patchReviewFinding{{Code: "behavior-regression"}, {Code: "scope-mismatch"}},
	}))
}
