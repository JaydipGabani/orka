package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

type reviewModelClient struct {
	disclosureModelClient
	requests *[]modelagent.Request
}

func (c reviewModelClient) Generate(ctx context.Context, request modelagent.Request) (modelagent.Result, error) {
	*c.requests = append(*c.requests, request)
	return c.disclosureModelClient.Generate(ctx, request)
}

func TestIndependentPatchReviewPinsDigestAndDoesNotReplay(t *testing.T) {
	patch := []byte("--- a/server.go\n+++ b/server.go\n@@ -1 +1 @@\n-old\n+new\n")
	decision := patchReviewDecision{Version: 1, PatchDigest: Digest(patch), Decision: "approve", Findings: []patchReviewFinding{}}
	raw, err := json.Marshal(decision)
	require.NoError(t, err)
	pipeline, session, state, policy, _, calls := disclosurePipelineFixture(t, string(raw))
	var requests []modelagent.Request
	pipeline.Agents = func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
		return reviewModelClient{
			disclosureModelClient: disclosureModelClient{accepted: accepted, output: string(raw), calls: calls},
			requests:              &requests,
		}
	}
	plan := investigate.Plan{
		Problem: "untrusted-incident-instruction-must-not-enter-review",
		Packet:  source.Packet{Files: []source.PacketFile{{Path: "server.go", Content: "package server\n"}}},
	}
	checks := ExecutionPlan{Controller: &controllerlab.Plan{
		Version: 1, Capability: controllerlab.KEDAEventPublishing,
		Expected: controllerExpectedOutcomes(controllerlab.KEDAEventPublishing),
	}}
	checks.Binding.ChecksDigest = Digest([]byte("checks"))
	ref, err := pipeline.reviewCandidate(t.Context(), session, session.run, policy, plan, checks, state, patch)
	require.NoError(t, err)
	require.NotNil(t, ref)
	require.Equal(t, 1, *calls)
	require.Len(t, requests, 1)
	require.Contains(t, requests[0].TaskName, "-patch-review-")
	require.Contains(t, requests[0].Prompt, Digest(patch))
	require.NotContains(t, requests[0].Prompt, plan.Problem)
	require.Contains(t, requests[0].Prompt, "ClusterTriggerAuthentication is not delegation")
	require.Contains(t, requests[0].Prompt, "namespace-local TriggerAuthentication")
	require.Contains(t, requests[0].Prompt, "Keep ScaledObject and ScaledJob ClusterTriggerAuthentication resolution unchanged")
	require.NotContains(t, requests[0].Prompt, "preserve explicit cluster authentication references")
	require.Empty(t, requests[0].Repository)
	require.Empty(t, requests[0].Commit)
	var evidence patchReviewEvidence
	require.NoError(t, readJSON(t.Context(), session, ref, &evidence))
	require.Equal(t, Digest(patch), evidence.PatchDigest)
	require.Equal(t, checks.Binding.ChecksDigest, evidence.ChecksDigest)
	require.Equal(t, state.ModelIdentity.Digest, evidence.ModelIdentity)
	require.NotEmpty(t, evidence.TaskUID)
	require.Equal(t, automatedReviewScope, evidence.Scope)
	again, err := pipeline.reviewCandidate(t.Context(), session, session.run, policy, plan, checks, state, patch)
	require.NoError(t, err)
	require.Equal(t, ref, again)
	require.Equal(t, 1, *calls, "the exact review result must be recovered, not regenerated")
}

func TestIndependentPatchReviewRejectsUncertainOrMismatchedDecisions(t *testing.T) {
	patch := []byte("synthetic patch")
	for _, verdict := range []string{"reject", "uncertain", "wrong-digest", "invalid-approval"} {
		decision := patchReviewDecision{
			Version: 1, PatchDigest: Digest(patch), Decision: verdict,
			Findings: []patchReviewFinding{{Path: "server.go", Code: "behavior-regression", Detail: "The patch changes legitimate behavior."}},
		}
		if verdict == "wrong-digest" {
			decision.Decision, decision.PatchDigest, decision.Findings = "approve", Digest([]byte("different")), []patchReviewFinding{}
		}
		if verdict == "invalid-approval" {
			decision.Decision = "approve"
		}
		raw, err := json.Marshal(decision)
		require.NoError(t, err)
		pipeline, session, state, policy, _, calls := disclosurePipelineFixture(t, string(raw))
		plan := investigate.Plan{Packet: source.Packet{Files: []source.PacketFile{{Path: "server.go"}}}}
		checks := ExecutionPlan{Controller: &controllerlab.Plan{Capability: controllerlab.KEDAEventPublishing}}
		_, err = pipeline.reviewCandidate(t.Context(), session, session.run, policy, plan, checks, state, patch)
		if verdict == "reject" {
			failure, ok := rejected(err)
			require.True(t, ok)
			require.Equal(t, "candidate-independent-review-rejected", failure.Code)
			require.Len(t, failure.ReviewFindings, 1)
		} else {
			require.ErrorIs(t, err, ErrNeedsInput)
		}
		require.Equal(t, 1, *calls)
		_, repeated := pipeline.reviewCandidate(t.Context(), session, session.run, policy, plan, checks, state, patch)
		require.Error(t, repeated)
		require.Equal(t, 1, *calls, "an identical patch cannot shop for a different review decision")
	}
}

func TestIndependentPatchReviewSchemaAndLegacyCompatibility(t *testing.T) {
	digest := Digest([]byte("patch"))
	packet := source.Packet{Files: []source.PacketFile{{Path: "server.go"}}}
	good := patchReviewDecision{Version: 1, PatchDigest: digest, Decision: "approve", Findings: []patchReviewFinding{}}
	require.True(t, validPatchReview(good, digest, packet))
	for _, mutate := range []func(*patchReviewDecision){
		func(r *patchReviewDecision) { r.Findings = nil },
		func(r *patchReviewDecision) { r.Version++ },
		func(r *patchReviewDecision) { r.Decision = "accepted" },
		func(r *patchReviewDecision) {
			r.Decision = "reject"
			r.Findings = []patchReviewFinding{{Path: "unselected.go", Code: "scope-mismatch", Detail: "unselected"}}
		},
		func(r *patchReviewDecision) {
			r.Decision = "uncertain"
			r.Findings = []patchReviewFinding{{Code: "insufficient-context", Detail: strings.Repeat("x", 513)}}
		},
	} {
		changed := good
		mutate(&changed)
		require.False(t, validPatchReview(changed, digest, packet))
	}
	pipeline, session, state, policy, clients, calls := disclosurePipelineFixture(t, `{}`)
	ref, err := pipeline.reviewCandidate(t.Context(), session, session.run, policy, investigate.Plan{},
		ExecutionPlan{Controller: &controllerlab.Plan{Capability: controllerlab.KEDANamespaceEvents}}, state, nil)
	require.NoError(t, err)
	require.Nil(t, ref)
	require.Zero(t, *clients)
	require.Zero(t, *calls)
}
