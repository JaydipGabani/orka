package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

func TestAmbiguousEditFeedbackIdentifiesPathIndexAndCount(t *testing.T) {
	pipeline, session, state, policy, _, calls := disclosurePipelineFixture(t, `{}`)
	raw := []byte(`{"summary":"Synthetic fix","edits":[{"path":"server.go","old":"duplicate","new":"replacement"}],"declaredChanges":[{"kind":"source","paths":["server.go"],"description":"Synthetic source change"}],"limitations":[]}`)
	ref, err := session.Put(t.Context(), "candidate-0-proposal.json", "application/json", raw)
	require.NoError(t, err)
	state.Attempts = []pipelineAttempt{{Proposal: ref}}
	plan := investigate.Plan{Packet: source.Packet{Files: []source.PacketFile{{Path: "server.go", Content: "duplicate\nduplicate\n"}}}}
	err = pipeline.proposePatch(t.Context(), session, session.run, StoredRequest{Mode: Generate}, policy, plan, ExecutionPlan{}, state, 0)
	rejection, ok := rejected(err)
	require.True(t, ok)
	require.Equal(t, "exact-source-edit-mismatch", rejection.Code)
	require.Equal(t, &candidateEditFailure{Index: 0, Path: "server.go", Matches: 2, Expected: 1}, rejection.EditFailure)
	require.Zero(t, *calls)
	feedback, err := json.Marshal(rejection)
	require.NoError(t, err)
	require.NotContains(t, string(feedback), "duplicate")
	require.NotContains(t, string(feedback), "replacement")
	state.Attempts[0].Feedback = feedback
	prompt, err := candidatePrompt(plan, ExecutionPlan{}, state, 1, raw)
	require.NoError(t, err)
	_, data, found := strings.Cut(prompt, "\nDATA:\n")
	require.True(t, found)
	var envelope struct {
		PreviousFailure promptPreview `json:"previousFailure"`
	}
	require.NoError(t, json.Unmarshal([]byte(data), &envelope))
	require.JSONEq(t, string(feedback), envelope.PreviousFailure.Text)
	require.Contains(t, prompt, "index is zero-based")
	require.Contains(t, prompt, "Use more unchanged surrounding context")
}
