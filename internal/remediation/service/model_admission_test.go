package service

import (
	"testing"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/stretchr/testify/require"
)

func TestModelSubmissionRequiresAdmissionIdentity(t *testing.T) {
	pipeline, session, state, policy, clients, calls := disclosurePipelineFixture(t, `{}`)
	state.ModelIdentity = nil
	_, err := pipeline.generate(t.Context(), session, session.run, policy, state, modelagent.Request{
		TaskName: "legacy-queued-run", Prompt: "Synthetic private technical content.",
	})
	require.ErrorIs(t, err, ErrNeedsInput)
	require.Zero(t, *clients, "legacy queued work must not select a new model boundary lazily")
	require.Zero(t, *calls)
	require.Zero(t, state.ModelCalls)
}
