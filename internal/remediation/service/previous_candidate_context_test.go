package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/stretchr/testify/require"
)

func TestRepairPromptPreservesCompleteMultiFilePreviousCandidate(t *testing.T) {
	previous, err := json.Marshal(map[string]any{
		"summary": "Synthetic multi-surface fix",
		"edits": []map[string]string{
			{"path": "runtime.go", "old": strings.Repeat("old-runtime\n", 600), "new": strings.Repeat("new-runtime\n", 600)},
			{"path": "admission.go", "old": "old-admission", "new": "new-admission"},
		},
	})
	require.NoError(t, err)
	require.Greater(t, len(previous), 4<<10)
	state := &pipelineState{Attempts: []pipelineAttempt{{Feedback: json.RawMessage(`{"code":"candidate-independent-review-rejected"}`)}}}
	prompt, err := candidatePrompt(investigate.Plan{}, ExecutionPlan{}, state, 1, previous)
	require.NoError(t, err)
	_, data, found := strings.Cut(prompt, "\nDATA:\n")
	require.True(t, found)
	var envelope struct {
		Previous promptPreview `json:"previousCandidate"`
	}
	require.NoError(t, json.Unmarshal([]byte(data), &envelope))
	require.False(t, envelope.Previous.Truncated)
	require.Equal(t, string(previous), envelope.Previous.Text)
	require.Equal(t, Digest(previous), envelope.Previous.Digest)
	require.Contains(t, prompt, "Preserve every still-required fix")
	require.LessOrEqual(t, len(prompt), 256<<10)
}
