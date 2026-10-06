package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

func TestFailureContextUsesOnlyNamedVerifiedOriginalTests(t *testing.T) {
	testBody := "func TestBlocked(t *testing.T) {\n\twait.Wait()\n}"
	content := "package sample\n\n" + testBody + "\n\nfunc TestOther(t *testing.T) {}\n"
	packet := source.Packet{Files: []source.PacketFile{
		{Path: "pkg/sample_test.go", Content: content},
		{Path: "pkg/sample.go", Content: "package sample\nfunc TestBlocked() {}\n"},
	}}
	feedback, err := json.Marshal(candidateRejected{Code: "candidate-build-failed", Diagnostics: []environment.Diagnostic{
		{Code: "go-test-failure", Identifier: "TestBlocked"},
		{Code: "go-test-failure", Identifier: "TestMissing"},
		{Code: "compiler-diagnostic", Identifier: "TestOther"},
	}})
	require.NoError(t, err)
	contexts := focusedTestFailureContext(packet, feedback)
	require.Equal(t, []testFailureContext{{
		Path: "pkg/sample_test.go", TestName: "TestBlocked", Original: testBody,
	}}, contexts)
	require.Equal(t, content, packet.Files[0].Content)
	plan := investigate.Plan{Packet: packet}
	state := &pipelineState{Attempts: []pipelineAttempt{{Feedback: feedback}}}
	prompt, err := candidatePrompt(plan, ExecutionPlan{}, state, 1, nil)
	require.NoError(t, err)
	_, data, found := strings.Cut(prompt, "\nDATA:\n")
	require.True(t, found)
	var envelope struct {
		Tests []testFailureContext `json:"failingOriginalTests"`
	}
	require.NoError(t, json.Unmarshal([]byte(data), &envelope))
	require.Equal(t, contexts, envelope.Tests)
	require.Contains(t, prompt, "not only add new tests")
	require.Contains(t, prompt, "Do not remove tests or weaken legitimate assertions")
}

func TestFailureContextBoundsAndMalformedInputs(t *testing.T) {
	feedback, err := json.Marshal(candidateRejected{Diagnostics: []environment.Diagnostic{
		{Code: "go-test-failure", Identifier: "TestLarge"},
	}})
	require.NoError(t, err)
	packet := source.Packet{Files: []source.PacketFile{{
		Path: "large_test.go", Content: "package sample\nfunc TestLarge() { /*" + strings.Repeat("x", 8<<10) + "*/ }\n",
	}}}
	require.Empty(t, focusedTestFailureContext(packet, feedback))
	packet.Files[0].Content = "not Go source"
	require.Empty(t, focusedTestFailureContext(packet, feedback))
	require.Empty(t, focusedTestFailureContext(packet, json.RawMessage(`{"broken":`)))
}
