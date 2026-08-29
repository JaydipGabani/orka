package api

import (
	"testing"

	"github.com/orka-agents/orka/internal/llm"
)

const (
	incompleteTestPartialContent = "partial"
	incompleteTestRefusalReason  = "refusal"
	incompleteTestDoneContent    = "done"
	incompleteTestToolName       = "list_tasks"
)

func TestValidateToolLoopCompletionAcceptsMaxTokensTextResponse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		resp    *llm.CompletionResponse
		wantErr bool
	}{
		{name: "max_tokens text only", resp: &llm.CompletionResponse{Content: incompleteTestPartialContent, StopReason: oaiParamMaxTokens}},
		{name: "length text only", resp: &llm.CompletionResponse{Content: incompleteTestPartialContent, StopReason: oaiStopReasonLength}},
		{
			name:    "max_tokens with truncated tool call",
			resp:    &llm.CompletionResponse{StopReason: oaiParamMaxTokens, ToolCalls: []llm.ToolCall{{ID: acpPublicConsumerToolCallID, Name: incompleteTestToolName}}},
			wantErr: true,
		},
		{name: "refusal outcome", resp: &llm.CompletionResponse{StopReason: incompleteTestRefusalReason}, wantErr: true},
		{name: "end of turn", resp: &llm.CompletionResponse{Content: incompleteTestDoneContent, StopReason: oaiStopReasonEndTurn}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateToolLoopCompletion(tc.resp)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateToolLoopCompletion() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
