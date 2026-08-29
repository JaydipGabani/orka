package controller

import (
	"errors"
	"strings"
	"testing"

	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
)

const (
	promptFailureTestGenericMessage = "prompt failed"
	promptFailureTestGenericCode    = "acp_prompt_failed"
)

func TestACPPromptFailureMessageProjectsRuntimeDetail(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		terminal harnessv2.Event
		want     string
	}{
		{name: "no failed payload", terminal: harnessv2.Event{Type: harnessv2.EventFailed}, want: promptFailureTestGenericMessage},
		{
			name:     "generic code only",
			terminal: harnessv2.Event{Type: harnessv2.EventFailed, Failed: &harnessv2.FailedEvent{Code: promptFailureTestGenericCode, Message: "ACP prompt failed"}},
			want:     "prompt failed: ACP prompt failed",
		},
		{
			name:     "provider upstream error keeps code and detail",
			terminal: harnessv2.Event{Type: harnessv2.EventFailed, Failed: &harnessv2.FailedEvent{Code: "provider_upstream_error", Message: "provider upstream returned HTTP 402 for every inference request: quota exceeded"}},
			want:     "prompt failed: provider_upstream_error: provider upstream returned HTTP 402 for every inference request: quota exceeded",
		},
		{
			name:     "code without message",
			terminal: harnessv2.Event{Type: harnessv2.EventFailed, Failed: &harnessv2.FailedEvent{Code: "turn_limit"}},
			want:     "prompt failed: turn_limit",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := acpPromptFailureMessage(tc.terminal); got != tc.want {
				t.Fatalf("acpPromptFailureMessage() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestACPPromptFailureMessageIsBounded(t *testing.T) {
	t.Parallel()
	terminal := harnessv2.Event{Type: harnessv2.EventFailed, Failed: &harnessv2.FailedEvent{
		Code: promptFailureTestGenericCode, Message: strings.Repeat("x", 4*acpPromptFailureMessageLimit),
	}}
	if got := acpPromptFailureMessage(terminal); len(got) != acpPromptFailureMessageLimit {
		t.Fatalf("len(acpPromptFailureMessage()) = %d, want %d", len(got), acpPromptFailureMessageLimit)
	}
}

func TestACPWorkspaceValidationFailureMessageProjectsSupervisorReason(t *testing.T) {
	t.Parallel()
	const generic = "workspace validation failed before a trusted delta was established"
	if got := acpWorkspaceValidationFailureMessage(errors.New("dial tcp: connection refused")); got != generic {
		t.Fatalf("non-client error message = %q, want %q", got, generic)
	}
	clientErr := &harnessv2.ClientError{StatusCode: 409, Code: harnessv2.ErrorCodeSessionPoisoned, Message: "workspace validation failed: validate: reserved workspace path"}
	got := acpWorkspaceValidationFailureMessage(clientErr)
	if !strings.HasPrefix(got, generic+": ") || !strings.Contains(got, "reserved workspace path") {
		t.Fatalf("client error message = %q", got)
	}
	if got := acpWorkspaceValidationFailureMessage(&harnessv2.ClientError{StatusCode: 409, Message: "   "}); got != generic {
		t.Fatalf("blank client message = %q, want %q", got, generic)
	}
}
