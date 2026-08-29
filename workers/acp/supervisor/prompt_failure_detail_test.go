package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/acp"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
)

func TestPromptFailureErrorDetailRendersRPCErrors(t *testing.T) {
	t.Parallel()
	rpcErr := &acp.RPCError{
		Code:    -32603,
		Message: "model not available for integrator http://127.0.0.1:1/_orka/provider/secret-route/v1/chat",
		Data:    json.RawMessage(`{"service":"session","errorName":"UnknownError"}`),
	}
	got := promptFailureErrorDetail(fmt.Errorf("prompt: %w", rpcErr))
	if !strings.HasPrefix(got, "session/UnknownError: model not available for integrator") {
		t.Fatalf("promptFailureErrorDetail() = %q", got)
	}
	if strings.Contains(got, "_orka/provider") {
		t.Fatalf("promptFailureErrorDetail() leaked the provider route: %q", got)
	}
	if got := promptFailureErrorDetail(nil); got != "" {
		t.Fatalf("promptFailureErrorDetail(nil) = %q, want empty", got)
	}
	if got := promptFailureErrorDetail(errors.New("transport closed")); got != "transport closed" {
		t.Fatalf("promptFailureErrorDetail(plain) = %q", got)
	}
	long := &acp.RPCError{Code: 1, Message: strings.Repeat("x", 2000)}
	if got := promptFailureErrorDetail(long); len(got) > 520 {
		t.Fatalf("promptFailureErrorDetail(long) len = %d, want bounded", len(got))
	}
}

func TestFailedEventStopReasonNeverEmitsNonFailureReasons(t *testing.T) {
	t.Parallel()
	cases := map[acp.StopReason]harnessv2.ACPStopReason{
		acp.StopReasonCancelled:       harnessv2.ACPStopReasonRefusal,
		acp.StopReasonEndTurn:         harnessv2.ACPStopReasonRefusal,
		acp.StopReasonRefusal:         harnessv2.ACPStopReasonRefusal,
		acp.StopReasonMaxTurnRequests: harnessv2.ACPStopReasonMaxTurnRequests,
		acp.StopReason(""):            harnessv2.ACPStopReason(""),
	}
	for in, want := range cases {
		got := failedEventStopReason(in)
		if got != want {
			t.Fatalf("failedEventStopReason(%q) = %q, want %q", in, got, want)
		}
		if err := (harnessv2.FailedEvent{StopReason: got, Code: "acp_prompt_failed", Message: "x"}).Validate(); err != nil {
			t.Fatalf("Validate(%q) = %v", got, err)
		}
	}
}
