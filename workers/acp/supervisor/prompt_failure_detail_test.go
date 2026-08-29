package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/acp"
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
