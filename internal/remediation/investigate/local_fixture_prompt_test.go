package investigate

import (
	"strings"
	"testing"
)

func TestInvestigationDistinguishesControlledReceiversFromProviderGuarantees(t *testing.T) {
	for _, instruction := range []string{
		"test-harness-controlled HTTP or HTTPS receiver as local-services",
		"Use external-service only when actual third-party or managed-service behavior is required",
		"cannot establish real Azure authorization",
		"Do not replace such provider guarantees with a local fixture",
	} {
		if !strings.Contains(identifyInstructions, instruction) {
			t.Fatalf("missing fixture versus provider boundary guidance: %s", instruction)
		}
	}
}
