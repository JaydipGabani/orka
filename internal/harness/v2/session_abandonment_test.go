package v2

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeleteRuntimeSessionAbandonmentRequiresExactPromptMetadata(t *testing.T) {
	for _, field := range []string{"task", "attempt", "prompt", "none"} {
		t.Run(field, func(t *testing.T) {
			request := DeleteRuntimeSessionRequest{
				Protocol: ProtocolVersion, Metadata: testMutationMetadata(t, true),
				Reason: "terminal_recovery", AbandonUnvalidatedPrompt: true,
			}
			switch field {
			case "task":
				request.Metadata.TaskUID = ""
			case "attempt":
				request.Metadata.TaskAttempt = 0
			case "prompt":
				request.Metadata.PromptID = ""
			}
			sealRequest(t, request, &request.Metadata.RequestDigest)
			if err := request.ValidateAt(testNow); (err == nil) != (field == "none") {
				t.Fatalf("abandonment metadata validation: field=%s error=%v", field, err)
			}
		})
	}
}

func TestDeleteRuntimeSessionAbandonmentPreservesLegacyDigest(t *testing.T) {
	request := DeleteRuntimeSessionRequest{Protocol: ProtocolVersion, Metadata: testMutationMetadata(t, false), Reason: "terminal_recovery"}
	sealRequest(t, request, &request.Metadata.RequestDigest)
	legacy := struct {
		Protocol string           `json:"protocol"`
		Metadata MutationMetadata `json:"metadata"`
		Reason   string           `json:"reason,omitempty"`
	}{Protocol: request.Protocol, Metadata: request.Metadata, Reason: request.Reason}
	digest, err := CanonicalRequestDigest(legacy)
	if err != nil || digest != request.Metadata.RequestDigest {
		t.Fatalf("ordinary deletion changed its wire digest: %v", err)
	}
	request.AbandonUnvalidatedPrompt = true
	request.Metadata.PromptID = "abandoned-prompt"
	if err := request.ValidateAt(testNow); err == nil {
		t.Fatal("abandonment did not require a new operation digest")
	}
	sealRequest(t, request, &request.Metadata.RequestDigest)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&legacy); err == nil {
		t.Fatal("an old supervisor silently accepted unsupported abandonment")
	}
}
