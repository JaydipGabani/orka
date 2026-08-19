package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestServeAdvertisesAndAcceptsRequiredCodexAuthentication(t *testing.T) {
	input := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"authenticate","params":{"methodId":"api-key"}}` + "\n" +
			`{"jsonrpc":"2.0","id":3,"method":"session/new","params":{}}` + "\n",
	)
	var output bytes.Buffer
	if err := serve(input, &output); err != nil {
		t.Fatalf("serve() error = %v", err)
	}

	decoder := json.NewDecoder(&output)
	var initialize struct {
		Result struct {
			ProtocolVersion int `json:"protocolVersion"`
			AuthMethods     []struct {
				ID string `json:"id"`
			} `json:"authMethods"`
		} `json:"result"`
	}
	if err := decoder.Decode(&initialize); err != nil {
		t.Fatal(err)
	}
	if initialize.Result.ProtocolVersion != protocolVersion || len(initialize.Result.AuthMethods) != 1 ||
		initialize.Result.AuthMethods[0].ID != apiKeyAuthMethod {
		t.Fatalf("initialize result = %#v", initialize.Result)
	}

	var authenticated struct {
		ID     int            `json:"id"`
		Result map[string]any `json:"result"`
	}
	if err := decoder.Decode(&authenticated); err != nil {
		t.Fatal(err)
	}
	if authenticated.ID != 2 || authenticated.Result == nil {
		t.Fatalf("authenticate result = %#v", authenticated)
	}

	var newSession struct {
		Result struct {
			SessionID string `json:"sessionId"`
		} `json:"result"`
	}
	if err := decoder.Decode(&newSession); err != nil {
		t.Fatal(err)
	}
	if newSession.Result.SessionID != providerSessionID {
		t.Fatalf("session ID = %q, want %q", newSession.Result.SessionID, providerSessionID)
	}
}

func TestTerminalResultThreatModelPreservesBinding(t *testing.T) {
	prompt := `Use this exact envelope and identity values; replace only threatModel with the complete markdown document:
	{
	  "schemaVersion": 1,
	  "kind": "orka.security.threat-model.v1",
	  "repositoryScan": "security-goof",
	  "scanId": "scan_123",
	  "policyDigest": "sha256:policy",
	  "threatModel": "# Threat Model\n\n..."
	}
	`
	result, err := terminalResult(prompt)
	if err != nil {
		t.Fatalf("terminalResult() error = %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(result, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["scanId"] != "scan_123" || envelope["policyDigest"] != "sha256:policy" {
		t.Fatalf("binding changed: %#v", envelope)
	}
	if threatModel, _ := envelope["threatModel"].(string); len(threatModel) == 0 || threatModel[0] != '#' {
		t.Fatalf("threatModel = %q, want markdown heading", threatModel)
	}
}

func TestTerminalResultReviewUsesMapperContextAndAddsRejectedEvidence(t *testing.T) {
	prompt := "Use this exact envelope, repository identity, and binding values. " +
		"Populate findings.findings; keep it an empty array when no supported finding exists:\n" +
		`{
	  "schemaVersion": 1,
	  "kind": "orka.security.findings.v1",
	  "repositoryScan": "security-goof",
	  "scanId": "scan_123",
	  "sliceId": "slice_api",
	  "policyDigest": "sha256:policy",
	  "contextDigest": "sha256:context",
	  "findings": {
	    "schemaVersion": 2,
	    "repository": {
	      "repoURL": "https://github.com/example/repo",
	      "branch": "main",
	      "headSHA": "abc"
	    },
	    "scan": {
	      "mode": "initial",
	      "sliceId": "slice_api",
	      "summary": "..."
	    },
	    "findings": []
	  }
	}

Valid evidence paths for this review:
- README.md (context)
- server.js (owned)

Cite findings only from included file ranges below.

--- README.md (context) ---
     1  docs

--- server.js (owned) ---
    17  app.post('/admin', handler)
`
	result, err := terminalResult(prompt)
	if err != nil {
		t.Fatalf("terminalResult() error = %v", err)
	}
	var envelope struct {
		Findings struct {
			Findings []struct {
				Evidence []struct {
					Path      string `json:"path"`
					StartLine int    `json:"startLine"`
				} `json:"evidence"`
			} `json:"findings"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(result, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Findings.Findings) != 2 {
		t.Fatalf("findings = %#v, want accepted and rejected fixtures", envelope.Findings.Findings)
	}
	if got := envelope.Findings.Findings[0].Evidence[0]; got.Path != "server.js" || got.StartLine != 17 {
		t.Fatalf("accepted evidence = %#v, want mapper-owned server.js:17", got)
	}
	if got := envelope.Findings.Findings[1].Evidence[0].Path; got != "outside-mapper-context.txt" {
		t.Fatalf("rejected evidence path = %q", got)
	}
}

func TestTerminalResultMalformedScanBreaksIdentityBinding(t *testing.T) {
	prompt := `Use this exact envelope and identity values; replace only threatModel with the complete markdown document:
	{
	  "schemaVersion": 1,
	  "kind": "orka.security.threat-model.v1",
	  "repositoryScan": "security-goof-malformed-result",
	  "scanId": "scan_123",
	  "policyDigest": "sha256:policy",
	  "threatModel": "# Threat Model\n\n..."
	}
	`
	result, err := terminalResult(prompt)
	if err != nil {
		t.Fatalf("terminalResult() error = %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(result, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["scanId"] == "scan_123" {
		t.Fatalf("malformed fixture preserved scan binding: %#v", envelope)
	}
}
