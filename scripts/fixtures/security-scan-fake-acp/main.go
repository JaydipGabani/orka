package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	jsonRPCVersion  = "2.0"
	protocolVersion = 1
	fieldJSONRPC    = "jsonrpc"
	fieldResult     = "result"
	contentTypeText = "text"

	methodInitialize    = "initialize"
	methodAuthenticate  = "authenticate"
	methodSessionNew    = "session/new"
	methodSessionPrompt = "session/prompt"
	methodSessionCancel = "session/cancel"
	methodSessionUpdate = "session/update"

	threatModelKind = "orka.security.threat-model.v1"
	findingsKind    = "orka.security.findings.v1"

	malformedScanMarker = "malformed-result"
	providerSessionID   = "security-scan-fixture-session"
	apiKeyAuthMethod    = "api-key"
)

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type promptRequest struct {
	Prompt []contentBlock `json:"prompt"`
}

type authenticateRequest struct {
	MethodID string `json:"methodId"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type evidenceCandidate struct {
	path string
	role string
}

func main() {
	if err := serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "security scan ACP fixture failed")
		os.Exit(2)
	}
}

func serve(input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	writer := bufio.NewWriter(output)
	defer writer.Flush() //nolint:errcheck

	for scanner.Scan() {
		var message rpcMessage
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			return err
		}
		switch message.Method {
		case methodInitialize:
			if err := writeMessage(writer, map[string]any{
				fieldJSONRPC: jsonRPCVersion,
				"id":         decodeID(message.ID),
				fieldResult: map[string]any{
					"protocolVersion": protocolVersion,
					"agentInfo":       map[string]any{"name": "orka-security-scan-fixture", "version": "1"},
					"agentCapabilities": map[string]any{
						"mcpCapabilities": map[string]any{"http": true},
					},
					"authMethods": []any{map[string]any{
						"id": apiKeyAuthMethod, "name": "API key",
					}},
				},
			}); err != nil {
				return err
			}
		case methodAuthenticate:
			var request authenticateRequest
			if err := json.Unmarshal(message.Params, &request); err != nil {
				return err
			}
			if request.MethodID != apiKeyAuthMethod {
				if err := writeMessage(writer, map[string]any{
					fieldJSONRPC: jsonRPCVersion,
					"id":         decodeID(message.ID),
					"error":      map[string]any{"code": -32602, "message": "unsupported authentication method"},
				}); err != nil {
					return err
				}
				continue
			}
			if err := writeMessage(writer, map[string]any{
				fieldJSONRPC: jsonRPCVersion,
				"id":         decodeID(message.ID),
				fieldResult:  map[string]any{},
			}); err != nil {
				return err
			}
		case methodSessionNew:
			if err := writeMessage(writer, map[string]any{
				fieldJSONRPC: jsonRPCVersion,
				"id":         decodeID(message.ID),
				fieldResult:  map[string]any{"sessionId": providerSessionID},
			}); err != nil {
				return err
			}
		case methodSessionPrompt:
			var request promptRequest
			if err := json.Unmarshal(message.Params, &request); err != nil {
				return err
			}
			result, err := terminalResult(promptText(request.Prompt))
			if err != nil {
				if writeErr := writeMessage(writer, map[string]any{
					fieldJSONRPC: jsonRPCVersion,
					"id":         decodeID(message.ID),
					"error":      map[string]any{"code": -32603, "message": "deterministic fixture could not build result"},
				}); writeErr != nil {
					return writeErr
				}
				continue
			}
			if err := writeMessage(writer, map[string]any{
				fieldJSONRPC: jsonRPCVersion,
				"method":     methodSessionUpdate,
				"params": map[string]any{
					"sessionId": providerSessionID,
					"update": map[string]any{
						"sessionUpdate": "agent_message_chunk",
						"content": map[string]any{
							"type": contentTypeText,
							"text": string(result),
						},
					},
				},
			}); err != nil {
				return err
			}
			if err := writeMessage(writer, map[string]any{
				fieldJSONRPC: jsonRPCVersion,
				"id":         decodeID(message.ID),
				fieldResult:  map[string]any{"stopReason": "end_turn"},
			}); err != nil {
				return err
			}
		case methodSessionCancel:
			// The fixture completes synchronously, so cancellation is always a no-op.
		}
	}
	return scanner.Err()
}

func writeMessage(writer *bufio.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := writer.Write(append(data, '\n')); err != nil {
		return err
	}
	return writer.Flush()
}

func decodeID(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	return value
}

func promptText(blocks []contentBlock) string {
	var out strings.Builder
	for _, block := range blocks {
		if block.Type != contentTypeText || block.Text == "" {
			continue
		}
		out.WriteString(block.Text)
		out.WriteByte('\n')
	}
	return out.String()
}

func terminalResult(prompt string) ([]byte, error) {
	envelope, err := contractEnvelope(prompt)
	if err != nil {
		return nil, err
	}
	kind, _ := envelope["kind"].(string)
	repositoryScan, _ := envelope["repositoryScan"].(string)
	if strings.Contains(repositoryScan, malformedScanMarker) {
		envelope["scanId"] = "scan_fixture_binding_mismatch"
		return json.Marshal(envelope)
	}

	switch kind {
	case threatModelKind:
		envelope["threatModel"] = "# Threat Model\n\n## Trust Boundaries\n\n" +
			"The HTTP request boundary, repository content, and privileged server operations are security-sensitive.\n\n" +
			"## Validation Scope\n\nFindings must be grounded in mapper-owned repository evidence."
	case findingsKind:
		if err := populateFindings(envelope, prompt); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported security result kind")
	}
	return json.Marshal(envelope)
}

func contractEnvelope(prompt string) (map[string]any, error) {
	marker := "Use this exact envelope"
	markerIndex := strings.Index(prompt, marker)
	if markerIndex < 0 {
		return nil, errors.New("terminal result contract marker is missing")
	}
	objectStart := strings.IndexByte(prompt[markerIndex:], '{')
	if objectStart < 0 {
		return nil, errors.New("terminal result envelope is missing")
	}
	objectStart += markerIndex
	data, err := extractJSONObject(prompt[objectStart:])
	if err != nil {
		return nil, err
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(data), &envelope); err != nil {
		return nil, err
	}
	return envelope, nil
}

func extractJSONObject(value string) (string, error) {
	depth := 0
	inString := false
	escaped := false
	for index, current := range value {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch current {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch current {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return value[:index+1], nil
			}
		}
		if depth < 0 {
			break
		}
	}
	return "", errors.New("terminal result envelope is incomplete")
}

func populateFindings(envelope map[string]any, prompt string) error {
	artifact, ok := envelope["findings"].(map[string]any)
	if !ok {
		return errors.New("findings artifact is missing")
	}
	scan, ok := artifact["scan"].(map[string]any)
	if !ok {
		return errors.New("findings scan identity is missing")
	}
	path, line, ok := reviewEvidence(prompt)
	if !ok {
		scan["summary"] = "No bounded source evidence was available to the deterministic fixture."
		artifact["findings"] = []any{}
		return nil
	}

	scan["summary"] = "Deterministic fixture produced one bounded finding and one rejected evidence diagnostic."
	artifact["findings"] = []any{
		map[string]any{
			"title":      "Missing authorization on a privileged server operation",
			"category":   "authorization",
			"severity":   "high",
			"confidence": "high",
			"triage":     "valid",
			"summary": "An attacker-controlled request reaches a privileged server operation without authorization, " +
				"crossing the application trust boundary.",
			"rootCause":    "The server operation is invoked before an authorization decision is enforced.",
			"reproduction": "Submit an untrusted request that reaches the cited operation without an authorized identity.",
			"remediation":  "Enforce authorization before invoking the privileged operation.",
			"evidence": []any{map[string]any{
				"path": path, "startLine": line, "endLine": line,
			}},
		},
		map[string]any{
			"title":       "Rejected fixture evidence outside mapper context",
			"category":    "fixture-invalid-evidence",
			"severity":    "medium",
			"confidence":  "medium",
			"summary":     "This deterministic record intentionally cites a file outside the trusted mapper context.",
			"remediation": "Reject findings whose evidence is outside the trusted context.",
			"evidence": []any{map[string]any{
				"path": "outside-mapper-context.txt", "startLine": 1, "endLine": 1,
			}},
		},
	}
	return nil
}

func reviewEvidence(prompt string) (string, int, bool) {
	const listStart = "Valid evidence paths for this review:\n"
	const listEnd = "\nCite findings only from included file ranges below."
	start := strings.Index(prompt, listStart)
	if start < 0 {
		return "", 0, false
	}
	start += len(listStart)
	end := strings.Index(prompt[start:], listEnd)
	if end < 0 {
		return "", 0, false
	}

	section := prompt[start : start+end]
	candidates := make([]evidenceCandidate, 0, strings.Count(section, "\n"))
	for line := range strings.SplitSeq(section, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "- ") || !strings.HasSuffix(line, ")") {
			continue
		}
		line = strings.TrimPrefix(line, "- ")
		roleStart := strings.LastIndex(line, " (")
		if roleStart <= 0 {
			continue
		}
		candidates = append(candidates, evidenceCandidate{
			path: strings.TrimSpace(line[:roleStart]),
			role: strings.TrimSuffix(line[roleStart+2:], ")"),
		})
	}
	for _, preferred := range []bool{true, false} {
		for _, candidate := range candidates {
			if preferred != preferredEvidence(candidate) {
				continue
			}
			if line, ok := firstIncludedLine(prompt, candidate); ok {
				return candidate.path, line, true
			}
		}
	}
	return "", 0, false
}

func preferredEvidence(candidate evidenceCandidate) bool {
	if candidate.role == "test" {
		return false
	}
	lower := strings.ToLower(candidate.path)
	base := strings.ToLower(filepath.Base(lower))
	if strings.HasPrefix(lower, "docs/") || strings.Contains(lower, "/docs/") ||
		strings.Contains(lower, "/test/") || strings.Contains(lower, "/tests/") ||
		strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") {
		return false
	}
	switch filepath.Ext(lower) {
	case ".c", ".cc", ".cpp", ".cs", ".go", ".java", ".js", ".jsx", ".kt", ".mjs", ".php", ".py",
		".rb", ".rs", ".sh", ".ts", ".tsx":
		return true
	default:
		return false
	}
}

func firstIncludedLine(prompt string, candidate evidenceCandidate) (int, bool) {
	header := "--- " + candidate.path + " (" + candidate.role + ") ---\n"
	_, content, found := strings.Cut(prompt, header)
	if !found {
		return 0, false
	}
	for line := range strings.SplitSeq(content, "\n") {
		if strings.HasPrefix(line, "--- ") {
			break
		}
		trimmed := strings.TrimLeft(line, " \t")
		separator := strings.Index(trimmed, "  ")
		if separator <= 0 {
			continue
		}
		lineNumber, err := strconv.Atoi(trimmed[:separator])
		if err == nil && lineNumber > 0 {
			return lineNumber, true
		}
	}
	return 0, false
}
