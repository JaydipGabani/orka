package buildjob

import (
	"bytes"
	"context"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

const buildRefFile = "build.ref"

var buildRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)

func validSettlementFields(wire WorkerResult) bool {
	return (wire.BuildRef == "" || buildRefPattern.MatchString(wire.BuildRef)) &&
		(!wire.DaemonSettled || wire.BuildRef != "")
}

func (process buildctlProcess) settle(m manifest, root *os.Root, directory string) (string, bool) {
	body, err := readPrivateMetadata(root, buildRefFile, 128)
	if err != nil || !buildRefPattern.Match(body) {
		return "", false
	}
	ref := string(body)
	// Cancellation of the build caller must not cancel its bounded settlement
	// check. This context carries no request values or credentials.
	ctx, cancel := context.WithTimeout(context.Background(), m.Limits.SettlementTimeout)
	defer cancel()
	for {
		evidence := &historyEvidence{ref: ref}
		err := process.command(ctx, historyArguments(m, ref), directory, evidence, io.Discard)
		if err == nil && evidence.completed && !evidence.invalid && len(bytes.TrimSpace(evidence.line)) == 0 {
			return ref, true
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ref, false
		case <-timer.C:
		}
	}
}

func historyArguments(m manifest, ref string) []string {
	// The ref's restricted alphabet cannot escape the template string. The
	// daemon event itself is never serialized: only this exact ref and presence
	// of CompletedAt are exposed by buildctl's Go template.
	format := `{{if .Record}}{{if eq .Record.Ref "` + ref +
		`"}}{"ref":{{json .Record.Ref}},"completed":{{if .Record.CompletedAt}}true{{else}}false{{end}}}{{end}}{{end}}`
	return append(connectionArguments(m), "debug", "histories", "--format", format)
}

type historyEvidence struct {
	ref       string
	line      []byte
	completed bool
	invalid   bool
}

func (e *historyEvidence) Write(body []byte) (int, error) {
	for _, character := range body {
		if character == '\n' {
			e.consume()
			e.line = e.line[:0]
			continue
		}
		if len(e.line) >= 1024 {
			e.invalid = true
			continue
		}
		e.line = append(e.line, character)
	}
	return len(body), nil
}

func (e *historyEvidence) consume() {
	if len(bytes.TrimSpace(e.line)) == 0 {
		return
	}
	var result struct {
		Ref       string `json:"ref"`
		Completed bool   `json:"completed"`
	}
	if decodeStrict(e.line, &result) != nil || result.Ref != e.ref || strings.TrimSpace(result.Ref) != result.Ref {
		e.invalid = true
		return
	}
	e.completed = e.completed || result.Completed
}
