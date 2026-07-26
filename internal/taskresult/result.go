/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

// Package taskresult defines the dependency-neutral structured task result
// contract shared by workers, controllers, tools, and runtime adapters.
package taskresult

import (
	"encoding/json"
	"fmt"
)

const (
	// MaxStructuredSummaryChars bounds agent-written summaries stored in structured
	// results. Diffs remain intact for workspace handoff, but oversized summaries
	// can otherwise blow up coordinator context windows and provider request limits.
	MaxStructuredSummaryChars = 32 * 1024
)

// StructuredResult is an optional structured envelope for task results.
// Workers can use this to include diffs, verdicts, and metadata alongside
// the human-readable summary. Plain-text results remain backward compatible.
type StructuredResult struct {
	Version    int      `json:"version"`
	Summary    string   `json:"summary"`
	BaseSHA    string   `json:"baseSHA,omitempty"`
	HeadSHA    string   `json:"headSHA,omitempty"`
	Diff       string   `json:"diff,omitempty"`
	Verdict    string   `json:"verdict,omitempty"`
	Feedback   string   `json:"feedback,omitempty"`
	Files      []string `json:"files,omitempty"`
	PushBranch string   `json:"pushBranch,omitempty"`
	PushError  string   `json:"pushError,omitempty"`
	// Data carries generic machine-readable task output. Keep large payloads in
	// artifacts and put references here; parent/coordinator summaries may bound it.
	Data      map[string]any `json:"data,omitempty"`
	Artifacts []ArtifactRef  `json:"artifacts,omitempty"`
}

// ArtifactRef is a safe structured reference to a task artifact. The artifact
// bytes remain in Orka artifact storage; this envelope carries only metadata
// that coordinators and remote runtimes can use to fetch or reason about it.
type ArtifactRef struct {
	Filename    string `json:"filename"`
	ContentType string `json:"contentType,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Description string `json:"description,omitempty"`
}

// FormatStructuredResult serializes a StructuredResult to JSON bytes.
func FormatStructuredResult(r *StructuredResult) ([]byte, error) {
	if r.Version == 0 {
		r.Version = 1
	}
	return json.Marshal(r)
}

// ParseStructuredResult attempts to parse a result string as a StructuredResult.
// If the input is not valid JSON or doesn't have the expected structure,
// it returns a StructuredResult with the raw input as Summary (backward compatible).
func ParseStructuredResult(raw string) *StructuredResult {
	var sr StructuredResult
	if err := json.Unmarshal([]byte(raw), &sr); err != nil || sr.Version == 0 {
		return &StructuredResult{
			Version: 1,
			Summary: raw,
		}
	}
	return &sr
}

// TruncateStructuredSummary bounds human-readable result summaries while making
// truncation explicit to downstream coordinators.
func TruncateStructuredSummary(summary string) string {
	if len(summary) <= MaxStructuredSummaryChars {
		return summary
	}
	return summary[:MaxStructuredSummaryChars] + fmt.Sprintf(
		"\n[summary truncated, full summary: %d chars]",
		len(summary),
	)
}
