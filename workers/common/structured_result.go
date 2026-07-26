/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package common

import "github.com/orka-agents/orka/internal/taskresult"

// StructuredResult is retained as a source-compatible alias.
type StructuredResult = taskresult.StructuredResult

// ArtifactRef is retained as a source-compatible alias.
type ArtifactRef = taskresult.ArtifactRef

// MaxStructuredSummaryChars is retained for source compatibility.
const MaxStructuredSummaryChars = taskresult.MaxStructuredSummaryChars

// FormatStructuredResult delegates to the dependency-neutral task result contract.
func FormatStructuredResult(r *StructuredResult) ([]byte, error) {
	return taskresult.FormatStructuredResult(r)
}

// ParseStructuredResult delegates to the dependency-neutral task result contract.
func ParseStructuredResult(raw string) *StructuredResult {
	return taskresult.ParseStructuredResult(raw)
}

// TruncateStructuredSummary delegates to the dependency-neutral task result contract.
func TruncateStructuredSummary(summary string) string {
	return taskresult.TruncateStructuredSummary(summary)
}
