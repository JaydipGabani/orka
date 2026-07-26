/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package taskresult

import (
	"reflect"
	"strings"
	"testing"
)

func TestFormatStructuredResultPreservesJSONContract(t *testing.T) {
	result := &StructuredResult{
		Summary:    "Added auth middleware",
		BaseSHA:    "abc123",
		HeadSHA:    "def456",
		Diff:       "diff --git a/auth.go b/auth.go\n+// auth",
		Verdict:    "APPROVED",
		Feedback:   "looks good",
		Files:      []string{"auth.go"},
		PushBranch: "feature/auth",
		PushError:  "push failed",
		Data:       map[string]any{"risk": "low", "count": float64(2)},
		Artifacts: []ArtifactRef{
			{
				Filename:    "evidence.json",
				ContentType: "application/json",
				Size:        128,
				Description: "review evidence",
			},
			{Filename: "notes.txt"},
		},
	}

	got, err := FormatStructuredResult(result)
	if err != nil {
		t.Fatalf("FormatStructuredResult() error = %v", err)
	}
	want := `{"version":1,"summary":"Added auth middleware","baseSHA":"abc123","headSHA":"def456","diff":"diff --git a/auth.go b/auth.go\n+// auth","verdict":"APPROVED","feedback":"looks good","files":["auth.go"],"pushBranch":"feature/auth","pushError":"push failed","data":{"count":2,"risk":"low"},"artifacts":[{"filename":"evidence.json","contentType":"application/json","size":128,"description":"review evidence"},{"filename":"notes.txt"}]}`
	if string(got) != want {
		t.Fatalf("FormatStructuredResult() = %s, want %s", got, want)
	}
	if result.Version != 1 {
		t.Fatalf("FormatStructuredResult() version = %d, want 1", result.Version)
	}
}

func TestFormatStructuredResultPreservesExplicitVersion(t *testing.T) {
	result := &StructuredResult{Version: 2, Summary: "test"}

	got, err := FormatStructuredResult(result)
	if err != nil {
		t.Fatalf("FormatStructuredResult() error = %v", err)
	}
	if string(got) != `{"version":2,"summary":"test"}` {
		t.Fatalf("FormatStructuredResult() = %s", got)
	}
	if result.Version != 2 {
		t.Fatalf("FormatStructuredResult() version = %d, want 2", result.Version)
	}
}

func TestParseStructuredResult(t *testing.T) {
	raw := `{"version":1,"summary":"done","baseSHA":"abc","headSHA":"def","diff":"patch","verdict":"APPROVED","feedback":"ship it","files":["a.go"],"pushBranch":"feature/a","pushError":"","data":{"answer":42},"artifacts":[{"filename":"evidence.json","contentType":"application/json","size":42,"description":"evidence"}]}`

	got := ParseStructuredResult(raw)
	want := &StructuredResult{
		Version:    1,
		Summary:    "done",
		BaseSHA:    "abc",
		HeadSHA:    "def",
		Diff:       "patch",
		Verdict:    "APPROVED",
		Feedback:   "ship it",
		Files:      []string{"a.go"},
		PushBranch: "feature/a",
		Data:       map[string]any{"answer": float64(42)},
		Artifacts: []ArtifactRef{{
			Filename:    "evidence.json",
			ContentType: "application/json",
			Size:        42,
			Description: "evidence",
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseStructuredResult() = %#v, want %#v", got, want)
	}
}

func TestParseStructuredResultFallsBackToPlainText(t *testing.T) {
	tests := []string{
		"just some text output",
		"{bad json",
		`{"summary":"missing version"}`,
		`{"version":0,"summary":"zero version"}`,
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			got := ParseStructuredResult(raw)
			want := &StructuredResult{Version: 1, Summary: raw}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("ParseStructuredResult(%q) = %#v, want %#v", raw, got, want)
			}
		})
	}
}

func TestTruncateStructuredSummary(t *testing.T) {
	atLimit := strings.Repeat("x", MaxStructuredSummaryChars)
	if got := TruncateStructuredSummary(atLimit); got != atLimit {
		t.Fatalf("summary at limit changed")
	}

	overLimit := atLimit + strings.Repeat("y", 128)
	want := atLimit + "\n[summary truncated, full summary: 32896 chars]"
	if got := TruncateStructuredSummary(overLimit); got != want {
		t.Fatalf("TruncateStructuredSummary() = %q, want %q", got, want)
	}
}
