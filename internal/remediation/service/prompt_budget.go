package service

import (
	"unicode/utf8"

	"github.com/orka-agents/orka/internal/remediation/environment"
)

type checkIntent struct {
	ID         string                 `json:"id"`
	Class      environment.CheckClass `json:"class"`
	Capability string                 `json:"capability"`
	Path       string                 `json:"path,omitempty"`
}

func checkIntents(plan environment.Plan) []checkIntent {
	checks := make([]checkIntent, 0, len(plan.Checks))
	for _, check := range plan.Checks {
		intent := checkIntent{ID: check.ID, Class: check.Class, Capability: check.Capability}
		if check.HTTP != nil {
			intent.Path = check.HTTP.Path
		}
		checks = append(checks, intent)
	}
	return checks
}

type promptPreview struct {
	Digest    string `json:"digest,omitempty"`
	Text      string `json:"text,omitempty"`
	Truncated bool   `json:"truncated"`
}

func previewPrompt(raw []byte, limit int) promptPreview {
	if len(raw) == 0 {
		return promptPreview{}
	}
	preview := promptPreview{Digest: Digest(raw)}
	if len(raw) > limit {
		raw = raw[:limit]
		for !utf8.Valid(raw) {
			raw = raw[:len(raw)-1]
		}
		preview.Truncated = true
	}
	preview.Text = string(raw)
	return preview
}
