package main

import "testing"

func TestDeriveSkillImportName(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		data     string
		want     string
	}{
		{"h1 heading wins", "docs/SKILL.md", "# Release Notes Helper\n\n## Description\n\nx\n", "release-notes-helper"},
		{"parent dir for conventional SKILL.md", "skills/pr-triage/SKILL.md", "## Description\n\nno heading\n", "pr-triage"},
		{"lowercase skill.md also uses parent", "skills/Pr_Triage/skill.md", "text\n", "pr-triage"},
		{"bare SKILL.md in cwd falls back to filename", "SKILL.md", "text\n", "skill"},
		{"other filename", "notes/My Skill.md", "text\n", "my-skill"},
		{"heading with symbols", "SKILL.md", "#   Deploy: v2 (beta)!\n", "deploy-v2-beta"},
		{"empty heading falls through", "skills/alpha/SKILL.md", "# \n", "alpha"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveSkillImportName(tt.filePath, []byte(tt.data)); got != tt.want {
				t.Fatalf("deriveSkillImportName(%q) = %q, want %q", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestDeriveSkillImportDescription(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"description section", "# n\n\n## Description\n\nUse this for triage.\nMore.\n\n## Instructions\n\n- step\n", "Use this for triage."},
		{"case-insensitive heading", "# n\n\n## DESCRIPTION\n\n  Trimmed text  \n", "Trimmed text"},
		{"no description section uses first paragraph", "# n\n\nFirst paragraph here.\n\n## Instructions\n\n- step\n", "First paragraph here."},
		{"only headings", "# n\n\n## Description\n\n## Instructions\n", ""},
		{"crlf", "# n\r\n\r\n## Description\r\n\r\nWindows line.\r\n", "Windows line."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveSkillImportDescription([]byte(tt.data)); got != tt.want {
				t.Fatalf("deriveSkillImportDescription() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeSkillNameBounds(t *testing.T) {
	long := ""
	for range 80 {
		long += "a"
	}
	if got := sanitizeSkillName(long); len(got) != 63 {
		t.Fatalf("expected 63-char name, got %d", len(got))
	}
	if got := sanitizeSkillName("---"); got != "" {
		t.Fatalf("expected empty name for dashes only, got %q", got)
	}
}
