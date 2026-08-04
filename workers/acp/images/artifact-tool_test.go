package main

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestValidatedURLAllowsPinnedGitHubReleaseRedirects(t *testing.T) {
	t.Parallel()
	accepted := []string{
		"https://github.com/github/copilot-cli/releases/download/v1.0.74/copilot-linux-x64.tar.gz",
		"https://release-assets.githubusercontent.com/github-production-release-asset/object?sig=ephemeral",
		"https://raw.githubusercontent.com/github/copilot-cli/commit/LICENSE.md",
	}
	for _, rawURL := range accepted {
		if _, err := validatedURL(rawURL); err != nil {
			t.Errorf("validatedURL(%q) error = %v", rawURL, err)
		}
	}

	rejected := []string{
		"http://github.com/github/copilot-cli/releases/download/v1.0.74/copilot-linux-x64.tar.gz",
		"https://github.com/github/copilot-cli/releases/download/v1.0.74/copilot-linux-x64.tar.gz?cache=bypass",
		"https://example.com/copilot.tar.gz",
		"https://github.com/other/project/releases/download/v1/artifact.tar.gz",
		"https://release-assets.githubusercontent.com/other/path?sig=ephemeral",
		"https://github.com/github/copilot-cli/releases/download/../../../../other/project/releases/download/v1/a",
		"https://github.com/github/copilot-cli/releases/download/%2e%2e/%2e%2e/a",
		"https://github.com/github/copilot-cli/releases/download/a%2Fb",
		"https://user@github.com/github/copilot-cli/releases/download/v1/copilot.tar.gz",
	}
	for _, rawURL := range rejected {
		if _, err := validatedURL(rawURL); err == nil {
			t.Errorf("validatedURL(%q) unexpectedly succeeded", rawURL)
		}
	}
}

func TestRedactDownloadErrorRemovesSignedQuery(t *testing.T) {
	t.Parallel()
	original := &url.Error{
		Op: "Get",
		URL: "https://release-assets.githubusercontent.com/github-production-release-asset/object" +
			"?alpha=opaque-marker&beta=opaque-marker",
		Err: errors.New(`failed to parse Location header "https://release-assets.githubusercontent.com/object` +
			`?alpha=opaque-marker"`),
	}
	redacted := redactDownloadError(original)
	message := redacted.Error()
	if strings.Contains(message, "alpha=") || strings.Contains(message, "beta=") ||
		strings.Contains(message, "opaque-marker") {
		t.Fatalf("redacted error exposed signed query: %q", message)
	}
	if !strings.Contains(message, "release-assets.githubusercontent.com/github-production-release-asset/object") ||
		!strings.Contains(message, "request failed") {
		t.Fatalf("redacted error lost safe diagnostics: %q", message)
	}
	if !strings.Contains(original.URL, "alpha=opaque-marker") {
		t.Fatal("redaction mutated the original url.Error")
	}
}
