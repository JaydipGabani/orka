package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

const (
	repositoryMonitorReviewContextTestPath   = "main.go"
	repositoryMonitorReviewContextTestPatch  = "@@ -1 +1,2 @@\n package main\n+// change"
	repositoryMonitorReviewContextTestStatus = "modified"
	repositoryMonitorReviewContextTestBase   = "base7"
	repositoryMonitorReviewContextTestHead   = "head7"
	repositoryMonitorReviewContextTestRepo   = "orka-agents/orka"
	repositoryMonitorReviewContextTestOwner  = "orka-agents"
	repositoryMonitorReviewContextTestName   = "orka"
)

func repositoryMonitorReviewContextTestPR() repositoryMonitorPullRequest {
	return repositoryMonitorPullRequest{Number: 7, BaseSHA: repositoryMonitorReviewContextTestBase, HeadSHA: repositoryMonitorReviewContextTestHead, HeadRepo: repositoryMonitorReviewContextTestRepo}
}

func repositoryMonitorReviewContextTestFile(name, patch string) repositoryMonitorPullRequestFileResponse {
	return repositoryMonitorPullRequestFileResponse{Filename: name, Status: repositoryMonitorReviewContextTestStatus, Additions: 1, Patch: patch}
}

func TestRepositoryMonitorReviewContextFromFilesRendersBoundedPayload(t *testing.T) {
	pr := repositoryMonitorReviewContextTestPR()
	files := []repositoryMonitorPullRequestFileResponse{
		{Filename: repositoryMonitorReviewContextTestPath, Status: repositoryMonitorReviewContextTestStatus, Additions: 1, Deletions: 0, Patch: repositoryMonitorReviewContextTestPatch},
		{Filename: "docs/new.md", PreviousFilename: "docs/old.md", Status: "renamed", Additions: 0, Deletions: 0},
		{Filename: "image.png", Status: "added", Additions: 0, Deletions: 0, Patch: ""},
	}
	got := repositoryMonitorReviewContextFromFiles(repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, pr, files)
	if got.SchemaVersion != repositoryMonitorReviewContextSchemaVersion || got.Repo != repositoryMonitorReviewContextTestRepo || got.PRNumber != 7 || got.BaseSHA != repositoryMonitorReviewContextTestBase || got.HeadSHA != repositoryMonitorReviewContextTestHead {
		t.Fatalf("context envelope = %#v, want schema/repo/pr/base/head", got)
	}
	if got.ChangedFileCount != 3 || len(got.Files) != 3 || got.Truncated.Files || got.Truncated.Bytes || got.ContextUnavailable != "" {
		t.Fatalf("context = %#v, want three files with no truncation", got)
	}
	if got.Files[0].Patch != repositoryMonitorReviewContextTestPatch || got.Files[0].PatchOmitted != "" {
		t.Fatalf("files[0] = %#v, want full patch", got.Files[0])
	}
	if got.Files[1].PreviousPath != "docs/old.md" || got.Files[1].PatchOmitted != repositoryMonitorReviewContextPatchUnavailable || got.Files[1].Patch != "" {
		t.Fatalf("files[1] = %#v, want previousPath and unavailable patch marker", got.Files[1])
	}
	if got.Files[2].PatchOmitted != repositoryMonitorReviewContextPatchUnavailable {
		t.Fatalf("files[2] = %#v, want unavailable patch marker for binary file", got.Files[2])
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, want := range []string{`"schemaVersion":"orka.prReview.context.v1"`, `"changedFileCount":3`, `"truncated":{"files":false,"bytes":false}`, `"patchOmitted":"unavailable"`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("encoded context %s does not contain %s", encoded, want)
		}
	}
	if strings.Contains(string(encoded), "contextUnavailable") {
		t.Fatalf("encoded context %s should omit contextUnavailable when GitHub answered", encoded)
	}
}

func TestRepositoryMonitorReviewContextFromFilesCapsFileCount(t *testing.T) {
	files := make([]repositoryMonitorPullRequestFileResponse, 0, repositoryMonitorReviewContextMaxFiles+25)
	for i := range cap(files) {
		files = append(files, repositoryMonitorReviewContextTestFile(fmt.Sprintf("pkg/file%03d.go", i), repositoryMonitorReviewContextTestPatch))
	}
	got := repositoryMonitorReviewContextFromFiles(repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, repositoryMonitorReviewContextTestPR(), files)
	if got.ChangedFileCount != repositoryMonitorReviewContextMaxFiles+25 {
		t.Fatalf("changedFileCount = %d, want the GitHub total", got.ChangedFileCount)
	}
	if len(got.Files) != repositoryMonitorReviewContextMaxFiles || !got.Truncated.Files || got.Truncated.Bytes {
		t.Fatalf("files = %d truncated = %#v, want %d files with files truncation only", len(got.Files), got.Truncated, repositoryMonitorReviewContextMaxFiles)
	}
	if got.Files[0].Path != "pkg/file000.go" || got.Files[len(got.Files)-1].Path != "pkg/file099.go" {
		t.Fatalf("files kept = %s..%s, want the first %d in GitHub order", got.Files[0].Path, got.Files[len(got.Files)-1].Path, repositoryMonitorReviewContextMaxFiles)
	}
}

func TestRepositoryMonitorReviewContextTruncatesPatchOnLineBoundary(t *testing.T) {
	var builder strings.Builder
	builder.WriteString("@@ -1,2000 +1,2000 @@\n")
	for i := 0; builder.Len() < repositoryMonitorReviewContextMaxPatchBytes+8192; i++ {
		fmt.Fprintf(&builder, "+line %04d %s\n", i, strings.Repeat("x", 90))
	}
	patch := builder.String()
	got := repositoryMonitorReviewContextFromFiles(repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, repositoryMonitorReviewContextTestPR(), []repositoryMonitorPullRequestFileResponse{repositoryMonitorReviewContextTestFile(repositoryMonitorReviewContextTestPath, patch)})
	if len(got.Files) != 1 || got.Files[0].PatchOmitted != repositoryMonitorReviewContextPatchTruncated {
		t.Fatalf("files = %#v, want one entry marked truncated", got.Files)
	}
	kept := got.Files[0].Patch
	if kept == "" || !strings.HasPrefix(patch, kept) {
		t.Fatalf("kept patch is not a prefix of the original patch")
	}
	if strings.HasSuffix(kept, "\n") || patch[len(kept)] != '\n' {
		t.Fatalf("kept patch does not end on a line boundary: tail %q", kept[max(len(kept)-40, 0):])
	}
	encoded, _ := json.Marshal(kept)
	if len(encoded) > repositoryMonitorReviewContextMaxPatchBytes {
		t.Fatalf("encoded patch = %d bytes, want <= %d", len(encoded), repositoryMonitorReviewContextMaxPatchBytes)
	}
	if got.Truncated.Bytes || got.Truncated.Files {
		t.Fatalf("truncated = %#v, want per-patch truncation not to flip payload flags", got.Truncated)
	}
}

func TestRepositoryMonitorReviewContextFromFilesCapsTotalBytes(t *testing.T) {
	bigPatch := "@@ -1,5 +1,5 @@\n" + strings.Repeat("+"+strings.Repeat("y", 118)+"\n", 480) // ~57 KiB
	files := make([]repositoryMonitorPullRequestFileResponse, 0, repositoryMonitorReviewContextMaxFiles)
	for i := range cap(files) {
		files = append(files, repositoryMonitorReviewContextTestFile(fmt.Sprintf("pkg/big%03d.go", i), bigPatch))
	}
	got := repositoryMonitorReviewContextFromFiles(repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, repositoryMonitorReviewContextTestPR(), files)
	encoded, err := json.MarshalIndent(got, "", repositoryMonitorReviewContextIndent)
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	if len(encoded) > repositoryMonitorReviewContextMaxBytes {
		t.Fatalf("encoded context = %d bytes, want <= %d", len(encoded), repositoryMonitorReviewContextMaxBytes)
	}
	if !got.Truncated.Bytes {
		t.Fatalf("truncated = %#v, want bytes truncation", got.Truncated)
	}
	withPatch, withoutPatch := 0, 0
	for i, file := range got.Files {
		switch {
		case file.Patch != "":
			if withoutPatch != 0 {
				t.Fatalf("files[%d] carries a patch after patches were dropped", i)
			}
			withPatch++
		case file.PatchOmitted == repositoryMonitorReviewContextPatchTruncated:
			withoutPatch++
		default:
			t.Fatalf("files[%d] = %#v, want patch or truncated marker", i, file)
		}
	}
	if withPatch < 10 || withoutPatch == 0 {
		t.Fatalf("files with patch = %d, without = %d, want patches dropped only after the budget filled", withPatch, withoutPatch)
	}
	if got.Truncated.Files && len(got.Files) == repositoryMonitorReviewContextMaxFiles {
		t.Fatalf("truncated.files is set although all %d files were kept", len(got.Files))
	}
	if !got.Truncated.Files && len(got.Files) != repositoryMonitorReviewContextMaxFiles {
		t.Fatalf("files = %d without truncated.files, want %d or the flag", len(got.Files), repositoryMonitorReviewContextMaxFiles)
	}
}

func TestRepositoryMonitorReviewContextFromFilesDropsFilesWhenMetadataExceedsBudget(t *testing.T) {
	longPath := strings.Repeat("d", repositoryMonitorReviewContextMaxPathBytes+200) + "/" + strings.Repeat("f", 100)
	files := make([]repositoryMonitorPullRequestFileResponse, 0, repositoryMonitorReviewContextMaxFiles)
	for i := range cap(files) {
		// Each entry keeps a maximal patch so the budget is exhausted by patches first, then metadata.
		files = append(files, repositoryMonitorReviewContextTestFile(fmt.Sprintf("%03d-%s", i, longPath), "@@ -1 +1 @@\n"+strings.Repeat("+"+strings.Repeat("z", 1000)+"\n", 70)))
	}
	got := repositoryMonitorReviewContextFromFiles(repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, repositoryMonitorReviewContextTestPR(), files)
	encoded, _ := json.MarshalIndent(got, "", repositoryMonitorReviewContextIndent)
	if len(encoded) > repositoryMonitorReviewContextMaxBytes {
		t.Fatalf("encoded context = %d bytes, want <= %d", len(encoded), repositoryMonitorReviewContextMaxBytes)
	}
	for i, file := range got.Files {
		if len(file.Path) > repositoryMonitorReviewContextMaxPathBytes {
			t.Fatalf("files[%d].path = %d bytes, want <= %d", i, len(file.Path), repositoryMonitorReviewContextMaxPathBytes)
		}
	}
	if !got.Truncated.Bytes {
		t.Fatalf("truncated = %#v, want bytes truncation", got.Truncated)
	}
}

func TestRepositoryMonitorReviewContextSanitizesUntrustedText(t *testing.T) {
	file := repositoryMonitorPullRequestFileResponse{
		Filename: "a\x00b\x1b[31m.go\n",
		Status:   "mod\x07ified" + strings.Repeat("s", 64),
		Patch:    "@@ -1 +1 @@\n-\x00old\r\n+\x1b[0mnew\tvalue\xff\n",
	}
	got := repositoryMonitorReviewContextFromFiles(repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, repositoryMonitorReviewContextTestPR(), []repositoryMonitorPullRequestFileResponse{file})
	if len(got.Files) != 1 {
		t.Fatalf("files = %#v, want one entry", got.Files)
	}
	entry := got.Files[0]
	if entry.Path != "ab[31m.go" {
		t.Fatalf("path = %q, want control characters stripped", entry.Path)
	}
	if strings.ContainsAny(entry.Status, "\x07") || len(entry.Status) > repositoryMonitorReviewContextMaxStatusBytes {
		t.Fatalf("status = %q, want sanitized and bounded to %d bytes", entry.Status, repositoryMonitorReviewContextMaxStatusBytes)
	}
	if entry.Patch != "@@ -1 +1 @@\n-old\n+[0mnew\tvalue\n" {
		t.Fatalf("patch = %q, want NUL/escape/CR/invalid UTF-8 stripped and newline/tab kept", entry.Patch)
	}
}

func TestRepositoryMonitorReviewContextErrorClassNeverLeaksDetails(t *testing.T) {
	secretURL := "upstream detail placeholder-credential github.example must not leak"
	cases := map[string]struct {
		err  error
		want string
	}{
		"api status":  {err: &repositoryMonitorGitHubAPIError{Operation: "pull request files request", StatusCode: http.StatusForbidden, Body: secretURL}, want: "github_api_status_403"},
		"wrapped api": {err: fmt.Errorf("wrap: %w", &repositoryMonitorGitHubAPIError{StatusCode: http.StatusInternalServerError}), want: "github_api_status_500"},
		"deadline":    {err: fmt.Errorf("request: %w", context.DeadlineExceeded), want: repositoryMonitorReviewContextErrorTimeout},
		"json":        {err: fmt.Errorf("parse: %w", &json.SyntaxError{Offset: 1}), want: repositoryMonitorReviewContextErrorInvalidPayload},
		"plain error": {err: errors.New(secretURL), want: repositoryMonitorReviewContextErrorRequestFailed},
		"nil":         {err: nil, want: ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := repositoryMonitorReviewContextErrorClass(tc.err)
			if got != tc.want {
				t.Fatalf("errorClass = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "placeholder-credential") || strings.Contains(got, "github.example") {
				t.Fatalf("errorClass %q leaks error details", got)
			}
		})
	}
}

func TestRepositoryMonitorBuildReviewContextMarksUnavailableOnGitHubError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"message":"upstream https://token@example.invalid"}`))
	}))
	t.Cleanup(server.Close)
	reconciler := &RepositoryMonitorReconciler{GitHubAPIBaseURL: server.URL}
	pr := repositoryMonitorReviewContextTestPR()
	got, err := reconciler.buildRepositoryMonitorReviewContext(context.Background(), repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, "token", pr)
	if err != nil {
		t.Fatalf("buildRepositoryMonitorReviewContext() error = %v, want nil so the review still runs", err)
	}
	if got.ContextUnavailable != "github_api_status_502" || len(got.Files) != 0 || got.ChangedFileCount != 0 {
		t.Fatalf("context = %#v, want contextUnavailable github_api_status_502 with no files", got)
	}
	if got.SchemaVersion != repositoryMonitorReviewContextSchemaVersion || got.HeadSHA != repositoryMonitorReviewContextTestHead || got.BaseSHA != repositoryMonitorReviewContextTestBase {
		t.Fatalf("context envelope = %#v, want schema and SHAs preserved", got)
	}
	rendered := renderRepositoryMonitorReviewContext(got)
	if strings.Contains(rendered, "example.invalid") || strings.Contains(rendered, "token@") {
		t.Fatalf("rendered context leaks GitHub error details:\n%s", rendered)
	}
	if !strings.Contains(rendered, `"contextUnavailable": "github_api_status_502"`) || !strings.Contains(rendered, `"files": []`) {
		t.Fatalf("rendered context = %s, want contextUnavailable and empty files array", rendered)
	}
}

func TestRepositoryMonitorBuildReviewContextMarksUnavailableOnNetworkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	reconciler := &RepositoryMonitorReconciler{GitHubAPIBaseURL: server.URL}
	got, err := reconciler.buildRepositoryMonitorReviewContext(context.Background(), repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, "", repositoryMonitorReviewContextTestPR())
	if err != nil {
		t.Fatalf("buildRepositoryMonitorReviewContext() error = %v, want nil", err)
	}
	if got.ContextUnavailable != repositoryMonitorReviewContextErrorNetwork {
		t.Fatalf("contextUnavailable = %q, want %q", got.ContextUnavailable, repositoryMonitorReviewContextErrorNetwork)
	}
}

func TestRepositoryMonitorBuildReviewContextFailsClosedOnHeadDrift(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/orka-agents/orka/pulls/7/files":
			_, _ = w.Write([]byte(`[{"filename":"main.go","status":"modified","additions":1,"deletions":0,"patch":"@@ -1 +1 @@\n-a\n+b"}]`))
		case "/repos/orka-agents/orka/pulls/7":
			_, _ = w.Write([]byte(`{"number":7,"state":"open","base":{"ref":"main","sha":"base7","repo":{"full_name":"orka-agents/orka"}},"head":{"ref":"feature","sha":"head7-moved","repo":{"full_name":"orka-agents/orka"}}}`))
		default:
			t.Errorf("unexpected GitHub request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	reconciler := &RepositoryMonitorReconciler{GitHubAPIBaseURL: server.URL}
	_, err := reconciler.buildRepositoryMonitorReviewContext(context.Background(), repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, "token", repositoryMonitorReviewContextTestPR())
	var driftErr *repositoryMonitorReviewContextDriftError
	if !errors.As(err, &driftErr) || driftErr.Field != "head SHA" || driftErr.Got != "head7-moved" {
		t.Fatalf("buildRepositoryMonitorReviewContext() error = %v, want head SHA drift error", err)
	}
}

func TestRepositoryMonitorBuildReviewContextUsesPatchesWhenHeadIsStable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		switch r.URL.Path {
		case "/repos/orka-agents/orka/pulls/7/files":
			_, _ = w.Write([]byte(`[{"filename":"main.go","status":"modified","additions":1,"deletions":1,"patch":"@@ -1 +1 @@\n-a\n+b"},{"filename":"logo.png","status":"added","additions":0,"deletions":0}]`))
		case "/repos/orka-agents/orka/pulls/7":
			_, _ = w.Write([]byte(`{"number":7,"state":"open","base":{"ref":"main","sha":"base7","repo":{"full_name":"orka-agents/orka"}},"head":{"ref":"feature","sha":"head7","repo":{"full_name":"orka-agents/orka"}}}`))
		default:
			t.Errorf("unexpected GitHub request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	reconciler := &RepositoryMonitorReconciler{GitHubAPIBaseURL: server.URL}
	got, err := reconciler.buildRepositoryMonitorReviewContext(context.Background(), repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, "token", repositoryMonitorReviewContextTestPR())
	if err != nil {
		t.Fatalf("buildRepositoryMonitorReviewContext() error = %v", err)
	}
	if got.ContextUnavailable != "" || got.ChangedFileCount != 2 || len(got.Files) != 2 {
		t.Fatalf("context = %#v, want two files and no unavailable marker", got)
	}
	if got.Files[0].Patch != "@@ -1 +1 @@\n-a\n+b" || got.Files[0].Deletions != 1 || got.Files[1].PatchOmitted != repositoryMonitorReviewContextPatchUnavailable {
		t.Fatalf("files = %#v, want patch for main.go and unavailable marker for logo.png", got.Files)
	}
}

func TestRepositoryMonitorReviewPromptWithoutContextStripsOnlyTheContextBlock(t *testing.T) {
	pr := repositoryMonitorReviewContextTestPR()
	monitor := repositoryMonitorInventoryTestMonitor()
	full := buildRepositoryMonitorReviewPrompt(monitor, repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, pr, repositoryMonitorReviewContextFromFiles(repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, pr, []repositoryMonitorPullRequestFileResponse{repositoryMonitorReviewContextTestFile(repositoryMonitorReviewContextTestPath, repositoryMonitorReviewContextTestPatch)}))
	unavailable := newRepositoryMonitorReviewContext(repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, pr)
	unavailable.ContextUnavailable = repositoryMonitorReviewContextErrorNetwork
	degraded := buildRepositoryMonitorReviewPrompt(monitor, repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, pr, unavailable)
	if full == degraded {
		t.Fatalf("prompts with different contexts should differ")
	}
	if repositoryMonitorReviewPromptWithoutContext(full) != repositoryMonitorReviewPromptWithoutContext(degraded) {
		t.Fatalf("prompts without the context block should match:\n%s\n---\n%s", repositoryMonitorReviewPromptWithoutContext(full), repositoryMonitorReviewPromptWithoutContext(degraded))
	}
	stripped := repositoryMonitorReviewPromptWithoutContext(full)
	if strings.Contains(stripped, repositoryMonitorReviewContextTestPatch) || !strings.Contains(stripped, `"schemaVersion": "orka.prReview.input.v1"`) || !strings.Contains(stripped, `"schemaVersion": "orka.prReview.v1"`) {
		t.Fatalf("stripped prompt should drop the context but keep the input/output contracts:\n%s", stripped)
	}
	if repositoryMonitorReviewPromptWithoutContext("spoofed review result") != "spoofed review result" {
		t.Fatalf("prompts without a context block must be returned unchanged")
	}
}

func TestRepositoryMonitorReviewPromptStaysUnderBudgetWithMaximalContext(t *testing.T) {
	bigPatch := "@@ -1,5 +1,5 @@\n" + strings.Repeat("+"+strings.Repeat("w", 118)+"\n", 600)
	files := make([]repositoryMonitorPullRequestFileResponse, 0, repositoryMonitorReviewContextMaxFiles*2)
	for i := range cap(files) {
		files = append(files, repositoryMonitorReviewContextTestFile(fmt.Sprintf("pkg/%03d/%s.go", i, strings.Repeat("n", 200)), bigPatch))
	}
	pr := repositoryMonitorReviewContextTestPR()
	prompt := buildRepositoryMonitorReviewPrompt(repositoryMonitorInventoryTestMonitor(), repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, pr, repositoryMonitorReviewContextFromFiles(repositoryMonitorReviewContextTestOwner, repositoryMonitorReviewContextTestName, pr, files))
	if len(prompt) > repositoryMonitorReviewContextMaxBytes+16<<10 {
		t.Fatalf("prompt = %d bytes, want context budget plus a small fixed prompt", len(prompt))
	}
	if !strings.Contains(prompt, `"truncated": {`) || !strings.Contains(prompt, `"files": true`) {
		t.Fatalf("prompt should mark file truncation:\n%s", prompt[:512])
	}
}

func repositoryMonitorInventoryTestMonitor() *corev1alpha1.RepositoryMonitor {
	monitor, _ := repositoryMonitorInventoryTestObjects("review-context")
	return monitor
}
