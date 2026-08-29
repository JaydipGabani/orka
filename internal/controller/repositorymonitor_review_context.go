package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Review context bounds. The encoded orka.prReview.context.v1 payload is
// embedded in Task.spec.prompt, so the total budget must stay well below the
// etcd object size limit (~1.5 MiB) together with the rest of the prompt and
// the Task object; 700 KiB leaves that margin while matching the documented
// contract in website/docs/guides/repository-monitors.md.
const (
	repositoryMonitorReviewContextSchemaVersion    = "orka.prReview.context.v1"
	repositoryMonitorReviewContextMaxFiles         = 100
	repositoryMonitorReviewContextMaxBytes         = 700 << 10
	repositoryMonitorReviewContextMaxPatchBytes    = 64 << 10
	repositoryMonitorReviewContextMaxPathBytes     = 512
	repositoryMonitorReviewContextMaxStatusBytes   = 32
	repositoryMonitorReviewContextPatchTruncated   = "truncated"
	repositoryMonitorReviewContextPatchUnavailable = "unavailable"
	repositoryMonitorReviewContextBeginMarker      = "--- BEGIN orka.prReview.context.v1 ---"
	repositoryMonitorReviewContextEndMarker        = "--- END orka.prReview.context.v1 ---"

	repositoryMonitorReviewContextErrorGitHubStatus   = "github_api_status_"
	repositoryMonitorReviewContextErrorTimeout        = "timeout"
	repositoryMonitorReviewContextErrorNetwork        = "network_error"
	repositoryMonitorReviewContextErrorInvalidPayload = "invalid_response"
	repositoryMonitorReviewContextErrorRequestFailed  = "request_failed"

	// repositoryMonitorReviewContextArrayItemPrefix mirrors the indentation
	// json.MarshalIndent("", "  ") applies to elements of the top-level
	// "files" array so per-file size accounting matches the final encoding.
	repositoryMonitorReviewContextArrayItemPrefix = "    "
	repositoryMonitorReviewContextIndent          = "  "
)

type repositoryMonitorReviewContextFile struct {
	Path         string `json:"path"`
	PreviousPath string `json:"previousPath,omitempty"`
	Status       string `json:"status"`
	Additions    int    `json:"additions"`
	Deletions    int    `json:"deletions"`
	Patch        string `json:"patch,omitempty"`
	PatchOmitted string `json:"patchOmitted,omitempty"`
}

type repositoryMonitorReviewContextTruncation struct {
	Files bool `json:"files"`
	Bytes bool `json:"bytes"`
}

type repositoryMonitorReviewContext struct {
	SchemaVersion      string                                   `json:"schemaVersion"`
	Repo               string                                   `json:"repo"`
	PRNumber           int64                                    `json:"prNumber"`
	BaseSHA            string                                   `json:"baseSHA"`
	HeadSHA            string                                   `json:"headSHA"`
	ChangedFileCount   int                                      `json:"changedFileCount"`
	Files              []repositoryMonitorReviewContextFile     `json:"files"`
	Truncated          repositoryMonitorReviewContextTruncation `json:"truncated"`
	ContextUnavailable string                                   `json:"contextUnavailable,omitempty"`
}

// repositoryMonitorReviewContextDriftError reports that the pull request base,
// head, or head repository changed while the review context was assembled.
type repositoryMonitorReviewContextDriftError struct {
	Number int64
	Field  string
	Want   string
	Got    string
}

func (e *repositoryMonitorReviewContextDriftError) Error() string {
	return fmt.Sprintf("pull request #%d %s changed during review context assembly: want %q, got %q", e.Number, e.Field, e.Want, e.Got)
}

func newRepositoryMonitorReviewContext(owner, repository string, pr repositoryMonitorPullRequest) repositoryMonitorReviewContext {
	return repositoryMonitorReviewContext{
		SchemaVersion: repositoryMonitorReviewContextSchemaVersion,
		Repo:          owner + "/" + repository,
		PRNumber:      pr.Number,
		BaseSHA:       pr.BaseSHA,
		HeadSHA:       pr.HeadSHA,
		Files:         []repositoryMonitorReviewContextFile{},
	}
}

// buildRepositoryMonitorReviewContext fetches the pull request file list with
// patches, then refetches the pull request and fails closed when the base,
// head, or head repository drifted. GitHub read failures do not fail the
// review: the returned context is marked unavailable with a sanitized error
// class only, so the reviewer inspects the checked-out tree instead.
func (r *RepositoryMonitorReconciler) buildRepositoryMonitorReviewContext(ctx context.Context, owner, repository, token string, pr repositoryMonitorPullRequest) (repositoryMonitorReviewContext, error) {
	logger := log.FromContext(ctx).WithName("repositorymonitor")
	files, err := r.listRepositoryMonitorPullRequestFiles(ctx, owner, repository, token, pr.Number)
	if err != nil {
		reviewContext := newRepositoryMonitorReviewContext(owner, repository, pr)
		reviewContext.ContextUnavailable = repositoryMonitorReviewContextErrorClass(err)
		logger.Info("pull request review context unavailable", "pr", pr.Number, "operation", "list_files", "errorClass", reviewContext.ContextUnavailable)
		return reviewContext, nil
	}
	current, err := r.fetchRepositoryMonitorPullRequest(ctx, owner, repository, token, pr.Number)
	if err != nil {
		reviewContext := newRepositoryMonitorReviewContext(owner, repository, pr)
		reviewContext.ContextUnavailable = repositoryMonitorReviewContextErrorClass(err)
		logger.Info("pull request review context unavailable", "pr", pr.Number, "operation", "refetch_pull_request", "errorClass", reviewContext.ContextUnavailable)
		return reviewContext, nil
	}
	if driftErr := repositoryMonitorReviewContextDrift(pr, *current); driftErr != nil {
		return repositoryMonitorReviewContext{}, driftErr
	}
	return repositoryMonitorReviewContextFromFiles(owner, repository, pr, files), nil
}

func repositoryMonitorReviewContextDrift(expected, current repositoryMonitorPullRequest) error {
	checks := []struct {
		field     string
		want, got string
	}{
		{field: "head SHA", want: expected.HeadSHA, got: current.HeadSHA},
		{field: "base SHA", want: expected.BaseSHA, got: current.BaseSHA},
		{field: "head repository", want: expected.HeadRepo, got: current.HeadRepo},
	}
	for _, check := range checks {
		if strings.TrimSpace(check.want) != strings.TrimSpace(check.got) {
			return &repositoryMonitorReviewContextDriftError{Number: expected.Number, Field: check.field, Want: check.want, Got: check.got}
		}
	}
	return nil
}

// repositoryMonitorReviewContextErrorClass reduces a GitHub read failure to a
// short class label. It never includes the error text, which may carry
// request URLs or response bodies.
func repositoryMonitorReviewContextErrorClass(err error) string {
	var apiErr *repositoryMonitorGitHubAPIError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &apiErr):
		return fmt.Sprintf("%s%d", repositoryMonitorReviewContextErrorGitHubStatus, apiErr.StatusCode)
	case errors.Is(err, context.DeadlineExceeded):
		return repositoryMonitorReviewContextErrorTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return repositoryMonitorReviewContextErrorTimeout
	}
	if _, ok := errors.AsType[*url.Error](err); ok {
		return repositoryMonitorReviewContextErrorNetwork
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		return repositoryMonitorReviewContextErrorInvalidPayload
	}
	return repositoryMonitorReviewContextErrorRequestFailed
}

// repositoryMonitorReviewContextFromFiles renders the bounded context payload:
// at most repositoryMonitorReviewContextMaxFiles files, at most
// repositoryMonitorReviewContextMaxPatchBytes encoded patch per file, and at
// most repositoryMonitorReviewContextMaxBytes encoded payload overall. When
// the byte budget is exhausted, remaining patches are dropped first and then
// remaining files, with the matching truncated flags set.
func repositoryMonitorReviewContextFromFiles(owner, repository string, pr repositoryMonitorPullRequest, files []repositoryMonitorPullRequestFileResponse) repositoryMonitorReviewContext {
	reviewContext := newRepositoryMonitorReviewContext(owner, repository, pr)
	reviewContext.ChangedFileCount = len(files)
	if len(files) > repositoryMonitorReviewContextMaxFiles {
		files = files[:repositoryMonitorReviewContextMaxFiles]
		reviewContext.Truncated.Files = true
	}

	used := repositoryMonitorReviewContextEncodedSize(reviewContext)
	patchesAllowed := true
	for _, file := range files {
		entry := repositoryMonitorReviewContextFileEntry(file)
		if !patchesAllowed {
			entry = repositoryMonitorReviewContextDropPatch(entry)
		}
		entrySize := repositoryMonitorReviewContextEntrySize(entry, len(reviewContext.Files))
		if used+entrySize > repositoryMonitorReviewContextMaxBytes && entry.Patch != "" {
			patchesAllowed = false
			reviewContext.Truncated.Bytes = true
			entry = repositoryMonitorReviewContextDropPatch(entry)
			entrySize = repositoryMonitorReviewContextEntrySize(entry, len(reviewContext.Files))
		}
		if used+entrySize > repositoryMonitorReviewContextMaxBytes {
			reviewContext.Truncated.Files = true
			reviewContext.Truncated.Bytes = true
			break
		}
		reviewContext.Files = append(reviewContext.Files, entry)
		used += entrySize
	}
	// The truncated flags flip after entries were sized, and the envelope is an
	// estimate; verify the final encoding and trim conservatively if needed.
	for repositoryMonitorReviewContextEncodedSize(reviewContext) > repositoryMonitorReviewContextMaxBytes && len(reviewContext.Files) > 0 {
		last := len(reviewContext.Files) - 1
		reviewContext.Truncated.Bytes = true
		if reviewContext.Files[last].Patch != "" {
			reviewContext.Files[last] = repositoryMonitorReviewContextDropPatch(reviewContext.Files[last])
			continue
		}
		reviewContext.Files = reviewContext.Files[:last]
		reviewContext.Truncated.Files = true
	}
	return reviewContext
}

func repositoryMonitorReviewContextFileEntry(file repositoryMonitorPullRequestFileResponse) repositoryMonitorReviewContextFile {
	entry := repositoryMonitorReviewContextFile{
		Path:         repositoryMonitorReviewContextBoundedField(file.Filename, repositoryMonitorReviewContextMaxPathBytes),
		PreviousPath: repositoryMonitorReviewContextBoundedField(file.PreviousFilename, repositoryMonitorReviewContextMaxPathBytes),
		Status:       repositoryMonitorReviewContextBoundedField(file.Status, repositoryMonitorReviewContextMaxStatusBytes),
		Additions:    max(file.Additions, 0),
		Deletions:    max(file.Deletions, 0),
	}
	patch := repositoryMonitorReviewContextSanitize(file.Patch)
	if patch == "" {
		entry.PatchOmitted = repositoryMonitorReviewContextPatchUnavailable
		return entry
	}
	entry.Patch, entry.PatchOmitted = repositoryMonitorReviewContextTruncatePatch(patch, repositoryMonitorReviewContextMaxPatchBytes)
	return entry
}

func repositoryMonitorReviewContextDropPatch(entry repositoryMonitorReviewContextFile) repositoryMonitorReviewContextFile {
	if entry.Patch == "" {
		return entry
	}
	entry.Patch = ""
	entry.PatchOmitted = repositoryMonitorReviewContextPatchTruncated
	return entry
}

// repositoryMonitorReviewContextTruncatePatch keeps whole lines of patch so
// that the JSON-encoded string fits within maxEncodedBytes. It returns the
// omission marker when anything was cut.
func repositoryMonitorReviewContextTruncatePatch(patch string, maxEncodedBytes int) (string, string) {
	if repositoryMonitorReviewContextEncodedStringSize(patch) <= maxEncodedBytes {
		return patch, ""
	}
	candidate := patch
	if len(candidate) > maxEncodedBytes {
		candidate = candidate[:maxEncodedBytes]
	}
	for {
		cut := strings.LastIndexByte(candidate, '\n')
		if cut < 0 {
			return "", repositoryMonitorReviewContextPatchTruncated
		}
		candidate = candidate[:cut]
		if repositoryMonitorReviewContextEncodedStringSize(candidate) <= maxEncodedBytes {
			return candidate, repositoryMonitorReviewContextPatchTruncated
		}
	}
}

func repositoryMonitorReviewContextBoundedField(value string, maxBytes int) string {
	value = strings.TrimSpace(repositoryMonitorReviewContextSanitize(value))
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\n", " "), "\t", " ")
	if len(value) <= maxBytes {
		return value
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

// repositoryMonitorReviewContextSanitize drops invalid UTF-8 and control
// characters other than newline and tab so GitHub-supplied text cannot carry
// terminal escapes or NUL bytes into the prompt.
func repositoryMonitorReviewContextSanitize(value string) string {
	value = strings.ToValidUTF8(value, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, value)
}

func repositoryMonitorReviewContextEncodedSize(reviewContext repositoryMonitorReviewContext) int {
	encoded, err := json.MarshalIndent(reviewContext, "", repositoryMonitorReviewContextIndent)
	if err != nil {
		return repositoryMonitorReviewContextMaxBytes + 1
	}
	return len(encoded)
}

func repositoryMonitorReviewContextEncodedStringSize(value string) int {
	encoded, err := json.Marshal(value)
	if err != nil {
		return len(value) + 2
	}
	return len(encoded)
}

// repositoryMonitorReviewContextEntrySize estimates the bytes one file entry
// adds to the indented payload, including the array separator and the
// per-element indentation applied by json.MarshalIndent.
func repositoryMonitorReviewContextEntrySize(entry repositoryMonitorReviewContextFile, existingEntries int) int {
	encoded, err := json.MarshalIndent(entry, repositoryMonitorReviewContextArrayItemPrefix, repositoryMonitorReviewContextIndent)
	if err != nil {
		return repositoryMonitorReviewContextMaxBytes + 1
	}
	// "[]" becomes "[\n    {...}\n  ]" for the first element; later elements add ",\n    ".
	overhead := len(",\n") + len(repositoryMonitorReviewContextArrayItemPrefix)
	if existingEntries == 0 {
		overhead = len("\n") + len(repositoryMonitorReviewContextArrayItemPrefix) + len("\n") + len(repositoryMonitorReviewContextIndent)
	}
	return len(encoded) + overhead
}

func renderRepositoryMonitorReviewContext(reviewContext repositoryMonitorReviewContext) string {
	if reviewContext.Files == nil {
		reviewContext.Files = []repositoryMonitorReviewContextFile{}
	}
	encoded, err := json.MarshalIndent(reviewContext, "", repositoryMonitorReviewContextIndent)
	if err != nil {
		fallback := newRepositoryMonitorReviewContext("", "", repositoryMonitorPullRequest{})
		fallback.Repo = reviewContext.Repo
		fallback.PRNumber = reviewContext.PRNumber
		fallback.BaseSHA = reviewContext.BaseSHA
		fallback.HeadSHA = reviewContext.HeadSHA
		fallback.ContextUnavailable = repositoryMonitorReviewContextErrorInvalidPayload
		encoded, _ = json.MarshalIndent(fallback, "", repositoryMonitorReviewContextIndent)
	}
	return repositoryMonitorReviewContextBeginMarker + "\n" + string(encoded) + "\n" + repositoryMonitorReviewContextEndMarker
}

// repositoryMonitorReviewPromptWithoutContext strips the embedded context
// block so an existing review Task can be compared against a freshly built
// one even when GitHub returned different (or no) diff context.
func repositoryMonitorReviewPromptWithoutContext(prompt string) string {
	start := strings.Index(prompt, repositoryMonitorReviewContextBeginMarker)
	if start < 0 {
		return prompt
	}
	_, after, found := strings.Cut(prompt[start:], repositoryMonitorReviewContextEndMarker)
	if !found {
		return prompt
	}
	return prompt[:start] + after
}
