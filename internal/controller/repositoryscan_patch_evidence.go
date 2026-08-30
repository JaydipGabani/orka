/*
Copyright (c) 2026.
MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/security"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/workerenv"
)

const (
	// repositoryScanPublishedCommitMaxFiles bounds the files a remediation
	// commit may touch; GitHub's commit endpoint returns at most 300 files.
	repositoryScanPublishedCommitMaxFiles    = 300
	repositoryScanForgeCredentialKey         = defaultACPWorkspaceCredentialKey
	repositoryScanArtifactStoreNotConfigured = "artifact store is not configured"
)

// verifyPatchTaskEvidence produces the patch diff and summary artifacts for a
// succeeded patch task. Two contracts are accepted:
//
//   - Artifact contract: both artifacts already exist in the artifact store
//     (written by a harness that uploads workspace artifacts) and verify
//     against each other.
//   - Harness-v2 result contract: the task's terminal result is an
//     identity-bound orka.security.patch.v1 envelope. The reviewable diff is
//     never taken from agent output; it is derived from the exact commit the
//     governed publication proved on the remote, fetched with the forge
//     credential, and the envelope's changedFiles must match it exactly. Both
//     artifacts are then persisted under the standard names so the API and
//     dashboard keep one contract.
func (r *RepositoryScanReconciler) verifyPatchTaskEvidence(
	ctx context.Context,
	scan *corev1alpha1.RepositoryScan,
	task *corev1alpha1.Task,
	findingID string,
	publication securityPatchPublicationReceipt,
) (patchVerificationResult, string, error) {
	if r.ArtifactStore == nil {
		return patchVerificationResult{}, repositoryScanArtifactStoreNotConfigured, nil
	}
	diffName, summaryName := patchArtifactNames(findingID)
	present, err := r.patchArtifactsPresent(ctx, task, diffName, summaryName)
	if err != nil {
		return patchVerificationResult{}, "", err
	}
	if present {
		return r.verifyPatchTaskArtifacts(ctx, scan, task, findingID)
	}

	result, validationProblem, err := r.loadAgentTaskResult(ctx, task)
	if err != nil {
		return patchVerificationResult{}, "", err
	}
	if validationProblem != "" {
		return patchVerificationResult{}, "patch artifacts are missing and the " + validationProblem, nil
	}
	summary, err := security.ParsePatchResult(result, security.PatchResultExpectation{RepositoryScan: scan.Name, FindingID: findingID})
	if err != nil {
		return patchVerificationResult{}, "patch terminal result is missing or invalid: " + err.Error(), nil
	}
	if publication.publication == nil || strings.TrimSpace(publication.publication.ExpectedCommitSHA) == "" {
		return patchVerificationResult{}, "verified patch publication commit is unavailable", nil
	}
	token, reason, err := r.repositoryScanForgeToken(ctx, scan)
	if err != nil || reason != "" {
		return patchVerificationResult{}, reason, err
	}
	targetRepo := security.CanonicalRepositoryCloneURL(scan.Spec.ForkRepo)
	if targetRepo == "" {
		targetRepo = security.CanonicalRepositoryCloneURL(scan.Spec.RepoURL)
	}
	owner, repository, err := security.ParseGitHubRepositoryURL(targetRepo)
	if err != nil {
		return patchVerificationResult{}, "repository scan publication target is not a canonical GitHub repository", nil
	}
	files, reason, err := r.fetchRepositoryScanPublishedCommit(ctx, owner, repository, publication.publication.ExpectedCommitSHA, token)
	if err != nil || reason != "" {
		return patchVerificationResult{}, reason, err
	}
	diff, commitPaths, reason := repositoryScanDiffFromPublishedCommit(files)
	if reason != "" {
		return patchVerificationResult{}, reason, nil
	}
	if _, err := repositoryMonitorPathsFromPatch(diff); err != nil {
		return patchVerificationResult{}, "published commit diff is not a canonical git diff: " + err.Error(), nil
	}
	if !sameStringSet(rootRelativePatchSummaryFiles(summary.ChangedFiles, scan), commitPaths) {
		return patchVerificationResult{}, "patch result changedFiles do not match the published commit", nil
	}
	summaryData, err := json.Marshal(summary)
	if err != nil {
		return patchVerificationResult{}, "", err
	}
	if err := r.ArtifactStore.SaveArtifact(ctx, task.Namespace, task.Name, diffName, "text/x-diff", []byte(diff)); err != nil {
		return patchVerificationResult{}, "", err
	}
	if err := r.ArtifactStore.SaveArtifact(ctx, task.Namespace, task.Name, summaryName, "application/json", summaryData); err != nil {
		return patchVerificationResult{}, "", err
	}
	return patchVerificationResult{diffArtifact: diffName, summaryArtifact: summaryName}, "", nil
}

func (r *RepositoryScanReconciler) patchArtifactsPresent(ctx context.Context, task *corev1alpha1.Task, names ...string) (bool, error) {
	for _, name := range names {
		if _, _, err := r.ArtifactStore.GetArtifact(ctx, task.Namespace, task.Name, name); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

// repositoryScanForgeToken reads the scan's forge credential. The token never
// leaves the controller: it authenticates the read of the published commit and
// is not persisted or logged.
func (r *RepositoryScanReconciler) repositoryScanForgeToken(ctx context.Context, scan *corev1alpha1.RepositoryScan) (string, string, error) {
	if scan.Spec.ForgeCredentialRef == nil || strings.TrimSpace(scan.Spec.ForgeCredentialRef.Name) == "" {
		return "", "spec.forgeCredentialRef is required to verify the published patch", nil
	}
	if r.Client == nil {
		return "", "forge credential client is not configured", nil
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: scan.Namespace, Name: strings.TrimSpace(scan.Spec.ForgeCredentialRef.Name)}
	if err := r.Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", "forge credential secret was not found", nil
		}
		return "", "", err
	}
	for _, name := range []string{repositoryScanForgeCredentialKey, "password", workerenv.GitHubToken} {
		if value := strings.TrimSpace(string(secret.Data[name])); value != "" {
			return value, "", nil
		}
	}
	return "", "forge credential secret carries no token", nil
}

type repositoryScanCommitFileResponse struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename"`
	Status           string `json:"status"`
	Patch            string `json:"patch"`
}

type repositoryScanCommitResponse struct {
	SHA   string                             `json:"sha"`
	Files []repositoryScanCommitFileResponse `json:"files"`
}

func (r *RepositoryScanReconciler) fetchRepositoryScanPublishedCommit(ctx context.Context, owner, repository, sha, token string) ([]repositoryScanCommitFileResponse, string, error) {
	if store.ValidateGitObjectID("published patch commit", sha) != nil {
		return nil, "verified patch publication commit is invalid", nil
	}
	baseURL := strings.TrimRight(r.GitHubAPIBaseURL, "/")
	if baseURL == "" {
		baseURL = repositoryMonitorDefaultGitHubAPIBaseURL
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/commits/%s", baseURL, url.PathEscape(owner), url.PathEscape(repository), url.PathEscape(sha))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	repositoryMonitorSetGitHubHeaders(req, token)
	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// The error text may carry the request URL; keep the persisted
		// reason class-only.
		return nil, "published patch commit could not be read from GitHub", nil
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := readRepositoryMonitorGitHubResponse(resp.Body, repositoryMonitorGitHubResponseLimit)
	if err != nil {
		return nil, "published patch commit response exceeded the read limit", nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Sprintf("published patch commit could not be read from GitHub (HTTP %d)", resp.StatusCode), nil
	}
	var commit repositoryScanCommitResponse
	if err := json.Unmarshal(body, &commit); err != nil {
		return nil, "published patch commit response is not valid JSON", nil
	}
	if !strings.EqualFold(strings.TrimSpace(commit.SHA), sha) {
		return nil, "published patch commit response does not match the verified commit", nil
	}
	if len(commit.Files) == 0 {
		return nil, "published patch commit contains no files", nil
	}
	if len(commit.Files) > repositoryScanPublishedCommitMaxFiles {
		return nil, "published patch commit exceeds the supported file count", nil
	}
	return commit.Files, "", nil
}

// repositoryScanDiffFromPublishedCommit renders the published commit's file
// patches as one canonical git diff. Renames, copies, and files without a
// textual patch (binary or oversized) cannot be reviewed as a patch and fail
// closed.
func repositoryScanDiffFromPublishedCommit(files []repositoryScanCommitFileResponse) (string, []string, string) {
	var diff strings.Builder
	paths := make([]string, 0, len(files))
	for _, file := range files {
		path := strings.TrimSpace(file.Filename)
		if path == "" || !security.SafeRepoPath(path) || strings.ContainsAny(path, " \"\\\t\r\n") {
			return "", nil, "published patch commit contains an unsafe file path"
		}
		if strings.TrimSpace(file.PreviousFilename) != "" && strings.TrimSpace(file.PreviousFilename) != path {
			return "", nil, "published patch commit renames or copies a file, which security patches do not support"
		}
		if strings.TrimSpace(file.Patch) == "" {
			return "", nil, "published patch commit contains a file without a text patch: " + path
		}
		fmt.Fprintf(&diff, "diff --git a/%s b/%s\n", path, path)
		switch strings.ToLower(strings.TrimSpace(file.Status)) {
		case "added":
			diff.WriteString("new file mode 100644\n")
			fmt.Fprintf(&diff, "--- /dev/null\n+++ b/%s\n", path)
		case "removed":
			diff.WriteString("deleted file mode 100644\n")
			fmt.Fprintf(&diff, "--- a/%s\n+++ /dev/null\n", path)
		case "modified", "changed", "":
			fmt.Fprintf(&diff, "--- a/%s\n+++ b/%s\n", path, path)
		default:
			return "", nil, "published patch commit contains an unsupported change: " + strings.TrimSpace(file.Status)
		}
		diff.WriteString(strings.TrimRight(file.Patch, "\n"))
		diff.WriteString("\n")
		paths = append(paths, path)
	}
	return diff.String(), paths, ""
}
