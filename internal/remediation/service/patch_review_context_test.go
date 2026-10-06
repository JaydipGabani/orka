package service

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

type contextReviewModels struct {
	t             *testing.T
	requests      []modelagent.Request
	tasks         map[string]modelagent.Result
	output        func(modelagent.Request) string
	afterAccepted func(modelagent.Request, modelagent.Result) error
}

type contextReviewModel struct {
	disclosureModelClient
	owner *contextReviewModels
}

func (m contextReviewModel) Generate(ctx context.Context, request modelagent.Request) (modelagent.Result, error) {
	m.owner.requests = append(m.owner.requests, request)
	if previous, found := m.owner.tasks[request.TaskName]; found {
		require.True(m.owner.t, request.RequireExisting)
		require.Equal(m.owner.t, previous.TaskUID, request.ExpectedTaskUID)
		return previous, nil
	}
	require.False(m.owner.t, request.RequireExisting)
	require.Empty(m.owner.t, request.ExpectedTaskUID)
	result := modelagent.Result{
		TaskName: request.TaskName, TaskUID: fmt.Sprintf("review-task-%d", len(m.owner.tasks)+1),
		Output: m.owner.output(request),
	}
	m.owner.tasks[request.TaskName] = result
	if err := m.accepted(ctx, result); err != nil {
		return result, err
	}
	if m.owner.afterAccepted != nil {
		return result, m.owner.afterAccepted(request, result)
	}
	return result, nil
}

func contextReviewJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return string(raw)
}

func contextReviewFile(name, content string) source.PacketFile {
	blob := sha1.Sum(fmt.Appendf(nil, "blob %d\x00%s", len(content), content))
	return source.PacketFile{
		Path: name, Content: content, BlobSHA: hex.EncodeToString(blob[:]),
		SHA256: strings.TrimPrefix(Digest([]byte(content)), "sha256:"),
	}
}

// This loopback Git API serves actual Git tree/blob identities, so the success
// path exercises Client.Inventory and Client.Packet rather than self-hash alone.
func contextReviewSource(t *testing.T, files []source.PacketFile) (source.Client, source.Target) {
	t.Helper()
	files = slices.Clone(files)
	slices.SortFunc(files, func(a, b source.PacketFile) int { return strings.Compare(a.Path, b.Path) })
	var tree []byte
	entries := make([]source.Entry, 0, len(files))
	replies := make(map[string]any)
	const prefix = "/repos/example/review-fixture"
	for _, file := range files {
		require.NotContains(t, file.Path, "/")
		tree = fmt.Appendf(tree, "100644 %s\x00", file.Path)
		identity, err := hex.DecodeString(file.BlobSHA)
		require.NoError(t, err)
		tree = append(tree, identity...)
		entries = append(entries, source.Entry{Path: file.Path, Mode: "100644", Size: int64(len(file.Content)), BlobSHA: file.BlobSHA})
		replies[prefix+"/git/blobs/"+file.BlobSHA] = map[string]any{
			"sha": file.BlobSHA, "encoding": "base64", "size": len(file.Content),
			"content": base64.StdEncoding.EncodeToString([]byte(file.Content)),
		}
	}
	treeID := sha1.Sum(append(fmt.Appendf(nil, "tree %d\x00", len(tree)), tree...))
	target := source.Target{
		Repository: source.Repository{URL: "https://github.com/example/review-fixture", Owner: "example", Name: "review-fixture", DefaultBranch: "main"},
		Ref:        "v1.0.0", Commit: strings.Repeat("c", 40), Tree: hex.EncodeToString(treeID[:]),
	}
	treeEntries := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		treeEntries = append(treeEntries, map[string]any{
			"path": entry.Path, "mode": entry.Mode, "size": entry.Size, "sha": entry.BlobSHA, "type": "blob",
		})
	}
	replies[prefix] = map[string]any{
		"full_name": "example/review-fixture", "html_url": target.Repository.URL,
		"default_branch": "main", "private": false, "visibility": "public", "archived": false,
		"owner": map[string]any{"login": "example"}, "name": "review-fixture",
	}
	replies[prefix+"/commits/"+target.Commit] = map[string]any{
		"sha": target.Commit, "commit": map[string]any{"tree": map[string]any{"sha": target.Tree}},
	}
	replies[prefix+"/git/trees/"+target.Tree] = map[string]any{"sha": target.Tree, "tree": treeEntries, "truncated": false}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
			http.Error(w, "unexpected authority", http.StatusForbidden)
			return
		}
		reply, found := replies[r.URL.Path]
		if !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(reply); err != nil {
			t.Errorf("write synthetic Git API reply: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return source.Client{APIBaseURL: server.URL, HTTPClient: server.Client()}, target
}

func TestPatchReviewContextResolvesMissingHelper(t *testing.T) {
	t.Parallel()
	base := contextReviewFile("dispatcher.go", "package dispatcher\nfunc owns(source, event string) bool {\n\treturn source == \"\" || resourceKey(source, \"\") == resourceKey(event, \"\")\n}\n")
	helper := contextReviewFile("identifier.go", "package dispatcher\nfunc resourceKey(namespace, name string) string {\n\treturn namespace + \"/\" + name\n}\n")
	client, target := contextReviewSource(t, []source.PacketFile{base, helper})
	packet, err := client.Packet(t.Context(), target, []string{base.Path})
	require.NoError(t, err)
	plan := investigate.Plan{Target: target, Packet: packet, Problem: "incident-instruction-not-for-independent-review"}
	patchText, err := remediation.CompilePatch(remediation.PatchProposal{Edits: []remediation.SourceEdit{{
		Path: base.Path, Old: `source == "" || `, New: "",
	}}}, map[string][]byte{base.Path: []byte(base.Content)})
	require.NoError(t, err)
	patch := []byte(patchText)
	checks := ExecutionPlan{Controller: &controllerlab.Plan{
		Version: 1, Capability: controllerlab.KEDAEventPublishing,
		Expected: controllerExpectedOutcomes(controllerlab.KEDAEventPublishing),
	}}
	checks.Binding.ChecksDigest = Digest([]byte("frozen-checks"))
	pipeline, session, state, policy, _, _ := disclosurePipelineFixture(t, `{}`)
	pipeline.Source = client
	models := &contextReviewModels{t: t, tasks: make(map[string]modelagent.Result)}
	models.output = func(request modelagent.Request) string {
		require.Empty(t, request.Repository)
		require.Empty(t, request.Commit)
		require.NotContains(t, request.Prompt, plan.Problem)
		require.NotContains(t, request.Prompt, "generator-rationale-not-for-independent-review")
		if strings.Contains(request.Prompt, "CONTEXT_SELECTION_DATA:\n") {
			var data struct {
				Index struct {
					Target  source.Target  `json:"target"`
					Entries []source.Entry `json:"entries"`
				} `json:"index"`
			}
			require.NoError(t, json.Unmarshal([]byte(strings.SplitN(request.Prompt, "CONTEXT_SELECTION_DATA:\n", 2)[1]), &data))
			require.Equal(t, target, data.Index.Target)
			require.True(t, slices.ContainsFunc(data.Index.Entries, func(entry source.Entry) bool {
				return entry.Path == helper.Path && entry.BlobSHA == helper.BlobSHA && entry.Mode == "100644"
			}))
			return `{"version":1,"paths":["identifier.go"]}`
		}
		var data struct {
			Source             source.Packet      `json:"source"`
			PatchDigest        string             `json:"patchDigest"`
			Patch              string             `json:"patch"`
			FrozenContract     controllerlab.Plan `json:"frozenContract"`
			SupplementalSource []source.Packet    `json:"supplementalSource"`
		}
		require.Contains(t, request.Prompt, "REVIEW_DATA:\n")
		require.NoError(t, json.Unmarshal([]byte(strings.SplitN(request.Prompt, "REVIEW_DATA:\n", 2)[1]), &data))
		require.Equal(t, packet, data.Source)
		require.Equal(t, patchText, data.Patch)
		require.Equal(t, Digest(patch), data.PatchDigest)
		require.Equal(t, *checks.Controller, data.FrozenContract)
		if len(data.SupplementalSource) == 0 {
			return contextReviewJSON(t, patchReviewDecision{
				Version: 1, PatchDigest: Digest(patch), Decision: "uncertain",
				Findings: []patchReviewFinding{{Path: base.Path, Code: "insufficient-context", Detail: "The resourceKey implementation is needed to assess namespace scope."}},
			})
		}
		require.Equal(t, []source.Packet{{Version: 1, Target: target, Files: []source.PacketFile{helper}}}, data.SupplementalSource)
		return contextReviewJSON(t, patchReviewDecision{Version: 1, PatchDigest: Digest(patch), Decision: "approve", Findings: []patchReviewFinding{}})
	}
	pipeline.Agents = func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
		return contextReviewModel{disclosureModelClient: disclosureModelClient{accepted: accepted}, owner: models}
	}
	proposal, err := pipeline.putJSON(t.Context(), session, "proposal", map[string]string{"summary": "generator-rationale-not-for-independent-review"})
	require.NoError(t, err)
	state.Attempts = []pipelineAttempt{{Proposal: proposal}}
	beforePlan, beforeChecks := contextReviewJSON(t, plan), contextReviewJSON(t, checks)
	beforeControl, beforeAttempts := contextReviewJSON(t, state.Control), contextReviewJSON(t, state.Attempts)
	review, err := pipeline.reviewCandidate(t.Context(), session, session.run, policy, plan, checks, state, patch)
	require.NoError(t, err)
	require.NotNil(t, review)
	require.Len(t, models.requests, 3, "uncertain review, bounded selection, then a review with new evidence")
	require.NotEqual(t, models.requests[0].TaskName, models.requests[2].TaskName)
	var evidence patchReviewEvidence
	require.NoError(t, readJSON(t.Context(), session, review, &evidence))
	require.Equal(t, "approve", evidence.Decision)
	require.Equal(t, target, evidence.Source)
	require.Equal(t, checks.Binding.ChecksDigest, evidence.ChecksDigest)
	require.Equal(t, Digest(patch), evidence.PatchDigest)
	require.Equal(t, models.requests[2].TaskName, evidence.TaskName)
	require.Equal(t, models.tasks[evidence.TaskName].TaskUID, evidence.TaskUID)
	require.Equal(t, beforePlan, contextReviewJSON(t, plan))
	require.Equal(t, beforeChecks, contextReviewJSON(t, checks))
	require.Equal(t, beforeControl, contextReviewJSON(t, state.Control))
	require.Equal(t, beforeAttempts, contextReviewJSON(t, state.Attempts))
	require.NoError(t, validateCandidatePaths(patchText, plan.Packet))
	require.ErrorIs(t, validateCandidatePaths("diff --git a/identifier.go b/identifier.go\n", plan.Packet), ErrNeedsInput)
	artifacts, err := session.store.ListRemediationArtifacts(t.Context(), session.run.Namespace, session.run.ID)
	require.NoError(t, err)
	var uncertain *store.RemediationArtifact
	for _, artifact := range artifacts {
		if strings.HasPrefix(artifact.Name, "patch-review-") {
			var receipt patchReviewEvidence
			require.NoError(t, readJSON(t.Context(), session, &artifact, &receipt))
			if receipt.Decision == "uncertain" {
				uncertain = &artifact
			}
		}
	}
	require.NotNil(t, uncertain, "the original uncertain review remains immutable evidence")
	current, err := session.Current(t.Context())
	require.NoError(t, err)
	var resumed pipelineState
	require.NoError(t, json.Unmarshal(current.StateJSON, &resumed))
	repeated, err := pipeline.reviewCandidate(t.Context(), session, current, policy, plan, checks, &resumed, patch)
	require.NoError(t, err)
	require.Equal(t, review, repeated)
	require.Len(t, models.requests, 3, "a restart must recover the exact approval, not shop for another verdict")
	require.Equal(t, 3, resumed.ModelCalls)
}
