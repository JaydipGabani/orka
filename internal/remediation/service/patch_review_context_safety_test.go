package service

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

type reviewContextSourceSpy struct {
	investigate.Source
	target                                   source.Target
	inventoryCalls, packetCalls, resolutions int
	inventory                                func([]source.Entry) ([]source.Entry, error)
	packet                                   func(source.Packet) (source.Packet, error)
}

func (s *reviewContextSourceSpy) Resolve(context.Context, string, string) (source.Target, error) {
	s.resolutions++
	return source.Target{}, ErrInvalid
}

func (s *reviewContextSourceSpy) Inventory(ctx context.Context, target source.Target) ([]source.Entry, error) {
	s.inventoryCalls++
	if target != s.target {
		return nil, ErrInvalid
	}
	entries, err := s.Source.Inventory(ctx, target)
	if err == nil && s.inventory != nil {
		return s.inventory(entries)
	}
	return entries, err
}

func (s *reviewContextSourceSpy) Packet(ctx context.Context, target source.Target, paths []string) (source.Packet, error) {
	s.packetCalls++
	if target != s.target {
		return source.Packet{}, ErrInvalid
	}
	packet, err := s.Source.Packet(ctx, target, paths)
	if err == nil && s.packet != nil {
		return s.packet(packet)
	}
	return packet, err
}

type reviewContextFixture struct {
	t        *testing.T
	pipeline *Pipeline
	session  *Session
	state    *pipelineState
	policy   Policy
	source   *reviewContextSourceSpy
	plan     investigate.Plan
	checks   ExecutionPlan
	patch    []byte
	models   *contextReviewModels
	selectFn func(modelagent.Request) string
	reviewFn func(patchReviewInput) patchReviewDecision
}

func newReviewContextFixture(t *testing.T, extra ...source.PacketFile) *reviewContextFixture {
	t.Helper()
	pipeline, session, state, policy, _, _ := disclosurePipelineFixture(t, `{}`)
	base := contextReviewFile("dispatcher.go", "package dispatcher\nfunc owns(a, b string) bool { return resourceKey(a) == resourceKey(b) }\n")
	files := []source.PacketFile{base, contextReviewFile("identifier.go", "package dispatcher\nfunc resourceKey(namespace string) string { return namespace }\n")}
	for _, file := range extra {
		i := slices.IndexFunc(files, func(existing source.PacketFile) bool { return existing.Path == file.Path })
		if i < 0 {
			files = append(files, file)
		} else {
			files[i] = file
		}
	}
	client, target := contextReviewSource(t, files)
	f := &reviewContextFixture{
		t: t, pipeline: pipeline, session: session, state: state, policy: policy,
		source: &reviewContextSourceSpy{Source: client, target: target},
		plan:   investigate.Plan{Target: target, Packet: source.Packet{Version: 1, Target: target, Files: []source.PacketFile{base}}},
		checks: ExecutionPlan{Controller: &controllerlab.Plan{
			Version: 1, Capability: controllerlab.KEDAEventPublishing, Expected: controllerExpectedOutcomes(controllerlab.KEDAEventPublishing),
		}},
		patch: []byte("diff --git a/dispatcher.go b/dispatcher.go\n--- a/dispatcher.go\n+++ b/dispatcher.go\n@@ -1,2 +1,2 @@\n package dispatcher\n-func owns(a, b string) bool { return resourceKey(a) == resourceKey(b) }\n+func owns(a, b string) bool { return a != \"\" && resourceKey(a) == resourceKey(b) }\n"),
	}
	f.checks.Binding.ChecksDigest = Digest([]byte("frozen-checks"))
	f.selectFn = func(modelagent.Request) string { return `{"version":1,"paths":["identifier.go"]}` }
	f.reviewFn = func(input patchReviewInput) patchReviewDecision {
		if len(input.SupplementalSource) == 0 {
			return contextReviewUncertain(input)
		}
		return patchReviewDecision{Version: 1, PatchDigest: input.PatchDigest, Decision: "approve", Findings: []patchReviewFinding{}}
	}
	f.models = &contextReviewModels{t: t, tasks: make(map[string]modelagent.Result)}
	f.models.output = func(request modelagent.Request) string {
		require.Empty(t, request.Repository)
		require.Empty(t, request.Commit)
		if strings.Contains(request.Prompt, "CONTEXT_SELECTION_DATA:\n") {
			return f.selectFn(request)
		}
		var input patchReviewInput
		parts := strings.SplitN(request.Prompt, "REVIEW_DATA:\n", 2)
		require.Len(t, parts, 2)
		require.NoError(t, decodeObject([]byte(parts[1]), 256<<10, &input))
		return contextReviewJSON(t, f.reviewFn(input))
	}
	pipeline.Source = f.source
	pipeline.Agents = func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
		return contextReviewModel{disclosureModelClient: disclosureModelClient{accepted: accepted}, owner: f.models}
	}
	return f
}

func contextReviewUncertain(input patchReviewInput) patchReviewDecision {
	return patchReviewDecision{
		Version: 1, PatchDigest: input.PatchDigest, Decision: "uncertain",
		Findings: []patchReviewFinding{{Path: "dispatcher.go", Code: "insufficient-context", Detail: "Need the called helper implementation."}},
	}
}

func (f *reviewContextFixture) run(ctx context.Context) (*store.RemediationArtifact, error) {
	return f.pipeline.reviewCandidate(ctx, f.session, f.session.run, f.policy, f.plan, f.checks, f.state, f.patch)
}

func (f *reviewContextFixture) resume() {
	f.t.Helper()
	current, err := f.session.Current(f.t.Context())
	require.NoError(f.t, err)
	var resumed pipelineState
	require.NoError(f.t, json.Unmarshal(current.StateJSON, &resumed))
	f.state = &resumed
}

func TestPatchReviewContextReceiptBindsAllInputs(t *testing.T) {
	t.Parallel()
	f := newReviewContextFixture(t)
	ref, err := f.run(t.Context())
	require.NoError(t, err)
	var evidence patchReviewEvidence
	require.NoError(t, readJSON(t.Context(), f.session, ref, &evidence))
	record := f.state.PatchReviews[Digest(f.patch)]
	require.Equal(t, record.Review, evidence.PreviousReview)
	require.Equal(t, ref, record.Context[0].Review)
	require.Equal(t, Digest([]byte(contextReviewJSON(t, f.plan.Packet))), evidence.BasePacketDigest)
	require.Equal(t, f.checks.Binding.ChecksDigest, evidence.ChecksDigest)
	require.Equal(t, f.plan.Target, evidence.Source)
	require.Equal(t, Digest(f.patch), evidence.PatchDigest)
	require.Equal(t, f.state.ModelIdentity.Digest, evidence.ModelIdentity)
	require.Len(t, evidence.SupplementalSource, 1)
	var added source.Packet
	require.NoError(t, readJSON(t.Context(), f.session, evidence.SupplementalSource[0], &added))
	require.Equal(t, f.plan.Target, added.Target)
	require.Equal(t, "identifier.go", added.Files[0].Path)
	require.Equal(t, Digest([]byte(contextReviewJSON(t, added))), evidence.SupplementalSource[0].Digest)
	require.Equal(t, f.session.run.ID+"-patch-review-"+strings.TrimPrefix(evidence.ContextDigest, "sha256:"), evidence.TaskName)
	require.Equal(t, f.models.tasks[evidence.TaskName].TaskUID, evidence.TaskUID)
	require.Equal(t, evidence.ContextDigest, Digest([]byte(contextReviewJSON(t, struct {
		InputDigest string   `json:"inputDigest"`
		Packets     []string `json:"packets"`
	}{record.InputDigest, []string{evidence.SupplementalSource[0].Digest}}))))
	var original patchReviewEvidence
	require.NoError(t, readJSON(t.Context(), f.session, record.Review, &original))
	require.Equal(t, "uncertain", original.Decision)
	require.Empty(t, original.ContextDigest)
	require.Nil(t, original.PreviousReview)
}

func TestPatchReviewContextRequiresOnlyInsufficientContext(t *testing.T) {
	for _, verdict := range []string{"approve", "reject", "uncertain", "mixed", "malformed", "wrong-patch"} {
		t.Run(verdict, func(t *testing.T) {
			t.Parallel()
			f := newReviewContextFixture(t)
			f.reviewFn = func(input patchReviewInput) patchReviewDecision {
				decision := contextReviewUncertain(input)
				switch verdict {
				case "approve":
					decision.Decision, decision.Findings = "approve", []patchReviewFinding{}
				case "reject":
					decision.Decision = "reject"
				case "uncertain":
					decision.Findings[0].Code = "fixture-tampering"
				case "mixed":
					decision.Findings = append(decision.Findings, patchReviewFinding{Code: "unrelated-credential-access", Detail: "Integrity concern."})
				case "malformed":
					decision.Findings[0].Code = "unknown-code"
				case "wrong-patch":
					decision.PatchDigest = Digest([]byte("another patch"))
				}
				return decision
			}
			ref, err := f.run(t.Context())
			if verdict == "approve" {
				require.NoError(t, err)
				require.NotNil(t, ref)
			} else {
				require.ErrorIs(t, err, ErrNeedsInput)
			}
			require.Zero(t, f.source.inventoryCalls)
			require.Zero(t, f.source.packetCalls)
			require.Len(t, f.models.requests, 1)
			f.resume()
			_, repeated := f.run(t.Context())
			if verdict != "approve" {
				require.ErrorIs(t, repeated, ErrNeedsInput)
			}
			require.Len(t, f.models.requests, 1)
			require.Empty(t, f.state.Attempts)
		})
	}
}

func TestPatchReviewContextInvalidSelectionsStopWithoutFetching(t *testing.T) {
	for _, selection := range []string{
		`{"version":1,"paths":[]}`,
		`{"version":1,"paths":null}`,
		`{"version":2,"paths":["identifier.go"]}`,
		`{"version":1,"paths":["identifier.go"],"paths":[]}`,
		`{"version":1,"paths":["identifier.go"],"repository":"https://github.com/other/project"}`,
		`{"version":1,"paths":["identifier.go"],"commit":"other"}`,
		`{"version":1,"paths":["identifier.go"],"shell":"read a file"}`,
		`{"version":1,"paths":["identifier.go","missing.go"]}`,
		`{"version":1,"paths":["dispatcher.go","identifier.go"]}`,
		`{"version":1,"paths":["identifier.go","identifier.go"]}`,
		`{"version":1,"paths":["../identifier.go"]}`,
		`{"version":1,"paths":["/identifier.go"]}`,
		`{"version":1,"paths":["https://github.com/example/review-fixture/identifier.go"]}`,
		`{"version":1,"paths":["settings.json"]}`,
	} {
		t.Run(selection, func(t *testing.T) {
			t.Parallel()
			f := newReviewContextFixture(t, contextReviewFile("settings.json", "{}\n"))
			f.selectFn = func(modelagent.Request) string { return selection }
			ref, err := f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.NotNil(t, ref)
			require.Equal(t, 1, f.source.inventoryCalls)
			require.Zero(t, f.source.packetCalls, "do not silently discard a required invalid path and fetch the rest")
			require.Len(t, f.models.requests, 2)
			record := f.state.PatchReviews[Digest(f.patch)]
			require.NotEmpty(t, record.StopReason)
			require.Empty(t, record.Context[0].Paths)
			f.resume()
			_, err = f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.Len(t, f.models.requests, 2)
			require.Equal(t, 1, f.source.inventoryCalls)
		})
	}
}

func TestPatchReviewContextRejectsUnverifiedPacket(t *testing.T) {
	for _, fault := range []string{"target", "commit", "tree", "path", "missing-file", "extra-file", "blob", "digest", "membership", "size"} {
		t.Run(fault, func(t *testing.T) {
			t.Parallel()
			f := newReviewContextFixture(t)
			f.source.packet = func(packet source.Packet) (source.Packet, error) {
				switch fault {
				case "target":
					packet.Target.Repository.Name = "different-project"
				case "commit":
					packet.Target.Commit = strings.Repeat("d", 40)
				case "tree":
					packet.Target.Tree = strings.Repeat("d", 40)
				case "path":
					packet.Files[0].Path = "outside.go"
				case "missing-file":
					packet.Files = nil
				case "extra-file":
					packet.Files = append(packet.Files, contextReviewFile("outside.go", "package outside\n"))
				case "blob":
					packet.Files[0].BlobSHA = strings.Repeat("e", 40)
				case "digest":
					packet.Files[0].SHA256 = strings.Repeat("e", 64)
				case "membership":
					packet.Files[0] = contextReviewFile("identifier.go", "package dispatcher\n// valid self-digests, but not the indexed Git blob\n")
				case "size":
					packet.Files[0].Content += "\n"
				}
				return packet, nil
			}
			ref, err := f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.NotNil(t, ref)
			require.Equal(t, 1, f.source.packetCalls)
			require.Len(t, f.models.requests, 2, "unverified bytes must never reach the augmented reviewer")
			require.NotEmpty(t, f.state.PatchReviews[Digest(f.patch)].StopReason)
			f.resume()
			_, err = f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.Equal(t, 1, f.source.packetCalls)
			require.Len(t, f.models.requests, 2)
		})
	}
}

func TestPatchReviewContextRejectsWrongInventoryModesAndIdentity(t *testing.T) {
	for _, fault := range []string{"symlink", "gitlink", "blob", "size", "duplicate", "base-blob", "empty"} {
		t.Run(fault, func(t *testing.T) {
			t.Parallel()
			f := newReviewContextFixture(t)
			f.source.inventory = func(entries []source.Entry) ([]source.Entry, error) {
				i := slices.IndexFunc(entries, func(entry source.Entry) bool { return entry.Path == "identifier.go" })
				switch fault {
				case "symlink":
					entries[i].Mode = "120000"
				case "gitlink":
					entries[i].Mode = "160000"
				case "blob":
					entries[i].BlobSHA = strings.Repeat("d", 40)
				case "size":
					entries[i].Size = 1
				case "duplicate":
					entries = append(entries, entries[i])
				case "base-blob":
					entries[0].BlobSHA = strings.Repeat("d", 40)
				case "empty":
					return nil, nil
				}
				return entries, nil
			}
			_, err := f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.LessOrEqual(t, len(f.models.requests), 2)
			require.NotEmpty(t, f.state.PatchReviews[Digest(f.patch)].StopReason)
		})
	}
}

func TestPatchReviewContextPreservesSourceAndCheckBindings(t *testing.T) {
	for _, fault := range []string{"plan-target", "base-packet", "checks-digest", "contract", "patch", "packet-artifact", "index-artifact"} {
		t.Run(fault, func(t *testing.T) {
			t.Parallel()
			f := newReviewContextFixture(t)
			ref, err := f.run(t.Context())
			require.NoError(t, err)
			f.resume()
			switch fault {
			case "plan-target":
				f.plan.Target.Commit = strings.Repeat("d", 40)
			case "base-packet":
				f.plan.Packet.Files[0] = contextReviewFile("dispatcher.go", "package dispatcher\n// changed base bytes\n")
			case "checks-digest":
				f.checks.Binding.ChecksDigest = Digest([]byte("other checks"))
			case "contract":
				f.checks.Controller.Version++
			case "patch":
				f.patch = append(f.patch, '\n')
				f.reviewFn = func(input patchReviewInput) patchReviewDecision {
					decision := contextReviewUncertain(input)
					decision.PatchDigest = strings.TrimPrefix(f.models.requests[0].TaskName, f.session.run.ID+"-patch-review-")
					decision.PatchDigest = "sha256:" + decision.PatchDigest
					return decision
				}
			case "packet-artifact":
				f.state.PatchReviews[Digest(f.patch)].Context[0].Packet.Digest = Digest([]byte("other packet"))
			case "index-artifact":
				f.state.PatchReviews[Digest(f.patch)].Context[0].Index.Digest = Digest([]byte("other index"))
			}
			again, err := f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.NotEqual(t, ref, again, "changed inputs cannot reuse the successful receipt")
			require.Equal(t, 1, f.source.inventoryCalls)
			require.Equal(t, 1, f.source.packetCalls)
			if fault == "patch" {
				require.Len(t, f.models.requests, 4, "a different patch has a different initial review, never the old approval")
				require.NotEqual(t, f.models.requests[2].TaskName, f.models.requests[3].TaskName)
			} else {
				require.Len(t, f.models.requests, 3)
			}
		})
	}
}

func TestPatchReviewContextEncodedPacketBoundary(t *testing.T) {
	for _, delta := range []int{-1, 0, 1} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			t.Parallel()
			f := newReviewContextFixture(t)
			seed := contextReviewFile("identifier.go", "package dispatcher\n//\n")
			packet := source.Packet{Version: 1, Target: f.plan.Target, Files: []source.PacketFile{seed}}
			size := len(contextReviewJSON(t, []source.Packet{packet}))
			helper := contextReviewFile(seed.Path, strings.TrimSuffix(seed.Content, "\n")+strings.Repeat("x", maxReviewContextBytes+delta-size)+"\n")
			client, target := contextReviewSource(t, []source.PacketFile{f.plan.Packet.Files[0], helper})
			f.source.Source, f.source.target = client, target
			f.plan.Target, f.plan.Packet.Target = target, target
			packet.Target, packet.Files[0] = target, helper
			require.Len(t, contextReviewJSON(t, []source.Packet{packet}), maxReviewContextBytes+delta)
			_, err := f.run(t.Context())
			if delta > 0 {
				require.ErrorIs(t, err, ErrNeedsInput)
				require.Len(t, f.models.requests, 2)
			} else {
				require.NoError(t, err)
				require.Len(t, f.models.requests, 3)
			}
		})
	}
}

func TestPatchReviewContextEncodedEscapingAndDisclosure(t *testing.T) {
	for _, content := range []string{
		"package dispatcher\n//" + strings.Repeat("<", 12000) + "\n",
		"package dispatcher\n// https://example.invalid/source?token=example-value\n",
	} {
		t.Run(fmt.Sprint(len(content)), func(t *testing.T) {
			t.Parallel()
			f := newReviewContextFixture(t, contextReviewFile("identifier.go", content))
			require.Less(t, len(content), maxReviewContextBytes)
			_, err := f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.Len(t, f.models.requests, 2)
			for _, request := range f.models.requests {
				require.NotContains(t, request.Prompt, content)
			}
			record := f.state.PatchReviews[Digest(f.patch)]
			require.NotEmpty(t, record.StopReason)
			require.Nil(t, record.Context[0].Packet, "blocked source is not persisted as a usable packet")
		})
	}
}

func TestPatchReviewContextIndexIsPrioritizedFilteredAndExplicitlyTruncated(t *testing.T) {
	t.Parallel()
	f := newReviewContextFixture(t)
	base := contextReviewFile("pkg/dispatch/dispatcher.go", "package dispatcher\n")
	packet := source.Packet{Version: 1, Target: f.plan.Target, Files: []source.PacketFile{base}}
	entry := func(file source.PacketFile) source.Entry {
		return source.Entry{Path: file.Path, Mode: "100644", Size: int64(len(file.Content)), BlobSHA: file.BlobSHA}
	}
	entries := make([]source.Entry, 0, 1514)
	entries = append(entries, entry(base))
	for i := range 1500 {
		entries = append(entries, entry(contextReviewFile(fmt.Sprintf("aaa/other/%04d&helper.go", i), "package helper\n")))
	}
	entries = append(entries, entry(contextReviewFile("pkg/dispatch/identifier.go", "package dispatcher\n")))
	for _, name := range []string{"vendor/helper.go", "third_party/helper.go", "node_modules/helper.js", ".hidden/helper.go", "build/helper.go",
		"config/helper.go", "secret.go", "credentials.go", "setup.py", "Dockerfile", "go.mod", "settings.yaml"} {
		entries = append(entries, entry(contextReviewFile(name, "package blocked\n")))
		require.False(t, reviewContextSourcePath(name), name)
	}
	index, err := boundedReviewContextIndex(f.plan.Target, []source.Packet{packet}, entries)
	require.NoError(t, err)
	require.True(t, index.Truncated)
	require.Equal(t, 1501, index.EligibleFiles)
	require.Equal(t, "pkg/dispatch/identifier.go", index.Entries[0].Path)
	require.True(t, strings.HasPrefix(index.Entries[1].Path, "aaa/other/"), "broader eligible source remains available after local neighbors")
	require.LessOrEqual(t, len(contextReviewJSON(t, index)), maxReviewIndexBytes)
	for _, offered := range index.Entries {
		require.True(t, reviewContextSourcePath(offered.Path))
		require.NotEqual(t, base.Path, offered.Path)
	}
	slices.Reverse(entries)
	again, err := boundedReviewContextIndex(f.plan.Target, []source.Packet{packet}, entries)
	require.NoError(t, err)
	require.Equal(t, index, again, "source API ordering must not change a frozen selection prompt")
}

func TestPatchReviewContextBoundsStopUncertaintyWithoutRepair(t *testing.T) {
	for _, scenario := range []string{"rounds", "no-new-context", "files", "combined-bytes", "model-selection", "model-review", "no-source"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			extra := []source.PacketFile{
				contextReviewFile("formatter.go", "package dispatcher\nfunc format() {}\n"),
				contextReviewFile("other.go", "package dispatcher\nfunc other() {}\n"),
				contextReviewFile("fourth.go", "package dispatcher\nfunc fourth() {}\n"),
			}
			if scenario == "combined-bytes" {
				extra[0] = contextReviewFile("formatter.go", "package dispatcher\n//"+strings.Repeat("x", 33<<10)+"\n")
				extra = append(extra, contextReviewFile("identifier.go", "package dispatcher\n//"+strings.Repeat("y", 33<<10)+"\n"))
			}
			f := newReviewContextFixture(t, extra...)
			f.reviewFn = contextReviewUncertain
			selections := 0
			f.selectFn = func(modelagent.Request) string {
				selections++
				if scenario == "files" {
					return `{"version":1,"paths":["identifier.go","formatter.go","other.go","fourth.go"]}`
				}
				if selections == 1 || scenario == "no-new-context" {
					return `{"version":1,"paths":["identifier.go"]}`
				}
				return `{"version":1,"paths":["formatter.go"]}`
			}
			if scenario == "model-selection" {
				f.policy.MaxModelCalls = 1
			}
			if scenario == "model-review" {
				f.policy.MaxModelCalls = 2
			}
			if scenario == "no-source" {
				f.pipeline.Source = nil
			}
			ref, err := f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.NotNil(t, ref)
			_, repairable := rejected(err)
			require.False(t, repairable)
			require.Empty(t, f.state.Attempts)
			require.LessOrEqual(t, f.state.ModelCalls, f.policy.MaxModelCalls)
			switch scenario {
			case "rounds":
				require.Len(t, f.models.requests, 5)
				require.Equal(t, 2, f.source.packetCalls)
			case "no-new-context", "combined-bytes":
				require.Len(t, f.models.requests, 4)
				require.Equal(t, 1, f.source.packetCalls)
			case "files":
				require.Len(t, f.models.requests, 3)
				require.Equal(t, 1, f.source.packetCalls)
			case "model-selection":
				require.Len(t, f.models.requests, 1)
				require.Zero(t, f.source.packetCalls)
			case "model-review":
				require.Len(t, f.models.requests, 2)
				require.Equal(t, 1, f.source.packetCalls)
			case "no-source":
				require.Len(t, f.models.requests, 1)
				require.Zero(t, f.source.inventoryCalls)
			}
			requests, inventories, packets := len(f.models.requests), f.source.inventoryCalls, f.source.packetCalls
			f.resume()
			_, err = f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.Len(t, f.models.requests, requests)
			require.Equal(t, inventories, f.source.inventoryCalls)
			require.Equal(t, packets, f.source.packetCalls)
			require.Zero(t, f.source.resolutions)
		})
	}
}

func TestPatchReviewContextRoundBudgetSurvivesCandidateRepair(t *testing.T) {
	t.Parallel()
	f := newReviewContextFixture(t, contextReviewFile("formatter.go", "package dispatcher\nfunc format() {}\n"))
	selections := 0
	f.selectFn = func(modelagent.Request) string {
		selections++
		if selections == 1 {
			return `{"version":1,"paths":["identifier.go"]}`
		}
		return `{"version":1,"paths":["formatter.go"]}`
	}
	f.reviewFn = func(input patchReviewInput) patchReviewDecision {
		decision := contextReviewUncertain(input)
		if len(input.SupplementalSource) != 0 && selections == 1 {
			decision.Decision = "reject"
			decision.Findings[0].Code = "behavior-regression"
		}
		return decision
	}
	review, err := f.run(t.Context())
	rejection, ok := rejected(err)
	require.True(t, ok)
	require.Equal(t, "candidate-independent-review-rejected", rejection.Code)
	f.resume()
	repeated, err := f.run(t.Context())
	_, ok = rejected(err)
	require.True(t, ok)
	require.Equal(t, review, repeated)
	require.Len(t, f.models.requests, 3)
	f.patch = append(f.patch, '\n')
	_, err = f.run(t.Context())
	require.ErrorIs(t, err, ErrNeedsInput)
	require.Len(t, f.models.requests, 6)
	rounds, files, _, err := reviewContextUsage(f.state, nil)
	require.NoError(t, err)
	require.Equal(t, 2, rounds)
	require.Equal(t, 2, files)
	require.Equal(t, 2, f.source.packetCalls)
}

func TestPatchReviewContextSecondRoundAddsEvidenceWithoutChangingAuthority(t *testing.T) {
	t.Parallel()
	f := newReviewContextFixture(t, contextReviewFile("formatter.go", "package dispatcher\nfunc format() {}\n"))
	selections := 0
	f.selectFn = func(modelagent.Request) string {
		selections++
		if selections == 1 {
			return `{"version":1,"paths":["identifier.go"]}`
		}
		return `{"version":1,"paths":["formatter.go"]}`
	}
	f.reviewFn = func(input patchReviewInput) patchReviewDecision {
		if len(input.SupplementalSource) < 2 {
			return contextReviewUncertain(input)
		}
		require.Equal(t, f.plan.Packet, input.Source)
		require.Equal(t, string(f.patch), input.Patch)
		require.Equal(t, *f.checks.Controller, input.FrozenContract)
		require.Equal(t, "identifier.go", input.SupplementalSource[0].Files[0].Path)
		require.Equal(t, "formatter.go", input.SupplementalSource[1].Files[0].Path)
		return patchReviewDecision{Version: 1, PatchDigest: input.PatchDigest, Decision: "approve", Findings: []patchReviewFinding{}}
	}
	ref, err := f.run(t.Context())
	require.NoError(t, err)
	require.Len(t, f.models.requests, 5)
	var receipt patchReviewEvidence
	require.NoError(t, readJSON(t.Context(), f.session, ref, &receipt))
	require.Len(t, receipt.SupplementalSource, 2)
	record := f.state.PatchReviews[Digest(f.patch)]
	require.Equal(t, record.Context[0].Review, receipt.PreviousReview)
	require.NotEqual(t, record.Review.Digest, receipt.PreviousReview.Digest)
	require.Equal(t, ref, record.Context[1].Review)
	f.resume()
	again, err := f.run(t.Context())
	require.NoError(t, err)
	require.Equal(t, ref, again)
	require.Len(t, f.models.requests, 5)
	require.Equal(t, 2, f.source.inventoryCalls)
	require.Equal(t, 2, f.source.packetCalls)
}

func TestPatchReviewContextFileCountBoundary(t *testing.T) {
	for _, count := range []int{3, 4, 5} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			t.Parallel()
			var extra []source.PacketFile
			paths := []string{"identifier.go"}
			for i := 1; i < count; i++ {
				name := fmt.Sprintf("helper%d.go", i)
				extra = append(extra, contextReviewFile(name, "package dispatcher\n"))
				paths = append(paths, name)
			}
			f := newReviewContextFixture(t, extra...)
			f.selectFn = func(modelagent.Request) string {
				return contextReviewJSON(t, patchReviewContextSelection{Version: 1, Paths: paths})
			}
			_, err := f.run(t.Context())
			if count > maxReviewContextFiles {
				require.ErrorIs(t, err, ErrNeedsInput)
				require.Zero(t, f.source.packetCalls)
				require.Len(t, f.models.requests, 2)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, f.source.packetCalls)
				require.Len(t, f.models.requests, 3)
			}
		})
	}
}

func TestPatchReviewContextAugmentedIntegrityAndMalformedVerdictsStop(t *testing.T) {
	for _, fault := range []string{"integrity", "malformed", "wrong-patch", "mixed-uncertainty"} {
		t.Run(fault, func(t *testing.T) {
			t.Parallel()
			f := newReviewContextFixture(t)
			f.reviewFn = func(input patchReviewInput) patchReviewDecision {
				decision := contextReviewUncertain(input)
				if len(input.SupplementalSource) != 0 {
					switch fault {
					case "integrity":
						decision.Decision, decision.Findings[0].Code = "reject", "fixture-tampering"
						decision.Findings[0].Path = "identifier.go"
					case "malformed":
						decision.Decision = "approve"
					case "wrong-patch":
						decision.PatchDigest = Digest([]byte("changed candidate"))
					case "mixed-uncertainty":
						decision.Findings = append(decision.Findings, patchReviewFinding{Code: "behavior-regression", Detail: "Not just missing context."})
					}
				}
				return decision
			}
			ref, err := f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.NotNil(t, ref, "retain the last valid review even if the augmented output is malformed")
			_, repairable := rejected(err)
			require.False(t, repairable)
			require.Len(t, f.models.requests, 3)
			f.resume()
			_, err = f.run(t.Context())
			require.ErrorIs(t, err, ErrNeedsInput)
			require.Len(t, f.models.requests, 3)
			require.Equal(t, 1, f.source.inventoryCalls)
			require.Equal(t, 1, f.source.packetCalls)
		})
	}
}

func TestPatchReviewContextCancellationAndDeadline(t *testing.T) {
	for _, stage := range []string{"before-review", "inventory", "packet", "deadline"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			f := newReviewContextFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			expected := context.Canceled
			switch stage {
			case "before-review":
				cancel()
			case "inventory":
				f.source.inventory = func(entries []source.Entry) ([]source.Entry, error) { cancel(); return entries, nil }
			case "packet":
				f.source.packet = func(packet source.Packet) (source.Packet, error) { cancel(); return packet, nil }
			case "deadline":
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				defer stop()
				expected = context.DeadlineExceeded
			}
			_, err := f.run(ctx)
			require.ErrorIs(t, err, expected)
			if stage == "before-review" || stage == "deadline" {
				require.Empty(t, f.models.requests)
				require.Zero(t, f.source.inventoryCalls)
			} else {
				require.LessOrEqual(t, len(f.models.requests), 2)
			}
		})
	}
}
