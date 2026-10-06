package service

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

type pipelineSource struct{ target source.Target }

func (s pipelineSource) Resolve(_ context.Context, repository, ref string) (source.Target, error) {
	if repository != s.target.Repository.URL || ref != s.target.Ref {
		return source.Target{}, ErrInvalid
	}
	return s.target, nil
}

func (s pipelineSource) Inventory(context.Context, source.Target) ([]source.Entry, error) {
	file := sourceFile()
	return []source.Entry{{Path: file.Path, Mode: "100644", Size: int64(len(file.Content)), BlobSHA: file.BlobSHA}}, nil
}

func (s pipelineSource) Packet(_ context.Context, target source.Target, paths []string) (source.Packet, error) {
	if target != s.target || len(paths) != 1 || paths[0] != "server.go" {
		return source.Packet{}, ErrInvalid
	}
	return source.Packet{Version: 1, Target: target, Files: []source.PacketFile{sourceFile()}}, nil
}

func sourceFile() source.PacketFile {
	content := "package server\nconst healthy = false\n"
	blob := sha1.Sum(fmt.Appendf(nil, "blob %d\x00%s", len(content), content))
	digest := sha256.Sum256([]byte(content))
	return source.PacketFile{Path: "server.go", Content: content, BlobSHA: hex.EncodeToString(blob[:]), SHA256: hex.EncodeToString(digest[:])}
}

type pipelineModels struct {
	t           *testing.T
	target      source.Target
	calls       int
	candidates  int
	tasks       map[string]modelagent.Result
	sawFeedback bool
	pauseFirst  chan struct{}
}

type pipelineModel struct {
	owner    *pipelineModels
	accepted func(context.Context, modelagent.Result) error
}

func (m pipelineModel) Snapshot(context.Context) (modelagent.PlanIdentity, error) {
	return modelagent.PlanIdentity{Digest: Digest([]byte("approved-model-identity"))}, nil
}

func (m pipelineModel) Cancel(context.Context, string, string) error { return nil }
func (m pipelineModel) Retire(context.Context, string, string) error { return nil }

func (m pipelineModel) Generate(ctx context.Context, request modelagent.Request) (modelagent.Result, error) {
	models := m.owner
	if strings.Contains(request.Prompt, "private-driver-key") || request.Repository != "" || request.Commit != "" || request.MaxTurns != 0 {
		models.t.Fatal("model received executor configuration or tool authority")
	}
	if prior, exists := models.tasks[request.TaskName]; exists {
		if !request.RequireExisting || request.ExpectedTaskUID != prior.TaskUID {
			models.t.Fatal("existing Task was not UID-fenced")
		}
		return prior, nil
	}
	if request.RequireExisting {
		return modelagent.Result{}, ErrUnknown
	}
	models.calls++
	var proposal any
	switch {
	case strings.Contains(request.Prompt, "Perform read-only source investigation"):
		proposal = investigate.Proposal{
			Problem: "synthetic invalid request accepted", Trigger: "invalid request", ExpectedBehavior: "reject invalid request",
			Targets:      []investigate.TargetSuggestion{{Repository: models.target.Repository.URL, Ref: models.target.Ref, Reason: "synthetic source"}},
			Requirements: []pv.EnvironmentRequirement{{Kind: "process", Name: "http"}}, Scope: "upstream-source", VersionStatus: "single",
			Missing: []string{}, Limitations: []string{}, LanguageHints: []string{"go"}, BuildHints: []string{"dalec"},
		}
	case strings.Contains(request.Prompt, "Select a small read-only source packet"):
		proposal = investigate.Selection{Paths: []string{"server.go"}, Expand: []string{}, Missing: []string{}, Limitations: []string{}}
	case strings.Contains(request.Prompt, "Prepare a declarative independent observation plan"):
		proposal = checksProposal{
			Version: 1, Namespaces: []environment.Namespace{{Alias: "subject"}},
			Resources: []environment.Resource{{ID: "server", Namespace: "subject",
				GVK: schema.GroupVersionKind{Version: "v1", Kind: "Pod"}, HTTP: &environment.HTTPWorkload{Port: 8080}}},
			Checks: []environment.Check{
				{ID: "repro", Class: environment.Reproduction, Capability: environment.HTTPExact, HTTP: &environment.HTTPProbe{
					Resource: "server", Protocol: "http", Path: "/invalid",
					Healthy: environment.HTTPExpectation{Status: 400, Body: "rejected\n"},
					Failure: &environment.HTTPExpectation{Status: 200, Body: "incorrectly accepted\n"}}},
				{ID: "normal", Class: environment.Normal, Capability: environment.HTTPExact, HTTP: &environment.HTTPProbe{
					Resource: "server", Protocol: "http", Path: "/health", Healthy: environment.HTTPExpectation{Status: 200, Body: "ok\n"}}},
			},
		}
	case strings.Contains(request.Prompt, "Produce a private candidate fix"):
		models.candidates++
		models.sawFeedback = models.sawFeedback || strings.Contains(request.Prompt, "candidate-build-failed")
		newValue := "true"
		if models.candidates == 1 {
			newValue = "missingSymbol"
		}
		proposal = remediation.PatchProposal{
			Summary: "fix the synthetic request check", Edits: []remediation.SourceEdit{{Path: "server.go", Old: "false", New: newValue}},
			DeclaredChanges: []pv.DeclaredChange{{Kind: "source", Paths: []string{"server.go"}, Description: "reject invalid requests"}},
			Limitations:     []string{},
		}
	default:
		models.t.Fatal("unexpected model stage")
	}
	raw, err := json.Marshal(proposal)
	if err != nil {
		models.t.Fatal(err)
	}
	result := modelagent.Result{TaskName: request.TaskName, TaskUID: "task-" + fmt.Sprint(models.calls), Output: string(raw)}
	models.tasks[request.TaskName] = result
	if err := m.accepted(ctx, result); err != nil {
		return result, err
	}
	if models.calls == 1 && models.pauseFirst != nil {
		close(models.pauseFirst)
		<-ctx.Done()
		return result, ctx.Err()
	}
	return result, nil
}

type pipelineEnvironment struct {
	selection AdapterSelection
	builds    int
	starts    int
	cleanups  int
}

func (e *pipelineEnvironment) Select(context.Context, Policy, investigate.Plan) (AdapterSelection, ExecutionAdapter, error) {
	return e.selection, e, nil
}

func (e *pipelineEnvironment) Resume(context.Context, Policy, AdapterSelection) (ExecutionAdapter, error) {
	return e, nil
}

func (e *pipelineEnvironment) FreezePlan(plan environment.Plan) (environment.Plan, error) {
	plan.Bind.ChecksDigest = environment.ChecksDigest(plan)
	return plan, nil
}

func (e *pipelineEnvironment) Build(_ context.Context, request environment.BuildRequest) (environment.BuildResult, error) {
	e.builds++
	result := environment.BuildResult{ID: request.OperationID, Bind: request.Plan.Bind}
	if strings.Contains(string(request.Patch), "missingSymbol") {
		result.Diagnostics = []environment.Diagnostic{{Code: "undefined-identifier", Count: 1}}
		return result, &environment.Error{Kind: environment.BuildFailed, Code: "compiler-failed"}
	}
	digit := "2"
	if request.Role == environment.Candidate {
		digit = "3"
	}
	result.Subject = environment.Subject{
		Role: request.Role, Image: "example.invalid/subject@sha256:" + strings.Repeat(digit, 64),
		PatchDigest: request.PatchDigest, BuildID: request.OperationID,
	}
	return result, nil
}

func (e *pipelineEnvironment) Start(_ context.Context, request environment.Request) (environment.Receipt, error) {
	e.starts++
	return environment.Receipt{Version: 1, Request: request, StartedAt: time.Now()}, nil
}

func (e *pipelineEnvironment) Observe(_ context.Context, receipt environment.Receipt) (environment.Observation, error) {
	e.cleanups++
	observed := environment.Observation{Receipt: receipt, Phase: environment.Completed, CleanupComplete: true}
	for _, check := range receipt.Request.Plan.Checks {
		matched := receipt.Request.Subject.Role == environment.Candidate || check.Class == environment.Normal
		status, body := check.HTTP.Healthy.Status, check.HTTP.Healthy.Body
		outcome := environment.OutcomeHealthy
		if !matched {
			status, body = check.HTTP.Failure.Status, check.HTTP.Failure.Body
			outcome = environment.OutcomeFailure
		}
		checkResult := environment.HTTPResult{
			CheckID: check.ID, Class: check.Class, PodUID: types.UID("observed-" + receipt.Request.OperationID),
			Image: receipt.Request.Subject.Image, RuntimeImageID: receipt.Request.Subject.Image,
			Status: status, BodyDigest: Digest([]byte(body)),
			HealthyStatus: check.HTTP.Healthy.Status, HealthyBodyDigest: Digest([]byte(check.HTTP.Healthy.Body)), Outcome: outcome,
		}
		if check.HTTP.Failure != nil {
			checkResult.FailureStatus = check.HTTP.Failure.Status
			checkResult.FailureBodyDigest = Digest([]byte(check.HTTP.Failure.Body))
		}
		observed.Checks = append(observed.Checks, checkResult)
	}
	return observed, nil
}

func (e *pipelineEnvironment) Cancel(context.Context, environment.Receipt) error { return nil }
func (e *pipelineEnvironment) CancelBuild(context.Context, string, string, environment.Plan) error {
	return nil
}

func TestPipelineAutomaticallyInvestigatesAndRepairsBuildFailure(t *testing.T) {
	for _, repository := range []string{"https://github.com/example/project", "https://github.com/another/component"} {
		t.Run(repository, func(t *testing.T) {
			target := source.Target{
				Repository: source.Repository{URL: repository, Owner: strings.Split(repository, "/")[3],
					Name: strings.Split(repository, "/")[4], DefaultBranch: "main"},
				Ref: "v1.2.3", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40),
			}

			models := &pipelineModels{t: t, target: target, tasks: make(map[string]modelagent.Result)}
			executor := &pipelineEnvironment{selection: AdapterSelection{
				Name: "synthetic", Capabilities: []string{environment.HTTPExact},
				Binding:  environment.Bind{SourceTarget: environment.SourceTarget{Repository: repository, Commit: target.Commit}},
				Original: environment.Subject{Role: environment.PublishedOriginal, Image: "example.invalid/subject@sha256:" + strings.Repeat("1", 64)},
			}}
			pipeline := &Pipeline{Source: pipelineSource{target: target}, Environments: executor,
				Agents: func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
					return pipelineModel{owner: models, accepted: accepted}
				}}
			service, _ := testService(t, pipeline)
			policy := service.policies["approved"]
			policy.Repositories = []string{repository}
			policy.Adapters[0].Repositories = []string{repository}
			service.policies["approved"] = policy
			request := requestFixture()
			request.Report = json.RawMessage(`{"title":"Synthetic bug","problem":"Invalid requests are accepted","versions":["1.2.3"],"restricted":false}`)
			run, _, err := service.Submit(t.Context(), "testing", "caller", request)
			if err != nil {
				t.Fatal(err)
			}
			if err := service.RunOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			status, err := service.Get(t.Context(), "testing", run.ID)
			if err != nil || status.Phase != store.RemediationPhaseSucceeded || status.Stage != "verified" {
				t.Fatalf("single submission did not complete: %+v %v", status, err)
			}
			if models.calls != 5 || models.candidates != 2 || !models.sawFeedback || executor.builds != 3 || executor.starts != 3 || executor.cleanups != 3 {
				t.Fatalf("wrong stage/repair counts: model=%d candidates=%d feedback=%v build=%d start=%d cleanup=%d",
					models.calls, models.candidates, models.sawFeedback, executor.builds, executor.starts, executor.cleanups)
			}
			ref, patch, err := service.Artifact(t.Context(), "testing", run.ID, "candidate.patch")
			if err != nil || ref.Digest != Digest(patch) || !strings.Contains(string(patch), "+const healthy = true") {
				t.Fatal("final artifact is not the measured corrected candidate", err)
			}
			if err := service.RunOnce(t.Context()); err != nil || models.calls != 5 || executor.starts != 3 {
				t.Fatal("completed run replayed effects", err)
			}
		})
	}
}
