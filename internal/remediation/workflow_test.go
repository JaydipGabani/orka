package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pv "github.com/orka-agents/orka/internal/patchverification"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/journal"
	"github.com/orka-agents/orka/internal/remediation/source"
	remediationvalidation "github.com/orka-agents/orka/internal/remediation/validation"
)

type generatorFunc func(context.Context, modelagent.Request) (modelagent.Result, error)

func (fn generatorFunc) Generate(ctx context.Context, req modelagent.Request) (modelagent.Result, error) {
	return fn(ctx, req)
}

type resolverFunc func(context.Context, string, string) (source.Target, error)

func (fn resolverFunc) Resolve(ctx context.Context, repo, ref string) (source.Target, error) {
	return fn(ctx, repo, ref)
}

type workflowValidator struct {
	starts  int
	resumes int
	unknown bool
}

func (v *workflowValidator) Start(_ context.Context, request pv.Request, started func(remediationvalidation.Receipt) error) (*pv.Record, error) {
	v.starts++
	if v.unknown {
		return nil, errors.New("unknown submission result")
	}
	if err := started(remediationvalidation.Receipt{Version: 1, Namespace: "validation", RequestID: "request-1"}); err != nil {
		return nil, err
	}
	return workflowRecord(request), nil
}

func (v *workflowValidator) Resume(_ context.Context, request pv.Request, _ remediationvalidation.Receipt) (*pv.Record, error) {
	v.resumes++
	return workflowRecord(request), nil
}

func workflowRecord(request pv.Request) *pv.Record {
	conclusion := pv.Reproduced
	if request.Action == pv.VerifyPatch {
		conclusion = pv.Verified
	}
	return &pv.Record{State: pv.RunFinalized, Assessment: pv.Assessment{Conclusion: conclusion}, Seal: &pv.Seal{}}
}

func newWorkflowTest(t *testing.T, restricted bool) (*Engine, *workflowValidator, *int) {
	t.Helper()
	raw := []byte(`{"title":"Synthetic report","problem":"Quantity outside range","repository":"https://github.com/example/project","versions":["v1.0.0"],"restricted":false}`)
	if restricted {
		raw = []byte(strings.Replace(string(raw), `"restricted":false`, `"restricted":true`, 1))
	}
	store, err := journal.Create(filepath.Join(t.TempDir(), "journal"), pv.Digest(raw))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := Initialize(store, raw, nil); err != nil {
		t.Fatal(err)
	}
	target := source.Target{Repository: source.Repository{URL: "https://github.com/example/project", Owner: "example", Name: "project", DefaultBranch: "main"},
		Ref: "v1.0.0", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)}
	calls := new(int)
	validator := &workflowValidator{}
	workDir := t.TempDir()
	if err := os.Chmod(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{
		Store: store, WorkDir: workDir, Image: "example/tool@" + pv.Digest([]byte("image")),
		Platform: "linux/amd64", Profile: pv.LocalServices, Validator: validator,
		Resolver: resolverFunc(func(_ context.Context, repo, ref string) (source.Target, error) {
			if repo != target.Repository.URL || ref != target.Ref {
				t.Fatal("source inference was silently changed")
			}
			return target, nil
		}),
		Materialize: func(_ context.Context, got source.Target, destination string) error {
			if got != target {
				t.Fatal("source materialization target changed")
			}
			return os.MkdirAll(destination, 0700)
		},
	}
	engine.Generator = generatorFunc(func(_ context.Context, request modelagent.Request) (modelagent.Result, error) {
		*calls++
		var proposal any
		switch {
		case strings.Contains(request.Prompt, "REPORT_DATA:"):
			if request.Repository != "" || request.Commit != "" {
				t.Fatal("target inference acquired source access")
			}
			proposal = TargetProposal{Problem: "quantity outside range", Trigger: "invalid quantity", ExpectedBehavior: "reject",
				Targets: []TargetSuggestion{{Repository: target.Repository.URL, Ref: target.Ref, Reason: "explicit test version"}}}
		case strings.Contains(request.Prompt, "FROZEN_CHECK_DATA:"):
			proposal = PatchProposal{Summary: "reject invalid quantity", Patch: "diff --git a/main.c b/main.c\n--- a/main.c\n+++ b/main.c\n",
				DeclaredChanges: []pv.DeclaredChange{{Kind: "source", Description: "input bounds", Paths: []string{"main.c"}}}}
		default:
			healthy, _ := pv.HTTPExpectation(200, "healthy\n")
			failure, _ := pv.HTTPExpectation(500, "broken\n")
			proposal = CheckProposal{
				Scope: []string{"problem", "normal"}, Files: []ProposedFile{{Path: "server.sh", Content: "#!/bin/sh\nexit 125\n", Executable: true}},
				Checks: []pv.Check{
					{ID: "problem", Kind: pv.Reproduction, HTTP: &pv.HTTPCheck{Version: 1, ServerCommand: []string{"/checks/server.sh"}, Path: "/problem"},
						Healthy: healthy, Failure: failure, TimeoutSeconds: 10},
					{ID: "normal", Kind: pv.Normal, HTTP: &pv.HTTPCheck{Version: 1, ServerCommand: []string{"/checks/server.sh"}, Path: "/normal"},
						Healthy: healthy, Failure: failure, TimeoutSeconds: 10},
				},
			}
		}
		content, err := json.Marshal(proposal)
		if err != nil {
			t.Fatal(err)
		}
		return modelagent.Result{TaskName: request.TaskName, TaskUID: "uid-" + request.TaskName, Output: string(content)}, nil
	})
	return engine, validator, calls
}

func TestWorkflowExactPlanApprovalAndIndependentStages(t *testing.T) {
	engine, validation, calls := newWorkflowTest(t, false)
	proposal, err := engine.Propose(t.Context())
	if err != nil || proposal.Phase != "targets-proposed" || proposal.PlanDigest == "" || *calls != 1 {
		t.Fatalf("plan failed: %+v %v", proposal, err)
	}
	engine.ApprovePlanDigest = pv.Digest([]byte("different plan"))
	if _, err := engine.Execute(t.Context()); !errors.Is(err, ErrApprovalRequired) || validation.starts != 0 {
		t.Fatal("wrong plan confirmation authorized execution", err)
	}
	engine.ApprovePlanDigest = proposal.PlanDigest
	result, err := engine.Execute(t.Context())
	if err != nil || result.Phase != "completed" || len(result.Targets) != 1 ||
		result.Targets[0].Conclusion != pv.Verified || validation.starts != 2 || *calls != 3 {
		t.Fatalf("coordinator did not connect independent stages: %+v %v starts=%d calls=%d", result, err, validation.starts, *calls)
	}
	if result.Targets[0].Baseline == nil || result.Targets[0].Patch == nil || result.Targets[0].Verification == nil {
		t.Fatal("completed workflow omitted private artifacts")
	}
	if _, err := engine.Execute(t.Context()); err != nil || *calls != 3 || validation.starts != 2 {
		t.Fatal("completed workflow replayed model or validation work", err)
	}
}

func TestWorkflowRestrictedModelGateBeforeInference(t *testing.T) {
	engine, _, calls := newWorkflowTest(t, true)
	if _, err := engine.Propose(t.Context()); !errors.Is(err, ErrModelApproval) || *calls != 0 {
		t.Fatal("restricted report reached the model without the explicit boundary", err)
	}
	engine.ModelDataApproved = true
	if _, err := engine.Propose(t.Context()); err != nil || *calls != 1 {
		t.Fatal("approved model planning failed", err)
	}
}

func TestWorkflowUnknownValidationSubmissionNeverReplays(t *testing.T) {
	engine, validation, _ := newWorkflowTest(t, false)
	plan, err := engine.Propose(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	engine.ApprovePlanDigest, validation.unknown = plan.PlanDigest, true
	if result, err := engine.Execute(t.Context()); err == nil || result.Phase != "blocked" || validation.starts != 1 {
		t.Fatal("unknown result was treated as successful")
	}
	if _, err := engine.Execute(t.Context()); err == nil || validation.starts != 1 || validation.resumes != 0 {
		t.Fatal("unknown submission was replayed")
	}
}

func TestWorkflowModelUIDReplacementRejected(t *testing.T) {
	engine, _, _ := newWorkflowTest(t, false)
	checkpoint, state, err := engine.load()
	if err != nil {
		t.Fatal(err)
	}
	request := "synthetic prompt"
	name := "remediate-" + strings.TrimPrefix(pv.Digest([]byte(checkpoint.RunID+"\x00targets\x00"+request)), "sha256:")[:40]
	state.Tasks = map[string]modelagent.Result{"targets": {TaskName: name, TaskUID: "original-uid"}}
	if err := engine.save(&checkpoint, state, "agent-targets"); err != nil {
		t.Fatal(err)
	}
	engine.Generator = generatorFunc(func(_ context.Context, request modelagent.Request) (modelagent.Result, error) {
		return modelagent.Result{TaskName: request.TaskName, TaskUID: "replaced-uid", Output: "not-authoritative"}, nil
	})
	if _, err := engine.generate(t.Context(), &checkpoint, &state, "targets", request, "", ""); err == nil {
		t.Fatal("replacement model Task supplied authoritative output")
	}
}
