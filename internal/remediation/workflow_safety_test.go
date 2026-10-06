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
	remediationvalidation "github.com/orka-agents/orka/internal/remediation/validation"
)

func TestWorkflowIncompleteReportBlocksModel(t *testing.T) {
	for _, warning := range []string{"missing_technical_details", "discussion_snapshot_incomplete"} {
		t.Run(warning, func(t *testing.T) {
			engine, _, calls := newWorkflowTest(t, false)
			checkpoint, state, err := engine.load()
			if err != nil {
				t.Fatal(err)
			}
			report, err := engine.report(state)
			if err != nil {
				t.Fatal(err)
			}
			report.Warnings = append(report.Warnings, warning)
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			state.Report, err = engine.Store.PutArtifact("incomplete-report.json", raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.save(&checkpoint, state, "ingested"); err != nil {
				t.Fatal(err)
			}
			summary, err := engine.Propose(t.Context())
			if err == nil || summary.Phase != "needs-input" || *calls != 0 {
				t.Fatalf("incomplete report reached model: %+v %v calls=%d", summary, err, *calls)
			}
		})
	}
}

func TestWorkflowTargetCannotEscapeConfirmedPlan(t *testing.T) {
	engine, _, _ := newWorkflowTest(t, false)
	if _, err := engine.Propose(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkpoint, state, err := engine.load()
	if err != nil {
		t.Fatal(err)
	}
	state.Targets[0].Target.Commit = strings.Repeat("c", 40)
	if err := engine.save(&checkpoint, state, "targets-proposed"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.load(); err == nil {
		t.Fatal("execution target changed without changing the approved plan")
	}
}

func TestWorkflowModelErrorPreservesKnownUID(t *testing.T) {
	engine, _, _ := newWorkflowTest(t, false)
	checkpoint, state, err := engine.load()
	if err != nil {
		t.Fatal(err)
	}
	prompt := "synthetic prompt"
	name := "remediate-" + strings.TrimPrefix(pv.Digest([]byte(checkpoint.RunID+"\x00targets\x00"+prompt)), "sha256:")[:40]
	state.Tasks = map[string]modelagent.Result{"targets": {TaskName: name, TaskUID: "original-uid"}}
	if err := engine.save(&checkpoint, state, "agent-targets"); err != nil {
		t.Fatal(err)
	}
	engine.Generator = generatorFunc(func(_ context.Context, request modelagent.Request) (modelagent.Result, error) {
		if request.ExpectedTaskUID != "original-uid" {
			t.Fatal("known Task UID was not passed to the resume-only model request")
		}
		return modelagent.Result{}, errors.New("temporary model transport error")
	})
	if _, err := engine.generate(t.Context(), &checkpoint, &state, "targets", prompt, "", ""); err == nil {
		t.Fatal("model transport failure was hidden")
	}
	if state.Tasks["targets"].TaskUID != "original-uid" {
		t.Fatal("transport error erased a durable Task UID")
	}
}

type invalidEvidenceValidator struct{ resumes int }

func (*invalidEvidenceValidator) Start(_ context.Context, request pv.Request, started func(remediationvalidation.Receipt) error) (*pv.Record, error) {
	if err := started(remediationvalidation.Receipt{Version: 1, RequestID: "invalid-evidence"}); err != nil {
		return nil, err
	}
	return workflowRecord(request), errors.New("evidence digest verification failed")
}

func (v *invalidEvidenceValidator) Resume(_ context.Context, request pv.Request, _ remediationvalidation.Receipt) (*pv.Record, error) {
	v.resumes++
	return workflowRecord(request), errors.New("evidence digest verification failed")
}

func TestWorkflowErrorBearingEvidenceCannotAdvanceAfterResume(t *testing.T) {
	engine, _, calls := newWorkflowTest(t, false)
	plan, err := engine.Propose(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	engine.ApprovePlanDigest = plan.PlanDigest
	validator := &invalidEvidenceValidator{}
	engine.Validator = validator
	for range 2 {
		summary, err := engine.Execute(t.Context())
		if err == nil || summary.Targets[0].Baseline != nil || summary.Targets[0].Patch != nil {
			t.Fatal("unverified evidence authorized patch generation on resume", err)
		}
	}
	if validator.resumes != 1 || *calls != 2 {
		t.Fatalf("invalid evidence was replayed or advanced: resumes=%d model calls=%d", validator.resumes, *calls)
	}
}

func TestStageChecksRejectsAliasesAndExtraFiles(t *testing.T) {
	files := []ProposedFile{{Path: "server.sh", Content: "#!/bin/sh\nexit 0\n", Executable: true}}
	t.Run("symlink root", func(t *testing.T) {
		root, outside := filepath.Join(t.TempDir(), "checks"), t.TempDir()
		if err := os.Symlink(outside, root); err != nil {
			t.Fatal(err)
		}
		if err := stageChecks(root, files); err == nil {
			t.Fatal("symlinked check root was accepted")
		}
		if _, err := os.Stat(filepath.Join(outside, "server.sh")); !os.IsNotExist(err) {
			t.Fatal("check staging wrote through an alias")
		}
	})
	t.Run("extra file", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := stageChecks(root, files); err == nil {
			t.Fatal("unexpected staged content was accepted")
		}
	})
	t.Run("exact resume", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "checks")
		for range 2 {
			if err := stageChecks(root, files); err != nil {
				t.Fatal(err)
			}
		}
	})
}
