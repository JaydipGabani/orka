package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

func reportRequest() pv.Request {
	request := fixtureRequest()
	request.Action, request.PatchedCommit = pv.ValidateReport, ""
	return request
}

func linkedRequest(runID string) pv.Request {
	return pv.Request{Action: pv.VerifyPatch, EarlierValidation: runID, PatchedCommit: strings.Repeat("b", 40),
		DeclaredChanges: []pv.DeclaredChange{{Kind: "configuration", Paths: []string{"config.json"},
			Description: "retain managed settings"}}}
}

func TestReportServiceConclusions(test *testing.T) {
	for _, scenario := range []struct {
		name string
		want pv.Conclusion
	}{
		{"reproduced", pv.Reproduced}, {"not-reproduced", pv.NotReproduced},
		{"mixed", pv.Reproduced}, {"untested", pv.UnableToValidate}, {"reproduction-only", pv.Reproduced},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			calls := 0
			dependencies := fixtureDependencies(pv.Verified, &calls)
			dependencies.Runner = &fakeRunner{check: func(_ context.Context, manifest pv.Manifest, binding pv.Binding,
				side string, check pv.Check) (pv.ExecutionEvidence, error) {
				calls++
				if side != pv.Original || binding.PatchedTaskID != "" {
					test.Fatal("report executed a patched arm")
				}
				output := check.Healthy.Stdout
				if check.Kind == pv.Reproduction && scenario.name != "not-reproduced" &&
					(scenario.name != "mixed" || check.ID == "problem-one") {
					output = check.Failure.Stdout
				}
				evidence := fixtureEvidence(manifest, binding, side, check, output)
				if scenario.name == "untested" && check.ID == "problem-two" {
					evidence.Observation.Skipped = true
				}
				return evidence, nil
			}}
			service := newTestService(test, dependencies)
			request := reportRequest()
			if scenario.name == "reproduction-only" {
				request.Checks = request.Checks[1:]
			}
			result, err := service.Start(test.Context(), request, nil)
			if err != nil || result.Action != pv.ValidateReport || result.Overall.Conclusion != scenario.want ||
				calls != len(request.Checks) || result.Progress.Required != len(request.Checks) ||
				result.Progress.Recorded != len(request.Checks) || result.ReportDigest == "" ||
				result.State != pv.RunFinalized || len(result.Overall.Checks) != len(request.Checks) {
				test.Fatalf("report result: %+v, calls=%d, %v", result, calls, err)
			}
			record, err := service.Record(test.Context(), result.RunID)
			if err != nil || len(Tasks(record)) != 1 || record.Seal == nil ||
				record.Manifest.Sources.Patched != (pv.SourceIdentity{}) {
				test.Fatalf("report projection or seal: %+v, %v", record, err)
			}
			before, _ := json.Marshal(record)
			if err := service.Close(); err != nil {
				test.Fatal(err)
			}
			reopened, err := New(test.Context(), service.dbPath, Dependencies{})
			if err != nil {
				test.Fatal(err)
			}
			defer func() { _ = reopened.Close() }()
			after, err := reopened.Record(test.Context(), result.RunID)
			encoded, _ := json.Marshal(after)
			if err != nil || !bytes.Equal(before, encoded) {
				test.Fatalf("report changed across reopen: %v", err)
			}
			cancelled, err := reopened.Cancel(test.Context(), result.RunID)
			if err != nil || !reflect.DeepEqual(cancelled, result) {
				test.Fatalf("completed report changed on cancellation: %+v, %v", cancelled, err)
			}
		})
	}
}

func TestActionServiceBaselineGate(test *testing.T) {
	for _, mode := range []string{"healthy", "skipped", "timeout", "setup", "missing", "ready"} {
		test.Run(mode, func(test *testing.T) {
			calls := []string{}
			dependencies := Dependencies{Prepare: fixturePrepare, Release: func(*pv.PreparedSources) error { return nil }}
			dependencies.Runner = &fakeRunner{check: func(_ context.Context, manifest pv.Manifest, binding pv.Binding,
				side string, check pv.Check) (pv.ExecutionEvidence, error) {
				calls = append(calls, side+":"+check.ID)
				output := check.Healthy.Stdout
				if side == pv.Original && check.Kind == pv.Reproduction && mode != "healthy" {
					output = check.Failure.Stdout
				}
				evidence := fixtureEvidence(manifest, binding, side, check, output)
				if side == pv.Original && check.ID == "problem-two" {
					switch mode {
					case "skipped":
						evidence.Observation.Skipped = true
					case "timeout":
						evidence.Observation.TimedOut = true
					case "setup":
						evidence.Observation.SetupError = "missing tool"
					case "missing":
						evidence.Observation.AttemptID = "foreign-attempt"
					}
				}
				return evidence, nil
			}}
			service := newTestService(test, dependencies)
			request := fixtureRequest()
			request.Action, request.DeclaredChanges = pv.VerifyPatch, linkedRequest("unused").DeclaredChanges
			result, _ := service.Start(test.Context(), request, nil)
			want, expectedCalls := pv.UnableToVerify, 3
			if mode == "ready" {
				want, expectedCalls = pv.Verified, 6
			}
			if result.Overall.Conclusion != want || len(calls) != expectedCalls ||
				len(result.Overall.Checks) != len(request.Checks) || result.Progress.Required != 6 {
				test.Fatalf("baseline gate: %+v, calls=%v", result, calls)
			}
			for index, call := range calls {
				side := pv.Original
				if index >= len(request.Checks) {
					side = pv.Patched
				}
				if !strings.HasPrefix(call, side+":") {
					test.Fatalf("checks were not original-first: %v", calls)
				}
			}
			if mode != "ready" && result.Overall.Checks[0].PatchedOutcome != "untested" {
				test.Fatal("missing patched evidence was not retained as untested")
			}
		})
	}
}

func TestRequirementsServiceNoWorkload(test *testing.T) {
	for _, action := range []pv.Action{pv.ValidateReport, pv.VerifyPatch} {
		test.Run(string(action), func(test *testing.T) {
			calls := 0
			service := newTestService(test, fixtureDependencies(pv.Verified, &calls))
			request := fixtureRequest()
			request.Action = action
			if action == pv.ValidateReport {
				request.PatchedCommit = ""
			} else {
				request.DeclaredChanges = linkedRequest("unused").DeclaredChanges
			}
			request.RequiredEnvironment = []pv.EnvironmentRequirement{
				{Kind: "process", Name: "modeled-manager"}, {Kind: "cluster", Name: "test-cluster"},
				{Kind: "controller", Name: "real-controller"}, {Kind: "external-service", Name: "remote-fixture"},
				{Kind: "test-identity", Name: "separate-identity"},
			}
			result, err := service.Start(test.Context(), request, nil)
			if err != nil || result.State != pv.RunFinalized || result.Overall.Conclusion != pv.UnavailableAction(action) ||
				calls != 0 || result.Progress.Recorded != 0 || len(result.Overall.Checks) != len(request.Checks) {
				test.Fatalf("unsupported setup: %+v, calls=%d, %v", result, calls, err)
			}
			for _, requirement := range request.RequiredEnvironment[1:] {
				if !strings.Contains(result.Overall.Reason, requirement.Name) {
					test.Fatalf("missing requirement was not named: %+v", result)
				}
			}
		})
	}
}

func TestLinkedServiceFreshBaselineAndImmutableEarlier(test *testing.T) {
	for _, brokenBaseline := range []bool{false, true} {
		name := "working-baseline"
		if brokenBaseline {
			name = "broken-baseline"
		}
		test.Run(name, func(test *testing.T) {
			calls := 0
			service := newTestService(test, fixtureDependencies(pv.Verified, &calls))
			report := reportRequest()
			report.RequiredEnvironment = []pv.EnvironmentRequirement{{Kind: "process", Name: "modeled-manager"}}
			report.Checks[1].Lifecycle = []string{"install", "reconcile", "restart", "upgrade"}
			result, err := service.Start(test.Context(), report, nil)
			if err != nil {
				test.Fatal(err)
			}
			earlier, err := service.Record(test.Context(), result.RunID)
			if err != nil {
				test.Fatal(err)
			}
			task := Tasks(earlier)[0]
			auxiliary, _, err := service.storage.GetArtifact(test.Context(), task.Namespace, task.Name, "task.json")
			if err != nil {
				test.Fatal(err)
			}
			oldResult, err := service.storage.GetResult(test.Context(), task.Namespace, task.Name)
			if err != nil {
				test.Fatal(err)
			}
			service.dependencies.Prepare = func(ctx context.Context, request pv.Request) (*pv.PreparedSources, error) {
				if request.ChecksDir == report.ChecksDir || request.OriginalCommit != report.OriginalCommit ||
					request.Repository != report.Repository || !reflect.DeepEqual(request.Checks, earlier.Manifest.Checks) {
					test.Fatal("linked request did not hydrate the exact frozen inputs")
				}
				if err := pv.ValidateFrozenChecks(ctx, request.ChecksDir, earlier.Manifest); err != nil {
					test.Fatal("restored checks changed bytes or mode", err)
				}
				return fixturePrepare(ctx, request)
			}
			if brokenBaseline {
				service.dependencies.Runner = &fakeRunner{check: func(_ context.Context, manifest pv.Manifest, binding pv.Binding,
					side string, check pv.Check) (pv.ExecutionEvidence, error) {
					calls++
					return fixtureEvidence(manifest, binding, side, check, check.Healthy.Stdout), nil
				}}
			}
			verified, err := service.Start(test.Context(), linkedRequest(result.RunID), nil)
			want, expectedCalls := pv.Verified, 9
			if brokenBaseline {
				want, expectedCalls = pv.UnableToVerify, 6
			}
			if err != nil || verified.RunID == result.RunID || verified.ReportDigest != result.ReportDigest ||
				verified.Overall.Conclusion != want || calls != expectedCalls || verified.EarlierValidation == nil ||
				verified.EarlierValidation.SealDigest != earlier.Seal.Digest {
				test.Fatalf("linked run: %+v, calls=%d, %v", verified, calls, err)
			}
			after, err := service.Record(test.Context(), result.RunID)
			if err != nil || !reflect.DeepEqual(earlier, after) {
				test.Fatal("link changed earlier evidence", err)
			}
			newAuxiliary, _, err := service.storage.GetArtifact(test.Context(), task.Namespace, task.Name, "task.json")
			if err != nil || !bytes.Equal(auxiliary, newAuxiliary) {
				test.Fatal("link rewrote earlier task projection", err)
			}
			newResult, err := service.storage.GetResult(test.Context(), task.Namespace, task.Name)
			if err != nil || !reflect.DeepEqual(oldResult, newResult) {
				test.Fatal("link rewrote earlier result projection", err)
			}
		})
	}
}

func TestLinkedServiceRejectsOverridesAndForeignDatabase(test *testing.T) {
	calls := 0
	service := newTestService(test, fixtureDependencies(pv.Verified, &calls))
	result, err := service.Start(test.Context(), reportRequest(), nil)
	if err != nil {
		test.Fatal(err)
	}
	for _, mode := range []string{"report", "base", "repository", "image", "checks", "empty-profile", "mode", "missing"} {
		test.Run(mode, func(test *testing.T) {
			request := linkedRequest(result.RunID)
			switch mode {
			case "report":
				request.Problem = "changed report"
			case "base":
				request.OriginalCommit = strings.Repeat("f", 40)
			case "repository":
				request.Repository = "/another/repository"
			case "image":
				request.Image = "another@" + pv.Digest([]byte("image"))
			case "checks":
				request.ChecksDir = test.TempDir()
			case "empty-profile":
				request.ProvidedFields = map[string]bool{"profile": true}
			case "mode":
				if err := os.Chmod(service.dbPath, 0644); err != nil {
					test.Fatal(err)
				}
				defer func() { _ = os.Chmod(service.dbPath, 0600) }()
			case "missing":
				request.EarlierValidation = "pv-unresolvable"
			}
			failed, err := service.Start(test.Context(), request, nil)
			if err == nil || failed.RunID != "" || calls != 3 {
				test.Fatalf("unauthorized or changed input reached execution: %+v, calls=%d, %v", failed, calls, err)
			}
		})
	}
	foreign := newTestService(test, fixtureDependencies(pv.Verified, &calls))
	if result, err := foreign.Start(test.Context(), linkedRequest(result.RunID), nil); err == nil || result.RunID != "" {
		test.Fatal("another database was treated as authorized earlier evidence")
	}
	if _, err := New(test.Context(), filepath.Join(test.TempDir(), "missing", "evidence.db"), Dependencies{}); err == nil {
		test.Fatal("inaccessible database was accepted")
	}
}

func TestReportServiceFailureIsActionAware(test *testing.T) {
	calls := 0
	dependencies := fixtureDependencies(pv.Verified, &calls)
	dependencies.Prepare = func(context.Context, pv.Request) (*pv.PreparedSources, error) {
		return nil, errors.New("source preparation unavailable")
	}
	service := newTestService(test, dependencies)
	result, err := service.Start(test.Context(), reportRequest(), nil)
	if err == nil || result.Overall.Conclusion != pv.UnableToValidate || calls != 0 {
		test.Fatalf("report failure used patch conclusion: %+v, %v", result, err)
	}
}

func TestReportServiceCancelAndRejectIncompleteLinks(test *testing.T) {
	calls := 0
	service := newTestService(test, fixtureDependencies(pv.Verified, &calls))
	result, err := service.Start(test.Context(), reportRequest(), func(summary Summary) error {
		_, err := service.Cancel(test.Context(), summary.RunID)
		return err
	})
	if err != nil || calls != 0 || result.State != pv.RunCancelled || result.Overall.Conclusion != pv.UnableToValidate {
		test.Fatalf("report cancellation: %+v, calls=%d, %v", result, calls, err)
	}
	if _, err := service.Start(test.Context(), linkedRequest(result.RunID), nil); err == nil {
		test.Fatal("cancelled report accepted as completed validation")
	}
	running := createRunning(test, service)
	if _, err := service.Start(test.Context(), linkedRequest(running.RunID), nil); err == nil {
		test.Fatal("unfinalized run accepted as completed validation")
	}
	verified, err := service.Start(test.Context(), fixtureRequest(), nil)
	if err != nil {
		test.Fatal(err)
	}
	if _, err := service.Start(test.Context(), linkedRequest(verified.RunID), nil); err == nil {
		test.Fatal("patch verification accepted as report validation")
	}
	if calls != 6 {
		test.Fatal("a rejected link executed a workload")
	}
	reopened, err := New(test.Context(), service.dbPath, Dependencies{})
	if err != nil {
		test.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	persisted, err := reopened.Get(test.Context(), result.RunID)
	if err != nil || !reflect.DeepEqual(persisted, result) {
		test.Fatalf("cancelled report changed after reopening: %+v, %v", persisted, err)
	}
}
