package local

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	orkav1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	pv "github.com/orka-agents/orka/internal/patchverification"
)

type fakeRunner struct {
	check func(context.Context, pv.Manifest, pv.Binding, string, pv.Check) (pv.ExecutionEvidence, error)
}

func (*fakeRunner) ResolveImage(_ context.Context, image, platform string) (pv.Environment, error) {
	return pv.Environment{Image: image, ImageID: pv.Digest([]byte("test image")), Platform: platform}, nil
}

func (*fakeRunner) FreezeEnvironment(environment pv.Environment) (pv.Environment, error) {
	return environment, nil
}

func (runner *fakeRunner) RunCheck(ctx context.Context, manifest pv.Manifest, binding pv.Binding, side string, check pv.Check, _, _ string) (pv.ExecutionEvidence, error) {
	return runner.check(ctx, manifest, binding, side, check)
}

func fixtureRequest() pv.Request {
	return pv.Request{Problem: "boundary defect", Scope: []string{"normal and two problem variations"}, Repository: "/unit-only/repo", ChecksDir: "/unit-only/checks", OriginalCommit: strings.Repeat("a", 40), PatchedCommit: strings.Repeat("b", 40), Image: "tool@" + pv.Digest([]byte("image")), Platform: "linux/amd64", Profile: pv.Offline,
		Checks: []pv.Check{
			{ID: "normal", Kind: pv.Normal, Command: []string{"/checks/run", "normal"}, Healthy: pv.Expectation{Stdout: "healthy\n"}, Failure: pv.Expectation{Stdout: "broken\n"}, TimeoutSeconds: 2},
			{ID: "problem-one", Kind: pv.Reproduction, Command: []string{"/checks/run", "one"}, Healthy: pv.Expectation{Stdout: "healthy\n"}, Failure: pv.Expectation{Stdout: "broken\n"}, TimeoutSeconds: 2},
			{ID: "problem-two", Kind: pv.Reproduction, Command: []string{"/checks/run", "two"}, Healthy: pv.Expectation{Stdout: "healthy\n"}, Failure: pv.Expectation{Stdout: "broken\n"}, TimeoutSeconds: 2},
		}}
}

func fixturePrepare(_ context.Context, request pv.Request) (*pv.PreparedSources, error) {
	provenance := make(map[string][]byte)
	for _, value := range []string{"unit-only original archive", "unit-only patched archive", "unit-only diff"} {
		provenance[pv.Digest([]byte(value))] = []byte(value)
	}
	file := []byte("#!/bin/sh\nexit 125\n")
	prepared := &pv.PreparedSources{Sources: pv.Sources{Repository: request.Repository,
		Original: pv.SourceIdentity{Commit: request.OriginalCommit, Tree: strings.Repeat("c", 40), ArchiveDigest: pv.Digest([]byte("unit-only original archive"))},
		Patched:  pv.SourceIdentity{Commit: request.PatchedCommit, Tree: strings.Repeat("d", 40), ArchiveDigest: pv.Digest([]byte("unit-only patched archive"))}, DiffDigest: pv.Digest([]byte("unit-only diff"))},
		Files: []pv.FrozenFile{{Path: "run", Content: file, Digest: pv.Digest(file), Executable: true}}, Provenance: provenance,
		Root: "/unit-only/prepared", OriginalDir: "/unit-only/prepared/original", PatchedDir: "/unit-only/prepared/patched", ChecksDir: "/unit-only/prepared/checks"}
	if request.Action == pv.ValidateReport {
		delete(prepared.Provenance, prepared.Sources.Patched.ArchiveDigest)
		delete(prepared.Provenance, prepared.Sources.DiffDigest)
		prepared.Sources.Patched, prepared.Sources.DiffDigest, prepared.PatchedDir = pv.SourceIdentity{}, "", ""
	}
	return prepared, nil
}

func fixtureEvidence(manifest pv.Manifest, binding pv.Binding, side string, check pv.Check, output string) pv.ExecutionEvidence {
	identity, tree := binding.OriginalTaskID, manifest.Sources.Original.Tree
	if side == pv.Patched {
		identity, tree = binding.PatchedTaskID, manifest.Sources.Patched.Tree
	}
	started := time.Now().UTC()
	observation := pv.Observation{RunID: binding.RunID, AttemptID: binding.AttemptID, TaskID: identity, ManifestDigest: binding.ManifestDigest,
		Side: side, CheckID: check.ID, SourceTree: tree, ImageID: manifest.Environment.ImageID, ContainerID: "unit-" + side + "-" + check.ID,
		Origin: "runner", StartedAt: started, FinishedAt: started.Add(time.Millisecond), Executed: true, ExitCode: new(0),
		StdoutDigest: pv.Digest([]byte(output)), StdoutBytes: len(output), StderrDigest: pv.Digest(nil)}
	return pv.ExecutionEvidence{Observation: observation, Blobs: map[string][]byte{observation.StdoutDigest: []byte(output), observation.StderrDigest: {}}}
}

func fixtureDependencies(outcome pv.Conclusion, calls *int) Dependencies {
	return Dependencies{Prepare: fixturePrepare, Release: func(*pv.PreparedSources) error { return nil }, PollInterval: 5 * time.Millisecond,
		Quiescent: func(context.Context) error { return nil }, Runner: &fakeRunner{check: func(_ context.Context, manifest pv.Manifest, binding pv.Binding, side string, check pv.Check) (pv.ExecutionEvidence, error) {
			*calls += 1
			output := check.Healthy.Stdout
			if side == pv.Original && check.Kind == pv.Reproduction {
				output = check.Failure.Stdout
			}
			if side == pv.Patched && ((outcome == pv.NotFixed && check.Kind == pv.Reproduction) || (outcome == pv.PartiallyFixed && check.ID == "problem-two") || (outcome == pv.Regression && check.Kind == pv.Normal)) {
				output = check.Failure.Stdout
			}
			if outcome == pv.UnableToVerify && check.ID == "problem-two" {
				output = "unexpected\n"
			}
			return fixtureEvidence(manifest, binding, side, check, output), nil
		}}}
}

func newTestService(t *testing.T, dependencies Dependencies) *Service {
	t.Helper()
	service, err := New(context.Background(), filepath.Join(t.TempDir(), "evidence.db"), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func TestServiceConclusions(t *testing.T) {
	for _, outcome := range []pv.Conclusion{pv.Verified, pv.NotFixed, pv.PartiallyFixed, pv.Regression, pv.UnableToVerify} {
		t.Run(string(outcome), func(t *testing.T) {
			calls := 0
			service := newTestService(t, fixtureDependencies(outcome, &calls))
			started := false
			result, err := service.Start(context.Background(), fixtureRequest(), func(summary Summary) error {
				started = true
				if calls != 0 || summary.JobStatus != "running" || summary.RunID == "" {
					t.Fatal("run ID was not emitted before execution")
				}
				return nil
			})
			expectedCalls := 6
			if outcome == pv.UnableToVerify {
				expectedCalls = 3
			}
			if err != nil || !started || result.Overall.Conclusion != outcome || calls != expectedCalls || result.Progress.Recorded != expectedCalls || result.JobStatus != "completed" {
				t.Fatalf("result=%+v calls=%d error=%v", result, calls, err)
			}
		})
	}
}

func TestServicePrepareFailure(t *testing.T) {
	calls := 0
	dependencies := fixtureDependencies(pv.Verified, &calls)
	dependencies.Prepare = func(context.Context, pv.Request) (*pv.PreparedSources, error) {
		return nil, errors.New("private diagnostic must not escape")
	}
	service := newTestService(t, dependencies)
	result, err := service.Start(context.Background(), fixtureRequest(), nil)
	if err == nil || strings.Contains(err.Error(), "private diagnostic") || result.Overall.Conclusion != pv.UnableToVerify || result.RunID != "" || calls != 0 {
		t.Fatalf("preparation did not fail closed: %+v %v", result, err)
	}
}

func TestServiceCancellation(t *testing.T) {
	for _, moment := range []string{"before", "during", "after"} {
		t.Run(moment, func(t *testing.T) {
			calls := 0
			dependencies := fixtureDependencies(pv.Verified, &calls)
			startedCheck := make(chan string, 1)
			stoppedCheck := make(chan struct{})
			if moment == "during" {
				dependencies.Runner = &fakeRunner{check: func(ctx context.Context, manifest pv.Manifest, binding pv.Binding, side string, check pv.Check) (pv.ExecutionEvidence, error) {
					calls++
					startedCheck <- binding.RunID
					<-ctx.Done()
					close(stoppedCheck)
					return fixtureEvidence(manifest, binding, side, check, "interrupted\n"), errors.New("check cancelled")
				}}
			}
			service := newTestService(t, dependencies)
			control, err := New(context.Background(), service.dbPath, Dependencies{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = control.Close() }()
			controlDone := make(chan error, 1)
			if moment == "during" {
				go func() {
					select {
					case runID := <-startedCheck:
						_, err := control.Cancel(context.Background(), runID)
						controlDone <- err
					case <-time.After(5 * time.Second):
						controlDone <- errors.New("check never started")
					}
				}()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := service.Start(ctx, fixtureRequest(), func(summary Summary) error {
				if moment == "before" {
					_, err := control.Cancel(context.Background(), summary.RunID)
					return err
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if moment == "after" {
				if result.Overall.Conclusion != pv.Verified {
					t.Fatal("expected completed verification before cancellation")
				}
				result, err = control.Cancel(context.Background(), result.RunID)
				if err != nil {
					t.Fatal(err)
				}
			}
			if moment == "during" {
				if err := <-controlDone; err != nil {
					t.Fatal(err)
				}
				select {
				case <-stoppedCheck:
				default:
					t.Fatal("cancelled check was not stopped")
				}
			}
			wantState, wantConclusion := pv.RunCancelled, pv.UnableToVerify
			if moment == "after" {
				wantState, wantConclusion = pv.RunFinalized, pv.Verified
			}
			if result.State != wantState || result.Overall.Conclusion != wantConclusion || (moment == "before" && calls != 0) || (moment == "during" && calls != 1) {
				t.Fatalf("cancellation failed: %+v calls=%d", result, calls)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := New(context.Background(), service.dbPath, Dependencies{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reopened.Close() }()
			persisted, err := reopened.Get(context.Background(), result.RunID)
			if err != nil || persisted.State != wantState || persisted.Overall.Conclusion != wantConclusion {
				t.Fatalf("cancellation did not survive reopen: %+v %v", persisted, err)
			}
		})
	}
}

func createRunning(t *testing.T, service *Service) pv.Binding {
	t.Helper()
	request := fixtureRequest()
	prepared, err := fixturePrepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	manifest := pv.Manifest{Version: pv.SchemaVersion, Problem: request.Problem, Scope: request.Scope, Sources: prepared.Sources, Files: prepared.Files, Checks: request.Checks,
		Environment: pv.Environment{Image: request.Image, ImageID: pv.Digest([]byte("image")), Profile: pv.Offline, Platform: request.Platform}}
	binding, err := pv.NewRunBinding(manifest, uuid.NewString(), uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.storage.CreatePatchVerificationRun(context.Background(), manifest, binding, prepared.Provenance); err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestServiceRecoveryRequiresAbsentOwner(t *testing.T) {
	service := newTestService(t, Dependencies{Quiescent: func(context.Context) error { return nil }})
	binding := createRunning(t, service)
	owner, err := AcquireOwner(service.dbPath, binding.RunID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := service.Recover(context.Background(), binding.RunID); !errors.Is(err, ErrLiveOwner) {
		t.Fatalf("live recovery was not rejected: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	service.dependencies.Quiescent = func(context.Context) error { return errors.New("orphan container") }
	if _, err := service.Recover(context.Background(), binding.RunID); err == nil {
		t.Fatal("recovery accepted an unquiesced executor")
	}
	service.dependencies.Quiescent = func(context.Context) error { return nil }
	result, err := service.Recover(context.Background(), binding.RunID)
	if err != nil || result.State != pv.RunInterrupted || result.Overall.Conclusion != pv.UnableToVerify {
		t.Fatalf("recovery failed: %+v %v", result, err)
	}
	reopened, err := New(context.Background(), service.dbPath, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	result, err = reopened.Get(context.Background(), binding.RunID)
	if err != nil || result.State != pv.RunInterrupted {
		t.Fatal("interruption did not persist", err)
	}
}

func TestServiceNewAttemptAndAuxiliaryTasks(t *testing.T) {
	calls := 0
	service := newTestService(t, fixtureDependencies(pv.Verified, &calls))
	seen := make(map[string]bool)
	request := fixtureRequest()
	for index := range 3 {
		if index == 2 {
			request.Problem = "new problem description"
		}
		result, err := service.Start(context.Background(), request, nil)
		if err != nil || seen[result.RunID] {
			t.Fatalf("attempt reused a run: %+v %v", result, err)
		}
		seen[result.RunID] = true
		record, err := service.Record(context.Background(), result.RunID)
		if err != nil {
			t.Fatal(err)
		}
		for _, task := range Tasks(record) {
			if _, err := uuid.Parse(string(task.UID)); err != nil || task.Namespace != TaskNamespace || task.Spec.Workspace.Intent != orkav1alpha1.WorkspaceIntentRead || task.Spec.RetryPolicy.MaxRetries != 0 || task.Spec.SecretRef != nil || task.Spec.Workspace.CreatePR || task.Spec.Command[2] != "exit 125" {
				t.Fatal("Task identity or sandbox placeholder is invalid")
			}
			content, _, err := service.storage.GetArtifact(context.Background(), task.Namespace, task.Name, "task.json")
			var persisted orkav1alpha1.Task
			if err != nil || json.Unmarshal(content, &persisted) != nil || persisted.UID != task.UID {
				t.Fatal("Task artifact missing", err)
			}
			if _, err := service.storage.GetResult(context.Background(), task.Namespace, task.Name); err != nil {
				t.Fatal("Task result missing", err)
			}
			if err := service.storage.DeleteArtifacts(context.Background(), task.Namespace, task.Name); err != nil {
				t.Fatal(err)
			}
		}
		after, err := service.Get(context.Background(), result.RunID)
		if err != nil || after.Overall.Conclusion != pv.Verified {
			t.Fatal("Task cleanup changed authoritative evidence", err)
		}
	}
}

func TestServiceFailedAttemptsAndRejectedCapture(t *testing.T) {
	for _, mode := range []string{"runner-error", "credential", "service-stderr", "unreferenced"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			dependencies := fixtureDependencies(pv.Verified, &calls)
			request := fixtureRequest()
			if mode == "service-stderr" {
				request.Profile = pv.LocalServices
				request.Services = []pv.Service{{ID: "fixture", Port: 8080, Command: []string{"/checks/run"}, ReadyOutput: "ready\n"}}
				for index := range request.Checks {
					request.Checks[index].Healthy.Services = map[string]string{"fixture": "ready\n"}
					request.Checks[index].Failure.Services = map[string]string{"fixture": "ready\n"}
				}
			}
			dependencies.Runner = &fakeRunner{check: func(_ context.Context, manifest pv.Manifest, binding pv.Binding, side string, check pv.Check) (pv.ExecutionEvidence, error) {
				calls++
				output := check.Healthy.Stdout
				if side == pv.Original && check.Kind == pv.Reproduction {
					output = check.Failure.Stdout
				}
				if mode == "credential" {
					output = "password=unit-test-not-a-real-credential"
				}
				evidence := fixtureEvidence(manifest, binding, side, check, output)
				if mode == "unreferenced" {
					evidence.Blobs[pv.Digest([]byte("extra"))] = []byte("extra")
				}
				if mode == "service-stderr" {
					content := []byte("ready\n")
					evidence.Observation.ServiceOutputs = map[string]pv.CapturedOutput{"fixture": {Digest: pv.Digest(content), Bytes: len(content)}}
					evidence.Blobs[pv.Digest(content)] = content
					return evidence, errors.New("fixture wrote private diagnostic output")
				}
				if mode == "runner-error" {
					return evidence, errors.New("private diagnostic must not escape")
				}
				return evidence, nil
			}}
			service := newTestService(t, dependencies)
			result, _ := service.Start(context.Background(), request, nil)
			if result.Overall.Conclusion != pv.UnableToVerify {
				t.Fatal("failed evidence became favorable", result)
			}
			record, err := service.Record(context.Background(), result.RunID)
			if err != nil || len(record.Evidence) == 0 {
				t.Fatal("failed attempt missing", err)
			}
			if mode == "runner-error" || mode == "service-stderr" {
				if calls != 3 || len(record.Evidence) != 3 || strings.Contains(record.Evidence[0].Observation.SetupError, "private diagnostic") {
					t.Fatal("did not collect every failed attempt safely")
				}
				for _, task := range Tasks(record) {
					if task.Status.Phase != orkav1alpha1.TaskPhaseFailed {
						t.Fatal("failed execution was projected as a successful Task")
					}
				}
			} else if calls != 1 || record.State != pv.RunInvalid || len(record.Incidents) == 0 {
				t.Fatal("invalid capture was not rejected durably")
			}
			for _, forbidden := range []string{"password=unit-test-not-a-real-credential", "extra", "private diagnostic must not escape"} {
				if _, err := service.storage.GetPatchVerificationBlob(context.Background(), result.RunID, pv.Digest([]byte(forbidden))); err == nil {
					t.Fatal("rejected or unreferenced bytes were persisted")
				}
			}
		})
	}
}

func TestServiceContextCancellationAndTimeout(t *testing.T) {
	for _, mode := range []string{"pre-cancelled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			dependencies := fixtureDependencies(pv.Verified, &calls)
			if mode == "deadline" {
				dependencies.Timeout = 150 * time.Millisecond
				dependencies.Runner = &fakeRunner{check: func(ctx context.Context, manifest pv.Manifest, binding pv.Binding, side string, check pv.Check) (pv.ExecutionEvidence, error) {
					calls++
					<-ctx.Done()
					return fixtureEvidence(manifest, binding, side, check, "timeout\n"), ctx.Err()
				}}
			}
			service := newTestService(t, dependencies)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "pre-cancelled" {
				cancel()
			}
			result, _ := service.Start(ctx, fixtureRequest(), nil)
			if result.Overall.Conclusion != pv.UnableToVerify || (mode == "pre-cancelled" && calls != 0) || (mode == "deadline" && result.State != pv.RunCancelled) {
				t.Fatalf("context cancellation failed: %+v calls=%d", result, calls)
			}
		})
	}
}

func TestServiceCleanupFailurePreventsSealSuccess(t *testing.T) {
	calls, releases := 0, 0
	dependencies := fixtureDependencies(pv.Verified, &calls)
	dependencies.Release = func(*pv.PreparedSources) error {
		releases++
		return errors.New("cleanup failed")
	}
	service := newTestService(t, dependencies)
	result, err := service.Start(context.Background(), fixtureRequest(), nil)
	if err == nil || result.Overall.Conclusion != pv.UnableToVerify || result.State != pv.RunInterrupted || releases != 1 || calls != 6 {
		t.Fatalf("cleanup failure was not terminal: %+v releases=%d calls=%d error=%v", result, releases, calls, err)
	}
	record, err := service.Record(context.Background(), result.RunID)
	if err != nil || (record.Seal != nil && record.Seal.Assessment.Conclusion == pv.Verified) {
		t.Fatal("cleanup failure produced a favorable seal", err)
	}
}

func TestServiceFreezesCallerOwnedInputs(t *testing.T) {
	calls := 0
	service := newTestService(t, fixtureDependencies(pv.Verified, &calls))
	request := fixtureRequest()
	result, err := service.Start(context.Background(), request, func(Summary) error {
		request.Checks[0].Healthy.Stdout = "changed after creation\n"
		request.Scope[0] = "different scope"
		return nil
	})
	if err != nil || result.Overall.Conclusion != pv.Verified {
		t.Fatalf("caller mutation affected frozen execution: %+v %v", result, err)
	}
	record, err := service.Record(context.Background(), result.RunID)
	if err != nil || record.Manifest.Checks[0].Healthy.Stdout != "healthy\n" || record.Manifest.Scope[0] != "normal and two problem variations" {
		t.Fatal("caller mutation changed persisted manifest", err)
	}
}
