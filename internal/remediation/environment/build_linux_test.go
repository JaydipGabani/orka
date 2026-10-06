//go:build linux

package environment

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type commandInstrumentation struct {
	Arguments []string          `json:"arguments"`
	Env       map[string]string `json:"env"`
	Files     []string          `json:"files"`
	Recipe    string            `json:"recipe"`
	Calls     int               `json:"calls"`
}

func readInstrumentation(t *testing.T, name string) commandInstrumentation {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var evidence commandInstrumentation
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	return evidence
}

func instrumentedBuilder(t *testing.T, f *fixture, mode string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executable = filepath.Join(f.root, "fixture-buildctl")
	if err := os.WriteFile(executable, content, 0700); err != nil {
		t.Fatal(err)
	}
	instrumentation := filepath.Join(f.root, "command.json")
	f.config.BuildKit = &BuildKitConfig{
		Command:          []string{executable, "-test.run=^TestBuildctlProcess$", "--", "buildctl-fixture", mode, instrumentation},
		ExecutableDigest: digest(content), Address: "unix:///operator-approved/buildkit.sock",
		WorkerImageArgument:  "FIXTURE_WORKER_IMAGE",
		WorkerEvidenceDigest: "sha256:" + strings.Repeat("8", 64),
		OutputRepository:     "registry.example.invalid/remediation",
	}
	return instrumentation
}

// This is an actual child process implementing the buildctl input/output
// boundary. It is not a Build method mock and does not execute recipe commands.
// Real Dalec/BuildKit qualification remains an operator deployment prerequisite.
func TestBuildctlProcess(t *testing.T) {
	index := slices.Index(os.Args, "buildctl-fixture")
	if index < 0 {
		return
	}
	if index+3 >= len(os.Args) {
		os.Exit(21)
	}
	mode, destination := os.Args[index+1], os.Args[index+2]
	args := os.Args[index+3:]
	evidence := commandInstrumentation{Arguments: args, Env: map[string]string{}, Calls: 1}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		evidence.Env[key] = value
	}
	var previous commandInstrumentation
	if data, err := os.ReadFile(destination); err == nil && json.Unmarshal(data, &previous) == nil {
		evidence.Calls += previous.Calls
	}
	options := map[string]string{}
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--opt", "--local":
			key, value, _ := strings.Cut(args[i+1], "=")
			options[key] = value
		case "--metadata-file":
			options["metadata"] = args[i+1]
		case "--output":
			options["output"] = args[i+1]
		}
	}
	contextRoot := options["context"]
	err := filepath.WalkDir(contextRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			name, err := filepath.Rel(contextRoot, path)
			if err != nil {
				return err
			}
			evidence.Files = append(evidence.Files, name)
		}
		return nil
	})
	if err != nil {
		os.Exit(22)
	}
	recipe, err := os.ReadFile(filepath.Join(contextRoot, options["filename"]))
	if err != nil || !validBuildFixtureOptions(options) {
		os.Exit(23)
	}
	evidence.Recipe = string(recipe)
	data, _ := json.Marshal(evidence)
	if os.WriteFile(destination, data, 0600) != nil {
		os.Exit(24)
	}
	switch mode {
	case "failure":
		fmt.Println("compiler.c:1: error: synthetic-private-marker password=fixture-only")
		os.Exit(4)
	case "overflow":
		fmt.Print(strings.Repeat("private-fixture-output", 100000))
		os.Exit(0)
	case "verbose-success":
		fmt.Print(strings.Repeat("non-sensitive-build-progress\n", 100000))
	case "timeout":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "passed-boolean":
		if os.WriteFile(options["metadata"], []byte(`{"passed":true}`), 0600) != nil {
			os.Exit(25)
		}
		os.Exit(0)
	case "symlink-metadata":
		if os.Symlink(destination, options["metadata"]) != nil {
			os.Exit(26)
		}
		os.Exit(0)
	}
	imageDigest := "sha256:" + strings.Repeat("2", 64)
	if strings.Contains(evidence.Recipe, "orka-candidate-") {
		imageDigest = "sha256:" + strings.Repeat("3", 64)
	}
	data, _ = json.Marshal(map[string]string{"containerimage.digest": imageDigest})
	if os.WriteFile(options["metadata"], data, 0600) != nil {
		os.Exit(27)
	}
	os.Exit(0)
}

func TestTypedBuildctlRequestAndImmutableResponse(t *testing.T) {
	t.Setenv("SYNTHETIC_PRIVATE_CREDENTIAL", "must-not-reach-child")
	for index, language := range []string{"go", "native"} {
		t.Run(language, func(t *testing.T) {
			f := testFixture(t)
			for i := range f.config.Repositories {
				if err := os.RemoveAll(f.config.Repositories[i].SourceRoot); err != nil {
					t.Fatal(err)
				}
				f.config.Repositories[i].SourceRoot = ""
			}
			instrumentation := instrumentedBuilder(t, &f, "success")
			a, _ := testAdapter(t, f)
			request := BuildRequest{
				RunID: language + "-build", OperationID: "control", Plan: f.plans[index], Role: RebuiltControl,
			}
			control, err := a.Build(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			request.Role, request.OperationID = Candidate, "candidate"
			request.Patch, request.PatchDigest = candidatePatch(), digest(candidatePatch())
			candidate, err := a.Build(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if control.Subject.Role != RebuiltControl || candidate.Subject.Role != Candidate ||
				control.Subject.Image == candidate.Subject.Image || control.Subject.BuildID == candidate.Subject.BuildID ||
				candidate.Subject.PatchDigest != request.PatchDigest || candidate.MetadataDigest == "" ||
				candidate.Built.EvidenceStatus != "partial" || candidate.CommandDigest == "" ||
				candidate.WorkerEvidenceDigest != f.config.BuildKit.WorkerEvidenceDigest {
				t.Fatal("build result did not distinguish pinned source/control/candidate evidence")
			}
			actual := readInstrumentation(t, instrumentation)
			if actual.Calls != 2 || len(actual.Files) != 4 || len(actual.Env) != 7 ||
				actual.Env["SYNTHETIC_PRIVATE_CREDENTIAL"] != "" ||
				!slices.Contains(actual.Arguments, "source="+request.Plan.Bind.Recipe.FrontendImage) ||
				!slices.Contains(actual.Arguments, "build-arg:FIXTURE_WORKER_IMAGE="+request.Plan.Bind.Recipe.WorkerImage) ||
				!strings.Contains(actual.Recipe, "BUILD_LANGUAGE: "+language) {
				t.Fatal("actual child argv, sanitized environment, or exact build context was wrong")
			}
			again, err := a.Build(t.Context(), request)
			if err != nil || !sameJSON(again, candidate) {
				t.Fatal("completed build was not recovered by typed identity")
			}
			if readInstrumentation(t, instrumentation).Calls != 2 {
				t.Fatal("replayed build executed another child")
			}
			work, err := os.ReadDir(f.config.TemporaryRoot)
			if err != nil || len(work) != 0 {
				t.Fatal("build left candidate inputs behind")
			}
			receipt, err := a.Start(t.Context(), Request{
				RunID: request.RunID, OperationID: "observe-built", Plan: request.Plan, Subject: candidate.Subject,
			})
			if err != nil {
				t.Fatal("trusted persisted build output was not accepted for observation")
			}
			if err := a.Cancel(t.Context(), receipt); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBuildFailuresAreBoundedAndDoNotExposeCompilerText(t *testing.T) {
	for _, mode := range []string{"failure", "overflow", "timeout", "passed-boolean", "symlink-metadata"} {
		t.Run(mode, func(t *testing.T) {
			f := testFixture(t)
			instrumentedBuilder(t, &f, mode)
			f.config.Limits.BuildTimeout = 10 * time.Second
			if mode == "timeout" {
				f.config.Limits.BuildTimeout = time.Second
			}
			f.config.Limits.MaxOutputBytes = 1024
			a, _ := testAdapter(t, f)
			started := time.Now()
			result, err := a.Build(t.Context(), BuildRequest{
				RunID: "bounded", OperationID: "control", Plan: f.plans[0], Role: RebuiltControl,
			})
			if err == nil || result.Subject.Image != "" || time.Since(started) > 5*time.Second {
				t.Fatal("failed or oversized builder output produced an image or escaped its time bound")
			}
			evidence, _ := json.Marshal(result)
			if strings.Contains(string(evidence)+err.Error(), "synthetic-private-marker") ||
				strings.Contains(string(evidence)+err.Error(), "password") {
				t.Fatal("raw compiler log entered diagnostics")
			}
			if mode == "failure" && (len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "compiler-type") {
				t.Fatal("trusted compiler classification was not retained")
			}
			if mode == "passed-boolean" {
				assertKind(t, err, BuildFailed)
			}
		})
	}
}

func TestBuilderMissingToolAndFrozenBindingFailClosed(t *testing.T) {
	f := testFixture(t)
	instrumentedBuilder(t, &f, "success")
	f.config.BuildKit.Command[0] = filepath.Join(f.root, "missing-buildctl")
	a, _ := testAdapter(t, f)
	request := BuildRequest{RunID: "prerequisite", OperationID: "control", Plan: f.plans[0], Role: RebuiltControl}
	_, err := a.Build(t.Context(), request)
	assertKind(t, err, NeedsAdapter)
	request.OperationID, request.RequireExisting = "lookup", true
	_, err = a.Build(t.Context(), request)
	assertKind(t, err, Unknown)
	request.Plan.Checks[0].HTTP.Healthy.Body = "post-patch-change"
	request.RequireExisting = false
	_, err = a.Build(t.Context(), request)
	assertKind(t, err, NeedsAdapter)
}

func TestVerboseSuccessfulBuildDrainsBoundedOutput(t *testing.T) {
	f := testFixture(t)
	instrumentedBuilder(t, &f, "verbose-success")
	f.config.Limits.MaxOutputBytes = 1024
	a, _ := testAdapter(t, f)
	result, err := a.Build(t.Context(), BuildRequest{
		RunID: "verbose", OperationID: "control", Plan: f.plans[0], Role: RebuiltControl,
	})
	if err != nil || result.Subject.Image == "" || !result.OutputTruncated {
		t.Fatalf("verbosity rejected a successful bounded build: %+v %v", result, err)
	}
}

func TestObservedBuildFailureIsRecoveredWithoutRerunning(t *testing.T) {
	f := testFixture(t)
	instrumentation := instrumentedBuilder(t, &f, "failure")
	a, _ := testAdapter(t, f)
	request := BuildRequest{RunID: "failed-build", OperationID: "candidate", Plan: f.plans[0],
		Role: Candidate, Patch: []byte("diff --git a/main.go b/main.go\n")}
	request.PatchDigest = digest(request.Patch)
	first, err := a.Build(t.Context(), request)
	assertKind(t, err, BuildFailed)
	request.RequireExisting = true
	second, err := a.Build(t.Context(), request)
	assertKind(t, err, BuildFailed)
	if first.ID != second.ID || len(second.Diagnostics) == 0 || readInstrumentation(t, instrumentation).Calls != 1 {
		t.Fatal("measured build failure was lost or executed again")
	}
}

func TestRecipeRejectsNetworkAndSharedCacheEscapes(t *testing.T) {
	for _, build := range []string{
		"build:\n  network_mode: sandbox\n  steps: []\n",
		"build:\n  caches:\n    - key: shared\n  steps: []\n",
	} {
		assertKind(t, offlineRecipe([]byte(build)), NeedsAdapter)
	}
	for _, build := range []string{"build:\n  steps: []\n", "build:\n  network_mode: none\n  steps: []\n"} {
		if err := offlineRecipe([]byte(build)); err != nil {
			t.Fatal(err)
		}
	}
}
