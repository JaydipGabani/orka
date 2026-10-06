package environment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/provenance"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type fixture struct {
	config Config
	plans  []Plan
	root   string
}

func testFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	config := Config{
		OutputRoot: filepath.Join(root, "output"), TemporaryRoot: filepath.Join(root, "work"),
		SyntheticScope: "unit-fixtures",
		Kubernetes:     &KubernetesConfig{ObserverCIDRs: []string{"192.0.2.1/32"}},
		AllowedGVKs:    []schema.GroupVersionKind{{Version: "v1", Kind: "Pod"}},
	}
	plans := make([]Plan, 0, 2)
	for _, language := range []string{"go", "native"} {
		source := filepath.Join(root, language, "source")
		recipes := filepath.Join(root, language, "recipes")
		for _, directory := range []string{source, filepath.Join(recipes, "patches")} {
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
		}
		recipe := fmt.Sprintf(`# syntax=registry.example.invalid/dalec@sha256:%s
name: http-%s
version: "1.0.0"
revision: "1"
sources:
  upstream:
    git:
      url: https://example.invalid/fixtures/%s
      commit: %s
  vendor:
    context: {name: context}
    path: patches
patches:
  upstream:
    - source: vendor
      path: first.patch
      strip: 1
    - source: vendor
      path: second.patch
      strip: 0
build:
  env:
    BUILD_LANGUAGE: %s
  steps:
    - command: make build
dependencies:
  build:
    compiler:
      version: ["=1.0.0"]
x-build-extensions:
  build-targets:
    linux/container:
      platforms: [linux/amd64]
`, strings.Repeat("f", 64), language, language, strings.Repeat("a", 40), language)
		files := map[string][]byte{
			"recipe.yml":           []byte(recipe),
			"patches/first.patch":  []byte("--- a/main\n+++ b/main\n@@ -1 +1 @@\n-before\n+vendor\n"),
			"patches/second.patch": []byte("--- main\n+++ main\n@@ -1 +1 @@\n-vendor\n+downstream\n"),
		}
		approved := map[string]string{}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(recipes, name), data, 0600); err != nil {
				t.Fatal(err)
			}
			approved[name] = digest(data)
		}
		if language == "go" {
			if err := os.WriteFile(filepath.Join(source, "main.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(filepath.Join(source, "main.c"), []byte("int main(void) { return 0; }\n"), 0600); err != nil {
			t.Fatal(err)
		}
		r := RecipePolicy{
			ID: language, Commit: strings.Repeat("b", 40), Path: "recipe.yml",
			Files: approved, UpstreamSource: "upstream", Target: "linux/container", Platform: "linux/amd64",
			FrontendImage: "registry.example.invalid/dalec@sha256:" + strings.Repeat("f", 64),
			WorkerImage:   "registry.example.invalid/worker@sha256:" + strings.Repeat("e", 64),
			OriginalImage: "registry.example.invalid/original@sha256:" + strings.Repeat("1", 64),
		}
		repo := RepositoryPolicy{
			ID: language, URL: "https://example.invalid/fixtures/" + language, SourceRoot: source,
			RecipeRoot: recipes, RecipeRepository: "https://example.invalid/fixtures/" + language + "-recipes",
			Recipes: []RecipePolicy{r}, CheckCapabilities: []string{HTTPExact, EventSink}, HTTPPorts: []int32{8080},
		}
		config.Repositories = append(config.Repositories, repo)
		plans = append(plans, Plan{
			Version: Version,
			Bind: Bind{
				SourceTarget: SourceTarget{Repository: repo.URL, Commit: strings.Repeat("a", 40)},
				Recipe: RecipeIdentity{
					ID: r.ID, Repository: repo.RecipeRepository, Commit: r.Commit, Path: r.Path,
					ContentDigest: approved[r.Path], Target: r.Target, Platform: r.Platform,
					FrontendImage: r.FrontendImage, WorkerImage: r.WorkerImage,
				},
			},
			Namespaces: []Namespace{{Alias: "scenario"}},
			Resources:  []Resource{{ID: "service", Namespace: "scenario", GVK: config.AllowedGVKs[0], HTTP: &HTTPWorkload{Port: 8080}}},
			Checks: []Check{
				{ID: "reproduce", Class: Reproduction, Capability: HTTPExact,
					HTTP: &HTTPProbe{Resource: "service", Protocol: "http", Path: "/repro",
						Healthy: HTTPExpectation{Status: 200, Body: "fixed"}, Failure: &HTTPExpectation{Status: 200, Body: "broken"}}},
				{ID: "normal", Class: Normal, Capability: HTTPExact,
					HTTP: &HTTPProbe{Resource: "service", Protocol: "http", Path: "/normal", Healthy: HTTPExpectation{Status: 200, Body: "healthy"}}},
			},
		})
	}
	adapter, err := newAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	for index, plan := range plans {
		plans[index], err = adapter.FreezePlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range []Role{PublishedOriginal, RebuiltControl, Candidate} {
			image, patch := config.Repositories[index].Recipes[0].OriginalImage, ""
			if role == RebuiltControl {
				image = "registry.example.invalid/control@sha256:" + strings.Repeat("2", 64)
			}
			if role == Candidate {
				image, patch = "registry.example.invalid/candidate@sha256:"+strings.Repeat("3", 64), digest(candidatePatch())
			}
			config.ImageBindings = append(config.ImageBindings, ImageBinding{
				ID: config.Repositories[index].ID + "-" + string(role), Role: role,
				SourceTarget: plan.Bind.SourceTarget, Recipe: plan.Bind.Recipe, ChecksDigest: plans[index].Bind.ChecksDigest,
				PatchDigest: patch, Image: image, EvidenceDigest: "sha256:" + strings.Repeat("9", 64),
			})
		}
	}
	return fixture{config: config, plans: plans, root: root}
}

func candidatePatch() []byte {
	return []byte("--- a/main\n+++ b/main\n@@ -1 +1 @@\n-downstream\n+candidate\n")
}

func testAdapter(t *testing.T, f fixture) (*Adapter, *fake.Clientset) {
	t.Helper()
	adapter, err := newAdapter(f.config)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientset()
	var sequence atomic.Int64
	client.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject().(metav1.Object)
		object.SetUID(types.UID(fmt.Sprintf("uid-%d", sequence.Add(1))))
		object.SetCreationTimestamp(metav1.Now())
		return false, nil, nil
	})
	client.PrependReactor("delete", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		deletion := action.(ktesting.DeleteAction)
		uid := deletion.GetDeleteOptions().Preconditions
		if uid == nil || uid.UID == nil || *uid.UID == "" {
			t.Error("delete did not use a UID precondition")
			return true, nil, errors.New("missing UID precondition")
		}
		current, err := client.Tracker().Get(action.GetResource(), action.GetNamespace(), deletion.GetName())
		if err != nil {
			return true, nil, err
		}
		if current.(metav1.Object).GetUID() != *uid.UID {
			return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), deletion.GetName(), errors.New("UID changed"))
		}
		return false, nil, nil
	})
	adapter.kube = client
	return adapter, client
}

func fixtureRequest(f fixture, index int, role Role, operation string) Request {
	for _, binding := range f.config.ImageBindings {
		if binding.Role == role && binding.SourceTarget == f.plans[index].Bind.SourceTarget {
			return Request{
				RunID: f.config.Repositories[index].ID + "-run", OperationID: operation, Plan: f.plans[index],
				Subject: Subject{Role: role, Image: binding.Image, PatchDigest: binding.PatchDigest, ExternalBindingID: binding.ID},
			}
		}
	}
	panic("fixture binding missing")
}

func assertKind(t *testing.T, err error, kind ErrorKind) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != kind {
		t.Fatalf("want %s, got %v", kind, err)
	}
}

func readyFixturePods(t *testing.T, client *fake.Clientset, receipt Receipt) {
	t.Helper()
	for _, identity := range receipt.Objects {
		if identity.Kind != "Pod" {
			continue
		}
		pod, err := client.CoreV1().Pods(identity.Namespace).Get(t.Context(), identity.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		pod.Status = corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: "10.20.30.40",
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "subject", Image: identity.Image, ImageID: identity.Image,
				ContainerID: "containerd://fixture", Ready: true,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		}
		if _, err := client.CoreV1().Pods(identity.Namespace).UpdateStatus(t.Context(), pod, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func attachHTTPFixture(t *testing.T, a *Adapter, handler http.Handler) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, endpoint.Host)
	}
	a.http.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)
}

func TestTwoRepositoryHTTPObservations(t *testing.T) {
	f := testFixture(t)
	for index, language := range []string{"go", "native"} {
		for _, role := range []Role{PublishedOriginal, RebuiltControl, Candidate} {
			t.Run(language+"/"+string(role), func(t *testing.T) {
				a, client := testAdapter(t, f)
				request := fixtureRequest(f, index, role, string(role))
				receipt, err := a.Start(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				readyFixturePods(t, client, receipt)
				var hits atomic.Int64
				attachHTTPFixture(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
						t.Error("observer transmitted credentials or an unexpected method")
					}
					switch r.URL.Path {
					case "/normal":
						_, _ = io.WriteString(w, "healthy")
					case "/repro":
						if role == Candidate {
							_, _ = io.WriteString(w, "fixed")
						} else {
							_, _ = io.WriteString(w, "broken")
						}
					default:
						t.Error("unexpected probe path")
					}
				}))
				result, err := a.Observe(t.Context(), receipt)
				if err != nil {
					t.Fatal(err)
				}
				if !result.CleanupComplete || result.Phase != Completed || len(result.Checks) != 2 || hits.Load() != 2 {
					t.Fatalf("incomplete observations: %+v", result)
				}
				expected := OutcomeFailure
				if role == Candidate {
					expected = OutcomeHealthy
				}
				if result.Checks[0].Outcome != expected || result.Checks[1].Outcome != OutcomeHealthy ||
					result.Checks[0].PodUID == "" || result.Checks[0].RuntimeImageID != request.Subject.Image {
					t.Fatal("HTTP evidence did not bind exact bytes, runtime image and UID")
				}
				if result.Failure != nil {
					t.Fatal("assertion outcomes were incorrectly classified as execution failure")
				}
				before := len(client.Actions())
				replayed, err := a.Observe(t.Context(), receipt)
				if err != nil || !sameJSON(replayed, result) || len(client.Actions()) != before {
					t.Fatal("saved observations were not restart-safe and replay-free")
				}
			})
		}
	}
}

func TestStrictPlanRejectsExecutionEscapesBeforeKubernetes(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	tests := []struct {
		name   string
		change func(*Plan)
	}{
		{"https", func(p *Plan) { p.Checks[0].HTTP.Protocol = "https" }},
		{"controller", func(p *Plan) { p.Resources[0].GVK.Kind = "Deployment" }},
		{"namespace-bound", func(p *Plan) { p.Namespaces = append(p.Namespaces, make([]Namespace, 4)...) }},
		{"duplicate-check", func(p *Plan) { p.Checks[1].ID = p.Checks[0].ID }},
		{"external-url", func(p *Plan) { p.Checks[0].HTTP.Path = "http://attacker.invalid" }},
		{"query-credential", func(p *Plan) { p.Checks[0].HTTP.Path = "/?token=private" }},
		{"event-sink", func(p *Plan) { p.Checks[0].Capability = EventSink; p.Checks[0].Event = &EventSinkProbe{} }},
		{"mutable-commit", func(p *Plan) { p.Bind.SourceTarget.Commit = "main" }},
		{"secret-literal", func(p *Plan) { p.Checks[0].HTTP.Healthy.Body = "password=private-fixture" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, _ := json.Marshal(f.plans[0])
			plan, err := DecodePlan(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			plan.Bind.ChecksDigest = ""
			test.change(&plan)
			_, err = a.FreezePlan(plan)
			assertKind(t, err, NeedsAdapter)
		})
	}
	request := fixtureRequest(f, 0, Candidate, "tampered")
	request.Plan.Checks[0].HTTP.Healthy.Body = "changed after patch"
	_, err := a.Start(t.Context(), request)
	assertKind(t, err, NeedsAdapter)
	if len(client.Actions()) != 0 {
		t.Fatal("invalid input reached Kubernetes")
	}
	for _, text := range []string{
		`{"version":1,"version":1}`, `{"version":1,"VERSION":1}`, `{"version":1,"command":"sh"}`,
		`{"version":1} {}`, `{"resources":[{"http":{"port":8080,"command":"sh"}}]}`,
	} {
		if _, err := DecodePlan(strings.NewReader(text)); err == nil {
			t.Fatal("ambiguous or executable model JSON was accepted")
		}
	}
}

func TestLostCreateAcknowledgementRecoversWithoutReplacement(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	var failed atomic.Bool
	client.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		if failed.Swap(true) {
			return false, nil, nil
		}
		object := action.(ktesting.CreateAction).GetObject()
		object.(metav1.Object).SetUID("lost-ack-pod")
		object.(metav1.Object).SetCreationTimestamp(metav1.Now())
		if err := client.Tracker().Create(action.GetResource(), object, action.GetNamespace()); err != nil {
			t.Fatal(err)
		}
		return true, nil, errors.New("unavailable after create")
	})
	request := fixtureRequest(f, 0, Candidate, "lost-ack")
	initial, err := a.Start(t.Context(), request)
	assertKind(t, err, Infrastructure)
	before := createCount(client)
	restarted, err := newAdapter(f.config)
	if err != nil {
		t.Fatal(err)
	}
	restarted.kube = client
	request.RequireExisting = true
	recovered, err := restarted.Start(t.Context(), request)
	if err != nil || createCount(client) != before || recovered.OperationDigest != initial.OperationDigest {
		t.Fatalf("lost acknowledgement was not safely recovered: %v", err)
	}
	if recovered.Objects[len(recovered.Objects)-1].UID != "lost-ack-pod" {
		t.Fatal("recovery did not capture the actual workload UID")
	}
	if err := restarted.Cancel(t.Context(), recovered); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Start(t.Context(), request); err != nil || createCount(client) != before {
		t.Fatal("consumed operation was recreated")
	}
}

func createCount(client *fake.Clientset) int {
	count := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" {
			count++
		}
	}
	return count
}

func TestRequireExistingNeverCreatesAndUIDReplacementBlocksCleanup(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	request := fixtureRequest(f, 0, Candidate, "lookup-only")
	request.RequireExisting = true
	receipt, err := a.Start(t.Context(), request)
	assertKind(t, err, Unknown)
	if createCount(client) != 0 {
		t.Fatal("lookup-only recovery created resources")
	}
	if err := a.Cancel(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
	request.RequireExisting, request.OperationID = false, "replacement"
	receipt, err = a.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	identity := receipt.Objects[len(receipt.Objects)-1]
	pod, err := client.CoreV1().Pods(identity.Namespace).Get(t.Context(), identity.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.UID = "replacement-not-owned"
	if _, err := client.CoreV1().Pods(identity.Namespace).Update(t.Context(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	assertKind(t, a.Cancel(t.Context(), receipt), Unknown)
	if _, err := client.CoreV1().Pods(identity.Namespace).Get(t.Context(), identity.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("cleanup deleted a replacement workload")
	}
	request.OperationID = "must-wait"
	_, err = a.Start(t.Context(), request)
	assertKind(t, err, Unknown)
}

func TestCleanupSettlementFencesRepeatedCandidates(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	request := fixtureRequest(f, 0, Candidate, "first")
	receipt, err := a.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	var pending atomic.Bool
	pending.Store(true)
	client.PrependReactor("delete", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return pending.Load(), nil, nil
	})
	err = a.Cancel(t.Context(), receipt)
	assertKind(t, err, Infrastructure)
	request.OperationID = "second"
	_, err = a.Start(t.Context(), request)
	assertKind(t, err, Unknown)
	pending.Store(false)
	if err := a.Cancel(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
	next, err := a.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if next.Objects[0].Name == receipt.Objects[0].Name || next.Objects[0].UID == receipt.Objects[0].UID {
		t.Fatal("candidate retry reused an earlier operation's namespace or UID")
	}
	if err := a.Cancel(t.Context(), next); err != nil {
		t.Fatal(err)
	}
}

func TestTimeoutCancelsWithoutObservation(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	receipt, err := a.Start(t.Context(), fixtureRequest(f, 0, Candidate, "timeout"))
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return receipt.Deadline.Add(time.Second) }
	observation, err := a.Observe(t.Context(), receipt)
	if err != nil || !observation.CleanupComplete || len(observation.Checks) != 0 ||
		observation.Failure == nil || observation.Failure.Kind != Infrastructure {
		t.Fatalf("timeout did not settle cleanup without evidence: %v", err)
	}
	namespaces, err := client.CoreV1().Namespaces().List(t.Context(), metav1.ListOptions{})
	if err != nil || len(namespaces.Items) != 0 {
		t.Fatal("timeout leaked a namespace")
	}
}

func TestConcurrentStartIsSingleCreateAndCapacityBounded(t *testing.T) {
	f := testFixture(t)
	f.config.Limits.MaxActiveRuns = 1
	a, client := testAdapter(t, f)
	request := fixtureRequest(f, 0, Candidate, "concurrent")
	var wg sync.WaitGroup
	results := make(chan Receipt, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			receipt, err := a.Start(t.Context(), request)
			results <- receipt
			errs <- err
		})
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var receipt Receipt
	for result := range results {
		if receipt.OperationDigest != "" && !sameJSON(receipt, result) {
			t.Fatal("concurrent Start returned different fenced resources")
		}
		receipt = result
	}
	if createCount(client) != 3 {
		t.Fatal("concurrent Start created replacement resources")
	}
	other := fixtureRequest(f, 1, Candidate, "capacity")
	partial, err := a.Start(t.Context(), other)
	assertKind(t, err, Infrastructure)
	if createCount(client) != 3 {
		t.Fatal("capacity exhaustion created another namespace")
	}
	if err := a.Cancel(t.Context(), partial); err != nil {
		t.Fatal(err)
	}
	if err := a.Cancel(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
}

func TestDalecInsertionPreservesOriginalBytesAndPatchOrder(t *testing.T) {
	f := testFixture(t)
	a, _ := testAdapter(t, f)
	for _, plan := range f.plans {
		snapshot, err := a.recipeSnapshot(BuildRequest{Plan: plan, Role: Candidate, Patch: candidatePatch(), PatchDigest: digest(candidatePatch())})
		if err != nil {
			t.Fatal(err)
		}
		if len(snapshot.baseline.OrderedPatches) != 2 || len(snapshot.built.OrderedPatches) != 3 ||
			provenance.CompareWithAdditionalPatch(snapshot.baseline, snapshot.built, digest(candidatePatch())) != nil ||
			snapshot.baseline.BuildEnvironment["BUILD_LANGUAGE"] != plan.Bind.Recipe.ID ||
			snapshot.built.EvidenceStatus != provenance.EvidencePartial {
			t.Fatal("candidate recipe lost downstream inputs or overstated provenance")
		}
		repo, recipe, err := a.policy(plan.Bind)
		if err != nil {
			t.Fatal(err)
		}
		original, err := os.ReadFile(filepath.Join(repo.RecipeRoot, recipe.Path))
		if err != nil {
			t.Fatal(err)
		}
		updated := snapshot.files[recipe.Path]
		position := 0
		for _, line := range bytes.SplitAfter(original, []byte("\n")) {
			found := bytes.Index(updated[position:], line)
			if found < 0 {
				t.Fatal("original recipe bytes were rewritten instead of inserted around")
			}
			position += found + len(line)
		}
		if bytes.Contains(updated, []byte("passed")) {
			t.Fatal("unexpected test-driver output in recipe")
		}
	}
}

func TestBuildNeedsAdapterWithoutPrerequisites(t *testing.T) {
	f := testFixture(t)
	a, _ := testAdapter(t, f)
	_, err := a.Build(t.Context(), BuildRequest{
		RunID: "build", OperationID: "control", Plan: f.plans[0], Role: RebuiltControl,
	})
	assertKind(t, err, NeedsAdapter)
}
