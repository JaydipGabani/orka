package environment

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

func TestHTTPStatusRedirectAndBodyLimits(t *testing.T) {
	for _, mode := range []string{"wrong-status", "redirect", "oversized", "passed-flag", "wrong-path"} {
		t.Run(mode, func(t *testing.T) {
			f := testFixture(t)
			a, client := testAdapter(t, f)
			receipt, err := a.Start(t.Context(), fixtureRequest(f, 0, Candidate, "http-bound"))
			if err != nil {
				t.Fatal(err)
			}
			readyFixturePods(t, client, receipt)
			attachHTTPFixture(t, a, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/normal" {
					_, _ = io.WriteString(w, "healthy")
					return
				}
				switch mode {
				case "wrong-status":
					w.WriteHeader(201)
					_, _ = io.WriteString(w, "fixed")
				case "redirect":
					w.Header().Set("Location", "/normal")
					w.WriteHeader(302)
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat("x", int(a.config.Limits.MaxBodyBytes)+1))
				case "passed-flag":
					_, _ = io.WriteString(w, `{"passed":true}`)
				case "wrong-path":
					http.NotFound(w, r)
				}
			}))
			observation, err := a.Observe(t.Context(), receipt)
			if err != nil || !observation.CleanupComplete {
				t.Fatalf("unsafe HTTP response did not fail closed with cleanup: %v", err)
			}
			if mode == "oversized" {
				if len(observation.Checks) != 0 || observation.Failure == nil || observation.Failure.Kind != Infrastructure {
					t.Fatal("truncated response was treated as a complete assertion")
				}
			} else if len(observation.Checks) != 2 || observation.Checks[0].Outcome != OutcomeOther ||
				observation.Failure != nil {
				t.Fatal("observer mistook a mismatched response for reproduction, health, or infrastructure failure")
			}
		})
	}
}

func TestDeleteUIDPreconditionSurvivesGetDeleteRace(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	receipt, err := a.Start(t.Context(), fixtureRequest(f, 0, Candidate, "delete-race"))
	if err != nil {
		t.Fatal(err)
	}
	identity := receipt.Objects[len(receipt.Objects)-1]
	client.PrependReactor("delete", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		current, err := client.Tracker().Get(action.GetResource(), identity.Namespace, identity.Name)
		if err != nil {
			t.Fatal(err)
		}
		current.(metav1.Object).SetUID("uid-replaced-during-delete")
		if err := client.Tracker().Update(action.GetResource(), current, identity.Namespace); err != nil {
			t.Fatal(err)
		}
		return false, nil, nil
	})
	assertKind(t, a.Cancel(t.Context(), receipt), Unknown)
	pod, err := client.CoreV1().Pods(identity.Namespace).Get(t.Context(), identity.Name, metav1.GetOptions{})
	if err != nil || pod.UID != "uid-replaced-during-delete" {
		t.Fatal("UID-fenced delete removed a replacement")
	}
}

func TestRuntimeMutationDuringProbeCannotProduceEvidence(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	receipt, err := a.Start(t.Context(), fixtureRequest(f, 0, Candidate, "during-probe"))
	if err != nil {
		t.Fatal(err)
	}
	readyFixturePods(t, client, receipt)
	identity := receipt.Objects[len(receipt.Objects)-1]
	attachHTTPFixture(t, a, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pod, err := client.CoreV1().Pods(identity.Namespace).Get(t.Context(), identity.Name, metav1.GetOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		pod.Status.ContainerStatuses[0].ContainerID = "containerd://replacement"
		if _, err := client.CoreV1().Pods(identity.Namespace).UpdateStatus(t.Context(), pod, metav1.UpdateOptions{}); err != nil {
			t.Error(err)
		}
		_, _ = io.WriteString(w, "fixed")
	}))
	result, err := a.Observe(t.Context(), receipt)
	if err != nil || result.Failure == nil || result.Failure.Kind != Unknown ||
		len(result.Checks) != 0 || !result.CleanupComplete {
		t.Fatal("HTTP bytes from a changed runtime were accepted")
	}
}

func TestKubernetesDefaultsDoNotPermitAdmissionEscapes(t *testing.T) {
	f := testFixture(t)
	a, _ := testAdapter(t, f)
	receipt, err := a.Intent(fixtureRequest(f, 0, Candidate, "defaults"))
	if err != nil {
		t.Fatal(err)
	}
	desired := a.pod(receipt, receipt.Objects[len(receipt.Objects)-1]).Spec
	actual := *desired.DeepCopy()
	actual.ServiceAccountName = "default"
	actual.SchedulerName = "default-scheduler"
	actual.DNSPolicy = corev1.DNSClusterFirst
	actual.NodeName = "scheduler-owned-node"
	actual.Containers[0].TerminationMessagePath = "/dev/termination-log"
	actual.Containers[0].TerminationMessagePolicy = corev1.TerminationMessageReadFile
	before := *actual.DeepCopy()
	if !samePodSpec(actual, desired) || !sameJSON(before, actual) {
		t.Fatal("default normalization rejected harmless defaults or mutated the observed object")
	}
	for _, mutate := range []func(*corev1.PodSpec){
		func(p *corev1.PodSpec) { p.ServiceAccountName = "privileged" },
		func(p *corev1.PodSpec) { p.HostNetwork = true },
		func(p *corev1.PodSpec) { p.Containers[0].Command = []string{"sh", "-c", "true"} },
		func(p *corev1.PodSpec) { p.Volumes = []corev1.Volume{{Name: "injected"}} },
		func(p *corev1.PodSpec) { p.Containers[0].Image = "registry.example.invalid/mutable:latest" },
		func(p *corev1.PodSpec) { p.Tolerations = []corev1.Toleration{{Operator: corev1.TolerationOpExists}} },
	} {
		changed := *actual.DeepCopy()
		mutate(&changed)
		if samePodSpec(changed, desired) {
			t.Fatal("admission mutation escaped the exact workload contract")
		}
	}
}

func TestCancelledStartSettlesCreatedNamespace(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client.PrependReactor("create", "networkpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
		cancel()
		return true, nil, context.Canceled
	})
	receipt, err := a.Start(ctx, fixtureRequest(f, 0, Candidate, "cancel-start"))
	assertKind(t, err, Infrastructure)
	result, err := a.Observe(t.Context(), receipt)
	if err != nil || !result.CleanupComplete || result.Failure == nil || len(result.Checks) != 0 {
		t.Fatal("cancelled Start leaked its already-created namespace")
	}
}

func TestRecipeRejectsSymlinksAndChangesOutsideCandidatePatch(t *testing.T) {
	f := testFixture(t)
	a, _ := testAdapter(t, f)
	root := f.config.Repositories[0].RecipeRoot
	original := filepath.Join(root, "recipe.yml")
	saved := filepath.Join(root, "recipe.saved")
	if os.Rename(original, saved) != nil || os.Symlink(saved, original) != nil {
		t.Fatal("could not construct safe local symlink fixture")
	}
	_, err := a.recipeSnapshot(BuildRequest{Plan: f.plans[0], Role: RebuiltControl})
	assertKind(t, err, NeedsAdapter)
	if os.Remove(original) != nil || os.Rename(saved, original) != nil {
		t.Fatal("could not restore recipe fixture")
	}
	data, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(original, append(data, []byte("# changed without acquisition approval\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = a.recipeSnapshot(BuildRequest{Plan: f.plans[0], Role: RebuiltControl})
	assertKind(t, err, NeedsAdapter)
}

func TestForeignNamespaceAndForgedExpectedUIDDoNotGetAdopted(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	request := fixtureRequest(f, 0, Candidate, "foreign")
	intent, err := a.Intent(request)
	if err != nil {
		t.Fatal(err)
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: intent.Objects[0].Name}}
	if _, err := client.CoreV1().Namespaces().Create(t.Context(), namespace, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	before := createCount(client)
	_, err = a.Start(t.Context(), request)
	assertKind(t, err, Unknown)
	if createCount(client) != before {
		t.Fatal("mismatched existing namespace was adopted")
	}
	request.Expected = []ObjectIdentity{{Kind: namespaceKind, Name: "not-derived-from-run", UID: types.UID("foreign")}}
	_, err = a.Intent(request)
	assertKind(t, err, Unknown)
}
