package environment

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func driftedConfig(f fixture) Config {
	config := f.config
	config.Repositories, config.ImageBindings, config.AllowedGVKs = nil, nil, nil
	kube := *config.Kubernetes
	kube.ObserverCIDRs = []string{"198.51.100.1/32"}
	config.Kubernetes = &kube
	config.SyntheticScope = "changed-scope"
	config.Limits = Limits{
		MaxOperations: 1, OperationTimeout: time.Second, ProbeTimeout: time.Millisecond,
		MaxBodyBytes: 1024, PodCPU: "500m", PodMemory: "128Mi",
	}
	return config
}

func TestObserveSettlesFrozenOperationAfterAllPoliciesAreRemoved(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	request := fixtureRequest(f, 0, Candidate, "older-completed")
	older, err := a.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Cancel(t.Context(), older); err != nil {
		t.Fatal(err)
	}
	request.OperationID = "in-flight"
	receipt, err := a.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	readyFixturePods(t, client, receipt)
	restarted, err := newAdapter(driftedConfig(f))
	if err != nil {
		t.Fatal(err)
	}
	restarted.kube = client
	attachHTTPFixture(t, restarted, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(10 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		if r.URL.Path == "/repro" {
			_, _ = io.WriteString(w, "fixed")
		} else {
			_, _ = io.WriteString(w, "healthy")
		}
	}))
	result, err := restarted.Observe(t.Context(), receipt)
	if err != nil || !result.CleanupComplete || result.Failure != nil || len(result.Checks) != 2 {
		t.Fatalf("configuration drift stranded or changed the operation: %v", err)
	}
	for _, check := range result.Checks {
		if check.Outcome != OutcomeHealthy {
			t.Fatal("frozen expectations changed during operator rollout")
		}
	}
	if !sameJSON(result.Receipt.Policy, receipt.Policy) || !result.Receipt.Deadline.Equal(receipt.Deadline) {
		t.Fatal("settlement changed frozen resource/network/deadline settings")
	}
	request.OperationID = "new-disallowed-operation"
	_, err = restarted.Start(t.Context(), request)
	assertKind(t, err, NeedsAdapter)
}

func TestRequireExistingUsesRecordedPolicyAcrossConfigurationDrift(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	request := fixtureRequest(f, 0, Candidate, "recover-under-drift")
	receipt, err := a.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	before := createCount(client)
	restarted, err := newAdapter(driftedConfig(f))
	if err != nil {
		t.Fatal(err)
	}
	restarted.kube = client
	request.RequireExisting = true
	recovered, err := restarted.Start(t.Context(), request)
	if err != nil || !sameJSON(recovered, receipt) || createCount(client) != before {
		t.Fatalf("restart replaced resources or rejected the recorded policy: %v", err)
	}
	if err := restarted.Cancel(t.Context(), recovered); err != nil {
		t.Fatal(err)
	}
}

func TestCancelRecoversParentReceiptAfterLocalJournalLoss(t *testing.T) {
	for _, useIntent := range []bool{false, true} {
		name := "acknowledged"
		if useIntent {
			name = "parent-intent"
		}
		t.Run(name, func(t *testing.T) {
			f := testFixture(t)
			a, client := testAdapter(t, f)
			request := fixtureRequest(f, 0, Candidate, "journal-loss")
			intent, err := a.Intent(request)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := a.Start(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(f.config.OutputRoot, runName(request.RunID)+".json")); err != nil {
				t.Fatal(err)
			}
			if _, err := client.CoreV1().Namespaces().Create(t.Context(),
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "another-case"}}, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			before := createCount(client)
			config := driftedConfig(f)
			config.OutputRoot = filepath.Join(f.root, "recovered-journal")
			restarted, err := newAdapter(config)
			if err != nil {
				t.Fatal(err)
			}
			restarted.kube = client
			if useIntent {
				receipt = intent
			}
			if err := restarted.Cancel(t.Context(), receipt); err != nil {
				t.Fatal(err)
			}
			namespaces, err := client.CoreV1().Namespaces().List(t.Context(), metav1.ListOptions{})
			if err != nil || len(namespaces.Items) != 1 || namespaces.Items[0].Name != "another-case" ||
				createCount(client) != before {
				t.Fatal("receipt recovery crossed case resources or created replacements")
			}
			result, err := restarted.Observe(t.Context(), receipt)
			if err != nil || result.Phase != Cancelled || !result.CleanupComplete || len(result.Checks) != 0 {
				t.Fatal("cancel recovery manufactured observation evidence")
			}
		})
	}
}

func TestObserveReconstructsFromParentReceiptWithoutReplay(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	request := fixtureRequest(f, 0, Candidate, "recover-observation")
	receipt, err := a.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	readyFixturePods(t, client, receipt)
	if err := os.Remove(filepath.Join(f.config.OutputRoot, runName(request.RunID)+".json")); err != nil {
		t.Fatal(err)
	}
	restarted, err := newAdapter(driftedConfig(f))
	if err != nil {
		t.Fatal(err)
	}
	restarted.kube = client
	attachHTTPFixture(t, restarted, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/normal" {
			_, _ = io.WriteString(w, "healthy")
		} else {
			_, _ = io.WriteString(w, "fixed")
		}
	}))
	before := createCount(client)
	result, err := restarted.Observe(t.Context(), receipt)
	if err != nil || !result.CleanupComplete || result.Failure != nil || len(result.Checks) != 2 ||
		createCount(client) != before {
		t.Fatalf("receipt observation recovery failed or recreated execution: %v", err)
	}
}

func TestRecoveryDoesNotCrossLabIdentity(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	receipt, err := a.Start(t.Context(), fixtureRequest(f, 0, Candidate, "cluster-fence"))
	if err != nil {
		t.Fatal(err)
	}
	config := driftedConfig(f)
	config.Kubernetes.Context = "different-lab"
	restarted, err := newAdapter(config)
	if err != nil {
		t.Fatal(err)
	}
	restarted.kube = client
	before := len(client.Actions())
	assertKind(t, restarted.Cancel(t.Context(), receipt), Unknown)
	if len(client.Actions()) != before {
		t.Fatal("cleanup touched a different lab identity")
	}
	if err := a.Cancel(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
}
