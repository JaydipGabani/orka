package isolation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type privateStore struct {
	mu      sync.Mutex
	encoded []byte
	fail    func(Receipt) bool
}

func (s *privateStore) persist(_ context.Context, receipt Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil && s.fail(receipt) {
		return errors.New("injected persistence failure")
	}
	var previous Receipt
	if len(s.encoded) != 0 {
		if err := json.Unmarshal(s.encoded, &previous); err != nil {
			return err
		}
	}
	if receipt.Revision != previous.Revision+1 || previous.CleanupComplete {
		return errors.New("stale revision or terminal tombstone")
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	s.encoded = encoded
	return nil
}

func (s *privateStore) load(t *testing.T) Receipt {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var receipt Receipt
	require.NoError(t, json.Unmarshal(s.encoded, &receipt))
	return receipt
}

type fixture struct {
	t       *testing.T
	kube    *fake.Clientset
	store   *privateStore
	clock   time.Time
	config  Config
	subject SubjectNamespace
	policy  PolicyIdentity
	labels  map[string]string
	results map[string]probe.Result
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ns := func(name, uid string) *corev1.Namespace {
		return &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid), ResourceVersion: "1", Labels: map[string]string{namespaceNameKey: name}},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}
	}
	subjectLabels := map[string]string{"component": "subject", "parent.run": "synthetic-run"}
	deny := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "subject-deny", Namespace: "proof-subject", UID: "deny-uid", ResourceVersion: "1"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
	client := fake.NewClientset(ns("kube-system", "cluster-uid"), ns("proof-subject", "subject-uid"), ns("proof-control", "control-uid"), deny)
	var counter atomic.Uint64
	client.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		created := action.(ktesting.CreateAction).GetObject().(metav1.Object)
		number := counter.Add(1)
		created.SetUID(types.UID(fmt.Sprintf("created-uid-%d", number)))
		created.SetResourceVersion(strconv.FormatUint(number+1, 10))
		created.SetCreationTimestamp(metav1.Now())
		if pod, ok := created.(*corev1.Pod); ok {
			pod.Spec.Tolerations = []corev1.Toleration{{
				Key: corev1.TaintNodeNotReady, Operator: corev1.TolerationOpExists,
				Effect: corev1.TaintEffectNoExecute, TolerationSeconds: new(int64(300)),
			}, {
				Key: corev1.TaintNodeUnreachable, Operator: corev1.TolerationOpExists,
				Effect: corev1.TaintEffectNoExecute, TolerationSeconds: new(int64(300)),
			}}
		}
		return false, nil, nil
	})
	// The fake tracker does not enforce UID deletion preconditions. Make the
	// harness enforce them, rather than letting name-only deletion tests pass.
	client.PrependReactor("delete", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		deletion := action.(ktesting.DeleteAction)
		options := deletion.GetDeleteOptions()
		actual, err := client.Tracker().Get(action.GetResource(), action.GetNamespace(), deletion.GetName())
		if err != nil {
			return true, nil, err
		}
		if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != actual.(metav1.Object).GetUID() {
			return true, nil, errors.New("UID precondition required")
		}
		return false, nil, nil
	})
	f := &fixture{
		t: t, kube: client, store: &privateStore{}, clock: time.Now().UTC(),
		config: Config{
			ProbeImage:       "example.invalid/trusted-probe@sha256:" + strings.Repeat("a", 64),
			ControlNamespace: SubjectNamespace{Name: "proof-control", UID: "control-uid"},
		},
		subject: SubjectNamespace{Name: "proof-subject", UID: "subject-uid"},
		policy:  policyIdentity(deny), labels: subjectLabels, results: map[string]probe.Result{},
	}
	return f
}

func (f *fixture) adapter() *Adapter {
	f.t.Helper()
	adapter, err := New(f.kube)
	require.NoError(f.t, err)
	adapter.now = func() time.Time { return f.clock }
	return adapter
}

func (f *fixture) start() Receipt {
	f.t.Helper()
	receipt, err := f.adapter().Start(context.Background(), f.config, "run-1", "operation-1", f.subject, f.labels, f.policy, f.store.persist)
	require.NoError(f.t, err)
	return receipt
}

func (f *fixture) drivePods(receipt Receipt) {
	f.t.Helper()
	for _, object := range receipt.Objects {
		if object.Kind != podKind || object.UID == "" || object.Deleted || object.DeleteRequested {
			continue
		}
		pod, err := f.kube.CoreV1().Pods(object.Namespace).Get(context.Background(), object.Name, metav1.GetOptions{})
		require.NoError(f.t, err)
		if pod.Status.Phase != "" && pod.Status.Phase != corev1.PodPending {
			continue
		}
		if object.Role == serverRole {
			pod.Spec.NodeName = "test-node"
			pod.Status = corev1.PodStatus{
				Phase: corev1.PodRunning, PodIP: "10.23.42.7",
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
				ContainerStatuses: []corev1.ContainerStatus{{
					Name: "probe", Image: f.config.ProbeImage, ImageID: "containerd://sha256:" + strings.Repeat("b", 64),
					Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(f.clock)}},
				}},
			}
			_, err = f.kube.CoreV1().Pods(object.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
			require.NoError(f.t, err)
			continue
		}
		result, supplied := f.results[object.Role]
		expect := probe.Reachable
		if object.Role == negativeRole {
			expect = probe.Blocked
		}
		if !supplied {
			result = probe.Result{Reachable: true, NonceMatched: true, FailureClass: probe.None}
			if expect == probe.Blocked {
				result = probe.Result{FailureClass: probe.DialTimeout}
			}
		}
		message, encodeErr := json.Marshal(result)
		require.NoError(f.t, encodeErr)
		started := f.clock
		f.clock = f.clock.Add(probe.Timeout)
		exitCode, phase, reason := int32(0), corev1.PodSucceeded, "Completed"
		if !probe.Matches(expect, result) {
			exitCode, phase, reason = 1, corev1.PodFailed, "Error"
		}
		pod.Status = corev1.PodStatus{
			Phase: phase,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "probe", Image: f.config.ProbeImage, ImageID: "containerd://sha256:" + strings.Repeat("b", 64),
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
					ExitCode: exitCode, Reason: reason, StartedAt: metav1.NewTime(started),
					FinishedAt: metav1.NewTime(f.clock), Message: string(message),
				}},
			}},
		}
		_, err = f.kube.CoreV1().Pods(object.Namespace).UpdateStatus(context.Background(), pod, metav1.UpdateOptions{})
		require.NoError(f.t, err)
	}
}

func (f *fixture) step(receipt Receipt) (Receipt, error) {
	f.t.Helper()
	f.drivePods(receipt)
	// Each call uses a fresh adapter and a JSON-decoded receipt. An in-memory
	// pointer or cache cannot accidentally make restart coverage pass.
	return f.adapter().Observe(context.Background(), f.store.load(f.t), f.store.persist)
}

func (f *fixture) until(receipt Receipt, condition func(Receipt) bool) Receipt {
	f.t.Helper()
	for range 80 {
		if condition(receipt) {
			return receipt
		}
		var err error
		receipt, err = f.step(receipt)
		require.NoError(f.t, err)
	}
	require.FailNow(f.t, "proof did not reach expected state")
	return Receipt{}
}

func (f *fixture) clean(receipt Receipt) Receipt {
	f.t.Helper()
	for range 80 {
		if receipt.CleanupComplete {
			return receipt
		}
		var err error
		receipt, err = f.adapter().Cancel(context.Background(), receipt, f.store.persist)
		require.NoError(f.t, err)
	}
	require.FailNow(f.t, "cleanup did not finish")
	return Receipt{}
}

func (f *fixture) noLeaks() {
	f.t.Helper()
	for _, namespace := range []string{f.subject.Name, f.config.ControlNamespace.Name} {
		pods, err := f.kube.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
		require.NoError(f.t, err)
		require.Empty(f.t, pods.Items)
	}
	controlPolicies, err := f.kube.NetworkingV1().NetworkPolicies(f.config.ControlNamespace.Name).List(context.Background(), metav1.ListOptions{})
	require.NoError(f.t, err)
	require.Empty(f.t, controlPolicies.Items)
	namespaces, err := f.kube.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	require.NoError(f.t, err)
	require.Len(f.t, namespaces.Items, 3)
	subjectPolicy, err := f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Get(context.Background(), f.policy.Name, metav1.GetOptions{})
	require.NoError(f.t, err)
	require.Equal(f.t, f.policy.UID, subjectPolicy.UID)
}

func TestProofBracketsDenialAndSurvivesEveryStepRestart(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.start()
	require.True(t, probe.ValidNonce(receipt.Nonce))
	require.Equal(t, uint64(1), receipt.Revision)
	require.Empty(t, mutations(f.kube))
	f.labels["component"] = "mutated-parent-map"
	require.Equal(t, "subject", receipt.Proof.SubjectSelectorLabels["component"])
	receipt = f.until(receipt, func(r Receipt) bool { return r.Phase == Cleaning })
	require.True(t, receipt.Proof.Verified)
	require.False(t, receipt.CleanupComplete)
	_, err := ExportProof(receipt)
	require.Error(t, err)
	receipt = f.until(receipt, func(r Receipt) bool { return r.CleanupComplete })
	proof, err := ExportProof(receipt)
	require.NoError(t, err)
	require.True(t, proof.SameNode)
	require.Equal(t, types.UID("cluster-uid"), proof.ClusterUID)
	require.Equal(t, f.policy, proof.Policy)
	require.Len(t, proof.Observations, 3)
	for i, phase := range []Phase{PositiveBefore, Negative, PositiveAfter} {
		require.Equal(t, phase, proof.Observations[i].Phase)
		require.Equal(t, proof.Endpoint.Pod.UID, proof.Observations[i].EndpointUID)
		require.Equal(t, proof.Endpoint.Address, proof.Observations[i].Target)
		require.Equal(t, proof.Endpoint.NodeName, proof.Observations[i].NodeName)
		require.NotEmpty(t, proof.Observations[i].Pod.UID)
		require.NotEmpty(t, proof.Observations[i].ImageID)
	}
	require.Equal(t, 4, podCreates(f.kube))
	f.noLeaks()
	_, err = f.adapter().Start(context.Background(), f.config, "run-1", "operation-1", f.subject,
		maps.Clone(proof.SubjectSelectorLabels), f.policy, f.store.persist)
	require.ErrorContains(t, err, "receipt-persistence-failed")
	require.Equal(t, 4, podCreates(f.kube))
}

func mutations(client *fake.Clientset) []ktesting.Action {
	var result []ktesting.Action
	for _, action := range client.Actions() {
		switch action.GetVerb() {
		case "create", "update", "patch", "delete":
			result = append(result, action)
		}
	}
	return result
}

func podCreates(client *fake.Clientset) int {
	total := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "pods" {
			total++
		}
	}
	return total
}
