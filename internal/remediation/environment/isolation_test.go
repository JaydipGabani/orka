package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/isolation"
	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type isolatedFixture struct {
	fixture
	adapter *Adapter
	client  *fake.Clientset
}

func isolatedEnvironment(t *testing.T, enforced bool, onPod func(*corev1.Pod)) isolatedFixture {
	t.Helper()
	f := testFixture(t)
	f.config.Isolation = &IsolationConfig{ProbeImage: "registry.example.invalid/network-probe@sha256:" + strings.Repeat("a", 64)}
	f.config.Limits.MaxNamespaces = 2
	adapter, err := newAdapter(f.config)
	require.NoError(t, err)
	cluster := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid", ResourceVersion: "1"}}
	client := fake.NewClientset(cluster)
	var sequence atomic.Uint64
	client.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject().DeepCopyObject()
		meta := object.(metav1.Object)
		id := sequence.Add(1)
		meta.SetUID(types.UID(fmt.Sprintf("created-%d", id)))
		meta.SetResourceVersion(fmt.Sprintf("%d", id+1))
		meta.SetCreationTimestamp(metav1.Now())
		switch typed := object.(type) {
		case *corev1.Namespace:
			typed.Status.Phase = corev1.NamespaceActive
			typed.Labels["kubernetes.io/metadata.name"] = typed.Name
		case *corev1.Pod:
			if len(typed.Spec.Containers) == 1 && typed.Spec.Containers[0].Image == f.config.Isolation.ProbeImage {
				fakeNetworkProbe(t, typed, enforced)
			}
		}
		if err := client.Tracker().Create(action.GetResource(), object, action.GetNamespace()); err != nil {
			return true, nil, err
		}
		if pod, ok := object.(*corev1.Pod); ok && onPod != nil {
			onPod(pod)
		}
		return true, object, nil
	})
	client.PrependReactor("delete", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		deletion := action.(ktesting.DeleteAction)
		actual, err := client.Tracker().Get(action.GetResource(), action.GetNamespace(), deletion.GetName())
		if err != nil {
			return true, nil, err
		}
		options := deletion.GetDeleteOptions()
		if options.Preconditions == nil || options.Preconditions.UID == nil ||
			*options.Preconditions.UID != actual.(metav1.Object).GetUID() {
			return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), deletion.GetName(), nil)
		}
		return false, nil, nil
	})
	adapter.kube = client
	adapter.clusterIdentity = jsonDigest(struct{ Domain, UID string }{
		"orka.remediation.environment.cluster.v1", string(cluster.UID),
	})
	return isolatedFixture{fixture: f, adapter: adapter, client: client}
}

func fakeNetworkProbe(t *testing.T, pod *corev1.Pod, enforced bool) {
	t.Helper()
	container := pod.Spec.Containers[0]
	status := corev1.ContainerStatus{
		Name: "probe", Image: container.Image, ImageID: container.Image, ContainerID: "synthetic-container",
	}
	if container.Args[0] == "serve" {
		pod.Spec.NodeName = "proof-node"
		status.Ready = true
		status.State.Running = &corev1.ContainerStateRunning{StartedAt: metav1.Now()}
		pod.Status = corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: "10.22.33.44",
			Conditions:        []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{status},
		}
		return
	}
	started := metav1.Now()
	negative := false
	for index, arg := range container.Args {
		if arg == "--expect" && container.Args[index+1] == string(probe.Blocked) {
			negative = true
		}
	}
	result := probe.Result{Reachable: true, NonceMatched: true, FailureClass: probe.None}
	phase, exit := corev1.PodSucceeded, int32(0)
	if negative {
		if enforced {
			// Real worker timeouts are separately tested with TCP. Kubernetes
			// timestamps permit a one-second interval for its two-second dial.
			timer := time.NewTimer(time.Second + 10*time.Millisecond)
			<-timer.C
			result = probe.Result{FailureClass: probe.DialTimeout}
		} else {
			phase, exit = corev1.PodFailed, 1
		}
	}
	message, err := json.Marshal(result)
	require.NoError(t, err)
	status.State.Terminated = &corev1.ContainerStateTerminated{
		ExitCode: exit, Reason: "Completed", StartedAt: started, FinishedAt: metav1.Now(), Message: string(message),
	}
	pod.Status = corev1.PodStatus{Phase: phase, ContainerStatuses: []corev1.ContainerStatus{status}}
}

func TestIsolationMissingCNIRejectsBeforeSubjectPod(t *testing.T) {
	t.Parallel()
	f := isolatedEnvironment(t, false, nil)
	receipt, err := f.adapter.Start(t.Context(), fixtureRequest(f.fixture, 0, Candidate, "unproven-egress"))
	require.Error(t, err)
	assertKind(t, err, NeedsAdapter)
	require.Zero(t, subjectCreateCount(f.client, f.config.Isolation.ProbeImage))
	require.Len(t, receipt.Proofs, 1)
	require.False(t, receipt.Proofs[0].Proof.Verified)
	require.NoError(t, f.adapter.Cancel(t.Context(), receipt))
	requireNoIsolatedLeaks(t, f)
}

func TestIsolationProofCompletesBeforeSubjectAndPinsNode(t *testing.T) {
	t.Parallel()
	f := isolatedEnvironment(t, true, nil)
	receipt, err := f.adapter.Start(t.Context(), fixtureRequest(f.fixture, 0, Candidate, "proven-egress"))
	require.NoError(t, err)
	require.Len(t, receipt.Proofs, 1)
	proof, err := isolation.ExportProof(receipt.Proofs[0])
	require.NoError(t, err)
	require.Equal(t, "proof-node", proof.Endpoint.NodeName)
	require.Equal(t, ownerLabels(receipt), proof.SubjectSelectorLabels)
	require.Equal(t, receipt.Policy.ProbeImage, f.config.Isolation.ProbeImage)
	namespaces := 0
	for _, object := range receipt.Objects {
		switch object.Kind {
		case namespaceKind:
			namespaces++
			require.NotEmpty(t, object.UID)
		case podKind:
			pod, err := f.client.CoreV1().Pods(object.Namespace).Get(t.Context(), object.Name, metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, proof.Endpoint.NodeName, pod.Spec.NodeName)
			require.Equal(t, proof.SubjectSelectorLabels, pod.Labels)
			require.False(t, pod.CreationTimestamp.Time.Before(proof.CompletedAt))
		}
	}
	require.Equal(t, 2, namespaces)
	require.Equal(t, 1, subjectCreateCount(f.client, f.config.Isolation.ProbeImage))
	readyFixturePods(t, f.client, receipt)
	attachHTTPFixture(t, f.adapter, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repro" {
			_, _ = io.WriteString(w, "fixed")
		} else {
			_, _ = io.WriteString(w, "healthy")
		}
	}))
	observed, err := f.adapter.Observe(t.Context(), receipt)
	require.NoError(t, err)
	require.Nil(t, observed.Failure)
	require.True(t, observed.CleanupComplete)
	require.Len(t, observed.Checks, 2)
	requireNoIsolatedLeaks(t, f)
}

func TestIsolationPolicyRevisionChangesInvalidateRealObservations(t *testing.T) {
	t.Parallel()
	for _, during := range []bool{false, true} {
		t.Run(fmt.Sprintf("during-http-%t", during), func(t *testing.T) {
			t.Parallel()
			f := isolatedEnvironment(t, true, nil)
			receipt, err := f.adapter.Start(t.Context(), fixtureRequest(f.fixture, 0, Candidate, "changed-policy"))
			require.NoError(t, err)
			readyFixturePods(t, f.client, receipt)
			mutate := func() {
				proof := receipt.Proofs[0].Proof
				policy, err := f.client.NetworkingV1().NetworkPolicies(proof.SubjectNamespace.Name).Get(t.Context(), proof.Policy.Name, metav1.GetOptions{})
				require.NoError(t, err)
				policy.ResourceVersion = "changed-after-proof"
				_, err = f.client.NetworkingV1().NetworkPolicies(policy.Namespace).Update(t.Context(), policy, metav1.UpdateOptions{})
				require.NoError(t, err)
			}
			if !during {
				mutate()
			}
			attachHTTPFixture(t, f.adapter, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if during {
					mutate()
				}
				_, _ = io.WriteString(w, "fixed")
			}))
			observed, err := f.adapter.Observe(t.Context(), receipt)
			require.NoError(t, err)
			require.NotNil(t, observed.Failure)
			require.Empty(t, observed.Checks)
			require.True(t, observed.CleanupComplete)
			requireNoIsolatedLeaks(t, f)
		})
	}
}

func TestIsolationCancellationPausesAndRestartDoesNotReplay(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	f := isolatedEnvironment(t, true, func(pod *corev1.Pod) {
		if pod.Spec.Containers[0].Name == "probe" && pod.Spec.Containers[0].Args[0] == "serve" {
			cancel()
		}
	})
	request := fixtureRequest(f.fixture, 0, Candidate, "paused-proof")
	receipt, err := f.adapter.Start(ctx, request)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, subjectCreateCount(f.client, f.config.Isolation.ProbeImage))
	require.Zero(t, isolationDeleteCount(f.client))
	require.Len(t, receipt.Proofs, 1)
	require.NotEmpty(t, receipt.Proofs[0].Nonce)
	nonce, generation := receipt.Proofs[0].Nonce, receipt.Proofs[0].OperationDigest
	restarted, err := newAdapter(f.config)
	require.NoError(t, err)
	restarted.kube, restarted.clusterIdentity = f.client, f.adapter.clusterIdentity
	request.RequireExisting = true
	recovered, err := restarted.Start(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, nonce, recovered.Proofs[0].Nonce)
	require.Equal(t, generation, recovered.Proofs[0].OperationDigest)
	require.Equal(t, 1, canaryCreateCount(f.client))
	require.Equal(t, 1, subjectCreateCount(f.client, f.config.Isolation.ProbeImage))
	require.NoError(t, restarted.Cancel(t.Context(), recovered))
	requireNoIsolatedLeaks(t, f)
}

func TestIsolationExplicitCancelCleansOnlyItsAnchoredProbePods(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	f := isolatedEnvironment(t, true, func(pod *corev1.Pod) {
		if pod.Spec.Containers[0].Name == "probe" && pod.Spec.Containers[0].Args[0] == "serve" {
			cancel()
		}
	})
	receipt, err := f.adapter.Start(ctx, fixtureRequest(f.fixture, 0, Candidate, "cancelled-proof"))
	require.ErrorIs(t, err, context.Canceled)
	foreign := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "foreign", UID: "foreign-uid", Labels: map[string]string{"kubernetes.io/metadata.name": "foreign"},
	}}
	require.NoError(t, f.client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("namespaces"), foreign, ""))
	require.NoError(t, f.adapter.Cancel(t.Context(), receipt))
	_, err = f.client.CoreV1().Namespaces().Get(t.Context(), foreign.Name, metav1.GetOptions{})
	require.NoError(t, err)
	pods, err := f.client.CoreV1().Pods("").List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, pods.Items)
	recorded, err := f.adapter.loadRun(receipt.Request.RunID, receipt.Request.Plan.Bind)
	require.NoError(t, err)
	require.True(t, recorded.Operations[receipt.OperationDigest].Receipt.Proofs[0].CleanupComplete)
	require.True(t, recorded.Operations[receipt.OperationDigest].Observation.CleanupComplete)
}

func TestIsolationReservesOneNamespaceAndFreezesImage(t *testing.T) {
	t.Parallel()
	f := isolatedEnvironment(t, true, nil)
	request := fixtureRequest(f.fixture, 0, Candidate, "namespace-quota")
	request.Plan.Namespaces = append(request.Plan.Namespaces, Namespace{Alias: "another"})
	request.Plan.Bind.ChecksDigest = ChecksDigest(request.Plan)
	_, err := f.adapter.Intent(request)
	require.ErrorContains(t, err, "isolation-namespace-budget")
	before, err := f.adapter.Intent(fixtureRequest(f.fixture, 0, Candidate, "frozen-image"))
	require.NoError(t, err)
	f.config.Isolation.ProbeImage = "different.invalid/probe@sha256:" + strings.Repeat("b", 64)
	after, err := f.adapter.Intent(fixtureRequest(f.fixture, 0, Candidate, "frozen-image"))
	require.NoError(t, err)
	require.Equal(t, before.ConfigDigest, after.ConfigDigest)
	require.Equal(t, before.Policy.ProbeImage, after.Policy.ProbeImage)
}

func TestIsolationReusesOwnedControlNamespaceSequentially(t *testing.T) {
	t.Parallel()
	f := isolatedEnvironment(t, true, nil)
	f.adapter.config.Limits.MaxNamespaces = 3
	request := fixtureRequest(f.fixture, 0, Candidate, "two-subject-namespaces")
	request.Plan.Namespaces = append(request.Plan.Namespaces, Namespace{Alias: "second"})
	request.Plan.Resources = append(request.Plan.Resources, Resource{
		ID: "second-service", Namespace: "second", GVK: f.config.AllowedGVKs[0], HTTP: &HTTPWorkload{Port: 8080},
	})
	request.Plan.Checks = append(request.Plan.Checks, Check{
		ID: "second-normal", Class: Normal, Capability: HTTPExact,
		HTTP: &HTTPProbe{Resource: "second-service", Protocol: "http", Path: "/normal", Healthy: HTTPExpectation{Status: 200, Body: "healthy"}},
	})
	request.Plan.Bind.ChecksDigest = ChecksDigest(request.Plan)
	receipt, err := f.adapter.Start(t.Context(), request)
	require.NoError(t, err)
	require.Len(t, receipt.Proofs, 2)
	require.Equal(t, receipt.Proofs[0].Config.ControlNamespace, receipt.Proofs[1].Config.ControlNamespace)
	require.NotEqual(t, receipt.Proofs[0].Nonce, receipt.Proofs[1].Nonce)
	for _, recorded := range receipt.Proofs {
		_, err := isolation.ExportProof(recorded)
		require.NoError(t, err)
	}
	require.Equal(t, 2, canaryCreateCount(f.client))
	require.Equal(t, 2, subjectCreateCount(f.client, f.config.Isolation.ProbeImage))
	require.NoError(t, f.adapter.Cancel(t.Context(), receipt))
	requireNoIsolatedLeaks(t, f)
}

func TestIsolationNodeAndSelectorDriftRejectBeforeHTTP(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"node", "selector"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			f := isolatedEnvironment(t, true, nil)
			receipt, err := f.adapter.Start(t.Context(), fixtureRequest(f.fixture, 0, Candidate, "changed-subject"))
			require.NoError(t, err)
			readyFixturePods(t, f.client, receipt)
			for _, object := range receipt.Objects {
				if object.Kind != podKind {
					continue
				}
				pod, err := f.client.CoreV1().Pods(object.Namespace).Get(t.Context(), object.Name, metav1.GetOptions{})
				require.NoError(t, err)
				if field == "node" {
					pod.Spec.NodeName = "unqualified-node"
				} else {
					pod.Labels["unexpected-egress-selector"] = "enabled"
				}
				_, err = f.client.CoreV1().Pods(object.Namespace).Update(t.Context(), pod, metav1.UpdateOptions{})
				require.NoError(t, err)
			}
			var calls atomic.Int64
			attachHTTPFixture(t, f.adapter, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
			observed, err := f.adapter.Observe(t.Context(), receipt)
			require.NoError(t, err)
			require.NotNil(t, observed.Failure)
			require.Zero(t, calls.Load())
			require.Empty(t, observed.Checks)
			require.True(t, observed.CleanupComplete)
			requireNoIsolatedLeaks(t, f)
		})
	}
}

func TestIsolationNilDoesNotClaimRuntimeQualification(t *testing.T) {
	t.Parallel()
	f := testFixture(t)
	adapter, _ := testAdapter(t, f)
	receipt, err := adapter.Start(t.Context(), fixtureRequest(f, 0, Candidate, "manual-only"))
	require.NoError(t, err)
	require.Empty(t, receipt.Proofs)
	require.Empty(t, receipt.Policy.ProbeImage)
	require.Empty(t, receipt.CreateIntents)
	require.NoError(t, adapter.Cancel(t.Context(), receipt))
}

func TestIsolationNilPreservesLegacyConfigurationJSON(t *testing.T) {
	t.Parallel()
	config := Config{}
	encoded, err := json.Marshal(config)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))
	_, included := fields["Isolation"]
	require.False(t, included)

	config.Isolation = &IsolationConfig{ProbeImage: "registry.example.invalid/probe@sha256:" + strings.Repeat("a", 64)}
	encoded, err = json.Marshal(config)
	require.NoError(t, err)
	var restored Config
	require.NoError(t, json.Unmarshal(encoded, &restored))
	require.Equal(t, config.Isolation, restored.Isolation)
}

func TestIsolationCleanupRechecksLiveClusterUID(t *testing.T) {
	t.Parallel()
	f := isolatedEnvironment(t, true, nil)
	receipt, err := f.adapter.Start(t.Context(), fixtureRequest(f.fixture, 0, Candidate, "cluster-replaced"))
	require.NoError(t, err)
	cluster, err := f.client.CoreV1().Namespaces().Get(t.Context(), "kube-system", metav1.GetOptions{})
	require.NoError(t, err)
	cluster.UID = "other-cluster"
	_, err = f.client.CoreV1().Namespaces().Update(t.Context(), cluster, metav1.UpdateOptions{})
	require.NoError(t, err)
	before := isolationDeleteCount(f.client)
	require.ErrorContains(t, f.adapter.Cancel(t.Context(), receipt), "isolation-cleanup-cluster-mismatch")
	require.Equal(t, before, isolationDeleteCount(f.client))
}

func TestIsolationRequireExistingDoesNotInventMissingProofGeneration(t *testing.T) {
	t.Parallel()
	f := isolatedEnvironment(t, true, nil)
	request := fixtureRequest(f.fixture, 0, Candidate, "missing-receipt")
	request.RequireExisting = true
	_, err := f.adapter.Start(t.Context(), request)
	require.ErrorContains(t, err, "isolation-recovery-receipt-required")
	require.Zero(t, createCount(f.client))
}

func TestIsolationConfigRejectsMissingClusterQuotaAndMutableImage(t *testing.T) {
	t.Parallel()
	trusted := "registry.example.invalid/probe@sha256:" + strings.Repeat("a", 64)
	for _, config := range []Config{
		{Isolation: &IsolationConfig{ProbeImage: trusted}, Limits: Limits{MaxNamespaces: 2}},
		{Kubernetes: &KubernetesConfig{}, Isolation: &IsolationConfig{ProbeImage: trusted}, Limits: Limits{MaxNamespaces: 1}},
		{Kubernetes: &KubernetesConfig{}, Isolation: &IsolationConfig{ProbeImage: "probe:latest"}, Limits: Limits{MaxNamespaces: 2}},
	} {
		require.Error(t, validateIsolationConfig(config))
	}
	config := Config{Kubernetes: &KubernetesConfig{}, Isolation: &IsolationConfig{ProbeImage: trusted}, Limits: Limits{MaxNamespaces: 2}}
	require.NoError(t, validateIsolationConfig(config))
	require.Equal(t, 1, modelNamespaceLimit(config))
	config.Isolation = nil
	require.NoError(t, validateIsolationConfig(config))
	require.Equal(t, 2, modelNamespaceLimit(config))
}

func subjectCreateCount(client *fake.Clientset, trustedImage string) int {
	total := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "pods" {
			pod := action.(ktesting.CreateAction).GetObject().(*corev1.Pod)
			if pod.Spec.Containers[0].Image != trustedImage {
				total++
			}
		}
	}
	return total
}

func canaryCreateCount(client *fake.Clientset) int {
	total := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "pods" {
			pod := action.(ktesting.CreateAction).GetObject().(*corev1.Pod)
			if pod.Spec.Containers[0].Name == "probe" && pod.Spec.Containers[0].Args[0] == "serve" {
				total++
			}
		}
	}
	return total
}

func isolationDeleteCount(client *fake.Clientset) int {
	total := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "delete" {
			total++
		}
	}
	return total
}

func requireNoIsolatedLeaks(t *testing.T, f isolatedFixture) {
	t.Helper()
	namespaces, err := f.client.CoreV1().Namespaces().List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, namespaces.Items, 1)
	require.Equal(t, "kube-system", namespaces.Items[0].Name)
	for _, kind := range []schema.GroupVersionResource{
		corev1.SchemeGroupVersion.WithResource("pods"),
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	} {
		switch kind.Resource {
		case "pods":
			list, err := f.client.CoreV1().Pods("").List(t.Context(), metav1.ListOptions{})
			require.NoError(t, err)
			require.Empty(t, list.Items)
		case "networkpolicies":
			list, err := f.client.NetworkingV1().NetworkPolicies("").List(t.Context(), metav1.ListOptions{})
			require.NoError(t, err)
			require.Empty(t, list.Items)
		}
	}
}
