package isolation

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestCancellationNeverDeletesImplicitly(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool { return r.Phase == PositiveBefore })
	before := deleteCount(f.kube.Actions())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.adapter().Observe(ctx, receipt, f.store.persist)
	require.Error(t, err)
	require.Equal(t, before, deleteCount(f.kube.Actions()))
	receipt = f.clean(receipt)
	require.Equal(t, Cancelled, receipt.Outcome)
	require.False(t, receipt.Proof.Verified)
	f.noLeaks()
}

func TestPersistIntentBeforeCreateAndRecoverOnlyForCleanup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.start()
	f.store.fail = func(receipt Receipt) bool { return receipt.Objects[0].UID != "" }
	acknowledged, err := f.adapter().Observe(context.Background(), receipt, f.store.persist)
	require.ErrorContains(t, err, "receipt-persistence-failed")
	require.NotEmpty(t, acknowledged.Objects[0].UID)
	durable := f.store.load(t)
	require.Empty(t, durable.Objects[0].UID)
	require.True(t, durable.Objects[0].CreateAttempted)
	f.store.fail = nil
	resumed, err := f.adapter().Observe(context.Background(), durable, f.store.persist)
	require.ErrorContains(t, err, "create-acknowledgement-required")
	require.Empty(t, resumed.Objects[0].UID)
	require.False(t, resumed.Proof.Verified)
	require.Equal(t, 0, podCreates(f.kube))
	resumed = f.clean(resumed)
	require.NotEmpty(t, resumed.Objects[0].UID)
	require.True(t, resumed.CleanupComplete)
	f.noLeaks()
}

func TestFailedInitialOrIntentPersistenceCreatesNothing(t *testing.T) {
	t.Parallel()
	for _, initial := range []bool{true, false} {
		t.Run(map[bool]string{true: "initial", false: "before-create"}[initial], func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.store.fail = func(receipt Receipt) bool { return initial || receipt.Objects[0].CreateAttempted }
			receipt, err := f.adapter().Start(context.Background(), f.config, "run-1", "operation-1", f.subject, f.labels, f.policy, f.store.persist)
			if !initial {
				require.NoError(t, err)
				_, err = f.adapter().Observe(context.Background(), receipt, f.store.persist)
			}
			require.ErrorContains(t, err, "receipt-persistence-failed")
			require.Empty(t, mutations(f.kube))
		})
	}
}

func TestCreateAcknowledgementLossCanBeCancelledWithoutLeaks(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.start()
	f.kube.PrependReactor("create", "networkpolicies", func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject()
		metadata := object.(metav1.Object)
		metadata.SetUID("acknowledgement-lost-uid")
		metadata.SetResourceVersion("2")
		require.NoError(t, f.kube.Tracker().Create(action.GetResource(), object, action.GetNamespace()))
		return true, nil, errors.New("synthetic transport failure")
	})
	receipt, err := f.adapter().Observe(context.Background(), receipt, f.store.persist)
	require.ErrorContains(t, err, "control-policy-create-not-acknowledged")
	require.Equal(t, Failed, receipt.Phase)
	require.Empty(t, receipt.Objects[0].UID)
	receipt = f.clean(receipt)
	require.True(t, receipt.CleanupComplete)
	f.noLeaks()
}

func TestCleanupWaitsForObservedAbsence(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool { return r.Phase == PositiveBefore })
	f.kube.PrependReactor("delete", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, nil
	})
	for range 12 {
		var err error
		receipt, err = f.adapter().Cancel(context.Background(), receipt, f.store.persist)
		require.NoError(t, err)
	}
	require.False(t, receipt.CleanupComplete)
	require.True(t, receipt.Objects[roleIndex(receipt, serverRole)].DeleteRequested)
	require.False(t, receipt.Objects[roleIndex(receipt, serverRole)].Deleted)
	_, err := ExportProof(receipt)
	require.Error(t, err)
	before := deleteCount(f.kube.Actions())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.adapter().Observe(ctx, receipt, f.store.persist)
	require.ErrorContains(t, err, contextEnded)
	_, err = f.adapter().Cancel(ctx, receipt, f.store.persist)
	require.ErrorContains(t, err, contextEnded)
	require.Equal(t, before, deleteCount(f.kube.Actions()))
}

func TestKnownUIDCannotBeWeakenedOnObserveOrDelete(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool { return r.Phase == PositiveBefore })
	object := receipt.Objects[roleIndex(receipt, serverRole)]
	pod, err := f.kube.CoreV1().Pods(object.Namespace).Get(context.Background(), object.Name, metav1.GetOptions{})
	require.NoError(t, err)
	pod.UID = "replacement-uid"
	_, err = f.kube.CoreV1().Pods(object.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	receipt, err = f.adapter().Observe(context.Background(), receipt, f.store.persist)
	require.Error(t, err)
	before := deleteCount(f.kube.Actions())
	for range 10 {
		receipt, err = f.adapter().Cancel(context.Background(), receipt, f.store.persist)
		if err != nil {
			break
		}
	}
	require.ErrorContains(t, err, "cleanup-identity")
	require.Equal(t, before, deleteCount(f.kube.Actions()))
	require.False(t, receipt.CleanupComplete)
	remaining, err := f.kube.CoreV1().Pods(object.Namespace).Get(context.Background(), object.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, pod.UID, remaining.UID)
}

func TestCleanupRejectsReplacedNamespaceAndCluster(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"proof-subject", "proof-control", "kube-system"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			receipt := f.until(f.start(), func(r Receipt) bool { return r.Phase == PositiveBefore })
			ns, err := f.kube.CoreV1().Namespaces().Get(context.Background(), name, metav1.GetOptions{})
			require.NoError(t, err)
			ns.UID = "replacement"
			_, err = f.kube.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
			require.NoError(t, err)
			before := deleteCount(f.kube.Actions())
			_, err = f.adapter().Cancel(context.Background(), receipt, f.store.persist)
			require.Error(t, err)
			require.Equal(t, before, deleteCount(f.kube.Actions()))
		})
	}
}

func TestUnknownUIDCleanupRejectsDifferentIntent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.start()
	f.store.fail = func(receipt Receipt) bool { return receipt.Objects[0].UID != "" }
	_, err := f.adapter().Observe(context.Background(), receipt, f.store.persist)
	require.Error(t, err)
	f.store.fail = nil
	receipt = f.store.load(t)
	object := receipt.Objects[0]
	policy, err := f.kube.NetworkingV1().NetworkPolicies(object.Namespace).Get(context.Background(), object.Name, metav1.GetOptions{})
	require.NoError(t, err)
	policy.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Namespace", Name: "other", UID: "unrelated"}}
	_, err = f.kube.NetworkingV1().NetworkPolicies(object.Namespace).Update(context.Background(), policy, metav1.UpdateOptions{})
	require.NoError(t, err)
	for range 10 {
		receipt, err = f.adapter().Cancel(context.Background(), receipt, f.store.persist)
		if err != nil {
			break
		}
	}
	require.ErrorContains(t, err, "cleanup-identity")
	require.Zero(t, deleteCount(f.kube.Actions()))
}

func deleteCount(actions []ktesting.Action) int {
	total := 0
	for _, action := range actions {
		if action.GetVerb() == "delete" {
			total++
		}
	}
	return total
}

func TestSubjectMustNotRunBeforeCleanup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.start()
	_, err := f.kube.CoreV1().Pods(f.subject.Name).Create(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "premature-subject", Namespace: f.subject.Name, Labels: f.labels},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	receipt, err = f.adapter().Observe(context.Background(), receipt, f.store.persist)
	require.ErrorContains(t, err, "probe-pod-identity-changed")
	require.False(t, receipt.Proof.Verified)
	receipt = f.clean(receipt)
	require.True(t, receipt.CleanupComplete)
	_, err = f.kube.CoreV1().Pods(f.subject.Name).Get(context.Background(), "premature-subject", metav1.GetOptions{})
	require.NoError(t, err)
}

func TestFailedCompletionPersistenceCannotExportProof(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool { return r.Phase == Cleaning && allDeleted(r) })
	f.store.fail = func(r Receipt) bool { return r.CleanupComplete }
	returned, err := f.adapter().Observe(context.Background(), receipt, f.store.persist)
	require.ErrorContains(t, err, "receipt-persistence-failed")
	_, err = ExportProof(returned)
	require.Error(t, err)
	canonical := f.store.load(t)
	require.False(t, canonical.CleanupComplete)
	f.store.fail = nil
	receipt, err = f.adapter().Observe(context.Background(), canonical, f.store.persist)
	require.NoError(t, err)
	_, err = ExportProof(receipt)
	require.NoError(t, err)
	f.noLeaks()
}

func TestNamespaceLabelDriftFailsProofButDoesNotPreventUIDCleanup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool { return r.Phase == PositiveBefore })
	ns, err := f.kube.CoreV1().Namespaces().Get(context.Background(), f.subject.Name, metav1.GetOptions{})
	require.NoError(t, err)
	ns.Labels["changed"] = "label"
	_, err = f.kube.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
	require.NoError(t, err)
	receipt, err = f.adapter().Observe(context.Background(), receipt, f.store.persist)
	require.ErrorContains(t, err, "namespace-labels-changed")
	receipt = f.clean(receipt)
	require.True(t, receipt.CleanupComplete)
	require.False(t, receipt.Proof.Verified)
	f.noLeaks()
}

func TestLastPolicyFenceIsCheckedAfterCleanup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool { return r.Phase == Cleaning })
	policy, err := f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Get(context.Background(), f.policy.Name, metav1.GetOptions{})
	require.NoError(t, err)
	policy.ResourceVersion = "changed-at-cleanup"
	_, err = f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Update(context.Background(), policy, metav1.UpdateOptions{})
	require.NoError(t, err)
	receipt = f.until(receipt, func(r Receipt) bool { return r.CleanupComplete })
	require.False(t, receipt.Proof.Verified)
	require.Equal(t, Rejected, receipt.Outcome)
	_, err = ExportProof(receipt)
	require.Error(t, err)
	f.noLeaks()
}
