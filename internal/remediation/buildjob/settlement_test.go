package buildjob

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetesting "k8s.io/client-go/testing"
)

func TestSIGKILLOrUnsettledWorkerCannotAcknowledgeDaemonCleanup(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit-unsettled", true: "sigkill-no-message"}[missing], func(t *testing.T) {
			f := newFixture(t)
			r := f.start(t)
			pod := f.pod(t, r, &WorkerResult{Version: Version, InputDigest: r.InputDigest, BuildOutcome: Infrastructure,
				BuildRef: "fixture-unsettled-ref", DaemonSettled: false})
			if missing {
				pod.Status.ContainerStatuses[0].State.Terminated.Message = ""
				pod.Status.ContainerStatuses[0].State.Terminated.ExitCode = 137
				pod.Status.ContainerStatuses[0].State.Terminated.Signal = 9
				require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, r.Namespace))
			}
			proof, err := f.backend.Cleanup(t.Context(), r)
			require.ErrorIs(t, err, ErrCleanup)
			require.False(t, proof.Stopped)
			require.False(t, proof.DaemonSettled)
			retained, err := f.kube.CoreV1().Pods(r.Namespace).Get(t.Context(), pod.Name, metav1.GetOptions{})
			require.NoError(t, err)
			require.Contains(t, retained.Finalizers, podFinalizer)
			require.NotNil(t, retained.DeletionTimestamp)
		})
	}
}

func TestMeasuredDaemonProofSurvivesPodLossAndBackendRestart(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	pod := f.pod(t, r, goodResult(r))
	result, err := f.backend.Observe(t.Context(), r)
	require.NoError(t, err)
	require.True(t, result.DaemonSettled)
	require.NoError(t, f.kube.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), r.Namespace, pod.Name))
	recovered, err := New(f.config)
	require.NoError(t, err)
	proof, err := recovered.Cleanup(t.Context(), r)
	require.NoError(t, err)
	require.True(t, proof.Stopped)
	require.True(t, proof.DaemonSettled)
	require.Contains(t, proof.PodUIDs, pod.UID)
}

func TestCancellationSettlementIsPersistedBeforePodRetentionRelease(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	pod := f.pod(t, r, nil)
	settlingKubelet(f, r, pod.UID)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var interrupted atomic.Bool
	f.kube.PrependReactor("update", "configmaps", func(action kubetesting.Action) (bool, runtime.Object, error) {
		record := action.(kubetesting.UpdateAction).GetObject().(*corev1.ConfigMap)
		if record.Annotations[settlementAnnotation] != "" && !interrupted.Swap(true) {
			cancel()
		}
		return false, nil, nil
	})
	proof, err := f.backend.Cleanup(ctx, r)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, proof.Stopped)
	record, err := f.kube.CoreV1().ConfigMaps(r.Namespace).Get(t.Context(), r.LedgerName, metav1.GetOptions{})
	require.NoError(t, err)
	proofs, err := settlementsFromLedger(record)
	require.NoError(t, err)
	require.Equal(t, "fixture-cancelled-ref", proofs[pod.UID].BuildRef)
	recovered, err := New(f.config)
	require.NoError(t, err)
	proof, err = recovered.Cleanup(t.Context(), r)
	require.NoError(t, err)
	require.True(t, proof.DaemonSettled)
	require.True(t, proof.Stopped)
}

func TestCompletedCleanupRequiresRetainedDaemonEvidenceOnReplay(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	f.pod(t, r, goodResult(r))
	proof, err := f.backend.Cleanup(t.Context(), r)
	require.NoError(t, err)
	require.True(t, proof.DaemonSettled)
	record, err := f.kube.CoreV1().ConfigMaps(r.Namespace).Get(t.Context(), r.LedgerName, metav1.GetOptions{})
	require.NoError(t, err)
	delete(record.Annotations, settlementAnnotation)
	require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), record, r.Namespace))
	_, err = f.backend.Cleanup(t.Context(), r)
	require.ErrorIs(t, err, ErrCleanup)
}
