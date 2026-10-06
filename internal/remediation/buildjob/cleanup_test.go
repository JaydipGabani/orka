package buildjob

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetesting "k8s.io/client-go/testing"
)

func TestExplicitCleanupStopsObservedPodAndSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	pod := f.pod(t, r, nil)
	result, err := f.backend.Observe(context.Background(), r)
	require.NoError(t, err)
	require.Equal(t, pod.UID, result.PodUID)
	settlingKubelet(f, r, pod.UID)
	proof, err := f.backend.Cleanup(context.Background(), r)
	require.NoError(t, err)
	require.True(t, proof.Stopped)
	require.True(t, proof.SubmissionSettled)
	require.True(t, proof.DaemonSettled)
	require.Contains(t, proof.PodUIDs, pod.UID)
	require.Equal(t, cleanupDigest(proof), proof.CleanupDigest)
	_, err = f.kube.CoreV1().Pods(r.Namespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	_, err = f.kube.BatchV1().Jobs(r.Namespace).Get(context.Background(), r.JobName, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	_, err = f.kube.CoreV1().Secrets(r.Namespace).Get(context.Background(), r.AnchorName, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	record, err := f.kube.CoreV1().ConfigMaps(r.Namespace).Get(context.Background(), r.LedgerName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, cleanedState, record.Annotations[stateAnnotation])
	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "package main")
	recovered, err := New(f.config)
	require.NoError(t, err)
	again, err := recovered.Cleanup(context.Background(), r)
	require.NoError(t, err)
	require.Equal(t, proof, again)
	_, err = recovered.Start(context.Background(), f.input)
	require.ErrorIs(t, err, ErrLost)
	for _, action := range f.kube.Actions() {
		if action.GetVerb() != "delete" {
			continue
		}
		options := action.(kubetesting.DeleteAction).GetDeleteOptions()
		require.NotNil(t, options.Preconditions)
		require.NotNil(t, options.Preconditions.UID)
		require.Equal(t, metav1.DeletePropagationForeground, *options.PropagationPolicy)
	}
}

func TestCleanupNeverAcknowledgesWhileAnObservedPodRemains(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	pod := f.pod(t, r, nil)
	settlingKubelet(f, r, pod.UID)
	deleteAttempted := make(chan struct{}, 1)
	var allowDelete atomic.Bool
	f.kube.PrependReactor("delete", "pods", func(kubetesting.Action) (bool, runtime.Object, error) {
		if allowDelete.Load() {
			return false, nil, nil
		}
		select {
		case deleteAttempted <- struct{}{}:
		default:
		}
		return true, nil, nil
	})
	type answer struct {
		proof CleanupReceipt
		err   error
	}
	completed := make(chan answer, 1)
	ctx := t.Context()
	go func() {
		proof, err := f.backend.Cleanup(ctx, r)
		completed <- answer{proof, err}
	}()
	select {
	case <-deleteAttempted:
	case <-time.After(time.Second):
		require.FailNow(t, "cleanup did not attempt exact Pod deletion")
	}
	select {
	case result := <-completed:
		require.FailNow(t, "cleanup returned while Pod still exists", "stopped=%v error=%v", result.proof.Stopped, result.err)
	case <-time.After(10 * time.Millisecond):
	}
	_, err := f.kube.CoreV1().Pods(r.Namespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
	require.NoError(t, err)
	allowDelete.Store(true)
	select {
	case result := <-completed:
		require.NoError(t, result.err)
		require.True(t, result.proof.Stopped)
	case <-time.After(time.Second):
		require.FailNow(t, "cleanup did not finish after Pod deletion")
	}
}

func TestCleanupInterruptionResumesWithoutLosingObservedUIDs(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	pod := f.pod(t, r, nil)
	settlingKubelet(f, r, pod.UID)
	ctx, cancel := context.WithCancel(context.Background())
	var first atomic.Bool
	f.kube.PrependReactor("delete", "pods", func(kubetesting.Action) (bool, runtime.Object, error) {
		if !first.Swap(true) {
			cancel()
			return true, nil, context.Canceled
		}
		return false, nil, nil
	})
	proof, err := f.backend.Cleanup(ctx, r)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, proof.Stopped)
	require.Contains(t, proof.PodUIDs, pod.UID)
	recovered, err := New(f.config)
	require.NoError(t, err)
	proof, err = recovered.Cleanup(context.Background(), r)
	require.NoError(t, err)
	require.True(t, proof.Stopped)
	require.Contains(t, proof.PodUIDs, pod.UID)
}

func TestPreparedOperationCanBeCleanedWithoutCreatingAJob(t *testing.T) {
	f := newFixture(t)
	f.kube.PrependReactor("update", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
		secret := action.(kubetesting.UpdateAction).GetObject().(*corev1.Secret)
		if secret.Annotations[stateAnnotation] == submittedState {
			return true, nil, apierrors.NewServiceUnavailable("intent rejected before persistence")
		}
		return false, nil, nil
	})
	r, err := f.backend.Start(context.Background(), f.input)
	require.ErrorIs(t, err, ErrAPI)
	require.Empty(t, r.JobUID)
	proof, err := f.backend.Cleanup(context.Background(), r)
	require.NoError(t, err)
	require.True(t, proof.Stopped)
	require.True(t, proof.SubmissionSettled)
	require.Empty(t, proof.JobUID)
	require.Zero(t, countActions(f.kube, "create", "jobs"))
}

func TestCleanupRejectsUnownedPodAndDoesNotDeleteIt(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	pod := f.pod(t, r, nil)
	pod.OwnerReferences[0].UID = "another-job"
	require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, r.Namespace))
	proof, err := f.backend.Cleanup(context.Background(), r)
	require.ErrorIs(t, err, ErrIdentity)
	require.False(t, proof.Stopped)
	require.Zero(t, countActions(f.kube, "delete", "pods"))
	_, err = f.kube.CoreV1().Pods(r.Namespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
	require.NoError(t, err)
}

func TestCleanupRejectsMissingPodWithoutDaemonEvidence(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	pod := f.pod(t, r, nil)
	_, err := f.backend.Observe(context.Background(), r)
	require.NoError(t, err)
	require.NoError(t, f.kube.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), r.Namespace, pod.Name))
	proof, err := f.backend.Cleanup(context.Background(), r)
	require.ErrorIs(t, err, ErrCleanup)
	require.False(t, proof.Stopped)
	require.False(t, proof.DaemonSettled)
	require.Contains(t, proof.PodUIDs, pod.UID)
}

func TestCleanupRecoversAnInterruptedAnchorLedgerBinding(t *testing.T) {
	f := newFixture(t)
	var once atomic.Bool
	f.kube.PrependReactor("update", "configmaps", func(kubetesting.Action) (bool, runtime.Object, error) {
		if !once.Swap(true) {
			return true, nil, apierrors.NewServiceUnavailable("anchor binding interrupted")
		}
		return false, nil, nil
	})
	r, err := f.backend.Start(context.Background(), f.input)
	require.ErrorIs(t, err, ErrAPI)
	require.NotEmpty(t, r.AnchorUID)
	proof, err := f.backend.Cleanup(context.Background(), r)
	require.NoError(t, err)
	require.True(t, proof.Stopped)
	require.True(t, proof.SubmissionSettled)
	require.Zero(t, countActions(f.kube, "create", "jobs"))
}
