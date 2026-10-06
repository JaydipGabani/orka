//go:build linux

package environment

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCancelBuildUsesSavedReceiptWithoutCatalogOrRecipeFiles(t *testing.T) {
	for _, mutate := range []string{"missing", "changed"} {
		t.Run(mutate, func(t *testing.T) {
			f := newJobFixture(t, false)
			f.settleOnDelete = true
			request := f.request()
			_, done, err := f.adapter.advanceBuildJob(t.Context(), request, f.adapter.buildIdentity(request))
			require.NoError(t, err)
			require.False(t, done)
			before := f.record(t, request)
			require.True(t, completeJobReceipt(*before.Job.Receipt))
			for _, repo := range f.config.Repositories {
				file := filepath.Join(repo.RecipeRoot, repo.Recipes[0].Path)
				if mutate == "missing" {
					require.NoError(t, os.Remove(file))
				} else {
					require.NoError(t, os.WriteFile(file, []byte("no longer an admitted recipe\n"), 0600))
				}
			}
			cleanup, err := newCleanupAdapter(f.config)
			require.NoError(t, err)
			cleanup.kube = f.kube
			require.Empty(t, cleanup.catalog)
			require.NoError(t, cleanup.CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
			record := f.record(t, request)
			require.Equal(t, before.Job.Receipt.JobUID, record.Job.Receipt.JobUID)
			require.True(t, buildJobCleaned(record.Job))
			require.True(t, record.Job.Cleanup.DaemonSettled)
			require.EqualValues(t, 1, f.buildCount.Load())
			_, err = cleanup.Build(t.Context(), request)
			require.Error(t, err)
		})
	}
}

func TestCleanupBuildRejectsChangedPlanBeforeAnyKubernetesMutation(t *testing.T) {
	f := newJobFixture(t, false)
	request := f.request()
	_, _, err := f.adapter.advanceBuildJob(t.Context(), request, f.adapter.buildIdentity(request))
	require.NoError(t, err)
	cleanup, err := newCleanupAdapter(f.config)
	require.NoError(t, err)
	cleanup.kube = f.kube
	record := f.record(t, request)
	changed := request.Plan
	changed.Bind.SourceTarget.Commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	require.Error(t, cleanup.CancelBuild(t.Context(), request.RunID, request.OperationID, changed))
	changed.Bind.ChecksDigest = ChecksDigest(changed)
	require.Error(t, cleanup.CancelBuild(t.Context(), request.RunID, request.OperationID, changed))
	_, err = f.kube.BatchV1().Jobs(record.Job.Receipt.Namespace).Get(t.Context(), record.Job.Receipt.JobName, metav1.GetOptions{})
	require.NoError(t, err)
	for _, action := range f.kube.Actions() {
		require.NotEqual(t, "delete", action.GetVerb())
	}
}

func TestCleanupBuildWithoutWorkerDaemonProofRemainsPending(t *testing.T) {
	f := newJobFixture(t, false)
	request := f.request()
	_, done, err := f.adapter.advanceBuildJob(t.Context(), request, f.adapter.buildIdentity(request))
	require.NoError(t, err)
	require.False(t, done)
	record := f.record(t, request)
	pods, err := f.kube.CoreV1().Pods(record.Job.Receipt.Namespace).List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, pods.Items, 1)
	pod := pods.Items[0].DeepCopy()
	pod.Status.Phase = corev1.PodFailed
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "build-worker", Image: f.config.BuildJobs.WorkerImage,
		ImageID: "docker-pullable://" + f.config.BuildJobs.WorkerImage, ContainerID: "containerd://sigkilled-worker",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			ExitCode: 137, Signal: 9, ContainerID: "containerd://sigkilled-worker",
		}},
	}}
	require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, pod.Namespace))
	cleanup, err := newCleanupAdapter(f.config)
	require.NoError(t, err)
	cleanup.kube = f.kube
	require.Empty(t, cleanup.catalog)
	require.Error(t, cleanup.CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	record = f.record(t, request)
	require.Equal(t, buildStarted, record.State)
	require.True(t, record.Job.CancelRequested)
	require.False(t, buildJobCleaned(record.Job))
	require.False(t, record.Job.Cleanup.DaemonSettled)
	require.Empty(t, record.Result.Subject.Image)
	retained, err := f.kube.CoreV1().Pods(pod.Namespace).Get(t.Context(), pod.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, retained.DeletionTimestamp)
	require.NotEmpty(t, retained.Finalizers)
	require.EqualValues(t, 1, f.buildCount.Load())
}
