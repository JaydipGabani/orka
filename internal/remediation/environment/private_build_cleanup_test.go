//go:build linux

package environment

import (
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPrivateBuildCleanupUsesAcceptedMapWithoutCurrentCatalog(t *testing.T) {
	f := newJobFixture(t, false)
	f.settleOnDelete = true
	f.config.BuildJobs.RegistrySecretName = "private-registry-v1"
	require.NoError(t, f.kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("secrets"), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "private-registry-v1", Namespace: "build-jobs", UID: "registry-uid", ResourceVersion: "1"},
		Type:       corev1.SecretTypeDockerConfigJson, Immutable: new(true),
		Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(
			`{"auths":{"registry.build-jobs.svc:5000":{"username":"fixture-user","password":"fixture-password"}}}`)},
	}, "build-jobs"))
	repo := &f.config.Repositories[0]
	recipe := &repo.Recipes[0]
	var patchName string
	for name := range recipe.Files {
		if name != recipe.Path {
			patchName = name
			break
		}
	}
	require.NotEmpty(t, patchName)
	raw := []byte("--- a/example.conf\n+++ b/example.conf\n@@ -1 +1 @@\n-old\n+endpoint=https://fixture:nonsecret@example.invalid\n")
	require.NoError(t, os.WriteFile(filepath.Join(repo.RecipeRoot, patchName), raw, 0600))
	recipe.Files = maps.Clone(recipe.Files)
	recipe.Files[patchName] = digest(raw)
	f.adapter = f.restart(t)
	request := f.request()
	_, done, err := f.adapter.advanceBuildJob(t.Context(), request, f.adapter.buildIdentity(request))
	require.NoError(t, err)
	require.False(t, done)
	before := f.record(t, request)
	require.Equal(t, map[string]string{patchName: digest(raw)}, before.Job.Input.BuildOnlyInputs)
	require.NoError(t, os.Remove(filepath.Join(repo.RecipeRoot, patchName)))
	require.NoError(t, os.Remove(filepath.Join(repo.RecipeRoot, recipe.Path)))
	cleanup, err := newCleanupAdapter(f.config)
	require.NoError(t, err)
	cleanup.kube = f.kube
	require.Empty(t, cleanup.catalog)
	require.NoError(t, cleanup.CancelBuild(t.Context(), request.RunID, request.OperationID, request.Plan))
	after := f.record(t, request)
	require.Equal(t, before.Job.Receipt.JobUID, after.Job.Receipt.JobUID)
	require.True(t, buildJobCleaned(after.Job))
	require.EqualValues(t, 1, f.buildCount.Load())
	_, err = cleanup.Build(t.Context(), request)
	require.Error(t, err, "cleanup authority cannot admit a new private-input build")
}
