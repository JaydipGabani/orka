package buildjob

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func registryFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, func(config *Config) { config.RegistrySecretName = "registry-auth-v1" })
	require.NoError(t, f.kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("secrets"), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "registry-auth-v1", Namespace: "builds", UID: "registry-secret", ResourceVersion: "1",
		},
		Type: corev1.SecretTypeDockerConfigJson, Immutable: new(true),
		Data: map[string][]byte{corev1.DockerConfigJsonKey: registryFixtureJSON("registry.builds.svc:5000")},
	}, "builds"))
	return f
}

func registryFixtureJSON(host string) []byte {
	body, _ := json.Marshal(registryAuthDocument{Auths: map[string]registryBasicAuth{
		host: {Username: "fixture-user", Password: "fixture-password-marker"},
	}})
	return body
}

func TestRegistryAuthAllowsOnlyExactOutputHostBasicCredentials(t *testing.T) {
	repository := "localhost:5000/private/output"
	require.NoError(t, validateRegistryAuth(registryFixtureJSON("localhost:5000"), repository))
	auth := base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-password-marker"))
	raw := []byte(`{"auths":{"localhost:5000":{"auth":"` + auth + `"}}}`)
	require.NoError(t, validateRegistryAuth(raw, repository))
	for _, body := range []string{
		`{}`,
		`{"auths":{}}`,
		`{"auths":{"other:5000":{"username":"fixture-user","password":"fixture-pass"}}}`,
		`{"auths":{"https://localhost:5000":{"username":"fixture-user","password":"fixture-pass"}}}`,
		`{"auths":{"localhost:5000":{"username":"fixture-user","password":"fixture-pass"},"other":{}}}`,
		`{"auths":{"localhost:5000":{"username":"fixture-user","password":"fixture-pass"}},"credsStore":"helper"}`,
		`{"auths":{"localhost:5000":{"username":"fixture-user","password":"fixture-pass"}},"credHelpers":{"localhost:5000":"helper"}}`,
		`{"auths":{"localhost:5000":{"username":"fixture-user","password":"fixture-pass","exec":"anything"}}}`,
		`{"auths":{"localhost:5000":{"identitytoken":"not-a-real-token"}}}`,
		`{"auths":{"localhost:5000":{"auth":"not-base64"}}}`,
		`{"auths":{"localhost:5000":{"username":"fixture-user"}}}`,
		`{"auths":{"localhost:5000":{"username":"fixture-user","password":"fixture\npass"}}}`,
		`{"auths":{"localhost:5000":{"auth":"` + auth + `","username":"different-user"}}}`,
		`{"auths":{"localhost:5000":{"username":"fixture-user","password":"first","password":"second"}}}`,
		string(raw) + strings.Repeat(" ", maxRegistryConfigBytes),
	} {
		err := validateRegistryAuth([]byte(body), repository)
		require.ErrorIs(t, err, ErrInvalid)
		require.NotContains(t, err.Error(), "fixture-password")
		require.NotContains(t, err.Error(), "fixture-user")
	}
}

func TestRegistrySecretProjectionAndMetadataNeverEnterContext(t *testing.T) {
	f := registryFixture(t)
	r := f.start(t)
	require.Equal(t, SecretIdentity{Name: "registry-auth-v1", UID: "registry-secret", ResourceVersion: "1"}, r.RegistrySecret)
	job, err := f.kube.BatchV1().Jobs(r.Namespace).Get(t.Context(), r.JobName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, job.Spec.Template.Spec.Containers, 1)
	require.Len(t, job.Spec.Template.Spec.Volumes, 5)
	projection := job.Spec.Template.Spec.Volumes[4].Secret
	require.Equal(t, "registry-auth-v1", projection.SecretName)
	require.Equal(t, []corev1.KeyToPath{{Key: corev1.DockerConfigJsonKey, Path: registryConfigFile}}, projection.Items)
	require.Equal(t, corev1.VolumeMount{Name: "registry-auth", MountPath: registryConfigDirectory, ReadOnly: true},
		job.Spec.Template.Spec.Containers[0].VolumeMounts[4])
	require.False(t, *job.Spec.Template.Spec.AutomountServiceAccountToken)
	require.Equal(t, "registry-secret", job.Annotations[registryUIDAnnotation])
	require.Equal(t, "1", job.Spec.Template.Annotations[registryVersionAnnotation])
	anchor, err := f.kube.CoreV1().Secrets(r.Namespace).Get(t.Context(), r.AnchorName, metav1.GetOptions{})
	require.NoError(t, err)
	m, input, err := unpackBundle(anchor.Data)
	require.NoError(t, err)
	require.Equal(t, "registry-auth-v1", m.RegistrySecretName)
	for _, content := range input.Files {
		require.NotContains(t, string(content), "fixture-password-marker")
	}
	require.NotContains(t, string(anchor.Data[manifestKey]), "fixture-password-marker")
	encoded, err := json.Marshal(r)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "fixture-password-marker")
	f.pod(t, r, goodResult(r))
	secret, err := f.kube.CoreV1().Secrets(r.Namespace).Get(t.Context(), "registry-auth-v1", metav1.GetOptions{})
	require.NoError(t, err)
	secret.ResourceVersion = "2"
	require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), secret, r.Namespace))
	result, err := f.backend.Observe(t.Context(), r)
	require.ErrorIs(t, err, ErrIdentity)
	require.False(t, result.Done)
	refused, err := f.backend.Start(t.Context(), f.input)
	require.ErrorIs(t, err, ErrIdentity)
	require.Equal(t, r.InputDigest, refused.InputDigest)
	require.Equal(t, r.ConfigurationDigest, refused.ConfigurationDigest)
	require.NotEqual(t, r.RegistrySecret, refused.RegistrySecret)
	require.NoError(t, f.backend.Cancel(t.Context(), r))
	_, err = f.kube.CoreV1().Secrets(r.Namespace).Get(t.Context(), "registry-auth-v1", metav1.GetOptions{})
	require.NoError(t, err)
}

func TestRegistryAuthReferenceAndSecretShapeFailClosed(t *testing.T) {
	for _, name := range []string{"../secret", "invalid/key", "buildkit-ca-v1", "buildkit-client-v1"} {
		f := newFixture(t)
		f.config.RegistrySecretName = name
		_, err := New(f.config)
		require.ErrorIs(t, err, ErrInvalid)
	}
	for _, mutate := range []func(*corev1.Secret){
		func(secret *corev1.Secret) { secret.Immutable = new(false) },
		func(secret *corev1.Secret) { secret.Type = corev1.SecretTypeOpaque },
		func(secret *corev1.Secret) { secret.Data = map[string][]byte{"config.json": []byte("{}")} },
		func(secret *corev1.Secret) { secret.Data["extra"] = []byte("invalid") },
	} {
		f := registryFixture(t)
		secret, err := f.kube.CoreV1().Secrets("builds").Get(t.Context(), "registry-auth-v1", metav1.GetOptions{})
		require.NoError(t, err)
		mutate(secret)
		require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), secret, "builds"))
		_, err = f.backend.Start(t.Context(), f.input)
		require.ErrorIs(t, err, ErrIdentity)
		require.Zero(t, countActions(f.kube, "create", "jobs"))
	}
}
