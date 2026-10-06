package buildjob

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetesting "k8s.io/client-go/testing"
)

func TestRemoteBuildKitRequiresOperatorMutualTLS(t *testing.T) {
	for _, tls := range []*TLS{
		nil,
		{CASecretName: "ca", ServerName: "buildkit.builds.svc"},
		{CASecretName: "ca", ClientSecretName: "../client", ServerName: "buildkit.builds.svc"},
		{CASecretName: "ca", ClientSecretName: "ca", ServerName: "buildkit.builds.svc"},
		{CASecretName: "ca", ClientSecretName: "client", ServerName: "unapproved.builds.svc"},
	} {
		f := newFixture(t)
		f.config.TLS = tls
		_, err := New(f.config)
		require.ErrorIs(t, err, ErrInvalid)
	}
}

func TestMutualTLSProjectsStrictKeysOnlyIntoTrustedClient(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	require.Equal(t, SecretIdentity{Name: "buildkit-ca-v1", UID: "ca-secret", ResourceVersion: "1"}, r.TLSSecrets.CA)
	require.Equal(t, SecretIdentity{Name: "buildkit-client-v1", UID: "client-secret", ResourceVersion: "1"}, r.TLSSecrets.Client)
	job, err := f.kube.BatchV1().Jobs(r.Namespace).Get(t.Context(), r.JobName, metav1.GetOptions{})
	require.NoError(t, err)
	pod := job.Spec.Template.Spec
	require.False(t, *pod.AutomountServiceAccountToken)
	require.Len(t, pod.Containers, 1)
	require.Len(t, pod.Volumes, 4)
	require.Equal(t, "buildkit-client-v1", pod.Volumes[3].Secret.SecretName)
	require.Equal(t, []corev1.KeyToPath{
		{Key: corev1.TLSCertKey, Path: corev1.TLSCertKey},
		{Key: corev1.TLSPrivateKeyKey, Path: corev1.TLSPrivateKeyKey},
	}, pod.Volumes[3].Secret.Items)
	require.EqualValues(t, 0440, *pod.Volumes[3].Secret.DefaultMode)
	require.Equal(t, corev1.VolumeMount{Name: "builder-client", MountPath: "/builder-client", ReadOnly: true},
		pod.Containers[0].VolumeMounts[3])
	require.Equal(t, string(r.TLSSecrets.Client.UID), job.Annotations[clientUIDAnnotation])
	require.Equal(t, r.TLSSecrets.Client.ResourceVersion, job.Spec.Template.Annotations[clientVersionAnnotation])
	anchor, err := f.kube.CoreV1().Secrets(r.Namespace).Get(t.Context(), r.AnchorName, metav1.GetOptions{})
	require.NoError(t, err)
	m, input, err := unpackBundle(anchor.Data)
	require.NoError(t, err)
	require.Equal(t, f.input.Files, input.Files)
	require.Equal(t, "buildkit-client-v1", m.TLS.ClientSecretName)
	encoded, err := json.Marshal(struct {
		Receipt Receipt
		Input   Input
		Data    map[string][]byte
	}{r, input, anchor.Data})
	require.NoError(t, err)
	for _, marker := range []string{"synthetic-key-material", "synthetic-certificate-material", "synthetic-ca-material"} {
		require.NotContains(t, string(encoded), marker)
		for _, body := range input.Files {
			require.NotContains(t, string(body), marker)
		}
	}
}

func TestTLSSecretShapeAndImmutabilityFailBeforeWorkloadCreation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*corev1.Secret)
	}{
		{"mutable", func(secret *corev1.Secret) { secret.Immutable = new(false) }},
		{"wrong-type", func(secret *corev1.Secret) { secret.Type = corev1.SecretTypeOpaque }},
		{"missing-key", func(secret *corev1.Secret) { delete(secret.Data, corev1.TLSPrivateKeyKey) }},
		{"extra-key", func(secret *corev1.Secret) { secret.Data["other"] = []byte("not projected") }},
		{"empty-key", func(secret *corev1.Secret) { secret.Data[corev1.TLSPrivateKeyKey] = nil }},
		{"missing-uid", func(secret *corev1.Secret) { secret.UID = "" }},
		{"missing-version", func(secret *corev1.Secret) { secret.ResourceVersion = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			secret, err := f.kube.CoreV1().Secrets("builds").Get(t.Context(), "buildkit-client-v1", metav1.GetOptions{})
			require.NoError(t, err)
			test.change(secret)
			require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), secret, "builds"))
			_, err = f.backend.Start(t.Context(), f.input)
			require.ErrorIs(t, err, ErrIdentity)
			require.Zero(t, countActions(f.kube, "create", "jobs"))
			require.Zero(t, countActions(f.kube, "create", "secrets"))
		})
	}
}

func TestTLSRotationRejectsObservationAndReplayButAllowsExactCleanup(t *testing.T) {
	for _, name := range []string{"buildkit-ca-v1", "buildkit-client-v1"} {
		for _, replace := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "-version", true: "-uid"}[replace], func(t *testing.T) {
				f := newFixture(t)
				r := f.start(t)
				f.pod(t, r, goodResult(r))
				secret, err := f.kube.CoreV1().Secrets(r.Namespace).Get(t.Context(), name, metav1.GetOptions{})
				require.NoError(t, err)
				secret.ResourceVersion = "rotated"
				if replace {
					secret.UID = "replacement"
				}
				require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), secret, r.Namespace))
				result, err := f.backend.Observe(t.Context(), r)
				require.ErrorIs(t, err, ErrIdentity)
				require.False(t, result.Done)
				refused, err := f.backend.Start(t.Context(), f.input)
				require.ErrorIs(t, err, ErrIdentity)
				require.Equal(t, r.InputDigest, refused.InputDigest)
				require.Equal(t, r.ConfigurationDigest, refused.ConfigurationDigest)
				require.NotEqual(t, r.TLSSecrets, refused.TLSSecrets)
				require.Equal(t, 1, countActions(f.kube, "create", "jobs"))
				require.NoError(t, f.backend.Cancel(t.Context(), r))
				_, err = f.kube.CoreV1().Secrets(r.Namespace).Get(t.Context(), name, metav1.GetOptions{})
				require.NoError(t, err)
			})
		}
	}
}

func TestTLSBindingIsCheckedImmediatelyBeforeJobCreate(t *testing.T) {
	f := newFixture(t)
	f.kube.PrependReactor("update", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
		secret := action.(kubetesting.UpdateAction).GetObject().(*corev1.Secret)
		if strings.HasSuffix(secret.Name, "-input") && secret.Annotations[stateAnnotation] == submittedState {
			object, err := f.kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), "builds", "buildkit-client-v1")
			if err != nil {
				return true, nil, err
			}
			client := object.(*corev1.Secret)
			client.ResourceVersion = "changed-before-create"
			if err := f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), client, "builds"); err != nil {
				return true, nil, err
			}
		}
		return false, nil, nil
	})
	_, err := f.backend.Start(t.Context(), f.input)
	require.ErrorIs(t, err, ErrIdentity)
	require.Zero(t, countActions(f.kube, "create", "jobs"))
}

func TestTLSBindingIsRecheckedAfterTerminationRead(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	f.pod(t, r, goodResult(r))
	f.kube.PrependReactor("get", "pods", func(kubetesting.Action) (bool, runtime.Object, error) {
		object, err := f.kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), r.Namespace, "buildkit-client-v1")
		if err != nil {
			return true, nil, err
		}
		secret := object.(*corev1.Secret)
		secret.ResourceVersion = "changed-during-observation"
		if err := f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), secret, r.Namespace); err != nil {
			return true, nil, err
		}
		return false, nil, nil
	})
	result, err := f.backend.Observe(t.Context(), r)
	require.ErrorIs(t, err, ErrIdentity)
	require.False(t, result.Done)
}

func TestTLSAPIErrorNeverReflectsSecretPayload(t *testing.T) {
	f := newFixture(t)
	f.kube.PrependReactor("get", "secrets", func(kubetesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("synthetic-key-material should not be returned")
	})
	_, err := f.backend.Start(context.Background(), f.input)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "synthetic-key-material")
}
