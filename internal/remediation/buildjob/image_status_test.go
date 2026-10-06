package buildjob

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestObserveAcceptsCRIConfigDigestWithExactManifestIdentity(t *testing.T) {
	f := newFixture(t)
	receipt := f.start(t)
	pod := f.pod(t, receipt, goodResult(receipt))
	pod.Status.ContainerStatuses[0].Image = "sha256:" + strings.Repeat("e", 64)
	require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, receipt.Namespace))
	result, err := f.backend.Observe(t.Context(), receipt)
	require.NoError(t, err)
	require.True(t, result.Done)
	require.Equal(t, Success, result.BuildOutcome)

	pod.Status.ContainerStatuses[0].ImageID = "docker-pullable://" + testImage("different", "f")
	require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, receipt.Namespace))
	_, err = f.backend.Observe(t.Context(), receipt)
	require.ErrorIs(t, err, ErrIdentity, "a config digest cannot replace the exact runtime manifest check")
}
