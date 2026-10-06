package agent

import (
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestNativeProviderNotReadyProvesNoSubmission(t *testing.T) {
	f := newNativeFixture(t)
	require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.provider), f.provider))
	f.provider.Status.Ready = false
	require.NoError(t, f.kube.Status().Update(t.Context(), f.provider))
	result, err := f.adapter.Generate(t.Context(), f.request)
	require.ErrorIs(t, err, ErrProviderNotReady)
	require.ErrorIs(t, err, ErrNotSubmitted)
	require.Empty(t, result.TaskUID)
	require.Zero(t, f.creates)
}
