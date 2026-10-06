package agent

import (
	"context"
	"errors"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestRetirementConflictRevalidatesUIDAndResourceVersion(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		f := newAcceptanceFixture(t, remediationpolicy.CopilotBackend)
		deletes := 0
		var staleVersion string
		f.adapter.Native.Client = interceptor.NewClient(f.kube, interceptor.Funcs{
			Delete: func(ctx context.Context, delegate client.WithWatch, object client.Object, options ...client.DeleteOption) error {
				deletes++
				if deletes == 1 {
					staleVersion = object.GetResourceVersion()
					task := &corev1alpha1.Task{}
					require.NoError(t, f.kube.Get(ctx, client.ObjectKeyFromObject(f.task), task))
					if replacement {
						require.NoError(t, f.kube.Delete(ctx, task))
						task.UID, task.ResourceVersion = "same-name-new-uid", ""
						require.NoError(t, f.kube.Create(ctx, task))
					} else {
						task.Labels["fixture.orka.ai/metadata-revision"] = "updated"
						require.NoError(t, f.kube.Update(ctx, task))
					}
					return apierrors.NewConflict(schema.GroupResource{Resource: "tasks"}, object.GetName(), errors.New("private response"))
				}
				parsed := &client.DeleteOptions{}
				for _, option := range options {
					option.ApplyToDelete(parsed)
				}
				require.NotEqual(t, staleVersion, object.GetResourceVersion())
				require.Equal(t, f.task.UID, *parsed.Preconditions.UID)
				require.Equal(t, object.GetResourceVersion(), *parsed.Preconditions.ResourceVersion)
				return delegate.Delete(ctx, object, options...)
			},
		})
		err := f.adapter.Retire(t.Context(), f.task.Name, string(f.task.UID))
		require.ErrorIs(t, err, ErrDependencyUnavailable)
		require.NotContains(t, err.Error(), "private response")
		err = f.adapter.Retire(t.Context(), f.task.Name, string(f.task.UID))
		if replacement {
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrDependencyUnavailable)
			require.Equal(t, 1, deletes, "a replacement must not reach the delete call")
		} else {
			require.ErrorIs(t, err, ErrCancellationPending)
			require.NoError(t, f.adapter.Retire(t.Context(), f.task.Name, string(f.task.UID)))
			require.Equal(t, 2, deletes)
		}
	}
}
