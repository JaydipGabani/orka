package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestCopilotFreshPreCreateReadFailsFastAndCanRetry(t *testing.T) {
	adapter, kube, _, creates := copilotFixture(t)
	identity, err := adapter.Snapshot(t.Context())
	require.NoError(t, err)
	request := Request{TaskName: "rm-" + strings.Repeat("b", 32) + "-checks", RunID: "rm-" + strings.Repeat("b", 32),
		Prompt: "synthetic pre-create retry", ExpectedIdentity: identity.Digest}
	outage, reads, accepted := true, 0, 0
	adapter.PollInterval = time.Hour
	adapter.Reader = interceptor.NewClient(kube, interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
			if _, task := object.(*corev1alpha1.Task); task {
				reads++
				if outage {
					return apierrors.NewServiceUnavailable("synthetic-api-response")
				}
			}
			return delegate.Get(ctx, key, object, options...)
		},
	})
	adapter.OnAccepted = func(ctx context.Context, result Result) error {
		accepted++
		task := &corev1alpha1.Task{}
		require.NoError(t, kube.Get(ctx, client.ObjectKey{Namespace: adapter.Namespace, Name: result.TaskName}, task))
		task.Status.Phase = corev1alpha1.TaskPhaseSucceeded
		task.Status.Execution = &corev1alpha1.TaskExecutionStatus{State: corev1alpha1.TaskExecutionStateSucceeded}
		require.NoError(t, kube.Status().Update(ctx, task))
		return adapter.Results.SaveResult(ctx, task.Namespace, task.Name, []byte(`{"summary":"synthetic"}`))
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result, err := adapter.Generate(ctx, request)
	require.ErrorIs(t, err, ErrDependencyUnavailable)
	require.ErrorIs(t, err, ErrNotSubmitted)
	require.NotContains(t, err.Error(), "synthetic-api-response")
	require.Empty(t, result.TaskUID)
	require.Empty(t, result.Output)
	require.NoError(t, ctx.Err())
	require.Equal(t, 1, reads)
	require.Zero(t, *creates)
	require.Zero(t, accepted)

	outage = false
	result, err = adapter.Generate(ctx, request)
	require.NoError(t, err)
	require.Equal(t, `{"summary":"synthetic"}`, result.Output)
	require.Equal(t, 1, *creates)
	require.Equal(t, 1, accepted)
}

func TestCopilotExistingReadsKeepBoundedWaitsWithoutCreating(t *testing.T) {
	for _, stage := range []string{"identity", "task"} {
		for _, fence := range []string{"require-existing", "uid"} {
			t.Run(stage+"/"+fence, func(t *testing.T) {
				adapter, kube, _, creates := copilotFixture(t)
				adapter.PollInterval = time.Millisecond
				request := Request{TaskName: "rm-" + strings.Repeat("b", 32) + "-checks", RunID: "rm-" + strings.Repeat("b", 32),
					Prompt: "synthetic existing operation"}
				if fence == "require-existing" {
					request.RequireExisting = true
				} else {
					request.ExpectedTaskUID = "synthetic-accepted-uid"
				}
				reads := 0
				adapter.Reader = interceptor.NewClient(kube, interceptor.Funcs{
					Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
						_, task := object.(*corev1alpha1.Task)
						if stage == "identity" || task {
							reads++
							return apierrors.NewServiceUnavailable("synthetic-api-response")
						}
						return delegate.Get(ctx, key, object, options...)
					},
				})
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
				result, err := adapter.Generate(ctx, request)
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.NotErrorIs(t, err, ErrNotSubmitted)
				require.Equal(t, request.ExpectedTaskUID, result.TaskUID)
				require.Greater(t, reads, 1)
				require.Zero(t, *creates)
			})
		}
	}
}

func TestCopilotCancelledFreshReadProvesNoCreate(t *testing.T) {
	adapter, kube, _, creates := copilotFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	adapter.Reader = interceptor.NewClient(kube, interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
			if _, task := object.(*corev1alpha1.Task); task {
				cancel()
				return ctx.Err()
			}
			return delegate.Get(ctx, key, object, options...)
		},
	})
	result, err := adapter.Generate(ctx, Request{TaskName: "rm-" + strings.Repeat("b", 32) + "-checks",
		RunID: "rm-" + strings.Repeat("b", 32), Prompt: "synthetic cancellation"})
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, ErrNotSubmitted)
	require.Empty(t, result.TaskUID)
	require.Zero(t, *creates)
}

func TestCopilotCancelledMissingReadCannotStartCreate(t *testing.T) {
	adapter, kube, _, creates := copilotFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	adapter.Reader = interceptor.NewClient(kube, interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
			if _, task := object.(*corev1alpha1.Task); task {
				cancel()
				return apierrors.NewNotFound(schema.GroupResource{Group: corev1alpha1.GroupVersion.Group, Resource: "tasks"}, key.Name)
			}
			return delegate.Get(ctx, key, object, options...)
		},
	})
	_, err := adapter.Generate(ctx, Request{TaskName: "rm-" + strings.Repeat("b", 32) + "-checks",
		RunID: "rm-" + strings.Repeat("b", 32), Prompt: "synthetic cancellation"})
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, ErrNotSubmitted)
	require.Zero(t, *creates)
}
