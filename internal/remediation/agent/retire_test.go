package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestRetireTransientFailuresPreserveExactTaskAndRetry(t *testing.T) {
	for _, backend := range []string{"", remediationpolicy.CopilotBackend} {
		for _, failure := range []string{"get", "delete"} {
			t.Run(backend+"/"+failure, func(t *testing.T) {
				f := newAcceptanceFixture(t, backend)
				outage := true
				deletes := 0
				if failure == "get" {
					f.readErr = fmt.Errorf("synthetic-api-response: %w", apierrors.NewServiceUnavailable("synthetic-api-response"))
				}
				f.adapter.Native.Client = interceptor.NewClient(f.kube, interceptor.Funcs{
					Delete: func(ctx context.Context, delegate client.WithWatch, task client.Object, options ...client.DeleteOption) error {
						parsed := &client.DeleteOptions{}
						for _, option := range options {
							option.ApplyToDelete(parsed)
						}
						require.NotNil(t, parsed.Preconditions)
						require.Equal(t, f.task.UID, *parsed.Preconditions.UID)
						require.Equal(t, task.GetResourceVersion(), *parsed.Preconditions.ResourceVersion)
						require.Equal(t, metav1.DeletePropagationForeground, *parsed.PropagationPolicy)
						deletes++
						if failure == "delete" && outage {
							return apierrors.NewTimeoutError("synthetic-api-response", 1)
						}
						return delegate.Delete(ctx, task, options...)
					},
				})
				err := f.adapter.Retire(t.Context(), f.task.Name, string(f.task.UID))
				require.ErrorIs(t, err, ErrDependencyUnavailable)
				require.NotErrorIs(t, err, ErrCancellationPending)
				require.NotContains(t, err.Error(), "synthetic-api-response")
				remaining := &corev1alpha1.Task{}
				require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.task), remaining))
				require.Equal(t, f.task.UID, remaining.UID)
				f.readErr, outage = nil, false
				require.ErrorIs(t, f.adapter.Retire(t.Context(), f.task.Name, string(f.task.UID)), ErrCancellationPending)
				require.NoError(t, f.adapter.Retire(t.Context(), f.task.Name, string(f.task.UID)))
				if failure == "get" {
					require.Equal(t, 1, deletes)
				} else {
					require.Equal(t, 2, deletes)
				}
				require.Zero(t, f.writes)
			})
		}
	}
}

func TestRetirePermanentAPIFailuresRemainTerminalAndSanitized(t *testing.T) {
	resource := schema.GroupResource{Group: corev1alpha1.GroupVersion.Group, Resource: "tasks"}
	for _, apiErr := range []error{
		apierrors.NewConflict(resource, "synthetic", errors.New("synthetic-api-response")),
		apierrors.NewForbidden(resource, "synthetic", errors.New("synthetic-api-response")),
		apierrors.NewBadRequest("synthetic-api-response"),
	} {
		for _, failure := range []string{"get", "delete"} {
			t.Run(fmt.Sprintf("%s/%T", failure, apiErr), func(t *testing.T) {
				f := newAcceptanceFixture(t, remediationpolicy.CopilotBackend)
				if failure == "get" {
					f.readErr = apiErr
				} else {
					f.adapter.Native.Client = interceptor.NewClient(f.kube, interceptor.Funcs{
						Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error { return apiErr },
					})
				}
				err := f.adapter.Retire(t.Context(), f.task.Name, string(f.task.UID))
				require.Error(t, err)
				if failure == "delete" && apierrors.IsConflict(apiErr) {
					require.ErrorIs(t, err, ErrDependencyUnavailable)
				} else {
					require.NotErrorIs(t, err, ErrDependencyUnavailable)
				}
				require.NotErrorIs(t, err, ErrCancellationPending)
				require.NotContains(t, err.Error(), "synthetic-api-response")
				require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.task), &corev1alpha1.Task{}))
			})
		}
	}
}

func TestRetireRejectsChangedTaskBeforeDelete(t *testing.T) {
	for _, backend := range []string{"", remediationpolicy.CopilotBackend} {
		for _, test := range []struct {
			name   string
			change func(*corev1alpha1.Task)
		}{
			{"uid", func(task *corev1alpha1.Task) { task.UID = "same-name-replacement" }},
			{"namespace", func(task *corev1alpha1.Task) { task.Namespace = "another-namespace" }},
			{"identity", func(task *corev1alpha1.Task) {
				task.Annotations[nativeIdentityAnnotation] = "sha256:" + strings.Repeat("f", 64)
			}},
			{"spec", func(task *corev1alpha1.Task) { task.Spec.Prompt = "changed synthetic prompt" }},
			{"request-digest", func(task *corev1alpha1.Task) { delete(task.Annotations, nativeRequestAnnotation) }},
		} {
			t.Run(backend+"/"+test.name, func(t *testing.T) {
				f := newAcceptanceFixture(t, backend)
				f.observed = test.change
				err := f.adapter.Retire(t.Context(), f.task.Name, string(f.task.UID))
				require.Error(t, err)
				require.NotErrorIs(t, err, ErrDependencyUnavailable)
				require.NotErrorIs(t, err, ErrCancellationPending)
				require.Zero(t, f.writes)
			})
		}
	}
}

func TestRetireWaitsForExactFinalizerBackedDeletion(t *testing.T) {
	for _, backend := range []string{"", remediationpolicy.CopilotBackend} {
		t.Run("backend="+backend, func(t *testing.T) {
			f := newAcceptanceFixture(t, backend)
			current := &corev1alpha1.Task{}
			require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.task), current))
			current.Finalizers = []string{"fixture.orka.ai/cleanup"}
			require.NoError(t, f.kube.Update(t.Context(), current))
			deletes := 0
			f.adapter.Native.Client = interceptor.NewClient(f.kube, interceptor.Funcs{
				Delete: func(ctx context.Context, delegate client.WithWatch, task client.Object, options ...client.DeleteOption) error {
					deletes++
					return delegate.Delete(ctx, task, options...)
				},
			})
			for range 3 {
				require.ErrorIs(t, f.adapter.Retire(t.Context(), f.task.Name, string(f.task.UID)), ErrCancellationPending)
			}
			require.Equal(t, 1, deletes)
			require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.task), current))
			require.NotNil(t, current.DeletionTimestamp)
			require.Equal(t, f.task.UID, current.UID)
			current.Finalizers = nil
			require.NoError(t, f.kube.Update(t.Context(), current))
			require.NoError(t, f.adapter.Retire(t.Context(), f.task.Name, string(f.task.UID)))
		})
	}
}

func TestRetireCallerCancellationIsNotDependencyOutage(t *testing.T) {
	f := newAcceptanceFixture(t, remediationpolicy.CopilotBackend)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := f.adapter.Retire(ctx, f.task.Name, string(f.task.UID))
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, ErrDependencyUnavailable)
	require.Zero(t, f.reads)
	require.Zero(t, f.writes)
}
