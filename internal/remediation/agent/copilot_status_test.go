package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestCopilotCompletionDistinguishesProjectionMetadataFromExecutionIdentity(t *testing.T) {
	tests := []struct {
		name   string
		change func(*corev1alpha1.Task)
		accept bool
	}{
		{"unchanged", func(*corev1alpha1.Task) {}, true},
		{"transition-time", func(task *corev1alpha1.Task) {
			task.Status.Execution.LastTransitionTime = &metav1.Time{Time: time.Unix(200, 0)}
		}, true},
		{"transition-time-omitted", func(task *corev1alpha1.Task) { task.Status.Execution.LastTransitionTime = nil }, true},
		{"reason", func(task *corev1alpha1.Task) { task.Status.Execution.Reason = "ProjectionDelivered" }, true},
		{"message", func(task *corev1alpha1.Task) { task.Status.Execution.Message = "projection redelivered" }, true},
		{"phase", func(task *corev1alpha1.Task) { task.Status.Phase = corev1alpha1.TaskPhaseFailed }, false},
		{"missing-execution", func(task *corev1alpha1.Task) { task.Status.Execution = nil }, false},
		{"state", func(task *corev1alpha1.Task) { task.Status.Execution.State = corev1alpha1.TaskExecutionStateCancelled }, false},
		{"outcome", func(task *corev1alpha1.Task) {
			task.Status.Execution.Outcome = corev1alpha1.TaskExecutionOutcomeCancelled
		}, false},
		{"attempt", func(task *corev1alpha1.Task) { task.Status.Execution.Attempt++ }, false},
		{"prompt", func(task *corev1alpha1.Task) { task.Status.Execution.PromptID = "different-prompt" }, false},
		{"request", func(task *corev1alpha1.Task) {
			task.Status.Execution.RequestDigest = "sha256:" + strings.Repeat("b", 64)
		}, false},
		{"pool-name", func(task *corev1alpha1.Task) { task.Status.Execution.RuntimePoolName = "different-pool" }, false},
		{"pool-uid", func(task *corev1alpha1.Task) { task.Status.Execution.RuntimePoolUID = "different-pool-uid" }, false},
		{"instance", func(task *corev1alpha1.Task) { task.Status.Execution.RuntimeInstanceID = "different-instance" }, false},
		{"session", func(task *corev1alpha1.Task) { task.Status.Execution.RuntimeSessionUID = "different-session" }, false},
		{"session-generation", func(task *corev1alpha1.Task) { task.Status.Execution.RuntimeSessionGeneration++ }, false},
		{"session-boot", func(task *corev1alpha1.Task) { task.Status.Execution.RuntimeSessionSupervisorBootID = "different-boot" }, false},
		{"session-profile", func(task *corev1alpha1.Task) {
			task.Status.Execution.RuntimeSessionProfileDigest = "sha256:" + strings.Repeat("b", 64)
		}, false},
		{"session-mcp", func(task *corev1alpha1.Task) {
			task.Status.Execution.RuntimeSessionMCPDigest = "sha256:" + strings.Repeat("b", 64)
		}, false},
		{"session-workspace", func(task *corev1alpha1.Task) {
			task.Status.Execution.RuntimeSessionWorkspaceDigest = "sha256:" + strings.Repeat("b", 64)
		}, false},
		{"session-recreation", func(task *corev1alpha1.Task) { task.Status.Execution.RuntimeSessionRecreationPending = true }, false},
		{"session-cleanup", func(task *corev1alpha1.Task) {
			task.Status.Execution.RuntimeSessionCleanupDigest = "sha256:" + strings.Repeat("b", 64)
		}, true},
		{"controller-epoch", func(task *corev1alpha1.Task) { task.Status.Execution.ControllerEpoch++ }, true},
		{"task-uid", func(task *corev1alpha1.Task) { task.UID = "different-task" }, false},
		{"task-spec", func(task *corev1alpha1.Task) { task.Spec.Prompt = "different-prompt" }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, kube, _, creates := copilotFixture(t)
			identity, err := adapter.Snapshot(t.Context())
			require.NoError(t, err)
			adapter.OnAccepted = func(ctx context.Context, result Result) error {
				task := &corev1alpha1.Task{}
				require.NoError(t, kube.Get(ctx, client.ObjectKey{Namespace: adapter.Namespace, Name: result.TaskName}, task))
				task.Status.Phase = corev1alpha1.TaskPhaseSucceeded
				task.Status.Execution = &corev1alpha1.TaskExecutionStatus{
					State: corev1alpha1.TaskExecutionStateSucceeded, Outcome: corev1alpha1.TaskExecutionOutcomeSucceeded,
					Attempt: 1, PromptID: "prompt-1", RequestDigest: "sha256:" + strings.Repeat("a", 64),
					RuntimePoolName: "pool-1", RuntimePoolUID: "pool-uid", RuntimeInstanceID: "instance-1",
					RuntimeSessionUID: "session-1", RuntimeSessionGeneration: 1, RuntimeSessionSupervisorBootID: "boot-1",
					RuntimeSessionProfileDigest: "sha256:" + strings.Repeat("a", 64), ControllerEpoch: 1,
					LastTransitionTime: &metav1.Time{Time: time.Unix(100, 0)},
				}
				require.NoError(t, kube.Status().Update(ctx, task))
				return adapter.Results.SaveResult(ctx, task.Namespace, task.Name, []byte(`{"summary":"completed once"}`))
			}
			completedReads := 0
			adapter.Reader = interceptor.NewClient(kube, interceptor.Funcs{
				Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
					if err := delegate.Get(ctx, key, object, options...); err != nil {
						return err
					}
					if task, ok := object.(*corev1alpha1.Task); ok && task.Status.Phase == corev1alpha1.TaskPhaseSucceeded {
						completedReads++
						if completedReads == 2 {
							tt.change(task)
						}
					}
					return nil
				},
			})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result, err := adapter.Generate(ctx, Request{
				TaskName: "rm-" + strings.Repeat("b", 32) + "-checks", RunID: "rm-" + strings.Repeat("b", 32),
				Prompt: "synthetic", ExpectedIdentity: identity.Digest,
			})
			if tt.accept {
				require.NoError(t, err)
				require.Equal(t, `{"summary":"completed once"}`, result.Output)
			} else {
				require.Error(t, err)
				require.NotErrorIs(t, err, context.DeadlineExceeded)
				require.Empty(t, result.Output)
			}
			require.Equal(t, 2, completedReads)
			require.Equal(t, 1, *creates)
		})
	}
}

func TestCopilotCompletionAllowsOnlyMonotonicRecoveryEvidence(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, tt := range []struct {
		name                        string
		beforeEpoch, afterEpoch     int64
		beforeCleanup, afterCleanup string
		accept                      bool
	}{
		{"unchanged", 2, 2, digest, digest, true},
		{"recovered", 2, 3, "", digest, true},
		{"regressed-epoch", 2, 1, digest, digest, false},
		{"removed-cleanup", 2, 3, digest, "", false},
		{"replaced-cleanup", 2, 3, digest, "sha256:" + strings.Repeat("b", 64), false},
		{"invalid-cleanup", 2, 3, "", "invalid-digest", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			adapter, kube, _, _ := copilotFixture(t)
			identity, err := adapter.Snapshot(t.Context())
			require.NoError(t, err)
			expected, err := adapter.task(Request{
				TaskName: "rm-" + strings.Repeat("b", 32) + "-checks", RunID: "rm-" + strings.Repeat("b", 32),
				Prompt: "synthetic", ExpectedIdentity: identity.Digest,
			})
			require.NoError(t, err)
			observed := expected.DeepCopy()
			observed.UID, observed.Generation = "copilot-task", 1
			observed.Status.Phase = corev1alpha1.TaskPhaseSucceeded
			observed.Status.Execution = &corev1alpha1.TaskExecutionStatus{
				State: corev1alpha1.TaskExecutionStateSucceeded, Outcome: corev1alpha1.TaskExecutionOutcomeSucceeded,
				Attempt: 1, PromptID: "prompt-1", RequestDigest: digest,
				ControllerEpoch: tt.afterEpoch, RuntimeSessionCleanupDigest: tt.afterCleanup,
			}
			require.NoError(t, kube.Create(t.Context(), observed))
			require.NoError(t, adapter.Results.SaveResult(t.Context(), observed.Namespace, observed.Name, []byte(`{"summary":"recovered"}`)))
			before := observed.DeepCopy()
			before.Status.Execution.ControllerEpoch = tt.beforeEpoch
			before.Status.Execution.RuntimeSessionCleanupDigest = tt.beforeCleanup
			original := before.DeepCopy()
			result := Result{TaskName: observed.Name, TaskUID: string(observed.UID)}
			output, err := adapter.completedCopilotResult(t.Context(), expected, before, identity, &result)
			require.Equal(t, original, before, "comparison must not mutate the original status")
			if tt.accept {
				require.NoError(t, err)
				require.Equal(t, `{"summary":"recovered"}`, output)
			} else {
				require.Error(t, err)
				require.Empty(t, output)
			}
		})
	}
}

func runningCopilotCleanupFixture(t *testing.T) (*acceptanceFixture, CopilotClient) {
	t.Helper()
	f := newAcceptanceFixture(t, remediationpolicy.CopilotBackend)
	f.task.Status.Phase = corev1alpha1.TaskPhaseRunning
	f.task.Status.Execution = &corev1alpha1.TaskExecutionStatus{State: corev1alpha1.TaskExecutionStateRunning, Attempt: 1}
	require.NoError(t, f.kube.Status().Update(t.Context(), f.task))
	return f, CopilotClient{
		Client: f.kube, Reader: f.adapter.Native.Reader,
		Namespace: f.task.Namespace, AgentName: f.request.Expected.AgentName,
	}
}

func TestCopilotCancellationRetriesStatusConflictsAndLostAcknowledgements(t *testing.T) {
	conflict := apierrors.NewConflict(schema.GroupResource{Resource: "tasks"}, "proposal", errors.New("private diagnostic"))
	for _, tt := range []struct {
		name      string
		failure   error
		committed bool
		want      error
	}{
		{"conflict", conflict, false, ErrCancellationPending},
		{"wrapped-conflict", fmt.Errorf("private wrapper: %w", conflict), false, ErrCancellationPending},
		{"unavailable", apierrors.NewServiceUnavailable("private diagnostic"), false, ErrDependencyUnavailable},
		{"lost-acknowledgement", apierrors.NewTimeoutError("private diagnostic", 1), true, ErrDependencyUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, adapter := runningCopilotCleanupFixture(t)
			writes := 0
			adapter.Client = interceptor.NewClient(f.kube, interceptor.Funcs{
				SubResourceUpdate: func(ctx context.Context, delegate client.Client, subresource string, object client.Object, options ...client.SubResourceUpdateOption) error {
					require.Equal(t, "status", subresource)
					writes++
					if writes == 1 {
						if tt.committed {
							require.NoError(t, delegate.Status().Update(ctx, object, options...))
						}
						return tt.failure
					}
					return delegate.Status().Update(ctx, object, options...)
				},
			})
			err := adapter.Cancel(t.Context(), f.task.Name, string(f.task.UID))
			require.ErrorIs(t, err, tt.want)
			require.NotContains(t, err.Error(), "private diagnostic")
			require.NotContains(t, err.Error(), "private wrapper")
			require.ErrorIs(t, adapter.Cancel(t.Context(), f.task.Name, string(f.task.UID)), ErrCancellationPending)
			wantWrites := 2
			if tt.committed {
				wantWrites = 1
			}
			require.Equal(t, wantWrites, writes)
			require.ErrorIs(t, adapter.Cancel(t.Context(), f.task.Name, string(f.task.UID)), ErrCancellationPending)
			require.Equal(t, wantWrites, writes, "an acknowledged cancellation must not keep rewriting status")

			current := &corev1alpha1.Task{}
			require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.task), current))
			require.Equal(t, corev1alpha1.TaskPhaseCancelled, current.Status.Phase)
			require.Equal(t, corev1alpha1.TaskExecutionStateRunning, current.Status.Execution.State)
			current.Status.Execution.State = corev1alpha1.TaskExecutionStateCancelled
			current.Status.Execution.Outcome = corev1alpha1.TaskExecutionOutcomeCancelled
			require.NoError(t, f.kube.Status().Update(t.Context(), current))
			require.NoError(t, adapter.Cancel(t.Context(), f.task.Name, string(f.task.UID)))
			require.Equal(t, wantWrites, writes)
		})
	}
}

func TestCopilotCancellationRetryDoesNotAdoptReplacement(t *testing.T) {
	f, adapter := runningCopilotCleanupFixture(t)
	writes := 0
	adapter.Client = interceptor.NewClient(f.kube, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
			writes++
			current := &corev1alpha1.Task{}
			require.NoError(t, f.kube.Get(ctx, client.ObjectKeyFromObject(f.task), current))
			require.NoError(t, f.kube.Delete(ctx, current))
			current.UID, current.ResourceVersion = "replacement-task", ""
			require.NoError(t, f.kube.Create(ctx, current))
			return apierrors.NewConflict(schema.GroupResource{Resource: "tasks"}, f.task.Name, errors.New("private diagnostic"))
		},
	})
	require.ErrorIs(t, adapter.Cancel(t.Context(), f.task.Name, string(f.task.UID)), ErrCancellationPending)
	require.ErrorIs(t, adapter.Cancel(t.Context(), f.task.Name, string(f.task.UID)), remediationpolicy.ErrIdentityChanged)
	require.Equal(t, 1, writes)
}

func TestCopilotCancellationClassifiesDependencyAndPermanentErrors(t *testing.T) {
	for _, stage := range []string{"read", "write"} {
		for _, tt := range []struct {
			name       string
			failure    error
			dependency bool
		}{
			{"unavailable", apierrors.NewServiceUnavailable("private diagnostic"), true},
			{"wrapped-timeout", fmt.Errorf("private wrapper: %w", apierrors.NewTimeoutError("private diagnostic", 1)), true},
			{"throttled", apierrors.NewTooManyRequests("private diagnostic", 1), true},
			{"forbidden", apierrors.NewForbidden(schema.GroupResource{Resource: "tasks"}, "proposal", errors.New("private diagnostic")), false},
		} {
			t.Run(stage+"/"+tt.name, func(t *testing.T) {
				f, adapter := runningCopilotCleanupFixture(t)
				if stage == "read" {
					f.readErr = tt.failure
				} else {
					adapter.Client = interceptor.NewClient(f.kube, interceptor.Funcs{
						SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
							return tt.failure
						},
					})
				}
				err := adapter.Cancel(t.Context(), f.task.Name, string(f.task.UID))
				require.Error(t, err)
				require.Equal(t, tt.dependency, errors.Is(err, ErrDependencyUnavailable))
				require.NotErrorIs(t, err, ErrCancellationPending)
				require.NotContains(t, err.Error(), "private diagnostic")
				require.NotContains(t, err.Error(), "private wrapper")
			})
		}
	}
}

func TestCopilotCancellationDoesNotRetryCancelledContext(t *testing.T) {
	f, adapter := runningCopilotCleanupFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	adapter.Client = interceptor.NewClient(f.kube, interceptor.Funcs{
		SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
			cancel()
			return apierrors.NewConflict(schema.GroupResource{Resource: "tasks"}, f.task.Name, errors.New("private diagnostic"))
		},
	})
	require.ErrorIs(t, adapter.Cancel(ctx, f.task.Name, string(f.task.UID)), context.Canceled)
}
