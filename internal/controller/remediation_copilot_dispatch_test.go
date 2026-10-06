package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRemediationQueueRetriesAuthorityOutageWithoutFailingTask(t *testing.T) {
	task := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{
		Name: "rm-" + strings.Repeat("a", 32) + "-checks",
	}}
	reconciler := &TaskReconciler{RemediationACPValidator: func(context.Context, *corev1alpha1.Task) error {
		return apierrors.NewServiceUnavailable("synthetic authorization outage")
	}}
	result, err := reconciler.queueACPRuntimeTask(t.Context(), task, nil)
	if err != nil || result.RequeueAfter <= 0 || task.Status.Phase == corev1alpha1.TaskPhaseFailed {
		t.Fatal("transient authority failure permanently failed a queued proposal", result, err)
	}
}

func TestRemediationDispatchSettlesAuthorityLossBeforePrompt(t *testing.T) {
	for _, test := range []struct {
		name      string
		rejectAt  int
		clearHook bool
		wantState store.PromptExecutionState
		creates   int32
	}{
		{"before-session", 1, false, store.PromptExecutionReserved, 0},
		{"after-submitting", 2, false, store.PromptExecutionFailed, 1},
		{"missing-hook-after-submitting", 2, true, store.PromptExecutionFailed, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			var creates, deletes, prompts atomic.Int32
			fixture := newTaskScopedCreateConflictFixture(t, ctx, test.name, types.UID("remediation-task"),
				func(profile harnessv2.RuntimeProfile, digest harnessv2.ProfileDigest, _ *client.Client) *httptest.Server {
					server := newDispatcherRuntimeServerWithOptions(t, profile, digest,
						dispatcherRuntimeServerOptions{onDelete: func(harnessv2.DeleteRuntimeSessionRequest) { deletes.Add(1) }},
						func(harnessv2.CreateRuntimeSessionRequest) { creates.Add(1) })
					handler := server.Config.Handler
					server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
						if strings.Contains(request.URL.Path, "/prompts/") {
							prompts.Add(1)
						}
						handler.ServeHTTP(w, request)
					})
					return server
				})
			defer fixture.stop()
			task := fixture.currentTask(t, ctx)
			// Exercise dispatch settlement independently of provider-specific
			// admission by enabling the callback on the existing bound fixture.
			task.Labels[labels.LabelCreatedBy] = remediationpolicy.CreatedBy
			if err := fixture.kubeClient.Update(ctx, task); err != nil {
				t.Fatal(err)
			}
			calls := 0
			fixture.dispatcher.RemediationDispatchValidator = func(context.Context, *corev1alpha1.Task, *corev1alpha1.RuntimePool) error {
				calls++
				if test.clearHook && calls == test.rejectAt-1 {
					fixture.dispatcher.RemediationDispatchValidator = nil
				}
				if calls == test.rejectAt {
					return errors.New("synthetic authority denial")
				}
				return nil
			}
			dispatchQueuedTask(ctx, t, fixture.dispatcher, task)
			attempt, err := fixture.dispatcher.Store.GetPromptAttempt(ctx, fixture.attemptID)
			if err != nil {
				t.Fatal(err)
			}
			if attempt.ExecutionState != test.wantState {
				t.Fatalf("attempt = %s, want %s", attempt.ExecutionState, test.wantState)
			}
			if creates.Load() != test.creates || deletes.Load() != test.creates || prompts.Load() != 0 {
				t.Fatalf("runtime effects = create:%d delete:%d prompt:%d; want %d/%d/0",
					creates.Load(), deletes.Load(), prompts.Load(), test.creates, test.creates)
			}
			wantCalls := test.rejectAt
			if test.clearHook {
				wantCalls--
			}
			if calls != wantCalls {
				t.Fatalf("authority checks = %d, want %d", calls, wantCalls)
			}
			current := fixture.currentTask(t, ctx)
			if test.wantState == store.PromptExecutionFailed && current.Status.Execution.State != corev1alpha1.TaskExecutionStateFailed {
				t.Fatal("durable terminal state was not projected onto the Task")
			}
		})
	}
}
