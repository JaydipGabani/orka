package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestCopilotGenerateRecoversTransientAcceptanceReads(t *testing.T) {
	for _, stage := range []string{"acknowledged-create", "uncertain-create", "accepted-identity"} {
		t.Run(stage, func(t *testing.T) {
			adapter, kube, _, creates := copilotFixture(t)
			adapter.PollInterval = time.Millisecond
			identity, err := adapter.Snapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			failures := 2
			adapter.Reader = interceptor.NewClient(kube, interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch,
				key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
				_, taskRead := object.(*corev1alpha1.Task)
				if failures > 0 && *creates > 0 &&
					((stage == "accepted-identity" && !taskRead) || (stage != "accepted-identity" && taskRead)) {
					failures--
					return apierrors.NewServiceUnavailable("synthetic private read diagnostic")
				}
				return c.Get(ctx, key, object, opts...)
			}})
			if stage == "uncertain-create" {
				writer := adapter.Client
				adapter.Client = interceptor.NewClient(kube, interceptor.Funcs{Create: func(ctx context.Context, _ client.WithWatch,
					object client.Object, opts ...client.CreateOption) error {
					if err := writer.Create(ctx, object, opts...); err != nil {
						return err
					}
					return apierrors.NewTimeoutError("synthetic lost acknowledgement", 1)
				}})
			}
			accepted := 0
			adapter.OnAccepted = func(ctx context.Context, result Result) error {
				accepted++
				if result.TaskUID == "" {
					t.Fatal("acceptance lacked the exact Task UID")
				}
				if stage == "acknowledged-create" && failures != 2 {
					t.Fatal("acknowledged UID was not checkpointed before follow-up reads")
				}
				task := &corev1alpha1.Task{}
				if err := kube.Get(ctx, client.ObjectKey{Namespace: adapter.Namespace, Name: result.TaskName}, task); err != nil {
					return err
				}
				task.Status.Phase = corev1alpha1.TaskPhaseSucceeded
				task.Status.Execution = &corev1alpha1.TaskExecutionStatus{State: corev1alpha1.TaskExecutionStateSucceeded}
				if err := kube.Status().Update(ctx, task); err != nil {
					return err
				}
				return adapter.Results.SaveResult(ctx, task.Namespace, task.Name, []byte(`{"summary":"synthetic retry proof"}`))
			}
			result, err := adapter.Generate(t.Context(), Request{
				TaskName: "rm-" + strings.Repeat("b", 32) + "-checks", RunID: "rm-" + strings.Repeat("b", 32),
				Prompt: "synthetic", ExpectedIdentity: identity.Digest,
			})
			if err != nil || result.Output != `{"summary":"synthetic retry proof"}` || *creates != 1 || accepted != 1 || failures != 0 {
				t.Fatalf("retry did not converge exactly once: creates=%d accepted=%d remainingFailures=%d err=%v",
					*creates, accepted, failures, err)
			}
		})
	}
}

func TestCopilotGenerateFreshIdentityOutageReturnsDependencyWithoutCreation(t *testing.T) {
	adapter, kube, _, creates := copilotFixture(t)
	adapter.PollInterval = time.Hour
	adapter.Reader = interceptor.NewClient(kube, interceptor.Funcs{Get: func(context.Context, client.WithWatch,
		client.ObjectKey, client.Object, ...client.GetOption) error {
		return apierrors.NewServiceUnavailable("synthetic transport outage")
	}})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := adapter.Generate(ctx, Request{
		TaskName: "rm-" + strings.Repeat("b", 32) + "-checks", RunID: "rm-" + strings.Repeat("b", 32), Prompt: "synthetic",
	})
	if !errors.Is(err, ErrDependencyUnavailable) || !errors.Is(err, ErrNotSubmitted) || *creates != 0 || ctx.Err() != nil {
		t.Fatal("fresh identity outage did not return safe retry proof immediately", err)
	}
}
