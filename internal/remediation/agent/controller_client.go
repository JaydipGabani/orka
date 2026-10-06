package agent

import (
	"context"
	"errors"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ControllerClient selects inference only from current operator configuration,
// but cleanup routes from the exact saved Task type. Removing a Copilot policy
// must not silently turn its cleanup into native Job cleanup.
type ControllerClient struct {
	Native  KubernetesClient
	Copilot *CopilotClient
}

func (c ControllerClient) Snapshot(ctx context.Context) (PlanIdentity, error) {
	if c.Copilot != nil {
		return c.Copilot.Snapshot(ctx)
	}
	return c.Native.Snapshot(ctx)
}

func (c ControllerClient) Generate(ctx context.Context, request Request) (Result, error) {
	if c.Copilot != nil {
		return c.Copilot.Generate(ctx, request)
	}
	return c.Native.Generate(ctx, request)
}

func (c ControllerClient) ResolveAccepted(ctx context.Context, request AcceptanceRequest) (Result, error) {
	// The observed Task and frozen identity select the cleanup backend, not
	// the currently configured inference client.
	return c.Native.ResolveAccepted(ctx, request)
}

func (c ControllerClient) Cancel(ctx context.Context, name, uid string) error {
	if c.Native.Reader == nil || name == "" || uid == "" {
		return errors.New("proposal cleanup reader is unavailable")
	}
	task := &corev1alpha1.Task{}
	if err := c.Native.Reader.Get(ctx, client.ObjectKey{Namespace: c.Native.Namespace, Name: name}, task); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return cleanupDependencyError(ctx, err, "proposal cleanup identity is unavailable")
	}
	if string(task.UID) != uid || task.Name != name || task.Namespace != c.Native.Namespace ||
		validateCleanupTask(task) != nil {
		return errors.New("proposal cleanup Task identity changed")
	}
	if task.DeletionTimestamp != nil {
		return ErrCancellationPending
	}
	if task.Spec.Type == corev1alpha1.TaskTypeAgent {
		return (CopilotClient{Client: c.Native.Client, Reader: c.Native.Reader, Results: c.Native.Results,
			Namespace: c.Native.Namespace, AgentName: c.Native.AgentName}).Cancel(ctx, name, uid)
	}
	return c.Native.Cancel(ctx, name, uid)
}

func (c ControllerClient) Retire(ctx context.Context, name, uid string) error {
	return c.Native.Retire(ctx, name, uid)
}
