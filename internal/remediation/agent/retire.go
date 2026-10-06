package agent

import (
	"context"
	"errors"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Retire removes a terminal proposal only after the caller has durably copied
// its result. UID/RV preconditions prevent deleting an externally replaced Task.
func (c KubernetesClient) Retire(ctx context.Context, name, uid string) error {
	if err := c.validateReader(ctx); err != nil {
		return err
	}
	if c.Client == nil || name == "" || uid == "" {
		return errors.New("proposal retirement requires exact Task identity")
	}
	task := &corev1alpha1.Task{}
	if err := c.Reader.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: name}, task); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return cleanupDependencyError(ctx, err, "proposal retirement observation failed")
	}
	if string(task.UID) != uid || task.Name != name || task.Namespace != c.Namespace ||
		validateCleanupTask(task) != nil {
		return errors.New("proposal retirement identity changed")
	}
	switch task.Status.Phase {
	case corev1alpha1.TaskPhaseSucceeded, corev1alpha1.TaskPhaseFailed, corev1alpha1.TaskPhaseCancelled:
	default:
		return ErrCancellationPending
	}
	if task.DeletionTimestamp != nil {
		return ErrCancellationPending
	}
	expectedUID, version := types.UID(uid), task.ResourceVersion
	propagation := metav1.DeletePropagationForeground
	if err := c.Client.Delete(ctx, task, &client.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &expectedUID, ResourceVersion: &version}, PropagationPolicy: &propagation,
	}); err != nil && !apierrors.IsNotFound(err) {
		if apierrors.IsConflict(err) && ctx.Err() == nil {
			// Status/finalizer writes may race this exact-RV deletion. The next
			// attempt must re-read and validate the UID/spec, never drop fences.
			return errors.Join(ErrDependencyUnavailable, errors.New("proposal retirement requires identity revalidation"))
		}
		return cleanupDependencyError(ctx, err, "proposal retirement could not be requested")
	}
	return ErrCancellationPending
}
