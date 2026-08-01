/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package api

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

const taskResourceNameForTokenCleanupTest = "tasks"

func TestCleanupTaskAfterTransactionTokenSetupFailureDeletesExactTaskUID(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	task := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{
		Name: "failed-token-task", Namespace: testDefaultNamespace, UID: types.UID("created-task-uid"),
	}}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(task.DeepCopy()).Build()
	guarded := &taskUIDPreconditionClient{Client: base}
	handlers := &Handlers{client: guarded}

	if err := handlers.cleanupTaskAfterTransactionTokenSetupFailure(context.Background(), task); err != nil {
		t.Fatalf("cleanupTaskAfterTransactionTokenSetupFailure() error = %v", err)
	}
	if guarded.preconditionUID != task.UID {
		t.Fatalf("delete UID precondition = %q, want %q", guarded.preconditionUID, task.UID)
	}
	current := &corev1alpha1.Task{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(task), current); !apierrors.IsNotFound(err) {
		t.Fatalf("created Task remained after exact-UID cleanup: %v", err)
	}
}

func TestCleanupTaskAfterTransactionTokenSetupFailurePreservesReplacementTask(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	created := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{
		Name: "recreated-token-task", Namespace: testDefaultNamespace, UID: types.UID("original-task-uid"),
	}}
	replacement := created.DeepCopy()
	replacement.UID = types.UID("replacement-task-uid")
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(replacement).Build()
	guarded := &taskUIDPreconditionClient{Client: base}
	handlers := &Handlers{client: guarded}

	if err := handlers.cleanupTaskAfterTransactionTokenSetupFailure(context.Background(), created); err == nil {
		t.Fatal("cleanup unexpectedly succeeded against a replacement Task")
	}
	if guarded.preconditionUID != created.UID {
		t.Fatalf("delete UID precondition = %q, want original UID %q", guarded.preconditionUID, created.UID)
	}
	current := &corev1alpha1.Task{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(replacement), current); err != nil {
		t.Fatalf("replacement Task was deleted: %v", err)
	}
	if current.UID != replacement.UID {
		t.Fatalf("remaining Task UID = %q, want replacement UID %q", current.UID, replacement.UID)
	}
}

func TestCleanupTaskAfterTransactionTokenSetupFailureRequiresUID(t *testing.T) {
	handlers := &Handlers{client: &taskUIDPreconditionClient{}}
	task := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Name: "missing-uid", Namespace: testDefaultNamespace}}
	if err := handlers.cleanupTaskAfterTransactionTokenSetupFailure(context.Background(), task); err == nil {
		t.Fatal("cleanup accepted a Task without a UID")
	}
}

type taskUIDPreconditionClient struct {
	client.Client
	preconditionUID types.UID
}

func (c *taskUIDPreconditionClient) Delete(
	ctx context.Context,
	object client.Object,
	opts ...client.DeleteOption,
) error {
	options := (&client.DeleteOptions{}).ApplyOptions(opts)
	if options.Preconditions == nil || options.Preconditions.UID == nil {
		return c.Client.Delete(ctx, object, opts...)
	}
	c.preconditionUID = *options.Preconditions.UID
	current := &corev1alpha1.Task{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
		return err
	}
	if current.UID != c.preconditionUID {
		return apierrors.NewConflict(
			schema.GroupResource{Group: corev1alpha1.GroupVersion.Group, Resource: taskResourceNameForTokenCleanupTest},
			object.GetName(),
			errors.New("UID precondition does not match"),
		)
	}
	return c.Client.Delete(ctx, object)
}
