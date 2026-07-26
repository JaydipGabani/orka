/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"errors"
	"testing"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
)

func TestSubstratePoolActorLeaseTaskHolderKeepsToolAnnotations(t *testing.T) {
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Name:      "actor-00000",
			Annotations: map[string]string{
				substratePoolActorLeaseToolNSAnno:   "tool-ns",
				substratePoolActorLeaseToolNameAnno: "tool-name",
				substratePoolActorLeaseToolUIDAnno:  "tool-uid",
			},
		},
	}
	task := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "task", UID: types.UID("task-uid")}}

	setSubstratePoolActorLeaseHolder(lease, task, "actor-00000")

	if lease.Labels[labels.LabelPurpose] != substratePoolActorLeasePurpose {
		t.Fatalf("purpose label = %q, want %q", lease.Labels[labels.LabelPurpose], substratePoolActorLeasePurpose)
	}
	if !substratePoolActorLeaseHeldByTask(lease, task) {
		t.Fatalf("lease should be held by task")
	}
	if lease.Annotations[substratePoolActorLeaseToolNSAnno] != "tool-ns" ||
		lease.Annotations[substratePoolActorLeaseToolNameAnno] != "tool-name" ||
		lease.Annotations[substratePoolActorLeaseToolUIDAnno] != "tool-uid" {
		t.Fatalf("task holder update should preserve existing tool annotations, got %#v", lease.Annotations)
	}
}

func TestSubstrateMCPPoolActorLeaseToolHolderClearsTaskAnnotations(t *testing.T) {
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Name:      "actor-00000",
			Annotations: map[string]string{
				substratePoolActorLeaseTaskNSAnno:   "task-ns",
				substratePoolActorLeaseTaskNameAnno: "task-name",
				substratePoolActorLeaseTaskUIDAnno:  "task-uid",
			},
		},
	}
	tool := &corev1alpha1.Tool{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "tool", UID: types.UID("tool-uid")}}

	setSubstrateMCPPoolActorLeaseHolder(lease, tool, "actor-00000")

	if lease.Labels[labels.LabelPurpose] != substratePoolActorLeasePurpose {
		t.Fatalf("purpose label = %q, want %q", lease.Labels[labels.LabelPurpose], substratePoolActorLeasePurpose)
	}
	if !substrateActorLeaseHeldByTool(lease, tool) {
		t.Fatalf("lease should be held by tool")
	}
	if _, ok := lease.Annotations[substratePoolActorLeaseTaskNSAnno]; ok {
		t.Fatalf("tool holder update should clear task namespace annotation")
	}
	if _, ok := lease.Annotations[substratePoolActorLeaseTaskNameAnno]; ok {
		t.Fatalf("tool holder update should clear task name annotation")
	}
	if _, ok := lease.Annotations[substratePoolActorLeaseTaskUIDAnno]; ok {
		t.Fatalf("tool holder update should clear task uid annotation")
	}
}

func TestSubstratePoolActorLeaseIdentityHelpers(t *testing.T) {
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "fallback-actor"}}
	if got := substrateActorLeaseActorID(lease); got != "fallback-actor" {
		t.Fatalf("actor id fallback = %q, want fallback-actor", got)
	}

	lease.Labels = map[string]string{substratePoolActorLeaseActorIDLabel: " labeled-actor "}
	if got := substrateActorLeaseActorID(lease); got != "labeled-actor" {
		t.Fatalf("actor id label = %q, want labeled-actor", got)
	}

	prefix, ordinal, ok := substratePoolActorPrefixAndOrdinal("pool-prefix-00042")
	if !ok || prefix != "pool-prefix" || ordinal != 42 {
		t.Fatalf("prefix/ordinal = %q, %d, %t; want pool-prefix, 42, true", prefix, ordinal, ok)
	}
	if _, _, ok := substratePoolActorPrefixAndOrdinal("pool-prefix-42"); ok {
		t.Fatalf("expected non-five-digit ordinal to be rejected")
	}
}

func TestTryReserveSubstratePoolActorTreatsAlreadyExistsAsUnavailable(t *testing.T) {
	ctx := context.Background()
	base := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	racedCreate := false
	kubeClient := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(_ context.Context, _ client.WithWatch, key client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
			return apierrors.NewNotFound(coordinationv1.Resource("leases"), key.Name)
		},
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			racedCreate = true
			return apierrors.NewAlreadyExists(coordinationv1.Resource("leases"), obj.GetName())
		},
	})
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Name: "task", Namespace: "default", UID: types.UID("task-uid")},
	}
	r := &TaskReconciler{Client: kubeClient}

	reserved, err := r.tryReserveSubstratePoolActor(ctx, task, "default", "actor-00000")
	if err != nil {
		t.Fatalf("tryReserveSubstratePoolActor() error = %v", err)
	}
	if reserved {
		t.Fatal("tryReserveSubstratePoolActor() reserved raced lease, want false")
	}
	if !racedCreate {
		t.Fatal("tryReserveSubstratePoolActor() did not attempt create")
	}
}

func TestTryReserveSubstrateMCPPoolActorTreatsPatchConflictAsUnavailable(t *testing.T) {
	ctx := context.Background()
	oldHolder := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Name: "old-task", Namespace: "default", UID: types.UID("old-task-uid")},
		Status: corev1alpha1.TaskStatus{
			Phase: corev1alpha1.TaskPhaseSucceeded,
			ExecutionWorkspace: &corev1alpha1.ExecutionWorkspaceStatus{
				Phase:  corev1alpha1.ExecutionWorkspacePhaseDeleted,
				Reason: corev1alpha1.ExecutionWorkspaceReasonDeleted,
			},
		},
	}
	lease := newSubstratePoolActorLease(oldHolder, "default", "actor-00000", "actor-00000")
	base := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(oldHolder, lease).Build()
	patchAttempted := false
	kubeClient := interceptor.NewClient(base, interceptor.Funcs{
		Patch: func(_ context.Context, _ client.WithWatch, obj client.Object, _ client.Patch, _ ...client.PatchOption) error {
			patchAttempted = true
			return apierrors.NewConflict(coordinationv1.Resource("leases"), obj.GetName(), errors.New("resource version changed"))
		},
	})
	tool := &corev1alpha1.Tool{
		ObjectMeta: metav1.ObjectMeta{Name: "tool", Namespace: "default", UID: types.UID("tool-uid")},
	}
	r := &ToolReconciler{Client: kubeClient}

	reserved, err := r.tryReserveSubstrateMCPPoolActor(ctx, tool, "default", "actor-00000")
	if err != nil {
		t.Fatalf("tryReserveSubstrateMCPPoolActor() error = %v", err)
	}
	if reserved {
		t.Fatal("tryReserveSubstrateMCPPoolActor() reserved conflicted lease, want false")
	}
	if !patchAttempted {
		t.Fatal("tryReserveSubstrateMCPPoolActor() did not attempt stale takeover")
	}
	var got coordinationv1.Lease
	if err := base.Get(ctx, client.ObjectKey{Namespace: "default", Name: "actor-00000"}, &got); err != nil {
		t.Fatalf("Get lease: %v", err)
	}
	if !substratePoolActorLeaseHeldByTask(&got, oldHolder) {
		t.Fatalf("lease holder changed after conflict to annotations %#v", got.Annotations)
	}
}
