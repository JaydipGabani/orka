package controllerlab

import (
	"context"
	"encoding/json"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func (a *Adapter) checkCleanupAnchors(ctx context.Context, s State) error {
	for _, namespace := range ownedNamespaces(s) {
		receipt := receiptFor(s, ref(namespaces, "", namespace))
		if receipt == nil || receipt.Deleted {
			continue
		}
		value, err := a.kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return failure(Infrastructure, "cleanup-namespace-unavailable")
		}
		if value.UID != receipt.Object.UID {
			return failure(OwnershipLost, "cleanup-namespace-uid-changed")
		}
	}
	return nil
}

func (a *Adapter) cleanup(ctx context.Context, s State, binding ImageBinding) (State, error) {
	if !s.ControllerStopped {
		return a.cleanupController(ctx, s, binding)
	}
	if s.Intent != nil {
		return a.recoverCleanupIntent(ctx, s, binding)
	}
	for i, receipt := range slices.Backward(s.Receipts) {
		if !receipt.Deleted {
			return a.cleanupReceipt(ctx, s, i)
		}
	}
	s.Phase = Complete
	return a.save(ctx, s)
}

func (a *Adapter) recoverCleanupIntent(ctx context.Context, s State, binding ImageBinding) (State, error) {
	object, err := a.get(ctx, s.Intent.Object)
	if apierrors.IsNotFound(err) {
		// An in-flight create can still arrive. Its persisted intent is not a
		// deletion receipt, even after the subject has been stopped.
		return a.save(ctx, s)
	}
	if err != nil {
		return s, failure(Infrastructure, "cleanup-intent-unavailable")
	}
	return a.adopt(ctx, s, binding, object, true)
}

func (a *Adapter) cleanupController(ctx context.Context, s State, binding ImageBinding) (State, error) {
	target := ref(deployments, s.Namespaces[0], controllerName)
	if s.Intent != nil && sameRef(s.Intent.Object, target) {
		return a.recoverCleanupIntent(ctx, s, binding)
	}
	for i, receipt := range s.Receipts {
		if sameRef(receipt.Object, target) && !receipt.Deleted {
			return a.cleanupReceipt(ctx, s, i)
		}
	}
	namespace := receiptFor(s, ref(namespaces, "", s.Namespaces[0]))
	if namespace != nil && !namespace.Deleted {
		// Do not select by subject-controlled labels: an orphan or replacement
		// Pod must not be hidden from the termination barrier by relabeling it.
		pods, err := a.kube.CoreV1().Pods(s.Namespaces[0]).List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			return s, failure(Infrastructure, "cleanup-controller-pods-unavailable")
		}
		if len(pods.Items) != 0 || pods.Continue != "" {
			return a.save(ctx, s)
		}
	}
	s.ControllerStopped = true
	return a.save(ctx, s)
}

func (a *Adapter) cleanupReceipt(ctx context.Context, s State, index int) (State, error) {
	receipt := &s.Receipts[index]
	object, err := a.get(ctx, receipt.Object)
	if apierrors.IsNotFound(err) {
		if !receipt.DeleteRequested {
			// GC can remove a receipted object after the subject changes its
			// ownerRefs. Authorize and request deletion of only the old UID;
			// never adopt or delete a same-name replacement.
			return a.requestReceiptDeletion(ctx, s, index, "")
		}
		receipt.Deleted = true
		if receipt.FinalizerRemoval != nil {
			receipt.FinalizerRemoval.Completed = true
		}
		return a.save(ctx, s)
	}
	if err != nil {
		return s, failure(Infrastructure, "cleanup-read-unavailable")
	}
	m, err := objectMetadata(object)
	if err != nil || m.GetUID() != receipt.Object.UID ||
		m.GetName() != receipt.Object.Name || m.GetNamespace() != receipt.Object.Namespace {
		return a.stop(ctx, s, failure(OwnershipLost, "cleanup-object-uid-changed"))
	}
	// The acknowledged UID is the cleanup authority. Never follow ownerRefs
	// supplied by the subject or require its labels/annotations to survive.
	if err := knownCleanupFinalizers(*receipt, m); err != nil {
		return a.stop(ctx, s, err)
	}
	if m.GetDeletionTimestamp() != nil && !receipt.DeleteRequested {
		// Establish our exact-UID deletion receipt before releasing a known
		// finalizer can complete an already-running garbage collection.
		return a.requestReceiptDeletion(ctx, s, index, m.GetResourceVersion())
	}
	if slices.Contains(m.GetFinalizers(), kedaFinalizer) {
		return a.removeKEDAFinalizer(ctx, s, index, m)
	}
	if receipt.FinalizerRemoval != nil && !receipt.FinalizerRemoval.Completed {
		receipt.FinalizerRemoval.Completed = true
		return a.save(ctx, s)
	}
	if receipt.DeleteRequested && m.GetDeletionTimestamp() != nil {
		return a.save(ctx, s)
	}
	if m.GetResourceVersion() == "" {
		return s, failure(Infrastructure, "cleanup-resource-version-required")
	}
	return a.requestReceiptDeletion(ctx, s, index, m.GetResourceVersion())
}

func (a *Adapter) requestReceiptDeletion(ctx context.Context, s State, index int, version string) (State, error) {
	receipt := &s.Receipts[index]
	if err := a.accept(ctx, s, "delete", receipt.Object); err != nil {
		return s, err
	}
	receipt.DeleteRequested = true
	s, err := a.save(ctx, s)
	if err != nil {
		return s, err
	}
	if err := a.delete(ctx, s.Receipts[index].Object, version); err != nil && !apierrors.IsNotFound(err) {
		// A conflict can be an RV race, not a replaced UID. Re-read the exact
		// object on the next bounded step before deciding ownership was lost.
		return s, failure(Infrastructure, "delete-acknowledgement-unavailable")
	}
	return a.save(ctx, s)
}

func knownCleanupFinalizers(receipt Receipt, object metav1.Object) error {
	for _, finalizer := range object.GetFinalizers() {
		if finalizer == kedaFinalizer && kedaFixture(receipt.Object.Resource) {
			continue
		}
		if finalizer == metav1.FinalizerDeleteDependents && object.GetDeletionTimestamp() != nil {
			continue
		}
		return failure(OwnershipLost, "unrecognized-cleanup-finalizer")
	}
	return nil
}

func (a *Adapter) removeKEDAFinalizer(ctx context.Context, s State, index int, object metav1.Object) (State, error) {
	if !s.ControllerStopped {
		return a.stop(ctx, s, failure(InvalidState, "controller-termination-required"))
	}
	receipt := &s.Receipts[index]
	if receipt.FinalizerRemoval != nil && receipt.FinalizerRemoval.Completed {
		return a.stop(ctx, s, failure(OwnershipLost, "finalizer-reappeared-after-removal"))
	}
	version := object.GetResourceVersion()
	if version == "" {
		return s, failure(Infrastructure, "finalizer-resource-version-required")
	}
	receipt.FinalizerRemoval = &FinalizerRemoval{ResourceVersion: version}
	s, err := a.save(ctx, s)
	if err != nil {
		return s, err
	}
	// Acceptance checks the durable intent, not the caller's unsaved state.
	target := s.Receipts[index].Object
	if err := a.accept(ctx, s, "remove-finalizer", target); err != nil {
		return s, err
	}
	result, err := a.patchKEDAFinalizer(ctx, target, version, object.GetFinalizers())
	if err != nil {
		return s, failure(Infrastructure, "finalizer-patch-not-acknowledged")
	}
	m, err := objectMetadata(result)
	if err != nil || m.GetUID() != target.UID || slices.Contains(m.GetFinalizers(), kedaFinalizer) {
		return a.stop(ctx, s, failure(OwnershipLost, "finalizer-patch-identity-changed"))
	}
	s.Receipts[index].FinalizerRemoval.Completed = true
	return a.save(ctx, s)
}

func (a *Adapter) patchKEDAFinalizer(ctx context.Context, object ObjectRef, version string, finalizers []string) (runtime.Object, error) {
	const testOperation = "test"
	remaining := make([]string, 0, len(finalizers))
	for _, finalizer := range finalizers {
		if finalizer != kedaFinalizer {
			remaining = append(remaining, finalizer)
		}
	}
	patch, err := json.Marshal([]struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}{
		{testOperation, "/metadata/uid", object.UID},
		{testOperation, "/metadata/resourceVersion", version},
		{testOperation, "/metadata/finalizers", finalizers},
		{"replace", "/metadata/finalizers", remaining},
	})
	if err != nil {
		return nil, failure(Infrastructure, "finalizer-patch-encoding")
	}
	return a.custom.Resource(object.Resource).Namespace(object.Namespace).Patch(ctx, object.Name, types.JSONPatchType, patch, metav1.PatchOptions{})
}

func validateCleanupReceipts(s State) error {
	if s.ControllerStopped {
		controller := receiptFor(s, ref(deployments, s.Namespaces[0], controllerName))
		if !slices.Contains([]Phase{Cleaning, Complete, Quarantined}, s.Phase) ||
			controller != nil && (!controller.DeleteRequested || !controller.Deleted) ||
			s.Intent != nil && s.Intent.Object.Resource == deployments {
			return failure(InvalidState, "invalid-controller-stop-receipt")
		}
	}
	for _, receipt := range s.Receipts {
		if removal := receipt.FinalizerRemoval; removal != nil {
			if !kedaFixture(receipt.Object.Resource) || removal.ResourceVersion == "" ||
				!s.ControllerStopped || receipt.Deleted && !removal.Completed {
				return failure(InvalidState, "invalid-finalizer-removal-receipt")
			}
		}
	}
	return nil
}
