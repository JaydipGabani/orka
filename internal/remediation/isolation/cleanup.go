package isolation

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Cancel explicitly authorizes step-wise cleanup using the frozen namespace and
// object UIDs. It never deletes either namespace or the parent's subject policy.
func (a *Adapter) Cancel(ctx context.Context, receipt Receipt, persist ReceiptCallback) (Receipt, error) {
	receipt = cloneReceipt(receipt)
	if ctx.Err() != nil {
		return receipt, &Error{Code: contextEnded}
	}
	if err := validateReceipt(receipt); err != nil {
		return receipt, err
	}
	if receipt.CleanupComplete {
		return receipt, nil
	}
	if receipt.Phase != Cleaning || receipt.Outcome == Passed {
		receipt.Phase, receipt.Proof.Verified = Cleaning, false
		if receipt.Outcome != Rejected {
			receipt.Outcome = Cancelled
		}
		if err := save(ctx, &receipt, persist); err != nil {
			return receipt, err
		}
	}
	return a.cleanupStep(ctx, receipt, persist)
}

func (a *Adapter) cleanupStep(ctx context.Context, receipt Receipt, persist ReceiptCallback) (Receipt, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return receipt, &Error{Code: contextEnded}
	}
	if err := a.verifyCleanupAnchors(ctx, receipt); err != nil {
		return receipt, err
	}
	for i := len(receipt.Objects) - 1; i >= 0; i-- {
		object := &receipt.Objects[i]
		if object.Deleted {
			continue
		}
		if !object.CreateAttempted {
			object.Deleted = true
			err := save(ctx, &receipt, persist)
			return receipt, err
		}
		err := a.cleanupObject(ctx, &receipt, i, persist)
		return receipt, err
	}
	if receipt.Outcome == Passed {
		if err := a.completeProof(ctx, &receipt); err != nil {
			receipt.Proof.Verified, receipt.Outcome = false, Rejected
			receipt.FailureCode = "proof-fence-changed-before-cleanup-completed"
		}
	}
	receipt.CleanupComplete, receipt.Phase = true, Complete
	err := save(ctx, &receipt, persist)
	if err != nil {
		// A failed acknowledgement cannot be exported as durable proof. The
		// caller must reload its canonical journal before retrying this step.
		receipt.Proof.Verified = false
	}
	return receipt, err
}

func (a *Adapter) cleanupObject(ctx context.Context, receipt *Receipt, index int, persist ReceiptCallback) error {
	object := &receipt.Objects[index]
	actual, err := a.getOwned(ctx, *receipt, *object)
	if apierrors.IsNotFound(err) {
		object.Deleted = true
		return save(ctx, receipt, persist)
	}
	if err != nil {
		return &Error{Code: "cleanup-identity-unavailable-or-changed"}
	}
	if object.UID == "" {
		// A create may have reached the API server before its acknowledgement
		// reached the journal. Only cleanup may recover that identity, after
		// checking the exact intent and the already-persisted namespace UID.
		object.UID, object.ResourceVersion = actual.GetUID(), actual.GetResourceVersion()
		return save(ctx, receipt, persist)
	}
	if !object.DeleteRequested {
		object.DeleteRequested = true
		if err := save(ctx, receipt, persist); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return &Error{Code: contextEnded}
	}
	options := metav1.DeleteOptions{
		Preconditions:     &metav1.Preconditions{UID: new(object.UID)},
		PropagationPolicy: new(metav1.DeletePropagationForeground), GracePeriodSeconds: new(int64(1)),
	}
	switch object.Kind {
	case podKind:
		err = a.kube.CoreV1().Pods(object.Namespace).Delete(ctx, object.Name, options)
	case policyKind:
		err = a.kube.NetworkingV1().NetworkPolicies(object.Namespace).Delete(ctx, object.Name, options)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return &Error{Code: "uid-fenced-delete-not-acknowledged"}
	}
	// Deletion acknowledgement is not absence. A later step must observe
	// NotFound, including after kubelet termination and foreground finalizers.
	return nil
}

func (a *Adapter) getOwned(ctx context.Context, receipt Receipt, object ObjectReceipt) (metav1.Object, error) {
	switch object.Kind {
	case podKind:
		actual, err := a.kube.CoreV1().Pods(object.Namespace).Get(ctx, object.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if !owned(receipt, object, actual) || (object.UID == "" && !matchesPod(receipt, object, actual)) {
			return nil, &Error{Code: "cleanup-owner-mismatch"}
		}
		return actual, nil
	case policyKind:
		actual, err := a.kube.NetworkingV1().NetworkPolicies(object.Namespace).Get(ctx, object.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if !owned(receipt, object, actual) || (object.UID == "" && !matchesPolicy(receipt, object, actual)) {
			return nil, &Error{Code: "cleanup-owner-mismatch"}
		}
		return actual, nil
	default:
		return nil, &Error{Code: "invalid-resource-kind"}
	}
}

func (a *Adapter) completeProof(ctx context.Context, receipt *Receipt) error {
	if !a.now().Before(receipt.Deadline) {
		return &Error{Code: "proof-deadline-exceeded"}
	}
	if err := a.verifyParentPolicies(ctx, *receipt); err != nil {
		return err
	}
	if err := a.verifyAnchors(ctx, *receipt); err != nil {
		return err
	}
	if err := a.requireEmpty(ctx, receipt.Proof.SubjectNamespace.Name, receipt.Config.ControlNamespace.Name); err != nil {
		return err
	}
	receipt.Proof.CompletedAt = a.now().UTC()
	return proofEvidence(*receipt)
}
