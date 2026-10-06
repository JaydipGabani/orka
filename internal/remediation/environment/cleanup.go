package environment

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (a *Adapter) Cancel(ctx context.Context, receipt Receipt) error {
	if err := a.validateReceipt(receipt); err != nil {
		return err
	}
	if a.kube == nil {
		return failure(NeedsAdapter, "dedicated-kubernetes-adapter-required")
	}
	// Cancellation must still settle owned resources when the work context has
	// expired. Cleanup itself is bounded and remains restartable via the journal.
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	unlock, err := a.lock(bounded, runName(receipt.Request.RunID))
	if err != nil {
		return err
	}
	defer unlock()
	state, err := a.loadRun(receipt.Request.RunID, receipt.Request.Plan.Bind)
	if err != nil {
		return err
	}
	record, err := a.recordForReceipt(state, receipt)
	if err != nil {
		return err
	}
	if record.Observation.CleanupComplete {
		return nil
	}
	frozen, err := a.forReceipt(record.Receipt)
	if err != nil {
		return err
	}
	record.CancelRequested, record.Observation.Phase = true, Cleaning
	if err := a.saveRun(receipt.Request.RunID, state); err != nil {
		return err
	}
	return frozen.cleanup(bounded, record, state)
}

func (a *Adapter) cleanup(ctx context.Context, record *operationRecord, state *runJournal) error {
	if err := a.cleanupIsolation(ctx, record, state); err != nil {
		return err
	}
	receipt := &record.Receipt
	if err := a.recoverCleanupObjects(ctx, receipt); err != nil {
		return err
	}
	if err := a.saveRun(receipt.Request.RunID, state); err != nil {
		return err
	}
	for _, kind := range []string{podKind, networkPolicyKind, namespaceKind} {
		for _, identity := range receipt.Objects {
			if identity.Kind != kind || identity.UID == "" {
				continue
			}
			metadata, err := a.lookupObject(ctx, identity)
			if apierrors.IsNotFound(err) {
				continue
			}
			if err != nil {
				return failure(Infrastructure, "cleanup-lookup-failed")
			}
			if !ownedForCleanup(metadata, *receipt, identity) {
				return failure(Unknown, "cleanup-object-identity-mismatch")
			}
			if kind == namespaceKind || kind == networkPolicyKind {
				namespace := identity.Namespace
				if kind == namespaceKind {
					namespace = identity.Name
				}
				pods, err := a.kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
				if err != nil || len(pods.Items) != 0 {
					return failure(Unknown, "namespace-contains-unsettled-workloads")
				}
			}
			switch kind {
			case podKind:
				err = a.kube.CoreV1().Pods(identity.Namespace).Delete(ctx, identity.Name, uidPreconditions(identity.UID))
			case networkPolicyKind:
				err = a.kube.NetworkingV1().NetworkPolicies(identity.Namespace).Delete(ctx, identity.Name, uidPreconditions(identity.UID))
			case namespaceKind:
				err = a.kube.CoreV1().Namespaces().Delete(ctx, identity.Name, uidPreconditions(identity.UID))
			}
			if err != nil && !apierrors.IsNotFound(err) {
				return failure(Unknown, "uid-fenced-cleanup-failed")
			}
			if _, err := a.lookupObject(ctx, identity); !apierrors.IsNotFound(err) {
				if err != nil {
					return failure(Infrastructure, "cleanup-lookup-failed")
				}
				return &Error{Kind: Infrastructure, Code: "cleanup-pending", Retryable: true}
			}
		}
	}
	// Confirm absence even for unacknowledged creates; this catches a resource
	// appearing between lookup and deletion and prevents a new candidate run.
	for _, identity := range receipt.Objects {
		if _, err := a.lookupObject(ctx, identity); !apierrors.IsNotFound(err) {
			return failure(Unknown, "cleanup-absence-unconfirmed")
		}
	}
	record.Observation.Phase, record.Observation.CleanupComplete = Completed, true
	if record.CancelRequested {
		record.Observation.Phase = Cancelled
	}
	record.Observation.Receipt = *receipt
	return a.saveRun(receipt.Request.RunID, state)
}

func (a *Adapter) recoverCleanupObjects(ctx context.Context, receipt *Receipt) error {
	// Recover only exact, owned objects whose create acknowledgement was lost.
	// The caller persists their UIDs before issuing a single delete.
	for i := range receipt.Objects {
		identity := &receipt.Objects[i]
		metadata, err := a.lookupObject(ctx, *identity)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return failure(Infrastructure, "cleanup-lookup-failed")
		}
		if !ownedForCleanup(metadata, *receipt, *identity) {
			return failure(Unknown, "cleanup-object-identity-mismatch")
		}
		if identity.UID == "" {
			if err := a.recoverCleanupIdentity(ctx, receipt, i, metadata); err != nil {
				return err
			}
		}
	}
	return nil
}

func ownedForCleanup(metadata metav1.Object, receipt Receipt, identity ObjectIdentity) bool {
	if identity.UID != "" {
		// Names and cluster scope were checked against the frozen receipt. A
		// recorded UID remains ours when mutable labels/spec change; a replacement
		// UID never does. Unacknowledged creates still require exact ownership.
		return metadata.GetUID() == identity.UID && metadata.GetName() == identity.Name &&
			metadata.GetNamespace() == identity.Namespace
	}
	return owned(metadata, receipt, identity)
}

func (a *Adapter) lookupObject(ctx context.Context, identity ObjectIdentity) (metav1.Object, error) {
	switch identity.Kind {
	case namespaceKind:
		return a.kube.CoreV1().Namespaces().Get(ctx, identity.Name, metav1.GetOptions{})
	case networkPolicyKind:
		return a.kube.NetworkingV1().NetworkPolicies(identity.Namespace).Get(ctx, identity.Name, metav1.GetOptions{})
	case podKind:
		return a.kube.CoreV1().Pods(identity.Namespace).Get(ctx, identity.Name, metav1.GetOptions{})
	default:
		return nil, failure(NeedsAdapter, "unknown-resource-kind")
	}
}
