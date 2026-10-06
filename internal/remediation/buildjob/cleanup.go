package buildjob

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func (b *Backend) Cancel(ctx context.Context, r Receipt) error {
	_, err := b.Cleanup(ctx, r)
	return err
}

func (b *Backend) Cleanup(ctx context.Context, r Receipt) (CleanupReceipt, error) {
	proof := CleanupReceipt{Receipt: r}
	if err := b.validateReceipt(r, false); err != nil {
		return proof, err
	}
	bounded, cancel := context.WithTimeout(ctx, b.config.Limits.CleanupTimeout)
	defer cancel()
	if _, err := b.namespace(bounded, r.NamespaceUID); err != nil {
		return proof, err
	}
	record, err := b.config.APIReader.CoreV1().ConfigMaps(r.Namespace).Get(bounded, r.LedgerName, metav1.GetOptions{})
	if err != nil {
		return proof, apiFailure(bounded, err, "build-cleanup-ledger-unavailable")
	}
	if err := b.prepareCleanupLedger(bounded, record, r); err != nil {
		return proof, err
	}
	if saved := record.Annotations[cleanupAnnotation]; saved != "" {
		if decodeStrict([]byte(saved), &proof) != nil || !sameCleanupIdentity(proof.Receipt, r) {
			return proof, failure(ErrIdentity, "build-cleanup-receipt-mismatch")
		}
		if proof.JobUID == "" && r.JobUID != "" {
			if proof.Stopped {
				return proof, failure(ErrIdentity, "build-cleanup-receipt-job-mismatch")
			}
			proof.JobUID = r.JobUID
		}
		r = proof.Receipt
	}
	if record.Annotations[stateAnnotation] == cleanedState {
		if !proof.Stopped || !proof.SubmissionSettled || !proof.DaemonSettled || proof.CleanupDigest != cleanupDigest(proof) {
			return proof, failure(ErrIdentity, "invalid-persisted-build-cleanup")
		}
		settled, err := b.ledgerDaemonSettled(record, &proof)
		if err != nil {
			return proof, err
		}
		if !settled {
			return proof, failure(ErrCleanup, "persisted-daemon-settlement-unproven")
		}
		return proof, b.confirmAbsent(bounded, r)
	}
	if err := b.saveCleanup(bounded, &proof, false); err != nil {
		return proof, err
	}
	seen := make(map[types.UID]bool, len(proof.PodUIDs))
	for _, uid := range proof.PodUIDs {
		seen[uid] = true
	}
	for {
		done, err := b.cleanupStep(bounded, &proof, seen)
		if err != nil {
			if ctx.Err() != nil {
				return proof, ctx.Err()
			}
			if bounded.Err() != nil {
				return proof, failure(ErrCleanup, "build-cleanup-still-pending")
			}
			return proof, err
		}
		if done {
			proof.Stopped = true
			proof.CleanupDigest = cleanupDigest(proof)
			if err := b.saveCleanup(bounded, &proof, true); err != nil {
				return CleanupReceipt{Receipt: proof.Receipt, PodUIDs: proof.PodUIDs}, err
			}
			return proof, nil
		}
		timer := time.NewTimer(b.config.Limits.PollInterval)
		select {
		case <-bounded.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return proof, ctx.Err()
			}
			return proof, failure(ErrCleanup, "build-cleanup-still-pending")
		case <-timer.C:
		}
	}
}

func sameCleanupIdentity(saved, given Receipt) bool {
	if saved.JobUID == "" {
		saved.JobUID = given.JobUID
	}
	if given.JobUID == "" {
		given.JobUID = saved.JobUID
	}
	return saved == given
}

func cleanupDigest(proof CleanupReceipt) string {
	return proof.BindingDigest()
}

func (b *Backend) prepareCleanupLedger(ctx context.Context, record *corev1.ConfigMap, r Receipt) error {
	if record.Annotations[anchorUIDAnnotation] != "" {
		return b.verifyLedger(record, r, true)
	}
	unbound := r
	unbound.AnchorUID = ""
	if err := b.verifyLedger(record, unbound, true); err != nil {
		return err
	}
	anchor, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{})
	if err != nil {
		return apiFailure(ctx, err, "partially-created-build-input-unavailable")
	}
	if _, _, err := b.verifyAnchor(anchor, r, true); err != nil {
		return err
	}
	return b.updateLedger(ctx, unbound, true, func(current *corev1.ConfigMap) error {
		if value := current.Annotations[anchorUIDAnnotation]; value != "" && value != string(r.AnchorUID) {
			return failure(ErrIdentity, "partially-created-build-input-replaced")
		}
		current.Annotations[anchorUIDAnnotation] = string(r.AnchorUID)
		return nil
	})
}

func (b *Backend) saveCleanup(ctx context.Context, proof *CleanupReceipt, done bool) error {
	return b.updateLedger(ctx, proof.Receipt, true, func(record *corev1.ConfigMap) error {
		if encoded := record.Annotations[cleanupAnnotation]; encoded != "" {
			var saved CleanupReceipt
			if decodeStrict([]byte(encoded), &saved) != nil || !sameCleanupIdentity(saved.Receipt, proof.Receipt) {
				return failure(ErrIdentity, "build-cleanup-progress-mismatch")
			}
			if record.Annotations[stateAnnotation] == cleanedState {
				if !saved.Stopped || !saved.SubmissionSettled || !saved.DaemonSettled || saved.CleanupDigest != cleanupDigest(saved) {
					return failure(ErrIdentity, "build-cleanup-progress-invalid")
				}
				if saved.JobUID != proof.JobUID && proof.JobUID != "" {
					return failure(ErrIdentity, "build-cleanup-receipt-job-mismatch")
				}
				settled, err := b.ledgerDaemonSettled(record, &saved)
				if err != nil {
					return err
				}
				if !settled {
					return failure(ErrCleanup, "persisted-daemon-settlement-unproven")
				}
				*proof = saved
				return nil
			}
			mergeCleanup(proof, saved)
		}
		if done {
			settled, err := b.ledgerDaemonSettled(record, proof)
			if err != nil {
				return err
			}
			if !settled {
				return failure(ErrCleanup, "merged-daemon-settlement-unproven")
			}
			proof.DaemonSettled = true
			proof.CleanupDigest = cleanupDigest(*proof)
		}
		raw, err := json.Marshal(proof)
		if err != nil || len(raw) > 16<<10 || len(proof.PodUIDs) > 64 {
			return failure(ErrLimit, "build-cleanup-receipt-size-limit")
		}
		record.Annotations[stateAnnotation] = cleanupState
		if done {
			record.Annotations[stateAnnotation] = cleanedState
		}
		record.Annotations[cleanupAnnotation] = string(raw)
		return nil
	})
}

func mergeCleanup(proof *CleanupReceipt, saved CleanupReceipt) {
	if proof.JobUID == "" {
		proof.JobUID = saved.JobUID
	}
	proof.SubmissionSettled = proof.SubmissionSettled || saved.SubmissionSettled
	seen := make(map[types.UID]bool, len(proof.PodUIDs)+len(saved.PodUIDs))
	for _, uid := range append(slices.Clone(proof.PodUIDs), saved.PodUIDs...) {
		seen[uid] = true
	}
	proof.PodUIDs = sortedUIDs(seen)
}

func (b *Backend) cleanupStep(ctx context.Context, proof *CleanupReceipt, seen map[types.UID]bool) (bool, error) {
	if proof.Stopped {
		return true, b.confirmAbsent(ctx, proof.Receipt)
	}
	if _, err := b.namespace(ctx, proof.NamespaceUID); err != nil {
		return false, err
	}
	submitted, err := b.closeAnchor(ctx, proof)
	if err != nil {
		return false, err
	}
	for _, uid := range proof.PodUIDs {
		seen[uid] = true
	}
	job, err := b.config.APIReader.BatchV1().Jobs(proof.Namespace).Get(ctx, proof.JobName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return false, apiFailure(ctx, err, "build-cleanup-job-unavailable")
	}
	if apierrors.IsNotFound(err) {
		job = nil
	}
	if err == nil {
		if err := b.verifyJob(job, proof.Receipt, true); err != nil {
			return false, err
		}
		proof.JobUID = job.UID
		proof.SubmissionSettled = true
		if err := b.saveCleanup(ctx, proof, false); err != nil {
			return false, err
		}
	}
	if submitted && proof.JobUID == "" {
		// Submission may still be in flight. Neither absence nor cancelling this
		// request proves that the original Create can no longer be accepted.
		return false, nil
	}
	pods, err := b.listPods(ctx, proof.Receipt)
	if err != nil {
		return false, err
	}
	if err := b.retainPods(ctx, proof.Receipt, pods); err != nil {
		return false, err
	}
	if job != nil && job.DeletionTimestamp == nil {
		err = b.config.Kube.BatchV1().Jobs(proof.Namespace).Delete(ctx, proof.JobName, deleteOptions(job.UID))
		if err != nil && !apierrors.IsNotFound(err) {
			return false, apiFailure(ctx, err, "build-job-delete-not-acknowledged")
		}
	}
	if err := b.stopPods(ctx, proof, pods, seen); err != nil {
		return false, err
	}
	if len(pods) != 0 {
		return false, nil
	}
	settled, err := b.daemonSettled(ctx, proof)
	if err != nil {
		return false, err
	}
	if !settled {
		return false, failure(ErrCleanup, "build-daemon-settlement-unproven")
	}
	proof.DaemonSettled = true
	absent, err := b.releaseJob(ctx, proof.Receipt)
	if err != nil || !absent {
		return false, err
	}
	absent, err = b.releaseAnchor(ctx, proof.Receipt)
	if err != nil || !absent {
		return false, err
	}
	if err := b.confirmAbsent(ctx, proof.Receipt); err != nil {
		return false, err
	}
	return true, nil
}

func (b *Backend) closeAnchor(ctx context.Context, proof *CleanupReceipt) (bool, error) {
	for range 5 {
		anchor, err := b.config.APIReader.CoreV1().Secrets(proof.Namespace).Get(ctx, proof.AnchorName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			// A known Job UID is fenced even if its input was removed. With no
			// UID, absence cannot establish that an ambiguous submitter stopped.
			return !proof.SubmissionSettled && proof.JobUID == "", nil
		}
		if err != nil {
			return false, apiFailure(ctx, err, "build-cleanup-anchor-unavailable")
		}
		if _, _, err := b.verifyAnchor(anchor, proof.Receipt, true); err != nil {
			return false, err
		}
		if accepted := types.UID(anchor.Annotations[jobUIDAnnotation]); accepted != "" {
			if proof.JobUID != "" && proof.JobUID != accepted {
				return false, failure(ErrIdentity, "build-cleanup-job-uid-mismatch")
			}
			if uid := types.UID(anchor.Annotations[podUIDAnnotation]); uid != "" && !slices.Contains(proof.PodUIDs, uid) {
				proof.PodUIDs = append(proof.PodUIDs, uid)
			}
			proof.JobUID = accepted
		}
		submitted := anchor.Annotations[submissionAnnotation] == "true"
		proof.SubmissionSettled = !submitted || proof.JobUID != ""
		if anchor.Annotations[stateAnnotation] == cleanupState {
			return submitted, nil
		}
		anchor = anchor.DeepCopy()
		anchor.Annotations = maps.Clone(anchor.Annotations)
		anchor.Annotations[stateAnnotation] = cleanupState
		_, err = b.config.Kube.CoreV1().Secrets(proof.Namespace).Update(ctx, anchor, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			continue
		}
		if err != nil {
			return false, apiFailure(ctx, err, "build-cleanup-anchor-not-fenced")
		}
		return submitted, nil
	}
	return false, failure(ErrAPI, "build-cleanup-anchor-contended")
}

func (b *Backend) stopPods(ctx context.Context, proof *CleanupReceipt, pods []corev1.Pod, seen map[types.UID]bool) error {
	for _, pod := range pods {
		if !ownedPod(&pod, proof.Receipt) {
			return failure(ErrIdentity, "build-cleanup-unowned-pod")
		}
		seen[pod.UID] = true
	}
	if len(seen) > 64 {
		return failure(ErrLimit, "build-cleanup-pod-limit")
	}
	proof.PodUIDs = sortedUIDs(seen)
	if err := b.saveCleanup(ctx, proof, false); err != nil {
		return err
	}
	for _, pod := range pods {
		if pod.DeletionTimestamp == nil {
			err := b.config.Kube.CoreV1().Pods(proof.Namespace).Delete(ctx, pod.Name, deleteOptions(pod.UID))
			if err != nil && !apierrors.IsNotFound(err) {
				return apiFailure(ctx, err, "build-pod-delete-not-acknowledged")
			}
		}
		settled, err := b.collectPodSettlement(ctx, proof.Receipt, &pod)
		if err != nil {
			return err
		}
		if settled {
			if err := b.releasePod(ctx, proof.Receipt, pod.Name, pod.UID); err != nil {
				return err
			}
		}
	}
	return nil
}

func deleteOptions(uid types.UID) metav1.DeleteOptions {
	return metav1.DeleteOptions{
		Preconditions:     &metav1.Preconditions{UID: new(uid)},
		PropagationPolicy: ptr.To(metav1.DeletePropagationForeground),
	}
}

func (b *Backend) releaseJob(ctx context.Context, r Receipt) (bool, error) {
	job, err := b.config.APIReader.BatchV1().Jobs(r.Namespace).Get(ctx, r.JobName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, apiFailure(ctx, err, "build-cleanup-job-unavailable")
	}
	if err := b.verifyJob(job, r, true); err != nil {
		return false, err
	}
	if slices.Contains(job.Finalizers, jobFinalizer) {
		job = job.DeepCopy()
		job.Finalizers = slices.DeleteFunc(job.Finalizers, func(value string) bool { return value == jobFinalizer })
		_, err := b.config.Kube.BatchV1().Jobs(r.Namespace).Update(ctx, job, metav1.UpdateOptions{})
		if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return false, apiFailure(ctx, err, "build-job-retention-not-released")
		}
	}
	return false, nil
}

func (b *Backend) releaseAnchor(ctx context.Context, r Receipt) (bool, error) {
	anchor, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, apiFailure(ctx, err, "build-cleanup-anchor-unavailable")
	}
	if _, _, err := b.verifyAnchor(anchor, r, true); err != nil {
		return false, err
	}
	if anchor.DeletionTimestamp == nil {
		err := b.config.Kube.CoreV1().Secrets(r.Namespace).Delete(ctx, r.AnchorName, deleteOptions(r.AnchorUID))
		if err != nil && !apierrors.IsNotFound(err) {
			return false, apiFailure(ctx, err, "build-input-delete-not-acknowledged")
		}
		return false, nil
	}
	if slices.Contains(anchor.Finalizers, anchorFinalizer) {
		anchor = anchor.DeepCopy()
		anchor.Finalizers = slices.DeleteFunc(anchor.Finalizers, func(value string) bool { return value == anchorFinalizer })
		_, err := b.config.Kube.CoreV1().Secrets(r.Namespace).Update(ctx, anchor, metav1.UpdateOptions{})
		if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return false, apiFailure(ctx, err, "build-input-retention-not-released")
		}
	}
	return false, nil
}

func (b *Backend) confirmAbsent(ctx context.Context, r Receipt) error {
	if _, err := b.namespace(ctx, r.NamespaceUID); err != nil {
		return err
	}
	record, err := b.config.APIReader.CoreV1().ConfigMaps(r.Namespace).Get(ctx, r.LedgerName, metav1.GetOptions{})
	if err != nil {
		return apiFailure(ctx, err, "build-cleanup-ledger-unavailable")
	}
	if err := b.verifyLedger(record, r, true); err != nil {
		return err
	}
	if _, err := b.config.APIReader.BatchV1().Jobs(r.Namespace).Get(ctx, r.JobName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		if err != nil {
			return apiFailure(ctx, err, "build-cleanup-job-absence-unavailable")
		}
		return failure(ErrCleanup, "build-job-still-present")
	}
	if _, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		if err != nil {
			return apiFailure(ctx, err, "build-cleanup-anchor-absence-unavailable")
		}
		return failure(ErrCleanup, "build-input-still-present")
	}
	pods, err := b.listPods(ctx, r)
	if err != nil {
		return err
	}
	if len(pods) != 0 {
		return failure(ErrCleanup, "build-pods-still-present")
	}
	return nil
}
