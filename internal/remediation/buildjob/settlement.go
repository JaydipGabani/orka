package buildjob

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const settlementAnnotation = "remediation.orka.ai/build-daemon-settlements"

type daemonSettlement struct {
	JobUID           types.UID `json:"jobUID"`
	PodUID           types.UID `json:"podUID"`
	ContainerImageID string    `json:"containerImageID"`
	BuildRef         string    `json:"buildRef"`
	InputDigest      string    `json:"inputDigest"`
}

func settlementsFromLedger(record *corev1.ConfigMap) (map[types.UID]daemonSettlement, error) {
	proofs := make(map[types.UID]daemonSettlement)
	if raw := record.Annotations[settlementAnnotation]; raw != "" {
		if len(raw) > 48<<10 || decodeStrict([]byte(raw), &proofs) != nil || len(proofs) > 64 {
			return nil, failure(ErrIdentity, "invalid-daemon-settlement-ledger")
		}
	}
	return proofs, nil
}

func (b *Backend) recordDaemonSettlement(
	ctx context.Context, r Receipt, pod *corev1.Pod, wire WorkerResult, cleaning bool,
) error {
	if !wire.DaemonSettled || !buildRefPattern.MatchString(wire.BuildRef) {
		return failure(ErrCleanup, "build-daemon-settlement-unproven")
	}
	_, imageID, err := b.termination(pod)
	if err != nil {
		return err
	}
	proof := daemonSettlement{JobUID: r.JobUID, PodUID: pod.UID, ContainerImageID: imageID,
		BuildRef: wire.BuildRef, InputDigest: r.InputDigest}
	return b.updateLedger(ctx, r, cleaning, func(record *corev1.ConfigMap) error {
		proofs, err := settlementsFromLedger(record)
		if err != nil {
			return err
		}
		if prior, found := proofs[pod.UID]; found && prior != proof {
			return failure(ErrIdentity, "daemon-settlement-identity-changed")
		}
		proofs[pod.UID] = proof
		raw, err := json.Marshal(proofs)
		if err != nil || len(raw) > 48<<10 {
			return failure(ErrLimit, "daemon-settlement-ledger-limit")
		}
		record.Annotations[settlementAnnotation] = string(raw)
		return nil
	})
}

func (b *Backend) daemonSettled(ctx context.Context, proof *CleanupReceipt) (bool, error) {
	if !proof.SubmissionSettled {
		return false, nil
	}
	if proof.JobUID == "" {
		return true, nil
	}
	if len(proof.PodUIDs) == 0 {
		return false, nil
	}
	record, err := b.config.APIReader.CoreV1().ConfigMaps(proof.Namespace).Get(ctx, proof.LedgerName, metav1.GetOptions{})
	if err != nil {
		return false, apiFailure(ctx, err, "daemon-settlement-ledger-unavailable")
	}
	if err := b.verifyLedger(record, proof.Receipt, true); err != nil {
		return false, err
	}
	return b.ledgerDaemonSettled(record, proof)
}

func (b *Backend) ledgerDaemonSettled(record *corev1.ConfigMap, proof *CleanupReceipt) (bool, error) {
	if !proof.SubmissionSettled {
		return false, nil
	}
	if proof.JobUID == "" {
		return true, nil
	}
	if len(proof.PodUIDs) == 0 {
		return false, nil
	}
	proofs, err := settlementsFromLedger(record)
	if err != nil {
		return false, err
	}
	for _, uid := range proof.PodUIDs {
		item, found := proofs[uid]
		if !found || item.JobUID != proof.JobUID || item.PodUID != uid || item.InputDigest != proof.InputDigest ||
			!buildRefPattern.MatchString(item.BuildRef) || !matchesImageID(b.config.WorkerImage, item.ContainerImageID) {
			return false, nil
		}
	}
	return true, nil
}

func (b *Backend) collectPodSettlement(ctx context.Context, r Receipt, pod *corev1.Pod) (bool, error) {
	copy := pod.DeepCopy()
	copy.DeletionTimestamp = nil
	if err := b.verifyPod(copy, r); err != nil {
		return false, err
	}
	terminated, _, err := b.termination(pod)
	if err != nil {
		return false, err
	}
	if terminated == nil {
		return false, nil
	}
	anchor, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{})
	if err != nil {
		return false, apiFailure(ctx, err, "settlement-input-anchor-unavailable")
	}
	m, input, err := b.verifyAnchor(anchor, r, true)
	if err != nil {
		return false, err
	}
	wire, err := readWorkerResult(terminated, r.InputDigest, diagnosticPaths(m, input))
	if err != nil {
		return false, err
	}
	if !wire.DaemonSettled {
		return false, failure(ErrCleanup, "worker-exited-without-daemon-settlement")
	}
	fresh, err := b.config.APIReader.CoreV1().Pods(r.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil {
		return false, apiFailure(ctx, err, "settlement-worker-unavailable")
	}
	if fresh.UID != pod.UID || !reflect.DeepEqual(fresh.Status.ContainerStatuses, pod.Status.ContainerStatuses) ||
		fresh.Status.Phase != pod.Status.Phase {
		return false, failure(ErrIdentity, "settlement-worker-changed")
	}
	fresh.DeletionTimestamp = nil
	if err := b.verifyPod(fresh, r); err != nil {
		return false, err
	}
	if _, err := b.namespace(ctx, r.NamespaceUID); err != nil {
		return false, err
	}
	job, err := b.config.APIReader.BatchV1().Jobs(r.Namespace).Get(ctx, r.JobName, metav1.GetOptions{})
	if err != nil {
		return false, apiFailure(ctx, err, "settlement-job-unavailable")
	}
	if err := b.verifyJob(job, r, true); err != nil {
		return false, err
	}
	latestAnchor, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{})
	if err != nil {
		return false, apiFailure(ctx, err, "settlement-anchor-unavailable")
	}
	if _, _, err := b.verifyAnchor(latestAnchor, r, true); err != nil {
		return false, err
	}
	if err := b.recordDaemonSettlement(ctx, r, pod, wire, true); err != nil {
		return false, err
	}
	return true, nil
}

func (b *Backend) retainPod(ctx context.Context, pod *corev1.Pod) error {
	if slices.Contains(pod.Finalizers, podFinalizer) {
		return nil
	}
	if pod.DeletionTimestamp != nil {
		return failure(ErrCleanup, "deleting-worker-lacks-settlement-retention")
	}
	retained := pod.DeepCopy()
	retained.Finalizers = append(retained.Finalizers, podFinalizer)
	if _, err := b.config.Kube.CoreV1().Pods(pod.Namespace).Update(ctx, retained, metav1.UpdateOptions{}); err != nil {
		return apiFailure(ctx, err, "worker-settlement-retention-unavailable")
	}
	return nil
}

func (b *Backend) retainPods(ctx context.Context, r Receipt, pods []corev1.Pod) error {
	for _, pod := range pods {
		if !ownedPod(&pod, r) {
			return failure(ErrIdentity, "build-cleanup-unowned-pod")
		}
		if pod.DeletionTimestamp == nil {
			if err := b.retainPod(ctx, &pod); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *Backend) releasePod(ctx context.Context, r Receipt, name string, uid types.UID) error {
	pod, err := b.config.APIReader.CoreV1().Pods(r.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return apiFailure(ctx, err, "settled-worker-unavailable")
	}
	if pod.UID != uid || !ownedPod(pod, r) {
		return failure(ErrIdentity, "settled-worker-replaced")
	}
	if slices.Contains(pod.Finalizers, podFinalizer) {
		pod = pod.DeepCopy()
		pod.Finalizers = slices.DeleteFunc(pod.Finalizers, func(value string) bool { return value == podFinalizer })
		if _, err := b.config.Kube.CoreV1().Pods(r.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil &&
			!apierrors.IsNotFound(err) {
			return apiFailure(ctx, err, "worker-settlement-retention-not-released")
		}
	}
	return nil
}
