package buildjob

import (
	"context"
	"maps"
	"reflect"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

func (b *Backend) Start(ctx context.Context, request Input) (Receipt, error) {
	input, policy, err := b.admit(request)
	if err != nil {
		return Receipt{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, b.config.Limits.APITimeout)
	defer cancel()
	namespaceUID, err := b.namespace(bounded, "")
	if err != nil {
		return Receipt{}, err
	}
	r := b.baseReceipt(input, namespaceUID)
	r.TLSSecrets, err = b.readTLSSecrets(bounded)
	if err != nil {
		return r, err
	}
	r.RegistrySecret, err = b.readRegistrySecret(bounded)
	if err != nil {
		return r, err
	}
	data, err := b.bundle(input, policy)
	if err != nil {
		return r, err
	}
	ledger, err := b.ensureLedger(bounded, r, input.RequireExisting || input.ExpectedJobUID != "")
	if err != nil {
		return r, err
	}
	r.LedgerUID = ledger.UID
	r.AnchorUID = types.UID(ledger.Annotations[anchorUIDAnnotation])
	anchor, err := b.ensureAnchor(bounded, r, data, input.RequireExisting || input.ExpectedJobUID != "")
	if err != nil {
		return r, err
	}
	r.AnchorUID = anchor.UID
	if err := b.updateLedger(bounded, r, false, func(record *corev1.ConfigMap) error {
		if uid := record.Annotations[anchorUIDAnnotation]; uid != "" && uid != string(r.AnchorUID) {
			return failure(ErrIdentity, "accepted-build-anchor-replaced")
		}
		record.Annotations[anchorUIDAnnotation] = string(r.AnchorUID)
		return nil
	}); err != nil {
		return r, err
	}
	r.JobUID = types.UID(anchor.Annotations[jobUIDAnnotation])
	if input.ExpectedJobUID != "" {
		if r.JobUID != "" && r.JobUID != input.ExpectedJobUID {
			return r, failure(ErrIdentity, "expected-build-job-uid-mismatch")
		}
		r.JobUID = input.ExpectedJobUID
	}
	job, err := b.ensureJob(bounded, r, anchor, input.RequireExisting || input.ExpectedJobUID != "")
	if err != nil {
		return r, err
	}
	if err := b.verifyJob(job, r, false); err != nil {
		return r, err
	}
	r.JobUID = job.UID
	if err := b.bindUID(bounded, r, jobUIDAnnotation, r.JobUID); err != nil {
		return r, err
	}
	if _, err := b.namespace(bounded, r.NamespaceUID); err != nil {
		return r, err
	}
	if err := b.verifyClientSecrets(bounded, r); err != nil {
		return r, err
	}
	latest, err := b.config.APIReader.BatchV1().Jobs(r.Namespace).Get(bounded, r.JobName, metav1.GetOptions{})
	if err != nil {
		return r, apiFailure(bounded, err, "accepted-build-job-unavailable")
	}
	if err := b.verifyJob(latest, r, false); err != nil {
		return r, err
	}
	return r, nil
}

func (b *Backend) ensureAnchor(ctx context.Context, r Receipt, data map[string][]byte, existing bool) (*corev1.Secret, error) {
	anchor, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) && !existing && r.AnchorUID == "" {
		anchor, err = b.config.Kube.CoreV1().Secrets(r.Namespace).Create(ctx, b.desiredAnchor(r, data), metav1.CreateOptions{})
		if err != nil {
			// A timeout/connection failure is not evidence that creation failed.
			// Get the deterministic identity; never blindly issue another create.
			anchor, err = b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{})
		}
	}
	if err != nil {
		return nil, apiFailure(ctx, err, "build-input-anchor-unavailable")
	}
	if _, _, err := b.verifyAnchor(anchor, r, false); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(anchor.Data, data) {
		return nil, failure(ErrIdentity, "operation-reused-with-different-build-input")
	}
	return anchor, nil
}

func (b *Backend) admitOperation(ctx context.Context, r Receipt) error {
	selector := labels.Set{managedLabel: managedBy, runLabel: protectedLabels(r)[runLabel]}.AsSelector().String()
	anchors, err := b.config.APIReader.CoreV1().ConfigMaps(r.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector, Limit: int64(b.config.Limits.MaxOperations + 1),
	})
	if err != nil {
		return apiFailure(ctx, err, "build-operation-inventory-unavailable")
	}
	if len(anchors.Items) >= b.config.Limits.MaxOperations || anchors.Continue != "" {
		return failure(ErrLimit, "build-operation-limit")
	}
	return nil
}

func (b *Backend) ensureJob(ctx context.Context, r Receipt, anchor *corev1.Secret, existing bool) (*batchv1.Job, error) {
	job, err := b.config.APIReader.BatchV1().Jobs(r.Namespace).Get(ctx, r.JobName, metav1.GetOptions{})
	if err == nil {
		return job, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, apiFailure(ctx, err, "build-job-read-unavailable")
	}
	if r.JobUID != "" {
		return nil, failure(ErrLost, "accepted-build-missing-replay-forbidden")
	}
	if anchor.Annotations[stateAnnotation] == submittedState {
		return nil, failure(ErrIndeterminate, "submitted-build-not-yet-observable-replay-forbidden")
	}
	if existing || anchor.Annotations[stateAnnotation] != preparedState {
		return nil, failure(ErrLost, "existing-build-missing-replay-forbidden")
	}
	if err := b.verifyClientSecrets(ctx, r); err != nil {
		return nil, err
	}
	won, err := b.markSubmitted(ctx, r)
	if err != nil {
		return nil, err
	}
	if won {
		if err := b.verifyClientSecrets(ctx, r); err != nil {
			return nil, err
		}
		job, err = b.config.Kube.BatchV1().Jobs(r.Namespace).Create(ctx, b.desiredJob(r), metav1.CreateOptions{})
		if err == nil {
			return job, nil
		}
	}
	// The intent is durable before Create. A second caller, or a crash between
	// intent and submission, may only recover a present Job. Missing evidence
	// burns this operation rather than allowing a duplicate build.
	job, err = b.config.APIReader.BatchV1().Jobs(r.Namespace).Get(ctx, r.JobName, metav1.GetOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, failure(ErrIndeterminate, "build-job-create-acknowledgement-unavailable")
	}
	return job, nil
}

func (b *Backend) markSubmitted(ctx context.Context, r Receipt) (bool, error) {
	for range 5 {
		anchor, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{})
		if err != nil {
			return false, apiFailure(ctx, err, "build-input-anchor-unavailable")
		}
		if _, _, err := b.verifyAnchor(anchor, r, false); err != nil {
			return false, err
		}
		if anchor.Annotations[stateAnnotation] != preparedState || anchor.Annotations[jobUIDAnnotation] != "" {
			return false, nil
		}
		anchor = anchor.DeepCopy()
		anchor.Annotations[stateAnnotation] = submittedState
		anchor.Annotations[submissionAnnotation] = "true"
		_, err = b.config.Kube.CoreV1().Secrets(r.Namespace).Update(ctx, anchor, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			continue
		}
		if err != nil {
			return false, apiFailure(ctx, err, "build-submission-intent-not-persisted")
		}
		return true, nil
	}
	return false, failure(ErrAPI, "build-submission-intent-contended")
}

func (b *Backend) bindUID(ctx context.Context, r Receipt, key string, uid types.UID) error {
	if uid == "" {
		return failure(ErrIdentity, "empty-build-object-uid")
	}
	for range 5 {
		anchor, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{})
		if err != nil {
			return apiFailure(ctx, err, "build-input-anchor-unavailable")
		}
		if _, _, err := b.verifyAnchor(anchor, r, false); err != nil {
			return err
		}
		if anchor.Annotations[stateAnnotation] != submittedState {
			return failure(ErrIdentity, "build-uid-binding-requires-submission")
		}
		if actual := anchor.Annotations[key]; actual != "" {
			if actual != string(uid) {
				return failure(ErrIdentity, "build-object-uid-replaced")
			}
			return nil
		}
		anchor = anchor.DeepCopy()
		anchor.Annotations = maps.Clone(anchor.Annotations)
		anchor.Annotations[key] = string(uid)
		_, err = b.config.Kube.CoreV1().Secrets(r.Namespace).Update(ctx, anchor, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			continue
		}
		if err != nil {
			return apiFailure(ctx, err, "build-object-uid-binding-not-persisted")
		}
		return nil
	}
	return failure(ErrAPI, "build-object-uid-binding-contended")
}

func (b *Backend) validateReceipt(r Receipt, requireJob bool) error {
	if r.Version != Version || !idPattern.MatchString(r.RunID) || !idPattern.MatchString(r.OperationID) ||
		r.Namespace != b.config.Namespace || r.NamespaceUID == "" || r.AnchorUID == "" ||
		r.LedgerUID == "" || r.LedgerName != r.JobName+"-record" ||
		r.ConfigurationDigest != b.digest || !digestPattern.MatchString(r.InputDigest) ||
		!b.validTLSBinding(r.TLSSecrets) ||
		!b.validRegistryBinding(r.RegistrySecret) ||
		r.JobName != operationName(r.RunID, r.OperationID) || r.AnchorName != r.JobName+"-input" ||
		(requireJob && r.JobUID == "") {
		return failure(ErrIdentity, "invalid-build-receipt")
	}
	return nil
}
