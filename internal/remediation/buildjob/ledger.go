package buildjob

import (
	"context"
	"maps"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A small metadata-only ledger outlives input cleanup. Without this tombstone,
// losing a final acknowledgement and retrying the same operation after deleting
// its Secret could create a second build. No private source is stored here.
func (b *Backend) desiredLedger(r Receipt) *corev1.ConfigMap {
	annotations := protectedAnnotations(r)
	annotations[stateAnnotation] = preparedState
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.LedgerName, Namespace: r.Namespace,
			Labels: protectedLabels(r), Annotations: annotations,
		},
		Immutable: new(true),
		Data: map[string]string{
			"run": r.RunID, "operation": r.OperationID,
			"inputDigest": r.InputDigest, "configurationDigest": r.ConfigurationDigest,
			"namespaceUID": string(r.NamespaceUID),
		},
	}
}

func (b *Backend) ensureLedger(ctx context.Context, r Receipt, existing bool) (*corev1.ConfigMap, error) {
	record, err := b.config.APIReader.CoreV1().ConfigMaps(r.Namespace).Get(ctx, r.LedgerName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) && !existing {
		if err := b.admitOperation(ctx, r); err != nil {
			return nil, err
		}
		record, err = b.config.Kube.CoreV1().ConfigMaps(r.Namespace).Create(ctx, b.desiredLedger(r), metav1.CreateOptions{})
		if err != nil {
			record, err = b.config.APIReader.CoreV1().ConfigMaps(r.Namespace).Get(ctx, r.LedgerName, metav1.GetOptions{})
		}
	}
	if err != nil {
		return nil, apiFailure(ctx, err, "build-operation-ledger-unavailable")
	}
	if err := b.verifyLedger(record, r, false); err != nil {
		return nil, err
	}
	return record, nil
}

func (b *Backend) verifyLedger(record *corev1.ConfigMap, r Receipt, cleaning bool) error {
	check := r
	check.LedgerUID = ""
	if record.UID == "" || record.ResourceVersion == "" || (r.LedgerUID != "" && record.UID != r.LedgerUID) ||
		record.Name != r.LedgerName || !protectedMetadata(record.ObjectMeta, check) ||
		record.Immutable == nil || !*record.Immutable || len(record.OwnerReferences) != 0 ||
		record.DeletionTimestamp != nil || len(record.BinaryData) != 0 ||
		!reflect.DeepEqual(record.Data, b.desiredLedger(check).Data) ||
		(r.AnchorUID != "" && record.Annotations[anchorUIDAnnotation] != string(r.AnchorUID)) {
		return failure(ErrIdentity, "build-operation-ledger-identity-mismatch")
	}
	state := record.Annotations[stateAnnotation]
	if state != preparedState && (!cleaning || state != cleanupState && state != cleanedState) {
		return failure(ErrLost, "build-operation-cleaned-replay-forbidden")
	}
	return nil
}

func (b *Backend) updateLedger(
	ctx context.Context, r Receipt, cleaning bool, change func(*corev1.ConfigMap) error,
) error {
	for range 5 {
		record, err := b.config.APIReader.CoreV1().ConfigMaps(r.Namespace).Get(ctx, r.LedgerName, metav1.GetOptions{})
		if err != nil {
			return apiFailure(ctx, err, "build-operation-ledger-unavailable")
		}
		check := r
		if record.Annotations[anchorUIDAnnotation] == "" && !cleaning {
			check.AnchorUID = ""
		}
		if err := b.verifyLedger(record, check, cleaning); err != nil {
			return err
		}
		record = record.DeepCopy()
		record.Annotations = maps.Clone(record.Annotations)
		if err := change(record); err != nil {
			return err
		}
		_, err = b.config.Kube.CoreV1().ConfigMaps(r.Namespace).Update(ctx, record, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			continue
		}
		if err != nil {
			return apiFailure(ctx, err, "build-operation-ledger-not-persisted")
		}
		return nil
	}
	return failure(ErrAPI, "build-operation-ledger-contended")
}
