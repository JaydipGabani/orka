/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/contexttoken"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/transactiontoken"
)

const (
	taskTransactionTokenOwnerKind       = "Task"
	taskTokenRequestOperationKey        = "operation"
	taskTokenRequestOperationCreateTask = "createTask"
	taskTokenRequestNamespaceKey        = "namespace"
	taskTokenRequestTaskNameKey         = "taskName"
	taskTokenRequestTaskUIDKey          = "taskUID"
	taskTokenRequestTransactionIDKey    = "txn"
)

func (r *TaskReconciler) reconcilePendingTaskTransactionToken(
	ctx context.Context,
	task *corev1alpha1.Task,
) (ready bool, fatal bool, err error) {
	if r == nil || r.Client == nil || task == nil || task.Annotations == nil {
		return false, false, nil
	}
	secretName := strings.TrimSpace(task.Annotations[labels.AnnotationTransactionTokenSecret])
	if secretName == "" {
		return false, false, nil
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: task.Namespace, Name: secretName}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("reading pending task transaction token secret: %w", err)
	}

	subjectBytes, hasSubject := secret.Data[transactiontoken.SubjectSecretKey]
	tokenBytes, hasToken := secret.Data[transactiontoken.TokenSecretKey]
	if !hasSubject && !hasToken {
		// Delegated child creation uses an empty placeholder Secret and completes
		// adoption synchronously in the creating worker.
		return false, false, nil
	}
	if !taskOwnsTransactionTokenSecret(task, secret) {
		return false, true, errors.New("task transaction token secret is not owned by the pending task")
	}
	if secret.Type != corev1.SecretTypeOpaque {
		return false, true, errors.New("task transaction token secret has an invalid type")
	}
	if hasSubject && hasToken {
		return false, true, errors.New("task transaction token secret contains both subject and task-bound tokens")
	}
	if hasToken {
		if strings.TrimSpace(string(tokenBytes)) == "" {
			return false, true, errors.New("task-bound transaction token is empty")
		}
		return true, false, nil
	}

	subjectToken := strings.TrimSpace(string(subjectBytes))
	if subjectToken == "" {
		return false, true, errors.New("task transaction token subject is empty")
	}
	if task.Spec.Transaction == nil || strings.TrimSpace(task.Spec.Transaction.Scope) == "" {
		return false, true, errors.New("pending task is missing verified transaction scope metadata")
	}
	config := r.BrokeredTransactionExchange
	if config == nil || config.Exchanger == nil || !config.TTS.Enabled() {
		return false, true, errors.New("task transaction token exchange is not configured")
	}
	if config.TTS.TokenSource != contexttoken.TTSTokenSourceIncoming {
		return false, true, fmt.Errorf("task transaction token exchange requires %q token source", contexttoken.TTSTokenSourceIncoming)
	}
	subjectTokenType := strings.TrimSpace(config.SubjectTokenType)
	if subjectTokenType == "" {
		subjectTokenType = contexttoken.SubjectTokenTypeForSource(contexttoken.TTSTokenSourceIncoming)
	}
	requestDetails := map[string]any{
		taskTokenRequestOperationKey: taskTokenRequestOperationCreateTask,
		taskTokenRequestNamespaceKey: task.Namespace,
		taskTokenRequestTaskNameKey:  task.Name,
		taskTokenRequestTaskUIDKey:   string(task.UID),
	}
	if transactionID := strings.TrimSpace(task.Spec.Transaction.ID); transactionID != "" {
		requestDetails[taskTokenRequestTransactionIDKey] = transactionID
	}
	taskToken, err := config.Exchanger.Exchange(ctx, contexttoken.ExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: subjectTokenType,
		Scope:            strings.TrimSpace(task.Spec.Transaction.Scope),
		RequestedTTL:     config.TTS.ChildTokenTTL,
		RequestDetails:   requestDetails,
	})
	if err != nil {
		return false, true, fmt.Errorf("exchanging task-bound transaction token: %w", err)
	}
	taskToken = strings.TrimSpace(taskToken)
	if taskToken == "" || taskToken == subjectToken {
		return false, true, errors.New("transaction token exchange did not return a distinct task-bound token")
	}
	secret.Data = map[string][]byte{transactiontoken.TokenSecretKey: []byte(taskToken)}
	if err := r.Update(ctx, secret); err != nil {
		return false, true, fmt.Errorf("persisting task-bound transaction token: %w", err)
	}
	return true, false, nil
}

func taskOwnsTransactionTokenSecret(task *corev1alpha1.Task, secret *corev1.Secret) bool {
	if task == nil || secret == nil || task.UID == "" {
		return false
	}
	for _, owner := range secret.OwnerReferences {
		if owner.APIVersion == corev1alpha1.GroupVersion.String() && owner.Kind == taskTransactionTokenOwnerKind &&
			owner.Name == task.Name && owner.UID == task.UID {
			return true
		}
	}
	return false
}

func (r *TaskReconciler) clearPendingTaskTransactionToken(ctx context.Context, task *corev1alpha1.Task) error {
	patch := client.MergeFrom(task.DeepCopy())
	delete(task.Annotations, labels.AnnotationTransactionTokenPending)
	delete(task.Annotations, labels.AnnotationTransactionTokenPendingSince)
	if err := r.Patch(ctx, task, patch); err != nil {
		return fmt.Errorf("clearing task transaction token pending state: %w", err)
	}
	return nil
}

func (r *TaskReconciler) cleanupOwnedTaskTransactionTokenSecret(ctx context.Context, task *corev1alpha1.Task) error {
	if r == nil || r.Client == nil || task == nil || task.Annotations == nil {
		return nil
	}
	secretName := strings.TrimSpace(task.Annotations[labels.AnnotationTransactionTokenSecret])
	if secretName == "" {
		return nil
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: task.Namespace, Name: secretName}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("reading task transaction token secret for cleanup: %w", err)
	}
	if !taskOwnsTransactionTokenSecret(task, secret) {
		return nil
	}
	if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting task transaction token secret: %w", err)
	}
	return nil
}
