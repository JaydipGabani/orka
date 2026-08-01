/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

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
	taskTokenRequestRotationKey         = "rotation"

	taskTokenExpiresAtSecretKey  = "token-expires-at"
	taskTokenRefreshAtSecretKey  = "token-refresh-at"
	taskTokenGenerationSecretKey = "token-generation"

	taskTokenMinimumRotationLifetime = 3 * time.Second
	taskTokenRefreshDivisor          = 3
)

type taskTokenOptimisticRetryError struct {
	err error
}

func (e taskTokenOptimisticRetryError) Error() string { return e.err.Error() }
func (e taskTokenOptimisticRetryError) Unwrap() error { return e.err }

func taskTokenRetryable(err error) bool {
	var retry taskTokenOptimisticRetryError
	return errors.As(err, &retry)
}

func (r *TaskReconciler) taskTokenReader() client.Reader {
	if r != nil && r.APIReader != nil {
		return r.APIReader
	}
	if r == nil {
		return nil
	}
	return r.Client
}

func (r *TaskReconciler) reconcilePendingTaskTransactionToken(
	ctx context.Context,
	task *corev1alpha1.Task,
	now time.Time,
) (ready bool, fatal bool, err error) {
	workloadSecret, wait, err := r.pendingTaskTransactionTokenSecret(ctx, task)
	if err != nil || wait {
		return false, false, err
	}
	if !taskOwnsTransactionTokenSecret(task, workloadSecret) {
		return false, true, errors.New("task transaction token Secret is not owned by the pending task")
	}
	if workloadSecret.Type != corev1.SecretTypeOpaque {
		return false, true, errors.New("task transaction token Secret has an invalid type")
	}

	taskToken := strings.TrimSpace(string(workloadSecret.Data[transactiontoken.TokenSecretKey]))
	if !directTaskTokenWorkloadSecret(task, workloadSecret) {
		// Delegated child creation uses an empty placeholder Secret and completes
		// adoption synchronously in the creating worker.
		return taskToken != "", false, nil
	}
	authoritySecret, err := r.taskTransactionRenewalAuthoritySecret(ctx, task)
	if err != nil {
		return false, true, err
	}
	if taskToken != "" {
		expiresAt, refreshAt, stateErr := renewableTaskTokenState(workloadSecret, taskToken)
		if stateErr != nil {
			return false, true, stateErr
		}
		if !expiresAt.After(now) {
			return false, true, errors.New("task-bound transaction token expired before setup completed")
		}
		if !now.Before(refreshAt) {
			if _, rotateErr := r.rotateTaskTransactionToken(ctx, task, authoritySecret, workloadSecret, now); rotateErr != nil {
				return false, !taskTokenRetryable(rotateErr), rotateErr
			}
		}
		return true, false, nil
	}
	if _, err := r.rotateTaskTransactionToken(ctx, task, authoritySecret, workloadSecret, now); err != nil {
		return false, !taskTokenRetryable(err), err
	}
	return true, false, nil
}

func (r *TaskReconciler) pendingTaskTransactionTokenSecret(
	ctx context.Context,
	task *corev1alpha1.Task,
) (*corev1.Secret, bool, error) {
	if r == nil || r.Client == nil || r.taskTokenReader() == nil || task == nil || task.Annotations == nil {
		return nil, true, nil
	}
	secretName := strings.TrimSpace(task.Annotations[labels.AnnotationTransactionTokenSecret])
	if secretName == "" {
		return nil, true, nil
	}
	secret := &corev1.Secret{}
	if err := r.taskTokenReader().Get(ctx, types.NamespacedName{Namespace: task.Namespace, Name: secretName}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("reading pending task transaction token Secret: %w", err)
	}
	return secret, false, nil
}

func directTaskTokenWorkloadSecret(task *corev1alpha1.Task, secret *corev1.Secret) bool {
	return task != nil && secret != nil && task.UID != "" &&
		secret.Labels[labels.LabelPurpose] == transactiontoken.WorkloadSecretPurpose &&
		secret.Labels[labels.LabelTaskUID] == labels.SelectorValue(string(task.UID))
}

func (r *TaskReconciler) taskTransactionRenewalAuthoritySecret(
	ctx context.Context,
	task *corev1alpha1.Task,
) (*corev1.Secret, error) {
	if r == nil || r.Client == nil || r.taskTokenReader() == nil || task == nil || task.UID == "" {
		return nil, errors.New("task transaction renewal authority cannot be resolved")
	}
	listed := &corev1.SecretList{}
	if err := r.taskTokenReader().List(ctx, listed,
		client.InNamespace(task.Namespace),
		client.MatchingLabels{
			labels.LabelPurpose: transactiontoken.AuthoritySecretPurpose,
			labels.LabelTaskUID: labels.SelectorValue(string(task.UID)),
		},
	); err != nil {
		return nil, fmt.Errorf("listing task transaction renewal authority: %w", err)
	}
	if len(listed.Items) != 1 {
		return nil, fmt.Errorf("task transaction renewal authority count is %d, want exactly one", len(listed.Items))
	}
	authority := listed.Items[0].DeepCopy()
	if !taskOwnsTransactionTokenSecret(task, authority) {
		return nil, errors.New("task transaction renewal authority is not owned by the task")
	}
	if authority.Type != corev1.SecretTypeOpaque ||
		authority.Labels[labels.LabelPurpose] != transactiontoken.AuthoritySecretPurpose ||
		authority.Labels[labels.LabelTaskUID] != labels.SelectorValue(string(task.UID)) {
		return nil, errors.New("task transaction renewal authority metadata is invalid")
	}
	if len(authority.Data) != 1 || strings.TrimSpace(string(authority.Data[transactiontoken.SubjectSecretKey])) == "" {
		return nil, errors.New("task transaction renewal authority data is invalid")
	}
	return authority, nil
}

func (r *TaskReconciler) rotateTaskTransactionToken(
	ctx context.Context,
	task *corev1alpha1.Task,
	authoritySecret *corev1.Secret,
	workloadSecret *corev1.Secret,
	now time.Time,
) (time.Time, error) {
	subjectToken := strings.TrimSpace(string(authoritySecret.Data[transactiontoken.SubjectSecretKey]))
	if subjectToken == "" {
		return time.Time{}, errors.New("task transaction renewal authority is empty")
	}
	if task.Spec.Transaction == nil || strings.TrimSpace(task.Spec.Transaction.Scope) == "" {
		return time.Time{}, errors.New("task is missing verified transaction scope metadata")
	}
	config := r.BrokeredTransactionExchange
	if config == nil || config.Exchanger == nil || !config.TTS.Enabled() {
		return time.Time{}, errors.New("task transaction token exchange is not configured")
	}
	if config.TTS.TokenSource != contexttoken.TTSTokenSourceIncoming {
		return time.Time{}, fmt.Errorf("task transaction token exchange requires %q token source", contexttoken.TTSTokenSourceIncoming)
	}
	subjectTokenType := strings.TrimSpace(config.SubjectTokenType)
	if subjectTokenType == "" {
		subjectTokenType = contexttoken.SubjectTokenTypeForSource(contexttoken.TTSTokenSourceIncoming)
	}
	generation, err := taskTokenGeneration(workloadSecret)
	if err != nil {
		return time.Time{}, err
	}
	if generation == ^uint64(0) {
		return time.Time{}, errors.New("task transaction token generation is exhausted")
	}
	nextGeneration := generation + 1
	requestDetails := map[string]any{
		taskTokenRequestOperationKey: taskTokenRequestOperationCreateTask,
		taskTokenRequestNamespaceKey: task.Namespace,
		taskTokenRequestTaskNameKey:  task.Name,
		taskTokenRequestTaskUIDKey:   string(task.UID),
		taskTokenRequestRotationKey:  nextGeneration,
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
		return time.Time{}, fmt.Errorf("exchanging task-bound transaction token: %w", err)
	}
	taskToken = strings.TrimSpace(taskToken)
	previousToken := strings.TrimSpace(string(workloadSecret.Data[transactiontoken.TokenSecretKey]))
	if taskToken == "" || taskToken == subjectToken || taskToken == previousToken {
		return time.Time{}, errors.New("transaction token exchange did not return a distinct task-bound token")
	}
	expiresAt, err := unverifiedTaskTokenExpiry(taskToken)
	if err != nil {
		return time.Time{}, fmt.Errorf("reading task-bound transaction token expiry: %w", err)
	}
	remaining := expiresAt.Sub(now)
	minimumLifetime := taskTokenMinimumRotationLifetime
	if task.Spec.Type == corev1alpha1.TaskTypeAI {
		minimumLifetime = transactiontoken.MinimumProjectedTokenRemainingLifetime
	}
	if remaining < minimumLifetime {
		return time.Time{}, errors.New("task-bound transaction token lifetime is too short for safe rotation")
	}
	refreshAt := now.Add(remaining / taskTokenRefreshDivisor)
	workloadSecret.Data = map[string][]byte{
		transactiontoken.TokenSecretKey: []byte(taskToken),
		taskTokenExpiresAtSecretKey:     []byte(expiresAt.UTC().Format(time.RFC3339Nano)),
		taskTokenRefreshAtSecretKey:     []byte(refreshAt.UTC().Format(time.RFC3339Nano)),
		taskTokenGenerationSecretKey:    []byte(strconv.FormatUint(nextGeneration, 10)),
	}
	return r.persistTaskTokenRotation(ctx, task, workloadSecret, generation, nextGeneration, refreshAt)
}

func (r *TaskReconciler) persistTaskTokenRotation(
	ctx context.Context,
	task *corev1alpha1.Task,
	intended *corev1.Secret,
	previousGeneration, intendedGeneration uint64,
	intendedRefresh time.Time,
) (time.Time, error) {
	if err := r.Update(ctx, intended); err == nil {
		return intendedRefresh, nil
	} else if !apierrors.IsConflict(err) {
		return time.Time{}, fmt.Errorf("persisting task-bound transaction token: %w", err)
	}
	fresh, err := r.freshTaskTokenWorkloadSecret(ctx, task, intended.Name)
	if err != nil {
		return time.Time{}, taskTokenOptimisticRetryError{err: err}
	}
	if refreshAt, complete := completedTaskTokenRotation(fresh, intendedGeneration); complete {
		return refreshAt, nil
	}
	generation, err := taskTokenGeneration(fresh)
	if err != nil || generation != previousGeneration {
		return time.Time{}, taskTokenOptimisticRetryError{err: errors.New("task token rotation changed concurrently")}
	}
	fresh.Data = cloneSecretData(intended.Data)
	if err := r.Update(ctx, fresh); err == nil {
		return intendedRefresh, nil
	} else if !apierrors.IsConflict(err) {
		return time.Time{}, fmt.Errorf("retrying task-bound transaction token persistence: %w", err)
	}
	latest, readErr := r.freshTaskTokenWorkloadSecret(ctx, task, intended.Name)
	if readErr == nil {
		if refreshAt, complete := completedTaskTokenRotation(latest, intendedGeneration); complete {
			return refreshAt, nil
		}
	}
	return time.Time{}, taskTokenOptimisticRetryError{err: errors.New("task token rotation conflict requires retry")}
}

func (r *TaskReconciler) freshTaskTokenWorkloadSecret(
	ctx context.Context,
	task *corev1alpha1.Task,
	name string,
) (*corev1.Secret, error) {
	fresh := &corev1.Secret{}
	if err := r.taskTokenReader().Get(ctx, types.NamespacedName{Namespace: task.Namespace, Name: name}, fresh); err != nil {
		return nil, fmt.Errorf("fresh-reading task transaction token Secret: %w", err)
	}
	if !taskOwnsTransactionTokenSecret(task, fresh) || fresh.Type != corev1.SecretTypeOpaque ||
		!directTaskTokenWorkloadSecret(task, fresh) {
		return nil, errors.New("fresh task transaction token Secret identity is invalid")
	}
	return fresh, nil
}

func completedTaskTokenRotation(secret *corev1.Secret, minimumGeneration uint64) (time.Time, bool) {
	generation, err := taskTokenGeneration(secret)
	if err != nil || generation < minimumGeneration {
		return time.Time{}, false
	}
	_, refreshAt, err := renewableTaskTokenState(secret, string(secret.Data[transactiontoken.TokenSecretKey]))
	return refreshAt, err == nil
}

func cloneSecretData(source map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(source))
	for key, value := range source {
		cloned[key] = append([]byte(nil), value...)
	}
	return cloned
}

func (r *TaskReconciler) reconcileActiveTaskTransactionToken(
	ctx context.Context,
	task *corev1alpha1.Task,
	now time.Time,
) (refreshAfter time.Duration, fatal bool, err error) {
	if task == nil || task.Spec.Transaction == nil || task.Annotations == nil ||
		(task.Spec.Type != corev1alpha1.TaskTypeAI && task.Spec.Type != corev1alpha1.TaskTypeAgent) {
		return 0, false, nil
	}
	secretName := strings.TrimSpace(task.Annotations[labels.AnnotationTransactionTokenSecret])
	if secretName == "" {
		return 0, false, nil
	}
	workloadSecret := &corev1.Secret{}
	if err := r.taskTokenReader().Get(ctx, types.NamespacedName{Namespace: task.Namespace, Name: secretName}, workloadSecret); err != nil {
		if apierrors.IsNotFound(err) {
			return 0, true, errors.New("task transaction token Secret is unavailable")
		}
		return 0, false, fmt.Errorf("reading active task transaction token Secret: %w", err)
	}
	if !taskOwnsTransactionTokenSecret(task, workloadSecret) {
		return 0, true, errors.New("active task transaction token Secret is not owned by the task")
	}
	if workloadSecret.Type != corev1.SecretTypeOpaque {
		return 0, true, errors.New("active task transaction token Secret has an invalid type")
	}
	if !directTaskTokenWorkloadSecret(task, workloadSecret) {
		return 0, false, nil
	}
	authoritySecret, err := r.taskTransactionRenewalAuthoritySecret(ctx, task)
	if err != nil {
		return 0, true, err
	}
	taskToken := strings.TrimSpace(string(workloadSecret.Data[transactiontoken.TokenSecretKey]))
	expiresAt, refreshAt, err := renewableTaskTokenState(workloadSecret, taskToken)
	if err != nil {
		return 0, true, err
	}
	if !expiresAt.After(now) {
		return 0, true, errors.New("task-bound transaction token expired before rotation")
	}
	if now.Before(refreshAt) {
		return refreshAt.Sub(now), false, nil
	}
	nextRefresh, err := r.rotateTaskTransactionToken(ctx, task, authoritySecret, workloadSecret, now)
	if err != nil {
		return 0, !taskTokenRetryable(err), err
	}
	return max(nextRefresh.Sub(now), time.Nanosecond), false, nil
}

func renewableTaskTokenState(secret *corev1.Secret, taskToken string) (time.Time, time.Time, error) {
	if secret == nil || strings.TrimSpace(taskToken) == "" {
		return time.Time{}, time.Time{}, errors.New("renewable task transaction token is missing")
	}
	expiresAt, err := parseTaskTokenSecretTime(secret, taskTokenExpiresAtSecretKey)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	tokenExpiresAt, err := unverifiedTaskTokenExpiry(taskToken)
	if err != nil || !tokenExpiresAt.Equal(expiresAt) {
		return time.Time{}, time.Time{}, errors.New("task transaction token expiry metadata does not match the token")
	}
	refreshAt, err := parseTaskTokenSecretTime(secret, taskTokenRefreshAtSecretKey)
	if err != nil || !refreshAt.Before(expiresAt) {
		return time.Time{}, time.Time{}, errors.New("task transaction token refresh metadata is invalid")
	}
	generation, err := taskTokenGeneration(secret)
	if err != nil || generation == 0 {
		return time.Time{}, time.Time{}, errors.New("task transaction token generation is invalid")
	}
	return expiresAt, refreshAt, nil
}

func taskTokenGeneration(secret *corev1.Secret) (uint64, error) {
	if secret == nil || len(secret.Data[taskTokenGenerationSecretKey]) == 0 {
		return 0, nil
	}
	generation, err := strconv.ParseUint(strings.TrimSpace(string(secret.Data[taskTokenGenerationSecretKey])), 10, 64)
	if err != nil {
		return 0, errors.New("task transaction token generation is invalid")
	}
	return generation, nil
}

func parseTaskTokenSecretTime(secret *corev1.Secret, key string) (time.Time, error) {
	value := strings.TrimSpace(string(secret.Data[key]))
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() {
		return time.Time{}, fmt.Errorf("task transaction token %s is invalid", key)
	}
	return parsed.UTC(), nil
}

func unverifiedTaskTokenExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, errors.New("task transaction token is not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, errors.New("task transaction token payload is invalid")
	}
	var claims struct {
		Expiration json.Number `json:"exp"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if decoder.Decode(&claims) != nil || claims.Expiration == "" {
		return time.Time{}, errors.New("task transaction token expiration is missing")
	}
	seconds, err := claims.Expiration.Int64()
	if err != nil || seconds <= 0 {
		return time.Time{}, errors.New("task transaction token expiration is invalid")
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func (r *TaskReconciler) handleWithTaskTransactionTokenRefresh(
	ctx context.Context,
	task *corev1alpha1.Task,
	handler func(context.Context, *corev1alpha1.Task) (ctrl.Result, error),
) (ctrl.Result, error) {
	refreshAfter, fatal, refreshErr := r.reconcileActiveTaskTransactionToken(ctx, task, time.Now())
	if refreshErr != nil {
		if !fatal {
			return ctrl.Result{}, refreshErr
		}
		logf.FromContext(ctx).Info("task-scoped transaction token refresh failed; failing closed")
		if cleanupErr := r.cleanupOwnedTaskTransactionTokenSecret(ctx, task); cleanupErr != nil {
			return ctrl.Result{}, cleanupErr
		}
		if r.Recorder != nil {
			r.Recorder.Event(task, corev1.EventTypeWarning, "TransactionTokenRefreshFailed", "task-scoped transaction token refresh failed")
		}
		return r.failTask(ctx, task, "task-scoped transaction token refresh failed")
	}
	result, err := handler(ctx, task)
	if err != nil || refreshAfter <= 0 {
		return result, err
	}
	if result.RequeueAfter <= 0 || refreshAfter < result.RequeueAfter {
		result.RequeueAfter = refreshAfter
	}
	return result, nil
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
	if r == nil || r.Client == nil || task == nil {
		return nil
	}
	var cleanupErrors []error
	if task.Annotations != nil {
		secretName := strings.TrimSpace(task.Annotations[labels.AnnotationTransactionTokenSecret])
		if secretName != "" {
			workloadSecret := &corev1.Secret{}
			if err := r.taskTokenReader().Get(ctx, types.NamespacedName{Namespace: task.Namespace, Name: secretName}, workloadSecret); err != nil {
				if !apierrors.IsNotFound(err) {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("reading task transaction token Secret for cleanup: %w", err))
				}
			} else if taskOwnsTransactionTokenSecret(task, workloadSecret) {
				if err := r.Delete(ctx, workloadSecret); err != nil && !apierrors.IsNotFound(err) {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("deleting task transaction token Secret: %w", err))
				}
			}
		}
	}
	if task.UID != "" {
		listed := &corev1.SecretList{}
		if err := r.taskTokenReader().List(ctx, listed,
			client.InNamespace(task.Namespace),
			client.MatchingLabels{
				labels.LabelPurpose: transactiontoken.AuthoritySecretPurpose,
				labels.LabelTaskUID: labels.SelectorValue(string(task.UID)),
			},
		); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("listing task transaction renewal authority for cleanup: %w", err))
		} else {
			for i := range listed.Items {
				authority := &listed.Items[i]
				if !taskOwnsTransactionTokenSecret(task, authority) {
					continue
				}
				if err := r.Delete(ctx, authority); err != nil && !apierrors.IsNotFound(err) {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("deleting task transaction renewal authority: %w", err))
				}
			}
		}
	}
	return errors.Join(cleanupErrors...)
}
