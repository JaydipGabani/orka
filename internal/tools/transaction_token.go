/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/contexttoken"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/taskmeta"
	"github.com/orka-agents/orka/internal/workerenv"
)

// childTransactionTokenPreparation contains the in-memory exchange state and
// parent-owned placeholder Secret created before a generated-name child Task.
// The subject token is never persisted or attached to the Task.
type childTransactionTokenPreparation struct {
	ttsClient        *contexttoken.TTSClient
	subjectToken     string
	subjectTokenType string
	scope            string
	requestedTTL     time.Duration
	requestDetails   map[string]any
}

// prepareChildTransactionToken validates the delegated scope and prepares an
// empty, parent-owned Secret referenced by the child Task. The actual child
// TxToken is not exchanged until Kubernetes has assigned the child name and UID.
func prepareChildTransactionToken(
	ctx context.Context,
	k8sClient client.Client,
	parentTask, childTask *corev1alpha1.Task,
	operation, agent string,
) (*childTransactionTokenPreparation, error) {
	ttsConfig, enabled, err := childTransactionTokenExchangeConfigForParent(parentTask)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if parentTask.UID == "" {
		return nil, fmt.Errorf("parent task UID is required for child transaction token exchange")
	}
	subjectToken, err := childTransactionSubjectToken(ttsConfig.TokenSource)
	if err != nil {
		return nil, err
	}
	scope := strings.TrimSpace(os.Getenv(workerenv.ContextTokenChildScope))
	if scope == "" {
		return nil, fmt.Errorf("%s is required when %s is set for child task tokens", workerenv.ContextTokenChildScope, workerenv.ContextTokenTTSEndpoint)
	}
	if err := validateChildTransactionScope(parentTask, scope); err != nil {
		return nil, err
	}
	subjectTokenType := strings.TrimSpace(os.Getenv(workerenv.ContextTokenSubjectTokenType))
	if subjectTokenType == "" {
		subjectTokenType = contexttoken.SubjectTokenTypeForSource(ttsConfig.TokenSource)
	}
	ttsClient, err := contexttoken.NewTTSClient(ttsConfig)
	if err != nil {
		return nil, fmt.Errorf("configuring child transaction token exchange: %w", err)
	}

	secretName, err := childTransactionTokenSecretName(parentTask.Name)
	if err != nil {
		return nil, err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            secretName,
			Namespace:       childTask.Namespace,
			OwnerReferences: taskOwnerReference(parentTask),
			Labels: map[string]string{
				labels.LabelParentTask: labels.SelectorValue(parentTask.Name),
			},
			Annotations: map[string]string{
				labels.AnnotationParentTaskName: parentTask.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
	}
	if err := k8sClient.Create(ctx, secret); err != nil {
		return nil, fmt.Errorf("creating child transaction token secret: %w", err)
	}

	stampChildTransactionScope(childTask, scope)
	if childTask.Annotations == nil {
		childTask.Annotations = map[string]string{}
	}
	childTask.Annotations[labels.AnnotationTransactionTokenSecret] = secretName

	requestDetails := map[string]any{
		"operation":    operation,
		"parentTask":   parentTask.Name,
		namespaceField: childTask.Namespace,
	}
	if agent != "" {
		requestDetails["agent"] = agent
	}
	if parentTask.Spec.Transaction != nil && parentTask.Spec.Transaction.ID != "" {
		requestDetails["txn"] = parentTask.Spec.Transaction.ID
	}
	return &childTransactionTokenPreparation{
		ttsClient:        ttsClient,
		subjectToken:     subjectToken,
		subjectTokenType: subjectTokenType,
		scope:            scope,
		requestedTTL:     ttsConfig.ChildTokenTTL,
		requestDetails:   requestDetails,
	}, nil
}

// completeChildTransactionToken exchanges a token bound to the actual child
// Task identity, then writes it and adopts the placeholder Secret in one update.
// The pending annotation prevents the child from beginning execution until this
// function succeeds and the caller clears the pending state.
func completeChildTransactionToken(
	ctx context.Context,
	k8sClient client.Client,
	childTask *corev1alpha1.Task,
	preparation *childTransactionTokenPreparation,
) error {
	if preparation == nil {
		return nil
	}
	if childTask == nil || strings.TrimSpace(childTask.Name) == "" {
		return fmt.Errorf("child task name is required for child transaction token exchange")
	}
	if childTask.UID == "" {
		return fmt.Errorf("child task UID is required for child transaction token exchange")
	}

	requestDetails := make(map[string]any, len(preparation.requestDetails)+2)
	maps.Copy(requestDetails, preparation.requestDetails)
	requestDetails["taskName"] = childTask.Name
	requestDetails["taskUID"] = string(childTask.UID)

	token, err := preparation.ttsClient.Exchange(ctx, contexttoken.ExchangeRequest{
		SubjectToken:     preparation.subjectToken,
		SubjectTokenType: preparation.subjectTokenType,
		Scope:            preparation.scope,
		RequestedTTL:     preparation.requestedTTL,
		RequestDetails:   requestDetails,
	})
	if err != nil {
		return fmt.Errorf("exchanging child transaction token: %w", err)
	}
	return adoptChildTransactionTokenSecret(ctx, k8sClient, childTask, token)
}

func childTransactionTokenExchangeConfig() (contexttoken.TTSConfig, bool, error) {
	ttsEndpoint := strings.TrimSpace(os.Getenv(workerenv.ContextTokenTTSEndpoint))
	if ttsEndpoint == "" {
		return contexttoken.TTSConfig{}, false, nil
	}
	ttsConfig, err := contexttoken.NewTTSConfig(
		ttsEndpoint,
		os.Getenv(workerenv.ContextTokenTTSAudience),
		os.Getenv(workerenv.ContextTokenTTSTimeout),
		os.Getenv(workerenv.ContextTokenTTSTokenSource),
		os.Getenv(workerenv.ContextTokenChildTokenTTL),
		"",
	)
	if err != nil {
		return contexttoken.TTSConfig{}, false, fmt.Errorf("configuring child transaction token exchange: %w", err)
	}
	return ttsConfig, ttsConfig.Enabled(), nil
}

func childTransactionTokenExchangeConfigForParent(parentTask *corev1alpha1.Task) (contexttoken.TTSConfig, bool, error) {
	ttsConfig, enabled, err := childTransactionTokenExchangeConfig()
	if err != nil {
		return contexttoken.TTSConfig{}, false, err
	}
	if !enabled || parentTask == nil || parentTask.Spec.Transaction == nil {
		return ttsConfig, false, nil
	}
	return ttsConfig, true, nil
}

func shouldPrepareChildTransactionToken(parentTask *corev1alpha1.Task) (bool, error) {
	_, enabled, err := childTransactionTokenExchangeConfigForParent(parentTask)
	return enabled, err
}

func childTransactionSubjectToken(tokenSource string) (string, error) {
	switch tokenSource {
	case contexttoken.TTSTokenSourceIncoming:
		if token, ok, err := workerenv.ReadTokenFileEnv(workerenv.ContextTokenSubjectTokenFile, "context token subject token"); ok || err != nil {
			return token, err
		}
		return workerenv.RequireTokenFileEnv(workerenv.TransactionTokenFile, "transaction token")
	case contexttoken.TTSTokenSourceServiceAccount:
		return serviceAccountSubjectToken()
	case contexttoken.TTSTokenSourceNone:
		return "", fmt.Errorf("context token TTS token source %q does not provide a subject token", tokenSource)
	default:
		return "", fmt.Errorf("unsupported context token TTS token source %q", tokenSource)
	}
}

func serviceAccountSubjectToken() (string, error) {
	if token := strings.TrimSpace(os.Getenv(workerenv.ServiceAccountToken)); token != "" {
		return token, nil
	}
	return workerenv.ReadTokenFile(workerenv.ServiceAccountTokenFile, "service account token")
}

func taskOwnerReference(task *corev1alpha1.Task) []metav1.OwnerReference {
	if task == nil || task.UID == "" {
		return nil
	}
	return []metav1.OwnerReference{{
		APIVersion: corev1alpha1.GroupVersion.String(),
		Kind:       "Task",
		Name:       task.Name,
		UID:        task.UID,
	}}
}

func childOwnerReference(childTask *corev1alpha1.Task) []metav1.OwnerReference {
	return taskOwnerReference(childTask)
}

func stampChildTransactionScope(childTask *corev1alpha1.Task, scope string) {
	if childTask == nil || childTask.Spec.Transaction == nil {
		return
	}
	scope = strings.TrimSpace(scope)
	childTask.Spec.Transaction.Scope = scope
	childTask.Spec.Transaction.Scopes = strings.Fields(scope)
	taskmeta.ApplyTransactionMetadata(&childTask.ObjectMeta, childTask.Spec.Transaction)
}

func adoptChildTransactionTokenSecret(ctx context.Context, k8sClient client.Client, childTask *corev1alpha1.Task, token string) error {
	if childTask == nil || childTask.Annotations == nil {
		return nil
	}
	secretName := strings.TrimSpace(childTask.Annotations[labels.AnnotationTransactionTokenSecret])
	if secretName == "" {
		return nil
	}
	if childTask.UID == "" {
		return fmt.Errorf("child task UID is required to adopt child transaction token secret %q", secretName)
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("child transaction token is required to adopt secret %q", secretName)
	}
	secret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: secretName, Namespace: childTask.Namespace}, secret); err != nil {
		return fmt.Errorf("getting child transaction token secret for adoption: %w", err)
	}
	secret.Data = map[string][]byte{"token": []byte(token)}
	secret.OwnerReferences = childOwnerReference(childTask)
	if err := k8sClient.Update(ctx, secret); err != nil {
		return fmt.Errorf("adopting child transaction token secret: %w", err)
	}
	return nil
}

func validateChildTransactionScope(parentTask *corev1alpha1.Task, childScope string) error {
	childScopes := strings.Fields(childScope)
	if len(childScopes) == 0 {
		return fmt.Errorf("child transaction scope is required")
	}
	if parentTask == nil || parentTask.Spec.Transaction == nil {
		return fmt.Errorf("parent transaction metadata is required for child token exchange")
	}
	parentScopes := parentTask.Spec.Transaction.Scopes
	if len(parentScopes) == 0 {
		parentScopes = strings.Fields(parentTask.Spec.Transaction.Scope)
	}
	if len(parentScopes) == 0 {
		return fmt.Errorf("parent transaction scopes are required for child token exchange")
	}
	for _, child := range childScopes {
		if !slices.Contains(parentScopes, child) {
			return fmt.Errorf("child transaction scope %q is not present in parent transaction scopes", child)
		}
	}
	return nil
}

func cleanupChildTransactionTokenSecret(ctx context.Context, k8sClient client.Client, childTask *corev1alpha1.Task) {
	if childTask == nil || childTask.Annotations == nil {
		return
	}
	secretName := strings.TrimSpace(childTask.Annotations[labels.AnnotationTransactionTokenSecret])
	if secretName == "" {
		return
	}
	if err := k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: childTask.Namespace}}); err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "failed to cleanup child transaction token secret", "secret", secretName, "namespace", childTask.Namespace)
	}
}

func cleanupChildTaskAfterTokenAdoptionFailure(ctx context.Context, k8sClient client.Client, childTask *corev1alpha1.Task) {
	if childTask == nil || childTask.Name == "" {
		cleanupChildTransactionTokenSecret(ctx, k8sClient, childTask)
		return
	}
	err := k8sClient.Delete(ctx, &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Name: childTask.Name, Namespace: childTask.Namespace}})
	if err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "failed to cleanup child task after transaction token secret adoption failure", "task", childTask.Name, "namespace", childTask.Namespace)
	}
	cleanupChildTransactionTokenSecret(ctx, k8sClient, childTask)
}

func childTransactionTokenSecretName(parentName string) (string, error) {
	timestamp := fmt.Sprintf("%x", time.Now().UnixNano())
	randomBytes := make([]byte, 5)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generating child transaction token secret suffix: %w", err)
	}
	suffix := fmt.Sprintf("txn-%s-%s", timestamp, hex.EncodeToString(randomBytes))
	base := dnsLabelPrefix(parentName)
	maxBaseLen := 63 - len(suffix) - 1
	if maxBaseLen < 1 {
		return "", fmt.Errorf("child transaction token secret suffix exceeds DNS label length")
	}
	if len(base) > maxBaseLen {
		base = strings.Trim(base[:maxBaseLen], "-")
	}
	if base == "" {
		base = "task"
	}
	return base + "-" + suffix, nil
}

func dnsLabelPrefix(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	out.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == '-':
			out.WriteRune(r)
		default:
			out.WriteRune('-')
		}
	}
	result := strings.Trim(out.String(), "-")
	if result == "" {
		return "task"
	}
	return result
}
