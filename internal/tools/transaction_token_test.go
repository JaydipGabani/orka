/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/contexttoken"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/transactiontoken"
	txtest "github.com/orka-agents/orka/internal/transactiontoken/testutil"
	"github.com/orka-agents/orka/internal/workerenv"
)

const childTransactionAudience = "child.example.test"

func TestPrepareAndCompleteChildTransactionToken(t *testing.T) {
	subjectPath := writeTestSubjectToken(t)
	issuer := newTransactionTokenIssuer(t)
	jwksServer := httptest.NewServer(issuer.JWKSHandler())
	defer jwksServer.Close()

	exchange := &childTokenExchange{}
	ttsServer := startChildTransactionTokenServer(t, issuer, exchange)
	defer ttsServer.Close()

	t.Setenv(workerenv.ContextTokenTTSEndpoint, ttsServer.URL+"/token_endpoint")
	t.Setenv(workerenv.ContextTokenTTSTokenSource, contexttoken.TTSTokenSourceIncoming)
	t.Setenv(workerenv.ContextTokenTTSAudience, childTransactionAudience)
	t.Setenv(workerenv.ContextTokenSubjectTokenFile, subjectPath)
	t.Setenv(workerenv.ContextTokenChildScope, childTransactionScope)
	t.Setenv(workerenv.ContextTokenChildTokenTTL, "42s")

	parent := parentTask()
	child := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultNamespace},
		Spec: corev1alpha1.TaskSpec{
			Transaction: parent.Spec.Transaction.DeepCopy(),
		},
	}
	fc := newFakeClient()
	preparation, err := prepareChildTransactionToken(context.Background(), fc, parent, child, "delegateTask", testResearcherAgentName)
	if err != nil {
		t.Fatalf("prepareChildTransactionToken() error = %v", err)
	}
	if preparation == nil {
		t.Fatal("prepareChildTransactionToken() returned nil preparation")
	}
	if exchange.called.Load() {
		t.Fatal("TTS exchange occurred before child task identity was assigned")
	}
	secretName := requirePreparedChildTransactionToken(t, fc, parent, child)

	child.Name = "child-task"
	child.UID = apitypes.UID("child-uid-1234")
	if err := completeChildTransactionToken(context.Background(), fc, child, preparation); err != nil {
		t.Fatalf("completeChildTransactionToken() error = %v", err)
	}
	requireChildTokenExchange(t, exchange, child, "parent-tx-token", transactiontoken.SubjectTokenTypeTransactionToken)
	requireAdoptedChildTransactionTokenSecret(t, fc, child, secretName, jwksServer.URL)
}

func TestCompleteChildTransactionTokenDefaultsToServiceAccountSubjectToken(t *testing.T) {
	issuer := newTransactionTokenIssuer(t)
	jwksServer := httptest.NewServer(issuer.JWKSHandler())
	defer jwksServer.Close()

	exchange := &childTokenExchange{}
	ttsServer := startChildTransactionTokenServer(t, issuer, exchange)
	defer ttsServer.Close()

	t.Setenv(workerenv.ContextTokenTTSEndpoint, ttsServer.URL+"/token_endpoint")
	t.Setenv(workerenv.ContextTokenTTSAudience, childTransactionAudience)
	t.Setenv(workerenv.ContextTokenChildScope, childTransactionScope)
	t.Setenv(workerenv.ContextTokenChildTokenTTL, "42s")
	t.Setenv(workerenv.ServiceAccountToken, "service-account-token")

	parent := parentTask()
	child := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "child-task",
			Namespace: defaultNamespace,
			UID:       apitypes.UID("child-uid-1234"),
		},
		Spec: corev1alpha1.TaskSpec{
			Transaction: parent.Spec.Transaction.DeepCopy(),
		},
	}
	fc := newFakeClient()
	preparation, err := prepareChildTransactionToken(context.Background(), fc, parent, child, "delegateTask", testResearcherAgentName)
	if err != nil {
		t.Fatalf("prepareChildTransactionToken() error = %v", err)
	}
	secretName := requirePreparedChildTransactionToken(t, fc, parent, child)
	if err := completeChildTransactionToken(context.Background(), fc, child, preparation); err != nil {
		t.Fatalf("completeChildTransactionToken() error = %v", err)
	}

	requireChildTokenExchange(t, exchange, child, "service-account-token", transactiontoken.SubjectTokenTypeAccessToken)
	requireAdoptedChildTransactionTokenSecret(t, fc, child, secretName, jwksServer.URL)
}

type childTokenExchange struct {
	called             atomic.Bool
	requestDetails     map[string]any
	audience           string
	scope              string
	subjectToken       string
	subjectTokenTyp    string
	requestedExpiresIn string
}

func writeTestSubjectToken(t *testing.T) string {
	t.Helper()

	subjectPath := filepath.Join(t.TempDir(), "subject-token")
	if err := os.WriteFile(subjectPath, []byte("parent-tx-token"), 0600); err != nil {
		t.Fatalf("failed to write subject token: %v", err)
	}
	return subjectPath
}

func newTransactionTokenIssuer(t *testing.T) *txtest.Issuer {
	t.Helper()
	return txtest.NewIssuer(t)
}

func startChildTransactionTokenServer(t *testing.T, issuer *txtest.Issuer, exchange *childTokenExchange) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token_endpoint" {
			t.Errorf("path = %q, want /token_endpoint", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		exchange.called.Store(true)
		exchange.subjectToken = r.FormValue("subject_token")
		exchange.audience = r.FormValue("audience")
		exchange.scope = r.FormValue("scope")
		exchange.subjectTokenTyp = r.FormValue("subject_token_type")
		exchange.requestedExpiresIn = r.FormValue("requested_expires_in")
		if err := json.Unmarshal([]byte(r.FormValue("request_details")), &exchange.requestDetails); err != nil {
			t.Errorf("request_details JSON error = %v", err)
			http.Error(w, "invalid request details", http.StatusBadRequest)
			return
		}
		childToken, err := issuer.SignClaims(transactiontoken.Claims{
			Issuer:             "https://tts.example.test",
			Audience:           childTransactionAudience,
			TransactionID:      parentTransactionID,
			Subject:            "spiffe://example.test/ns/default/sa/child",
			Scope:              childTransactionScope,
			RequestingWorkload: "spiffe://example.test/ns/default/sa/orka-worker",
			TransactionContext: exchange.requestDetails,
		}, time.Minute)
		if err != nil {
			t.Errorf("sign child transaction token: %v", err)
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":      childToken,
			"issued_token_type": "urn:ietf:params:oauth:token-type:txn_token",
			"token_type":        "N_A",
		})
	}))
}

func requireChildTokenExchange(
	t *testing.T,
	exchange *childTokenExchange,
	child *corev1alpha1.Task,
	wantSubjectToken, wantSubjectTokenType string,
) {
	t.Helper()

	if !exchange.called.Load() {
		t.Fatal("expected child transaction token exchange")
	}
	if exchange.subjectToken != wantSubjectToken {
		t.Fatalf("subject_token = %q, want %q", exchange.subjectToken, wantSubjectToken)
	}
	if exchange.scope != childTransactionScope {
		t.Fatalf("scope = %q, want %q", exchange.scope, childTransactionScope)
	}
	if exchange.audience != childTransactionAudience {
		t.Fatalf("audience = %q, want child.example.test", exchange.audience)
	}
	if exchange.subjectTokenTyp != wantSubjectTokenType {
		t.Fatalf("subject_token_type = %q, want %q", exchange.subjectTokenTyp, wantSubjectTokenType)
	}
	if exchange.requestedExpiresIn != "42" {
		t.Fatalf("requested_expires_in = %q, want 42", exchange.requestedExpiresIn)
	}
	if exchange.requestDetails["operation"] != "delegateTask" ||
		exchange.requestDetails["agent"] != testResearcherAgentName ||
		exchange.requestDetails["txn"] != parentTransactionID ||
		exchange.requestDetails["parentTask"] != parentTaskName ||
		exchange.requestDetails[namespaceField] != child.Namespace ||
		exchange.requestDetails["taskName"] != child.Name ||
		exchange.requestDetails["taskUID"] != string(child.UID) {
		t.Fatalf("request_details = %#v", exchange.requestDetails)
	}
}

func requirePreparedChildTransactionToken(
	t *testing.T,
	fc client.Client,
	parent *corev1alpha1.Task,
	child *corev1alpha1.Task,
) string {
	t.Helper()

	secretName := child.Annotations[labels.AnnotationTransactionTokenSecret]
	if secretName == "" {
		t.Fatal("expected child transaction token secret annotation")
	}
	secret := &corev1.Secret{}
	if err := fc.Get(context.Background(), client.ObjectKey{Name: secretName, Namespace: defaultNamespace}, secret); err != nil {
		t.Fatalf("failed to get child transaction token secret: %v", err)
	}
	if len(secret.Data) != 0 {
		t.Fatalf("prepared child transaction token secret contains data before child identity assignment: %#v", secret.Data)
	}
	if child.Spec.Transaction.Scope != childTransactionScope {
		t.Fatalf("child transaction scope = %q, want %q", child.Spec.Transaction.Scope, childTransactionScope)
	}
	if got, want := child.Spec.Transaction.Scopes, []string{childTransactionScope}; !slices.Equal(got, want) {
		t.Fatalf("child transaction scopes = %#v, want %#v", got, want)
	}
	if got := child.Annotations[labels.AnnotationTransactionScope]; got != childTransactionScope {
		t.Fatalf("transaction scope annotation = %q, want %q", got, childTransactionScope)
	}
	if len(secret.OwnerReferences) != 1 {
		t.Fatalf("ownerReferences = %#v, want parent task owner before child task adoption", secret.OwnerReferences)
	}
	preAdoptionOwner := secret.OwnerReferences[0]
	if preAdoptionOwner.Name != parent.Name || preAdoptionOwner.UID != parent.UID {
		t.Fatalf("ownerReference = %#v, want parent task name %q uid %q", preAdoptionOwner, parent.Name, parent.UID)
	}
	if preAdoptionOwner.BlockOwnerDeletion != nil {
		t.Fatalf("ownerReference BlockOwnerDeletion = %#v, want nil", preAdoptionOwner.BlockOwnerDeletion)
	}
	return secretName
}

func requireAdoptedChildTransactionTokenSecret(
	t *testing.T,
	fc client.Client,
	child *corev1alpha1.Task,
	secretName, jwksURL string,
) {
	t.Helper()

	adoptedSecret := &corev1.Secret{}
	if err := fc.Get(context.Background(), client.ObjectKey{Name: secretName, Namespace: defaultNamespace}, adoptedSecret); err != nil {
		t.Fatalf("failed to get adopted child transaction token secret: %v", err)
	}
	if len(adoptedSecret.OwnerReferences) != 1 {
		t.Fatalf("ownerReferences = %#v, want child task owner", adoptedSecret.OwnerReferences)
	}
	owner := adoptedSecret.OwnerReferences[0]
	if owner.Name != child.Name || owner.UID != child.UID {
		t.Fatalf("ownerReference = %#v, want child task name %q uid %q", owner, child.Name, child.UID)
	}
	if owner.Name == parentTaskName {
		t.Fatalf("ownerReference = %#v, want child task owner not parent task", owner)
	}
	if owner.BlockOwnerDeletion != nil {
		t.Fatalf("ownerReference BlockOwnerDeletion = %#v, want nil", owner.BlockOwnerDeletion)
	}
	secretToken := string(adoptedSecret.Data["token"])
	if secretToken == "" {
		t.Fatal("adopted child transaction token secret is missing token data")
	}
	claims, err := txtest.Verify(context.Background(), jwksURL, childTransactionAudience, secretToken)
	if err != nil {
		t.Fatalf("failed to verify child TxToken from secret: %v", err)
	}
	if claims.TransactionID != parentTransactionID {
		t.Fatalf("child token txn = %q, want %q", claims.TransactionID, parentTransactionID)
	}
	if claims.Scope != childTransactionScope {
		t.Fatalf("child token scope = %q, want %q", claims.Scope, childTransactionScope)
	}
	if claims.TransactionContext["taskName"] != child.Name || claims.TransactionContext["taskUID"] != string(child.UID) {
		t.Fatalf("child token transaction context = %#v, want task name %q uid %q", claims.TransactionContext, child.Name, child.UID)
	}
}

func TestPrepareChildTransactionTokenRequiresParentUID(t *testing.T) {
	var called atomic.Bool
	ttsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		http.Error(w, "unexpected TTS call", http.StatusInternalServerError)
	}))
	defer ttsServer.Close()

	t.Setenv(workerenv.ContextTokenTTSEndpoint, ttsServer.URL+"/token_endpoint")

	parent := parentTask()
	parent.UID = ""
	child := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultNamespace},
		Spec: corev1alpha1.TaskSpec{
			Transaction: parent.Spec.Transaction.DeepCopy(),
		},
	}
	k8sClient := newFakeClient()

	_, err := prepareChildTransactionToken(context.Background(), k8sClient, parent, child, "delegateTask", testResearcherAgentName)
	if err == nil || !strings.Contains(err.Error(), "parent task UID is required") {
		t.Fatalf("prepareChildTransactionToken() error = %v, want parent UID error", err)
	}
	if called.Load() {
		t.Fatal("TTS was called despite missing parent UID")
	}
	if child.Annotations[labels.AnnotationTransactionTokenSecret] != "" {
		t.Fatalf("unexpected child transaction token secret annotation: %#v", child.Annotations)
	}
	secrets := &corev1.SecretList{}
	if err := k8sClient.List(context.Background(), secrets, client.InNamespace(defaultNamespace)); err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}
	if len(secrets.Items) != 0 {
		t.Fatalf("unexpected secrets created without parent UID: %#v", secrets.Items)
	}
}

func TestAdoptChildTransactionTokenSecretRequiresChildUID(t *testing.T) {
	child := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "child-task",
			Namespace: defaultNamespace,
			Annotations: map[string]string{
				labels.AnnotationTransactionTokenSecret: "child-token-secret",
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "child-token-secret",
			Namespace: defaultNamespace,
		},
	}
	k8sClient := newFakeClient(secret)

	err := adoptChildTransactionTokenSecret(context.Background(), k8sClient, child, "child-token")
	if err == nil || !strings.Contains(err.Error(), "child task UID is required") {
		t.Fatalf("adoptChildTransactionTokenSecret() error = %v, want child UID error", err)
	}
	gotSecret := &corev1.Secret{}
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: secret.Name, Namespace: secret.Namespace}, gotSecret); err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}
	if len(gotSecret.OwnerReferences) != 0 {
		t.Fatalf("secret ownerReferences = %#v, want unchanged empty refs", gotSecret.OwnerReferences)
	}
}

func TestCleanupChildTransactionTokenSecretOnlyDeletesAnnotatedPreparedSecret(t *testing.T) {
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-child-token-secret",
			Namespace: defaultNamespace,
		},
	}
	preparedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prepared-child-token-secret",
			Namespace: defaultNamespace,
		},
	}
	child := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "child-task",
			Namespace: defaultNamespace,
			Annotations: map[string]string{
				labels.AnnotationTransactionTokenSecret: preparedSecret.Name,
			},
		},
	}
	k8sClient := newFakeClient(existingSecret, preparedSecret)

	cleanupChildTaskAfterTokenAdoptionFailure(context.Background(), k8sClient, child)

	gotExisting := &corev1.Secret{}
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: existingSecret.Name, Namespace: existingSecret.Namespace}, gotExisting); err != nil {
		t.Fatalf("existing child transaction token secret was deleted: %v", err)
	}
	gotPrepared := &corev1.Secret{}
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: preparedSecret.Name, Namespace: preparedSecret.Namespace}, gotPrepared); err == nil {
		t.Fatalf("prepared child transaction token secret still exists: %#v", gotPrepared)
	}
}

func TestCleanupChildTaskAfterTokenAdoptionFailureAttemptsSecretCleanupWhenTaskDeleteFails(t *testing.T) {
	forcedErr := errors.New("forced task delete failure")
	child := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "child-task",
			Namespace: defaultNamespace,
			Annotations: map[string]string{
				labels.AnnotationTransactionTokenSecret: "child-token-secret",
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "child-token-secret",
			Namespace: defaultNamespace,
		},
	}
	k8sClient := newFakeClientWithInterceptorFuncs(interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(*corev1alpha1.Task); ok {
				return forcedErr
			}
			return c.Delete(ctx, obj, opts...)
		},
	}, child, secret)

	cleanupChildTaskAfterTokenAdoptionFailure(context.Background(), k8sClient, child)

	gotSecret := &corev1.Secret{}
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: secret.Name, Namespace: secret.Namespace}, gotSecret); err == nil {
		t.Fatalf("expected child transaction token secret to be deleted despite task delete failure")
	}
}

func TestCompleteChildTransactionTokenFailsClosedOnTTSExchangeError(t *testing.T) {
	subjectPath := filepath.Join(t.TempDir(), "subject-token")
	if err := os.WriteFile(subjectPath, []byte("parent-tx-token"), 0600); err != nil {
		t.Fatalf("failed to write subject token: %v", err)
	}
	ttsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporarily_unavailable","error_description":"maintenance"}`))
	}))
	defer ttsServer.Close()

	t.Setenv(workerenv.ContextTokenTTSEndpoint, ttsServer.URL+"/token_endpoint")
	t.Setenv(workerenv.ContextTokenTTSTokenSource, contexttoken.TTSTokenSourceIncoming)
	t.Setenv(workerenv.ContextTokenSubjectTokenFile, subjectPath)
	t.Setenv(workerenv.ContextTokenChildScope, childTransactionScope)

	parent := parentTask()
	child := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "child-task",
			Namespace: defaultNamespace,
			UID:       apitypes.UID("child-uid-1234"),
		},
		Spec: corev1alpha1.TaskSpec{Transaction: parent.Spec.Transaction.DeepCopy()},
	}
	k8sClient := newFakeClient()
	preparation, err := prepareChildTransactionToken(context.Background(), k8sClient, parent, child, "delegateTask", testResearcherAgentName)
	if err != nil {
		t.Fatalf("prepareChildTransactionToken() error = %v", err)
	}
	secretName := requirePreparedChildTransactionToken(t, k8sClient, parent, child)
	err = completeChildTransactionToken(context.Background(), k8sClient, child, preparation)
	if err == nil || !strings.Contains(err.Error(), "exchanging child transaction token") || !strings.Contains(err.Error(), "temporarily_unavailable") {
		t.Fatalf("completeChildTransactionToken() error = %v, want TTS exchange failure", err)
	}
	secret := &corev1.Secret{}
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: secretName, Namespace: defaultNamespace}, secret); err != nil {
		t.Fatalf("get prepared secret after failed exchange: %v", err)
	}
	if len(secret.Data) != 0 {
		t.Fatalf("prepared secret contains token data after failed exchange: %#v", secret.Data)
	}
}

func TestPrepareChildTransactionTokenRejectsScopeExpansion(t *testing.T) {
	subjectPath := filepath.Join(t.TempDir(), "subject-token")
	if err := os.WriteFile(subjectPath, []byte("parent-tx-token"), 0600); err != nil {
		t.Fatalf("failed to write subject token: %v", err)
	}
	ttsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("TTS should not be called when child scope exceeds parent")
	}))
	defer ttsServer.Close()
	t.Setenv(workerenv.ContextTokenTTSEndpoint, ttsServer.URL+"/token_endpoint")
	t.Setenv(workerenv.ContextTokenTTSTokenSource, contexttoken.TTSTokenSourceIncoming)
	t.Setenv(workerenv.ContextTokenSubjectTokenFile, subjectPath)
	t.Setenv(workerenv.ContextTokenChildScope, "orka:admin")

	child := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Namespace: defaultNamespace}}
	_, err := prepareChildTransactionToken(context.Background(), newFakeClient(), parentTask(), child, "delegateTask", testResearcherAgentName)
	if err == nil || !strings.Contains(err.Error(), "not present in parent") {
		t.Fatalf("prepareChildTransactionToken() error = %v, want scope expansion error", err)
	}
}

func TestPrepareChildTransactionTokenDisabledWithoutTTSURL(t *testing.T) {
	child := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Namespace: defaultNamespace}}
	preparation, err := prepareChildTransactionToken(context.Background(), newFakeClient(), parentTask(), child, "delegateTask", testResearcherAgentName)
	if err != nil {
		t.Fatalf("prepareChildTransactionToken() error = %v", err)
	}
	if preparation != nil {
		t.Fatalf("prepareChildTransactionToken() = %#v, want nil when TTS is disabled", preparation)
	}
	if child.Annotations[labels.AnnotationTransactionTokenSecret] != "" {
		t.Fatalf("unexpected transaction token secret annotation: %#v", child.Annotations)
	}
}

func TestPrepareChildTransactionTokenDisabledForNonTransactionalParent(t *testing.T) {
	var called atomic.Bool
	ttsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		http.Error(w, "unexpected TTS call", http.StatusInternalServerError)
	}))
	defer ttsServer.Close()

	t.Setenv(workerenv.ContextTokenTTSEndpoint, ttsServer.URL+"/token_endpoint")
	t.Setenv(workerenv.ContextTokenTTSTokenSource, contexttoken.TTSTokenSourceIncoming)
	t.Setenv(workerenv.ContextTokenChildScope, childTransactionScope)

	parent := parentTask()
	parent.Spec.Transaction = nil
	child := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "child-task",
			Namespace: defaultNamespace,
		},
	}
	k8sClient := newFakeClient()

	preparation, err := prepareChildTransactionToken(context.Background(), k8sClient, parent, child, "delegateTask", testResearcherAgentName)
	if err != nil {
		t.Fatalf("prepareChildTransactionToken() error = %v", err)
	}
	if preparation != nil {
		t.Fatalf("prepareChildTransactionToken() = %#v, want nil for non-transactional parent", preparation)
	}
	if called.Load() {
		t.Fatal("TTS was called for non-transactional parent task")
	}
	if child.Annotations[labels.AnnotationTransactionTokenSecret] != "" {
		t.Fatalf("unexpected child transaction token secret annotation: %#v", child.Annotations)
	}
	secrets := &corev1.SecretList{}
	if err := k8sClient.List(context.Background(), secrets, client.InNamespace(defaultNamespace)); err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}
	if len(secrets.Items) != 0 {
		t.Fatalf("unexpected child transaction token secrets: %#v", secrets.Items)
	}
}

func TestChildTransactionTokenSecretNameExtremeParentNames(t *testing.T) {
	tests := []struct {
		name       string
		parentName string
	}{
		{
			name:       "very long",
			parentName: strings.Repeat("parent-task-name-", 20) + "tail",
		},
		{
			name:       "sixty plus hyphens",
			parentName: strings.Repeat("-", 64),
		},
		{
			name:       "hyphen heavy",
			parentName: "----" + strings.Repeat("parent-", 40) + "----",
		},
		{
			name:       "all hyphen",
			parentName: strings.Repeat("-", 120),
		},
		{
			name:       "invalid chars uppercase unicode",
			parentName: "Parent_Task 日本語 ☃ WITH/slashes.and spaces",
		},
		{
			name:       "mixed long hyphen suffixed",
			parentName: strings.Repeat("Parent_TASK---with.invalid_chars-", 8) + strings.Repeat("-", 24),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := childTransactionTokenSecretName(tt.parentName)
			if err != nil {
				t.Fatalf("childTransactionTokenSecretName(%q) error = %v", tt.parentName, err)
			}
			if got == "" {
				t.Fatalf("childTransactionTokenSecretName(%q) returned an empty name", tt.parentName)
			}
			if len(got) > 63 {
				t.Fatalf("childTransactionTokenSecretName(%q) = %q, length %d > 63", tt.parentName, got, len(got))
			}
			if errs := validation.IsDNS1123Label(got); len(errs) > 0 {
				t.Fatalf("childTransactionTokenSecretName(%q) = %q, not DNS-1123 label: %v", tt.parentName, got, errs)
			}
			if strings.HasPrefix(got, "-") || strings.HasSuffix(got, "-") {
				t.Fatalf("childTransactionTokenSecretName(%q) = %q, has leading or trailing hyphen", tt.parentName, got)
			}
		})
	}
}
