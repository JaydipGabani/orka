package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/kubernetes"

	remediationservice "github.com/orka-agents/orka/internal/remediation/service"
	"github.com/orka-agents/orka/internal/store"
)

type remediationServiceCall struct {
	operation, namespace, id, actor, name, digest string
	request                                       remediationservice.Request
	revision                                      uint64
	limit                                         int
}

type remediationServiceStub struct {
	calls     []remediationServiceCall
	status    remediationservice.Status
	artifact  *store.RemediationArtifact
	content   []byte
	err       error
	policyErr error
	page      remediationservice.RunList
	drain     remediationservice.DrainStatus
}

func newRemediationServiceStub() *remediationServiceStub {
	content := []byte(`{"conclusion":"unverified synthetic evidence"}`)
	artifact := &store.RemediationArtifact{
		Name: "evidence.json", Digest: remediationservice.Digest(content),
		Size: int64(len(content)), MediaType: "application/json",
	}
	return &remediationServiceStub{
		status: remediationservice.Status{
			ID: "run-current", Namespace: "default", RequestID: "request-current",
			Mode: remediationservice.Generate, Policy: "approved", Phase: store.RemediationPhaseQueued,
			Revision: 1, Artifacts: []store.RemediationArtifact{*artifact},
		},
		content: content, artifact: artifact,
		page:  remediationservice.RunList{Items: []remediationservice.RunSummary{}},
		drain: remediationservice.DrainStatus{Namespace: "default", Complete: true, IntakeDrained: true},
	}
}

func (s *remediationServiceStub) PolicyName(namespace, name string) (string, error) {
	s.calls = append(s.calls, remediationServiceCall{operation: "policy", namespace: namespace, name: name})
	if name == "" {
		name = "approved"
	}
	return name, s.policyErr
}

func (s *remediationServiceStub) Submit(_ context.Context, namespace, actor string, request remediationservice.Request) (remediationservice.Status, bool, error) {
	s.calls = append(s.calls, remediationServiceCall{operation: "submit", namespace: namespace, actor: actor, request: request})
	return s.status, true, s.err
}

func (s *remediationServiceStub) Get(_ context.Context, namespace, id string) (remediationservice.Status, error) {
	s.calls = append(s.calls, remediationServiceCall{operation: "get", namespace: namespace, id: id})
	return s.status, s.err
}

func (s *remediationServiceStub) Cancel(_ context.Context, namespace, id string) (remediationservice.Status, error) {
	s.calls = append(s.calls, remediationServiceCall{operation: "cancel", namespace: namespace, id: id})
	return s.status, s.err
}

func (s *remediationServiceStub) Approve(_ context.Context, namespace, id, digest, actor string) (remediationservice.Status, error) {
	s.calls = append(s.calls, remediationServiceCall{operation: "approve", namespace: namespace, id: id, digest: digest, actor: actor})
	return s.status, s.err
}

func (s *remediationServiceStub) Artifact(_ context.Context, namespace, id, name string) (*store.RemediationArtifact, []byte, error) {
	s.calls = append(s.calls, remediationServiceCall{operation: "artifact", namespace: namespace, id: id, name: name})
	return s.artifact, s.content, s.err
}

func (s *remediationServiceStub) List(_ context.Context, namespace string, limit int, before string) (remediationservice.RunList, error) {
	s.calls = append(s.calls, remediationServiceCall{operation: "list", namespace: namespace, name: before, limit: limit})
	return s.page, s.err
}

func (s *remediationServiceStub) DrainNamespace(_ context.Context, namespace string) (remediationservice.DrainStatus, error) {
	s.calls = append(s.calls, remediationServiceCall{operation: "drain", namespace: namespace})
	return s.drain, s.err
}

func (s *remediationServiceStub) ReconcileCleanup(_ context.Context, namespace, id, actor string, revision uint64) (remediationservice.Status, error) {
	s.calls = append(s.calls, remediationServiceCall{operation: "reconcile", namespace: namespace, id: id, actor: actor, revision: revision})
	return s.status, s.err
}

type remediationRouteCase struct {
	method, path, body, operation string
	permission                    authorizationv1.ResourceAttributes
	code                          int
}

func remediationRouteCases() []remediationRouteCase {
	return []remediationRouteCase{
		{http.MethodPost, "/api/v1/remediations", `{"requestID":"request-current","incident":"123456"}`, "submit",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "remediations", Verb: "create"}, http.StatusAccepted},
		{http.MethodGet, "/api/v1/remediations/run-current", "", "get",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "remediations", Verb: "get", Name: "run-current"}, http.StatusOK},
		{http.MethodGet, "/api/v1/remediations", "", "list",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "remediations", Verb: "list"}, http.StatusOK},
		{http.MethodGet, "/api/v1/remediations/drain", "", "drain",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "remediations", Subresource: "drain", Verb: "get"}, http.StatusOK},
		{http.MethodPost, "/api/v1/remediations/run-current/reconcile", `{"expectedRevision":8}`, "reconcile",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "remediations", Subresource: "reconcile", Verb: "update", Name: "run-current"}, http.StatusAccepted},
		{http.MethodPost, "/api/v1/remediations/run-current/approve", `{"planDigest":"sha256:` + strings.Repeat("a", 64) + `"}`, "approve",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "remediations", Subresource: "approve", Verb: "update", Name: "run-current"}, http.StatusAccepted},
		{http.MethodPost, "/api/v1/remediations/run-current/cancel", "", "cancel",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "remediations", Subresource: "cancel", Verb: "update", Name: "run-current"}, http.StatusAccepted},
		{http.MethodGet, "/api/v1/remediations/run-current/artifacts/evidence.json", "", "artifact",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "remediations", Subresource: "artifacts", Verb: "get", Name: "run-current"}, http.StatusOK},
	}
}

func remediationPolicyPermission(name string) authorizationv1.ResourceAttributes {
	return authorizationv1.ResourceAttributes{
		Namespace: "default", Group: "core.orka.ai", Resource: "remediationpolicies", Verb: "use", Name: name,
	}
}

func TestRemediationExternalAPIAuthorization(t *testing.T) {
	for _, route := range remediationRouteCases() {
		t.Run(route.method+route.path, func(t *testing.T) {
			for _, decision := range []string{"allowed", "denied", "review-error", "evaluation-error", "explicit-denied", "missing-client", "typed-nil-client"} {
				t.Run(decision, func(t *testing.T) {
					f := newExternalAuthorizationFixture(t)
					service := newRemediationServiceStub()
					f.server.handlers.remediationService = service
					if decision == "missing-client" {
						f.server.handlers.clientset = nil
					}
					if decision == "typed-nil-client" {
						var missing *kubernetes.Clientset
						f.server.handlers.clientset = missing
					}
					f.review = func(review *authorizationv1.SubjectAccessReview) error {
						f.requireIdentity(t, review.Spec)
						if review.Spec.ResourceAttributes.Resource == "remediationpolicies" {
							require.Equal(t, remediationPolicyPermission("approved"), *review.Spec.ResourceAttributes)
						} else {
							require.Equal(t, route.permission, *review.Spec.ResourceAttributes)
						}
						switch decision {
						case "allowed":
							review.Status.Allowed = true
						case "review-error":
							return errors.New("private authorizer detail")
						case "evaluation-error":
							review.Status.Allowed, review.Status.EvaluationError = true, "private authorizer detail"
						case "explicit-denied":
							review.Status.Allowed, review.Status.Denied = true, true
						}
						return nil
					}
					code, body := f.request(t, route.method, route.path, route.body)
					require.NotContains(t, body, "private authorizer detail")
					if decision != "allowed" {
						require.Equal(t, http.StatusForbidden, code, body)
						require.Empty(t, service.calls)
						return
					}
					require.Equal(t, route.code, code, body)
					require.NotEmpty(t, service.calls)
					call := service.calls[len(service.calls)-1]
					require.Equal(t, route.operation, call.operation)
					require.Equal(t, "default", call.namespace)
					if route.operation == "submit" {
						require.Equal(t, f.user.Username, call.actor)
						require.Equal(t, "approved", call.request.Policy)
						require.Equal(t, "request-current", call.request.RequestID)
						require.Equal(t, remediationservice.Generate, call.request.Mode)
						require.Len(t, f.reviews, 3)
					} else {
						require.Equal(t, route.permission.Name, call.id)
						require.Len(t, f.reviews, 2)
						if route.operation == "reconcile" {
							require.Equal(t, f.user.Username, call.actor)
							require.EqualValues(t, 8, call.revision)
						}
					}
				})
			}
		})
	}
}

func TestRemediationRequiresNamedPolicyUseBeforeSubmission(t *testing.T) {
	for _, supplied := range []bool{false, true} {
		t.Run(fmt.Sprintf("supplied=%t", supplied), func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newRemediationServiceStub()
			f.server.handlers.remediationService = service
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				review.Status.Allowed = review.Spec.ResourceAttributes.Resource == "remediations"
				return nil
			}
			body := `{"requestID":"request-current","incident":"123456"}`
			name := "approved"
			if supplied {
				body = `{"requestID":"request-current","incident":"123456","policy":"chosen"}`
				name = "chosen"
			}
			code, content := f.request(t, http.MethodPost, "/api/v1/remediations", body)
			require.Equal(t, http.StatusForbidden, code, content)
			require.Len(t, service.calls, 1)
			require.Equal(t, "policy", service.calls[0].operation)
			require.Equal(t, remediationPolicyPermission(name), *f.reviews[len(f.reviews)-1].ResourceAttributes)
		})
	}
}

func TestRemediationDisabledAndAnonymous(t *testing.T) {
	for _, route := range remediationRouteCases() {
		for _, state := range []string{"disabled", "typed-nil", "enabled"} {
			t.Run(route.path+"/"+state, func(t *testing.T) {
				f := newExternalAuthorizationFixture(t)
				switch state {
				case "disabled":
					f.server.handlers.remediationService = nil
				case "typed-nil":
					var service *remediationservice.Service
					f.server.handlers.remediationService = service
				}
				code, body, _ := validationHTTPRequest(t, f.server.app, route.method, route.path, route.body)
				want := http.StatusNotFound
				if state == "enabled" {
					want = http.StatusUnauthorized
				}
				require.Equal(t, want, code, body)
				require.Empty(t, f.reviews)
				require.Zero(t, f.tokenReviews)

				f.allowOnly(t, authorizationv1.ResourceAttributes{
					Namespace: "default", Group: "core.orka.ai", Resource: "tasks", Verb: "list",
				})
				code, body = f.request(t, http.MethodGet, "/api/v1/tasks", "")
				require.Equal(t, http.StatusOK, code, body)
			})
		}
	}
}

func TestRemediationRejectsNonTokenReviewAuthentication(t *testing.T) {
	provider := newTestOIDCProvider(t)
	for _, identity := range []string{AuthTypeOIDC, AuthTypeContextToken} {
		for _, route := range remediationRouteCases() {
			t.Run(identity+"/"+route.path, func(t *testing.T) {
				f := newExternalAuthorizationFixture(t)
				service := newRemediationServiceStub()
				config := ServerConfig{
					WatchNamespace: "default", EnforceNamespaceIsolation: true,
					Clientset: f.clientset, RemediationService: service,
				}
				header := "Authorization"
				var credential string
				if identity == AuthTypeOIDC {
					config.OIDC = provider.config()
					credential = "Bearer " + provider.issueToken(t, testOIDCTokenOptions{Namespace: "default"})
				} else {
					config.ContextTokens = testContextTokenConfig(t, provider, "")
					header = TransactionTokenHeaderName
					credential = issueTestContextToken(t, provider, nil, map[string]any{
						"scope": ContextTokenScopeTaskCreate, "tctx": map[string]any{"namespace": "default"},
					})
				}
				server := NewServer(f.kube, nil, config)
				request := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set(header, credential)
				response, err := server.app.Test(request)
				require.NoError(t, err)
				require.NoError(t, response.Body.Close())
				require.Equal(t, http.StatusForbidden, response.StatusCode)
				require.Empty(t, f.reviews)
				require.Empty(t, service.calls)
			})
		}
	}
}

func TestRemediationCrossNamespaceDenied(t *testing.T) {
	for _, route := range remediationRouteCases() {
		for _, namespace := range []string{"other", "%20default%20", "Default", "..%2Fdefault"} {
			t.Run(route.path+"/"+namespace, func(t *testing.T) {
				f := newExternalAuthorizationFixture(t)
				service := newRemediationServiceStub()
				f.server.handlers.remediationService = service
				code, body := f.request(t, route.method, route.path+"?namespace="+namespace, route.body)
				require.Equal(t, http.StatusForbidden, code, body)
				require.Empty(t, service.calls)
				require.Empty(t, f.reviews)
			})
		}
	}
}

func TestRemediationStrictRequestAndSafeErrors(t *testing.T) {
	for name, body := range map[string]string{
		"unknown":       `{"requestID":"request-current","incident":"123456","agent":"private-sentinel"}`,
		"host-path":     `{"requestID":"request-current","incident":"123456","workDir":"/private-sentinel"}`,
		"model":         `{"requestID":"request-current","incident":"123456","model":"private-sentinel"}`,
		"duplicate":     `{"requestID":"request-current","incident":"123456","incident":"private-sentinel"}`,
		"case-alias":    `{"requestID":"request-current","incident":"123456","Incident":"private-sentinel"}`,
		"malformed":     `{"requestID":"private-sentinel"`,
		"null":          `null`,
		"extra-value":   `{"requestID":"request-current","incident":"123456"} {"private-sentinel":1}`,
		"two-inputs":    `{"requestID":"request-current","incident":"123456","report":{"title":"private-sentinel"}}`,
		"missing-patch": `{"requestID":"request-current","incident":"123456","mode":"verify"}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newRemediationServiceStub()
			f.server.handlers.remediationService = service
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				review.Status.Allowed = true
				return nil
			}
			code, content := f.request(t, http.MethodPost, "/api/v1/remediations", body)
			require.Equal(t, http.StatusBadRequest, code, content)
			require.NotContains(t, content, "private-sentinel")
			require.Empty(t, service.calls)
		})
	}
}

func TestRemediationRetryableAdmissionFailureIsRedactedServiceUnavailable(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newRemediationServiceStub()
	service.err = errors.Join(remediationservice.ErrRetryable, errors.New("private-upstream-marker"))
	f.server.handlers.remediationService = service
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		review.Status.Allowed = true
		return nil
	}
	code, content := f.request(t, http.MethodPost, "/api/v1/remediations",
		`{"requestID":"request-current","incident":"123456"}`)
	require.Equal(t, http.StatusServiceUnavailable, code, content)
	require.NotContains(t, content, "private-upstream-marker")
	require.Equal(t, "submit", service.calls[len(service.calls)-1].operation)
}

func TestRemediationBodyLimit(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newRemediationServiceStub()
	f.server.handlers.remediationService = service
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		review.Status.Allowed = true
		return nil
	}
	valid := `{"requestID":"request-current","incident":"123456"}`
	atLimit := valid + strings.Repeat(" ", remediationservice.MaxRequestBytes-len(valid))
	code, content := f.request(t, http.MethodPost, "/api/v1/remediations", atLimit)
	require.Equal(t, http.StatusAccepted, code, content)
	service.calls = nil
	code, content = f.request(t, http.MethodPost, "/api/v1/remediations", atLimit+" ")
	require.Equal(t, http.StatusRequestEntityTooLarge, code, content)
	require.Empty(t, service.calls)
}

func TestRemediationRejectsEncodedBodyBeforeDecoding(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newRemediationServiceStub()
	f.server.handlers.remediationService = service
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		review.Status.Allowed = true
		return nil
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/remediations", strings.NewReader(strings.Repeat("private-sentinel", 1024)))
	request.Header.Set("Authorization", "Bearer synthetic-encoded-fixture")
	request.Header.Set("Content-Encoding", "gzip")
	response, err := f.server.app.Test(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	require.Empty(t, service.calls)
}

func TestRemediationApprovalStrictDigest(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `{"planDigest":"bad"}`,
		`{"planDigest":"sha256:` + strings.Repeat("a", 64) + `","planDigest":"private-sentinel"}`,
		`{"planDigest":"sha256:` + strings.Repeat("a", 64) + `","extra":"private-sentinel"}`,
		`{"planDigest":"sha256:` + strings.Repeat("a", 64) + `"} null`,
	} {
		f := newExternalAuthorizationFixture(t)
		service := newRemediationServiceStub()
		f.server.handlers.remediationService = service
		f.review = func(review *authorizationv1.SubjectAccessReview) error {
			review.Status.Allowed = true
			return nil
		}
		code, content := f.request(t, http.MethodPost, "/api/v1/remediations/run-current/approve", body)
		require.Equal(t, http.StatusBadRequest, code, content)
		require.NotContains(t, content, "private-sentinel")
		require.Empty(t, service.calls)
	}
}

func TestRemediationArtifactResponse(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newRemediationServiceStub()
	service.artifact.MediaType = "text/html"
	f.server.handlers.remediationService = service
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		review.Status.Allowed = true
		return nil
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/remediations/run-current/artifacts/evidence.json", nil)
	request.Header.Set("Authorization", "Bearer synthetic-artifact-fixture")
	response, err := f.server.app.Test(request)
	require.NoError(t, err)
	defer response.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "private, no-store", response.Header.Get("Cache-Control"))
	require.Equal(t, "application/octet-stream", response.Header.Get("Content-Type"))
	require.Equal(t, "attachment; filename=evidence.json", response.Header.Get("Content-Disposition"))
	require.Equal(t, "nosniff", response.Header.Get("X-Content-Type-Options"))
	digest := sha256.Sum256(service.content)
	require.Equal(t, "sha-256="+base64.StdEncoding.EncodeToString(digest[:]), response.Header.Get("Digest"))
	require.Equal(t, `"`+service.artifact.Digest+`"`, response.Header.Get("ETag"))
}

func TestRemediationArtifactRejectsUnsafeNamesAndCorruption(t *testing.T) {
	for _, name := range []string{".", "..", "%2e%2e%2fsecret", "bad%0d%0aheader", strings.Repeat("a", 257)} {
		t.Run(name, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newRemediationServiceStub()
			f.server.handlers.remediationService = service
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				review.Status.Allowed = true
				return nil
			}
			code, _ := f.request(t, http.MethodGet, "/api/v1/remediations/run-current/artifacts/"+name, "")
			require.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, code)
			require.Empty(t, service.calls)
		})
	}
	for _, corruption := range []string{"nil", "name", "digest", "size"} {
		t.Run(corruption, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newRemediationServiceStub()
			f.server.handlers.remediationService = service
			switch corruption {
			case "nil":
				service.artifact = nil
			case "name":
				service.artifact.Name = "another.json"
			case "digest":
				service.artifact.Digest = remediationservice.Digest([]byte("other"))
			case "size":
				service.artifact.Size++
			}
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				review.Status.Allowed = true
				return nil
			}
			code, body := f.request(t, http.MethodGet, "/api/v1/remediations/run-current/artifacts/evidence.json", "")
			require.Equal(t, http.StatusInternalServerError, code)
			require.NotContains(t, body, string(service.content))
		})
	}
}

func TestRemediationSafeServiceErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{store.ErrNotFound, http.StatusNotFound},
		{store.ErrConflict, http.StatusConflict},
		{store.ErrDuplicateMismatch, http.StatusConflict},
		{store.ErrCapacity, http.StatusTooManyRequests},
		{store.ValidationErrorf("private-sentinel"), http.StatusBadRequest},
		{remediationservice.ErrApproval, http.StatusConflict},
		{remediationservice.ErrIntakeConnectorUnavailable, http.StatusNotImplemented},
		{remediationservice.ErrPolicy, http.StatusForbidden},
		{errors.New("private-sentinel"), http.StatusInternalServerError},
	} {
		f := newExternalAuthorizationFixture(t)
		service := newRemediationServiceStub()
		service.err = fmt.Errorf("private-sentinel: %w", tc.err)
		f.server.handlers.remediationService = service
		f.review = func(review *authorizationv1.SubjectAccessReview) error {
			review.Status.Allowed = true
			return nil
		}
		code, body := f.request(t, http.MethodGet, "/api/v1/remediations/run-current", "")
		require.Equal(t, tc.code, code, body)
		require.NotContains(t, body, "private-sentinel")
	}
}

func TestRemediationHandlerCannotBypassTokenReviewOrSAR(t *testing.T) {
	for _, user := range []*UserInfo{nil, {AuthType: AuthTypeOIDC}, {AuthType: AuthTypeTokenReview}, validationUserInfo()} {
		service := newRemediationServiceStub()
		h := NewHandlers(HandlersConfig{WatchNamespace: "default", RemediationService: service})
		app := fiber.New()
		app.Use(func(c fiber.Ctx) error {
			c.Locals(UserInfoContextKey, user)
			return c.Next()
		})
		app.Get("/api/v1/remediations/:id", h.GetRemediation)
		code, _, _ := validationHTTPRequest(t, app, http.MethodGet, "/api/v1/remediations/run-current", "")
		if user == nil {
			require.Equal(t, http.StatusUnauthorized, code)
		} else {
			require.Equal(t, http.StatusForbidden, code)
		}
		require.Empty(t, service.calls)
	}
}
