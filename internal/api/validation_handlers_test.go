package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

type validationServiceCall struct {
	operation, namespace, id, identity, digest string
	request                                    pv.Request
}

type validationServiceStub struct {
	calls                           []validationServiceCall
	submission, linked              *pv.KubernetesSubmission
	record                          *pv.Record
	blob                            []byte
	submitErr, getErr, linkedErr    error
	cancelErr, evidenceErr, blobErr error
	onSubmit                        func(pv.Request) error
	onLinked, onCancel              func()
}

func newValidationServiceStub() *validationServiceStub {
	return &validationServiceStub{
		submission: &pv.KubernetesSubmission{
			Namespace: "default", RequestID: "request-current", RunID: "run-current",
			Manifest: pv.Manifest{Action: pv.ValidateReport}, State: pv.SubmissionRunning,
			RequiredChecks: 6, RecordedChecks: 2,
			Assessment: &pv.Assessment{Conclusion: pv.UnableToValidate, Reason: "checks remain"},
		},
		linked: &pv.KubernetesSubmission{
			Namespace: "default", RequestID: "request-earlier", RunID: "run-earlier",
		},
		record: &pv.Record{
			Binding: pv.Binding{RunID: "run-current"}, State: pv.RunFinalized,
			Assessment: pv.Assessment{Conclusion: pv.Reproduced},
		},
		blob: []byte("protected evidence"),
	}
}

func (s *validationServiceStub) SubmitRequest(_ context.Context, namespace, identity string, request pv.Request) (*pv.KubernetesSubmission, error) {
	s.calls = append(s.calls, validationServiceCall{operation: "submit", namespace: namespace, identity: identity, request: request})
	if s.onSubmit != nil {
		if err := s.onSubmit(request); err != nil {
			return nil, err
		}
	}
	return s.submission, s.submitErr
}

func (s *validationServiceStub) GetSubmission(_ context.Context, namespace, id string) (*pv.KubernetesSubmission, error) {
	s.calls = append(s.calls, validationServiceCall{operation: "get", namespace: namespace, id: id})
	return s.submission, s.getErr
}

func (s *validationServiceStub) LinkedValidation(_ context.Context, namespace, id string) (*pv.KubernetesSubmission, error) {
	s.calls = append(s.calls, validationServiceCall{operation: "linked", namespace: namespace, id: id})
	if s.onLinked != nil {
		s.onLinked()
	}
	return s.linked, s.linkedErr
}

func (s *validationServiceStub) Cancel(_ context.Context, namespace, id string) error {
	s.calls = append(s.calls, validationServiceCall{operation: "cancel", namespace: namespace, id: id})
	if s.cancelErr != nil {
		return s.cancelErr
	}
	if s.onCancel != nil {
		s.onCancel()
	} else if s.submission.State != pv.SubmissionTerminal {
		s.submission.State = pv.SubmissionCancelling
	}
	return nil
}

func (s *validationServiceStub) Evidence(_ context.Context, namespace, id string) (*pv.Record, error) {
	s.calls = append(s.calls, validationServiceCall{operation: "evidence", namespace: namespace, id: id})
	return s.record, s.evidenceErr
}

func (s *validationServiceStub) EvidenceBlob(_ context.Context, namespace, id, digest string) ([]byte, error) {
	s.calls = append(s.calls, validationServiceCall{operation: "blob", namespace: namespace, id: id, digest: digest})
	return s.blob, s.blobErr
}

func (s *validationServiceStub) operations() []string {
	operations := make([]string, len(s.calls))
	for i, call := range s.calls {
		operations[i] = call.operation
	}
	return operations
}

func validationRequestJSON() string {
	return `{"action":"validate-report","problem":"parser rejects input","scope":["parser"],` +
		`"repository":"repos/example","originalCommit":"` + strings.Repeat("1", 40) + `",` +
		`"checksDir":"checks/repro","checks":[{"id":"repro","kind":"reproduction",` +
		`"command":["./repro"],"healthy":{"exitCode":0,"stdout":"ok"},"failure":{"exitCode":1,"stdout":"bad"},"timeoutSeconds":5}]}`
}

func linkedValidationRequestJSON(fields string) string {
	return `{"action":"verify-patch","earlierValidation":"run-earlier","patchedCommit":"` + strings.Repeat("2", 40) + `",` +
		`"declaredChanges":[{"kind":"source","description":"Fix parser","paths":["parser.go"]}]` + fields + `}`
}

type validationRouteCase struct {
	method, path, body string
	permission         authorizationv1.ResourceAttributes
	status             int
	operations         []string
}

func validationRouteCases() []validationRouteCase {
	return []validationRouteCase{
		{http.MethodPost, "/api/v1/validations", validationRequestJSON(),
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "validations", Verb: "create"},
			http.StatusAccepted, []string{"submit"}},
		{http.MethodGet, "/api/v1/validations/request-current", "",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "validations", Verb: "get", Name: "request-current"},
			http.StatusOK, []string{"get"}},
		{http.MethodGet, "/api/v1/validations/request-current/evidence", "",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "validations", Subresource: "evidence", Verb: "get", Name: "request-current"},
			http.StatusOK, []string{"evidence"}},
		{http.MethodGet, "/api/v1/validations/request-current/evidence/" + pv.Digest([]byte("protected evidence")), "",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "validations", Subresource: "evidence", Verb: "get", Name: "request-current"},
			http.StatusOK, []string{"blob"}},
		{http.MethodPost, "/api/v1/validations/request-current/cancel", "",
			authorizationv1.ResourceAttributes{Namespace: "default", Group: "core.orka.ai", Resource: "validations", Subresource: "cancel", Verb: "update", Name: "request-current"},
			http.StatusAccepted, []string{"cancel", "get"}},
	}
}

func validationUserInfo() *UserInfo {
	return &UserInfo{
		AuthType: AuthTypeTokenReview, Username: "system:serviceaccount:default:viewer",
		UID: "viewer-uid", Namespace: "default", Groups: []string{"system:authenticated"},
	}
}

func validationHandlerApp(h *Handlers, user *UserInfo, middleware ...fiber.Handler) *fiber.App {
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		if user != nil {
			c.Locals(UserInfoContextKey, user)
		}
		return c.Next()
	})
	for _, handler := range middleware {
		app.Use(handler)
	}
	app.Post("/api/v1/validations", h.CreateValidation)
	app.Get("/api/v1/validations/:id", h.GetValidation)
	app.Get("/api/v1/validations/:id/evidence", h.GetValidationEvidence)
	app.Get("/api/v1/validations/:id/evidence/:digest", h.GetValidationEvidenceBlob)
	app.Post("/api/v1/validations/:id/cancel", h.CancelValidation)
	return app
}

func validationHTTPRequest(t *testing.T, app *fiber.App, method, path, body string) (int, string, http.Header) {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request)
	require.NoError(t, err)
	defer response.Body.Close() //nolint:errcheck
	content, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.StatusCode, string(content), response.Header
}

func TestExternalAPIValidationAuthorization(t *testing.T) {
	for _, route := range validationRouteCases() {
		t.Run(route.method+route.path, func(t *testing.T) {
			for _, decision := range []string{"allowed", "denied", "evaluation-error", "review-error", "explicit-denied", "missing-client", "typed-nil-client"} {
				t.Run(decision, func(t *testing.T) {
					f := newExternalAuthorizationFixture(t)
					service := newValidationServiceStub()
					f.server.handlers.validationService = service
					switch decision {
					case "missing-client":
						f.server.handlers.clientset = nil
					case "typed-nil-client":
						var missing *kubernetes.Clientset
						f.server.handlers.clientset = missing
					}
					f.review = func(review *authorizationv1.SubjectAccessReview) error {
						review.Status.Allowed = decision != "denied"
						switch decision {
						case "evaluation-error":
							review.Status.EvaluationError = "authorizer unavailable"
						case "review-error":
							return errors.New("review transport unavailable")
						case "explicit-denied":
							review.Status.Denied = true
						}
						return nil
					}
					status, body := f.request(t, route.method, route.path, route.body)
					require.Equal(t, 1, f.tokenReviews)
					require.Zero(t, f.kubeCalls)
					if decision == "allowed" {
						require.Equal(t, route.status, status, body)
						require.Equal(t, route.operations, service.operations())
						require.Len(t, f.reviews, 2, "route and handler must both authorize their exact resource")
						for _, call := range service.calls {
							require.Equal(t, "default", call.namespace)
							if call.operation == "submit" {
								require.Equal(t, f.user.Username, call.identity)
							} else {
								require.Equal(t, "request-current", call.id)
							}
						}
					} else {
						require.Equal(t, http.StatusForbidden, status, body)
						require.Empty(t, service.calls, "authorization must precede service access")
						require.NotContains(t, body, "protected evidence")
						if decision == "missing-client" || decision == "typed-nil-client" {
							require.Empty(t, f.reviews)
						} else {
							require.Len(t, f.reviews, 1)
						}
					}
					for _, review := range f.reviews {
						f.requireIdentity(t, review)
						require.Equal(t, route.permission, *review.ResourceAttributes)
					}
				})
			}
		})
	}
}

func TestValidationHandlerAuthorizationWithoutRouteMiddleware(t *testing.T) {
	for _, route := range validationRouteCases() {
		for _, missingClient := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s%s/missing-client=%t", route.method, route.path, missingClient), func(t *testing.T) {
				f := newExternalAuthorizationFixture(t)
				service := newValidationServiceStub()
				f.server.handlers.validationService = service
				if missingClient {
					f.server.handlers.clientset = nil
				}
				app := validationHandlerApp(f.server.handlers, validationUserInfo())
				status, body, _ := validationHTTPRequest(t, app, route.method, route.path, route.body)
				require.Equal(t, http.StatusForbidden, status, body)
				require.Empty(t, service.calls)
				if missingClient {
					require.Empty(t, f.reviews)
				} else {
					require.Len(t, f.reviews, 1)
					require.Equal(t, route.permission, *f.reviews[0].ResourceAttributes)
				}
			})
		}
	}
}

func TestValidationRequiresTokenReviewIdentity(t *testing.T) {
	for _, route := range validationRouteCases() {
		t.Run(route.method+route.path, func(t *testing.T) {
			for _, identity := range []string{"anonymous", AuthTypeOIDC, AuthTypeContextToken, "", "unknown", "missing-username", "subject-only", "blank-username"} {
				t.Run(identity, func(t *testing.T) {
					f := newExternalAuthorizationFixture(t)
					service := newValidationServiceStub()
					f.server.handlers.validationService = service
					user := validationUserInfo()
					want := http.StatusForbidden
					switch identity {
					case "anonymous":
						user = nil
						want = http.StatusUnauthorized
					case "missing-username":
						user.Username = ""
					case "subject-only":
						user.Username, user.Subject = "", "not-a-TokenReview-username"
					case "blank-username":
						user.Username = " \t "
					default:
						user.AuthType = identity
					}
					app := validationHandlerApp(f.server.handlers, user)
					status, body, _ := validationHTTPRequest(t, app, route.method, route.path, route.body)
					require.Equal(t, want, status, body)
					require.Empty(t, service.calls)
					require.Empty(t, f.reviews)
				})
			}
		})
	}
}

func TestExternalAPIValidationRejectsOIDCAndContextTokens(t *testing.T) {
	provider := newTestOIDCProvider(t)
	for _, identity := range []string{AuthTypeOIDC, AuthTypeContextToken} {
		for _, route := range validationRouteCases() {
			t.Run(identity+"/"+route.method+route.path, func(t *testing.T) {
				f := newExternalAuthorizationFixture(t)
				service := newValidationServiceStub()
				cfg := ServerConfig{
					WatchNamespace: "default", EnforceNamespaceIsolation: true,
					Clientset: f.clientset, ValidationService: service,
				}
				header := "Authorization"
				var credential string
				if identity == AuthTypeOIDC {
					cfg.OIDC = provider.config()
					credential = "Bearer " + provider.issueToken(t, testOIDCTokenOptions{Namespace: "default"})
				} else {
					cfg.ContextTokens = testContextTokenConfig(t, provider, "")
					header = TransactionTokenHeaderName
					credential = issueTestContextToken(t, provider, nil, map[string]any{
						"scope": ContextTokenScopeTaskCreate, "tctx": map[string]any{"namespace": "default"},
					})
				}
				server := NewServer(f.kube, nil, cfg)
				request := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set(header, credential)
				response, err := server.app.Test(request)
				require.NoError(t, err)
				defer response.Body.Close() //nolint:errcheck
				require.Equal(t, http.StatusForbidden, response.StatusCode)
				require.Zero(t, f.tokenReviews)
				require.Empty(t, f.reviews)
				require.Empty(t, service.calls)
			})
		}
	}
}

func TestValidationNamespaceResolution(t *testing.T) {
	for _, route := range validationRouteCases() {
		for _, tc := range []struct {
			name, watch, identityNamespace, query, namespace string
			isolation                                        bool
		}{
			{"watch-default", "default", "default", "", "default", true},
			{"watch-explicit", "default", "default", "default", "default", true},
			{"watch-mismatch", "default", "default", "other", "", false},
			{"identity-default", "", "team-a", "", "team-a", true},
			{"explicit", "", "default", "team-a", "team-a", false},
			{"fallback", "", "", "", "default", false},
			{"isolation-mismatch", "", "default", "team-a", "", true},
			{"identity-without-namespace", "default", "", "", "", true},
			{"padded", "", "default", "%20default%20", "", false},
			{"blank", "", "default", "%20", "", false},
			{"uppercase", "", "default", "Default", "", false},
			{"path", "", "default", "..%2Fdefault", "", false},
		} {
			t.Run(route.method+route.path+"/"+tc.name, func(t *testing.T) {
				f := newExternalAuthorizationFixture(t)
				service := newValidationServiceStub()
				h := f.server.handlers
				h.validationService, h.watchNamespace, h.enforceNamespaceIsolation = service, tc.watch, tc.isolation
				f.review = func(review *authorizationv1.SubjectAccessReview) error {
					review.Status.Allowed = true
					return nil
				}
				user := validationUserInfo()
				user.Namespace = tc.identityNamespace
				app := validationHandlerApp(h, user)
				status, body, _ := validationHTTPRequest(t, app, route.method, route.path+"?namespace="+tc.query, route.body)
				if tc.namespace == "" {
					require.Equal(t, http.StatusForbidden, status, body)
					require.Empty(t, service.calls)
					require.Empty(t, f.reviews)
					return
				}
				require.Equal(t, route.status, status, body)
				require.Len(t, f.reviews, 1)
				require.Equal(t, tc.namespace, f.reviews[0].ResourceAttributes.Namespace)
				for _, call := range service.calls {
					require.Equal(t, tc.namespace, call.namespace)
				}
			})
		}
	}
}

func TestValidationDisabledService(t *testing.T) {
	for _, route := range validationRouteCases() {
		for _, typedNil := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s%s/typed-nil=%t", route.method, route.path, typedNil), func(t *testing.T) {
				f := newExternalAuthorizationFixture(t)
				if typedNil {
					var service *validationServiceStub
					f.server.handlers.validationService = service
				}
				app := validationHandlerApp(f.server.handlers, validationUserInfo())
				status, body, _ := validationHTTPRequest(t, app, route.method, route.path, route.body)
				require.Equal(t, http.StatusNotFound, status, body)
				require.Contains(t, body, "validation API is disabled")
				require.Empty(t, f.reviews)
			})
		}
	}
}

func TestValidationCreateStrictJSON(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"empty", "", http.StatusBadRequest},
		{"truncated", `{"action":`, http.StatusBadRequest},
		{"null", `null`, http.StatusBadRequest},
		{"array", `[]`, http.StatusBadRequest},
		{"trailing", validationRequestJSON() + `{}`, http.StatusBadRequest},
		{"unknown", strings.Replace(validationRequestJSON(), `"scope":`, `"unknown":true,"scope":`, 1), http.StatusBadRequest},
		{"duplicate", strings.Replace(validationRequestJSON(), `"problem":`, `"problem":"first","problem":`, 1), http.StatusBadRequest},
		{"case-duplicate", strings.Replace(validationRequestJSON(), `"problem":`, `"Problem":"first","problem":`, 1), http.StatusBadRequest},
		{"nested-duplicate", strings.Replace(validationRequestJSON(), `"exitCode":0`, `"exitCode":1,"exitCode":0`, 1), http.StatusBadRequest},
		{"nested-unknown", strings.Replace(validationRequestJSON(), `"exitCode":0`, `"extra":true,"exitCode":0`, 1), http.StatusBadRequest},
		{"invalid-type", strings.Replace(validationRequestJSON(), `"scope":["parser"]`, `"scope":"parser"`, 1), http.StatusBadRequest},
		{"invalid-utf8", strings.Replace(validationRequestJSON(), "parser rejects input", string([]byte{0xff}), 1), http.StatusBadRequest},
		{"oversized", strings.Repeat(" ", (1<<20)+1), http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newValidationServiceStub()
			f.server.handlers.validationService = service
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				review.Status.Allowed = true
				return nil
			}
			status, body := f.request(t, http.MethodPost, "/api/v1/validations", tc.body)
			require.Equal(t, tc.status, status, body)
			require.Less(t, len(body), 256)
			require.Empty(t, service.calls)
		})
	}
}

func TestValidationCreatePreservesPathsAndFieldPresence(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newValidationServiceStub()
	f.server.handlers.validationService = service
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		review.Status.Allowed = true
		return nil
	}
	body := strings.Replace(validationRequestJSON(), `"action":"validate-report"`, `"patchFile":"patches/fix.diff"`, 1)
	body = strings.Replace(body, `"problem":`, `"variables":null,"gaps":[],"problem":`, 1)
	status, result := f.request(t, http.MethodPost, "/api/v1/validations?namespace=default", body)
	require.Equal(t, http.StatusAccepted, status, result)
	require.Len(t, service.calls, 1)
	call := service.calls[0]
	require.Equal(t, f.user.Username, call.identity)
	require.Equal(t, "default", call.namespace)
	require.Equal(t, "repos/example", call.request.Repository)
	require.Equal(t, "checks/repro", call.request.ChecksDir)
	require.Equal(t, "patches/fix.diff", call.request.PatchFile)
	require.Equal(t, map[string]bool{
		"problem": true, "scope": true, "repository": true, "originalCommit": true,
		"patchFile": true, "checksDir": true, "checks": true, "variables": true, "gaps": true,
	}, call.request.ProvidedFields)
	require.Nil(t, call.request.Variables)
	require.NotNil(t, call.request.Gaps)
}

func TestExternalAPIValidationLinkedEvidenceAuthorization(t *testing.T) {
	for _, decision := range []string{"allowed", "denied", "evaluation-error", "review-error", "explicit-denied", "run-id-only", "missing-client", "typed-nil-client"} {
		t.Run(decision, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newValidationServiceStub()
			f.server.handlers.validationService = service
			service.onLinked = func() {
				require.Len(t, f.reviews, 2, "creation must be authorized before looking up a link")
				switch decision {
				case "missing-client":
					f.server.handlers.clientset = nil
				case "typed-nil-client":
					var missing *kubernetes.Clientset
					f.server.handlers.clientset = missing
				}
			}
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				f.requireIdentity(t, review.Spec)
				attributes := review.Spec.ResourceAttributes
				require.Equal(t, "core.orka.ai", attributes.Group)
				require.Equal(t, "validations", attributes.Resource)
				require.Equal(t, "default", attributes.Namespace)
				review.Status.Allowed = true
				if attributes.Subresource == "" {
					require.Equal(t, "create", attributes.Verb)
					require.Empty(t, attributes.Name)
					return nil
				}
				require.Equal(t, "get", attributes.Verb)
				require.Equal(t, "evidence", attributes.Subresource)
				require.Equal(t, service.linked.RequestID, attributes.Name, "authorize the submission, not the caller-supplied run ID")
				require.Equal(t, []string{"linked"}, service.operations(), "evidence cannot be consumed before the named grant")
				switch decision {
				case "denied":
					review.Status.Allowed = false
				case "evaluation-error":
					review.Status.EvaluationError = "authorizer unavailable"
				case "review-error":
					return errors.New("authorization unavailable")
				case "explicit-denied":
					review.Status.Denied = true
				case "run-id-only":
					review.Status.Allowed = attributes.Name == service.linked.RunID
				}
				return nil
			}
			service.onSubmit = func(request pv.Request) error {
				require.Len(t, f.reviews, 3)
				require.Equal(t, "run-earlier", request.EarlierValidation)
				return nil
			}
			status, body := f.request(t, http.MethodPost, "/api/v1/validations", linkedValidationRequestJSON(""))
			require.Equal(t, 1, f.tokenReviews)
			require.Equal(t, "default", service.calls[0].namespace)
			require.Equal(t, "run-earlier", service.calls[0].id)
			if decision == "allowed" {
				require.Equal(t, http.StatusAccepted, status, body)
				require.Equal(t, []string{"linked", "submit"}, service.operations())
			} else {
				require.Equal(t, http.StatusForbidden, status, body)
				require.Equal(t, []string{"linked"}, service.operations())
			}
			if decision == "missing-client" || decision == "typed-nil-client" {
				require.Len(t, f.reviews, 2)
			} else {
				require.Len(t, f.reviews, 3)
			}
		})
	}
}

func TestValidationLinkedCreateDeniedBeforeLookup(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newValidationServiceStub()
	f.server.handlers.validationService = service
	status, body := f.request(t, http.MethodPost, "/api/v1/validations", linkedValidationRequestJSON(""))
	require.Equal(t, http.StatusForbidden, status, body)
	require.Empty(t, service.calls)
	require.Len(t, f.reviews, 1)
	require.Equal(t, "create", f.reviews[0].ResourceAttributes.Verb)
	require.Equal(t, "validations", f.reviews[0].ResourceAttributes.Resource)
}

func TestValidationLinkedLookupFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*validationServiceStub)
		status int
	}{
		{"missing", func(s *validationServiceStub) { s.linkedErr = fmt.Errorf("lookup: %w", pv.ErrRunNotFound) }, http.StatusNotFound},
		{"lookup-error", func(s *validationServiceStub) { s.linkedErr = errors.New("private lookup error") }, http.StatusInternalServerError},
		{"nil", func(s *validationServiceStub) { s.linked = nil }, http.StatusNotFound},
		{"cross-namespace", func(s *validationServiceStub) { s.linked.Namespace = "other-tenant" }, http.StatusNotFound},
		{"mismatched-run", func(s *validationServiceStub) { s.linked.RunID = "another-run" }, http.StatusNotFound},
		{"missing-request-id", func(s *validationServiceStub) { s.linked.RequestID = "" }, http.StatusNotFound},
		{"padded-request-id", func(s *validationServiceStub) { s.linked.RequestID = " request-earlier " }, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newValidationServiceStub()
			tc.change(service)
			f.server.handlers.validationService = service
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				require.Equal(t, "create", review.Spec.ResourceAttributes.Verb)
				require.Empty(t, review.Spec.ResourceAttributes.Subresource)
				review.Status.Allowed = true
				return nil
			}
			status, body := f.request(t, http.MethodPost, "/api/v1/validations", linkedValidationRequestJSON(""))
			require.Equal(t, tc.status, status, body)
			require.Equal(t, []string{"linked"}, service.operations())
			require.Equal(t, "default", service.calls[0].namespace)
			require.Equal(t, "run-earlier", service.calls[0].id)
			require.NotContains(t, body, "private lookup error")
			require.NotContains(t, body, "other-tenant")
		})
	}
}

func TestValidationLinkedFrozenFieldsRemainEnforced(t *testing.T) {
	for _, fields := range []string{
		`,"problem":"changed"`,
		`,"scope":[]`,
		`,"checks":[]`,
		`,"variables":null`,
		`,"gaps":[]`,
		`,"originalCommit":""`,
		`,"OriginalCommit":""`,
		`,"Variables":null`,
		`,"Scope":null`,
	} {
		t.Run(fields, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newValidationServiceStub()
			service.linked.Manifest = pv.Manifest{
				Problem: "frozen problem", Scope: []string{"parser"}, Gaps: []string{"known gap"},
				Sources:     pv.Sources{Original: pv.SourceIdentity{Commit: strings.Repeat("1", 40)}},
				Environment: pv.Environment{Variables: map[string]string{"MODE": "frozen"}},
				Checks:      []pv.Check{{ID: "repro"}},
			}
			service.onSubmit = func(request pv.Request) error {
				require.Equal(t, "evidence", f.reviews[len(f.reviews)-1].ResourceAttributes.Subresource)
				return pv.MatchLinkedRequest(request, service.linked.Manifest)
			}
			f.server.handlers.validationService = service
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				review.Status.Allowed = true
				return nil
			}
			status, body := f.request(t, http.MethodPost, "/api/v1/validations", linkedValidationRequestJSON(fields))
			require.Contains(t, []int{http.StatusBadRequest, http.StatusUnprocessableEntity}, status, body)
			if status == http.StatusBadRequest {
				require.Empty(t, service.calls, "noncanonical JSON fields must be rejected before consuming a link")
				return
			}
			require.Contains(t, body, string(pv.UnableToVerify))
			require.Equal(t, []string{"linked", "submit"}, service.operations())
			require.NotContains(t, body, "frozen problem")
		})
	}
}

func TestValidationProjectsServiceResults(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newValidationServiceStub()
	f.server.handlers.validationService = service
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		review.Status.Allowed = true
		return nil
	}
	app := validationHandlerApp(f.server.handlers, validationUserInfo())
	for _, tc := range []struct {
		path string
		want any
	}{
		{"/api/v1/validations/request-current", service.submission},
		{"/api/v1/validations/request-current/evidence", service.record},
	} {
		status, body, _ := validationHTTPRequest(t, app, http.MethodGet, tc.path, "")
		require.Equal(t, http.StatusOK, status, body)
		expected, err := json.Marshal(tc.want)
		require.NoError(t, err)
		require.JSONEq(t, string(expected), body)
	}
	digest := pv.Digest(service.blob)
	status, body, header := validationHTTPRequest(t, app, http.MethodGet, "/api/v1/validations/request-current/evidence/"+digest, "")
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, string(service.blob), body)
	require.Equal(t, fiber.MIMEOctetStream, header.Get(fiber.HeaderContentType))
	require.Equal(t, digest, service.calls[len(service.calls)-1].digest)
}

func TestValidationCancelReturnsActualSubmission(t *testing.T) {
	for _, state := range []pv.SubmissionState{pv.SubmissionPreparing, pv.SubmissionRunning, pv.SubmissionCancelling, pv.SubmissionTerminal} {
		t.Run(string(state), func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newValidationServiceStub()
			service.submission.State = state
			f.server.handlers.validationService = service
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				require.Equal(t, "update", review.Spec.ResourceAttributes.Verb)
				require.Equal(t, "cancel", review.Spec.ResourceAttributes.Subresource)
				review.Status.Allowed = true
				return nil
			}
			status, body := f.request(t, http.MethodPost, "/api/v1/validations/request-current/cancel", "")
			require.Equal(t, http.StatusAccepted, status, body)
			require.Equal(t, []string{"cancel", "get"}, service.operations())
			wantState := pv.SubmissionCancelling
			if state == pv.SubmissionTerminal {
				wantState = state
			}
			var actual pv.KubernetesSubmission
			require.NoError(t, json.Unmarshal([]byte(body), &actual))
			require.Equal(t, wantState, actual.State)
			require.Equal(t, *service.submission, actual)
		})
	}
}

func TestValidationCancelReadFailureDoesNotInventState(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newValidationServiceStub()
	service.getErr = errors.New("private store read failure")
	f.server.handlers.validationService = service
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		review.Status.Allowed = true
		return nil
	}
	status, body := f.request(t, http.MethodPost, "/api/v1/validations/request-current/cancel", "")
	require.Equal(t, http.StatusInternalServerError, status, body)
	require.Equal(t, []string{"cancel", "get"}, service.operations())
	require.NotContains(t, body, "cancelling")
	require.NotContains(t, body, "private store")
}

func TestValidationCancelReturnsConcurrentCompletion(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newValidationServiceStub()
	service.onCancel = func() {
		service.submission.State = pv.SubmissionTerminal
		service.submission.RecordedChecks = service.submission.RequiredChecks
		service.submission.Assessment = &pv.Assessment{Conclusion: pv.Reproduced}
	}
	f.server.handlers.validationService = service
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		review.Status.Allowed = true
		return nil
	}
	status, body := f.request(t, http.MethodPost, "/api/v1/validations/request-current/cancel", "")
	require.Equal(t, http.StatusAccepted, status, body)
	var actual pv.KubernetesSubmission
	require.NoError(t, json.Unmarshal([]byte(body), &actual))
	require.Equal(t, *service.submission, actual)
	require.Equal(t, pv.SubmissionTerminal, actual.State)
	require.Equal(t, []string{"cancel", "get"}, service.operations())
}

func TestValidationOperationErrors(t *testing.T) {
	for _, route := range validationRouteCases()[1:] {
		for _, tc := range []struct {
			name   string
			err    error
			status int
		}{
			{"not-found", fmt.Errorf("private lookup: %w", pv.ErrRunNotFound), http.StatusNotFound},
			{"closed", fmt.Errorf("private lookup: %w", pv.ErrClosed), http.StatusConflict},
			{"unavailable", errors.New("private store failure"), http.StatusInternalServerError},
		} {
			t.Run(route.method+route.path+"/"+tc.name, func(t *testing.T) {
				f := newExternalAuthorizationFixture(t)
				service := newValidationServiceStub()
				service.getErr, service.cancelErr, service.evidenceErr, service.blobErr = tc.err, tc.err, tc.err, tc.err
				f.server.handlers.validationService = service
				f.review = func(review *authorizationv1.SubjectAccessReview) error {
					review.Status.Allowed = true
					return nil
				}
				status, body := f.request(t, route.method, route.path, "")
				require.Equal(t, tc.status, status, body)
				require.Less(t, len(body), 256)
				require.NotContains(t, body, "private")
				require.Equal(t, route.operations[:1], service.operations())
			})
		}
	}
}

func TestValidationCreateSanitizesErrorsAndLogs(t *testing.T) {
	for _, action := range []pv.Action{pv.ValidateReport, pv.VerifyPatch, ""} {
		t.Run(string(action), func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newValidationServiceStub()
			service.submitErr = errors.New("private repository /private/input/repository contains private problem text")
			f.server.handlers.validationService = service
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				review.Status.Allowed = true
				return nil
			}
			var logs bytes.Buffer
			logger := funcr.NewJSON(func(entry string) { logs.WriteString(entry) }, funcr.Options{})
			app := validationHandlerApp(f.server.handlers, validationUserInfo(), func(c fiber.Ctx) error {
				c.SetContext(logf.IntoContext(c.Context(), logger))
				return c.Next()
			})
			body := strings.Replace(validationRequestJSON(), "parser rejects input", "private problem text", 1)
			if action != pv.ValidateReport {
				body = strings.Replace(body, `"action":"validate-report"`,
					`"action":"`+string(action)+`","patchFile":"/private/input/patch","declaredChanges":[{"kind":"source","description":"Fix parser"}]`, 1)
			}
			status, result, _ := validationHTTPRequest(t, app, http.MethodPost, "/api/v1/validations", body)
			require.Equal(t, http.StatusUnprocessableEntity, status, result)
			require.Equal(t, string(pv.UnavailableAction(action)), result)
			require.Contains(t, logs.String(), `"namespace":"default"`)
			require.Contains(t, logs.String(), `"action":"`+string(pv.ActionOrDefault(action))+`"`)
			require.Contains(t, logs.String(), `"stage":"preparation"`)
			for _, sensitive := range []string{"private repository", "/private/input", "private problem text", "repos/example", "checks/repro"} {
				require.NotContains(t, result, sensitive)
				require.NotContains(t, logs.String(), sensitive)
			}
		})
	}
}

func TestValidationCreateDoesNotLogUnrecognizedAction(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newValidationServiceStub()
	f.server.handlers.validationService = service
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		review.Status.Allowed = true
		return nil
	}
	var logs bytes.Buffer
	logger := funcr.NewJSON(func(entry string) { logs.WriteString(entry) }, funcr.Options{})
	app := validationHandlerApp(f.server.handlers, validationUserInfo(), func(c fiber.Ctx) error {
		c.SetContext(logf.IntoContext(c.Context(), logger))
		return c.Next()
	})
	untrustedAction := strings.Repeat("private-content/", 100)
	body := strings.Replace(validationRequestJSON(), "validate-report", untrustedAction, 1)
	status, result, _ := validationHTTPRequest(t, app, http.MethodPost, "/api/v1/validations", body)
	require.Equal(t, http.StatusBadRequest, status, result)
	require.Contains(t, logs.String(), `"action":"invalid"`)
	require.Contains(t, logs.String(), `"stage":"decoding"`)
	require.NotContains(t, logs.String(), untrustedAction)
	require.NotContains(t, result, untrustedAction)
	require.Empty(t, service.calls)
}
