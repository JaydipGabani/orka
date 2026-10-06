package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"

	remediationservice "github.com/orka-agents/orka/internal/remediation/service"
	"github.com/orka-agents/orka/internal/store"
)

func TestRemediationCleanupReconcileStrictRevision(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `{"expectedRevision":0}`, `{"expectedRevision":-1}`, `{"expectedRevision":1.5}`,
		`{"expectedRevision":"8"}`, `{"expectedRevision":9223372036854775807}`,
		`{"expectedRevision":8,"expectedRevision":9}`, `{"ExpectedRevision":8}`,
		`{"expectedRevision":8,"state":{"private-sentinel":true}}`, `{"expectedRevision":8} null`,
	} {
		t.Run(body, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newRemediationServiceStub()
			f.server.handlers.remediationService = service
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				review.Status.Allowed = true
				return nil
			}
			code, content := f.request(t, http.MethodPost, "/api/v1/remediations/run-current/reconcile", body)
			require.Equal(t, http.StatusBadRequest, code, content)
			require.Empty(t, service.calls)
			require.NotContains(t, content, "private-sentinel")
		})
	}
}

func TestRemediationOperatorDoesNotBorrowReadPermission(t *testing.T) {
	for _, route := range remediationRouteCases() {
		if route.operation != "reconcile" && route.operation != "drain" && route.operation != "list" {
			continue
		}
		t.Run(route.operation, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			service := newRemediationServiceStub()
			f.server.handlers.remediationService = service
			f.review = func(review *authorizationv1.SubjectAccessReview) error {
				permission := review.Spec.ResourceAttributes
				review.Status.Allowed = permission.Resource == "remediations" && permission.Subresource == "" && permission.Verb == "get"
				return nil
			}
			code, body := f.request(t, route.method, route.path, route.body)
			require.Equal(t, http.StatusForbidden, code, body)
			require.Empty(t, service.calls)
		})
	}
}

func TestRemediationMetadataPaginationAndIntegrity(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	service := newRemediationServiceStub()
	f.server.handlers.remediationService = service
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		review.Status.Allowed = true
		return nil
	}
	for _, query := range []string{"limit=0", "limit=-1", "limit=101", "limit=nan", "continue=..%2Fprivate-sentinel"} {
		code, body := f.request(t, http.MethodGet, "/api/v1/remediations?"+query, "")
		require.Equal(t, http.StatusBadRequest, code, body)
		require.NotContains(t, body, "private-sentinel")
		require.Empty(t, service.calls)
	}
	service.page = remediationservice.RunList{Items: []remediationservice.RunSummary{
		{ID: "run-current", Namespace: "default", Phase: store.RemediationPhaseCancelling, Revision: 8},
	}, Continue: "run-current"}
	code, body := f.request(t, http.MethodGet, "/api/v1/remediations?limit=1&continue=older-run", "")
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, "older-run", service.calls[0].name)
	require.Equal(t, 1, service.calls[0].limit)
	for _, private := range []string{"report", "requestJson", "policyJson", "stateJson", "artifacts", "submittedBy"} {
		require.NotContains(t, body, private)
	}
	service.page.Items[0].Namespace = "foreign"
	code, body = f.request(t, http.MethodGet, "/api/v1/remediations", "")
	require.Equal(t, http.StatusInternalServerError, code, body)
	require.NotContains(t, body, "foreign")
	service.page.Items[0].Namespace, service.page.Continue = "default", "wrong-run"
	code, _ = f.request(t, http.MethodGet, "/api/v1/remediations", "")
	require.Equal(t, http.StatusInternalServerError, code)

	service.err = store.ErrConflict
	code, body = f.request(t, http.MethodPost, "/api/v1/remediations/run-current/reconcile", `{"expectedRevision":8}`)
	require.Equal(t, http.StatusConflict, code, body)
	require.NotContains(t, strings.ToLower(body), "force")
}
