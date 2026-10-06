package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/events"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
)

func remediationAPITask(name, namespace string) *corev1alpha1.Task {
	return &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace,
			Labels:      map[string]string{labels.LabelCreatedBy: remediationpolicy.CreatedBy},
			Annotations: map[string]string{remediationpolicy.RunAnnotation: "example-run"},
		},
		Spec: corev1alpha1.TaskSpec{Type: corev1alpha1.TaskTypeAI, Prompt: "example proposal prompt"},
		Status: corev1alpha1.TaskStatus{
			Phase: corev1alpha1.TaskPhaseSucceeded, ResultRef: &corev1alpha1.ResultReference{Available: true},
		},
	}
}

func allowRemediationTaskFixture(t *testing.T, f *externalAuthorizationFixture) {
	t.Helper()
	f.review = func(review *authorizationv1.SubjectAccessReview) error {
		f.requireIdentity(t, review.Spec)
		review.Status.Allowed = true
		return nil
	}
}

func TestRemediationTaskPrivacyAllPublicTaskReads(t *testing.T) {
	for _, route := range []struct{ method, suffix, body string }{
		{http.MethodGet, "", ""},
		{http.MethodGet, "/result", ""},
		{http.MethodGet, "/logs", ""},
		{http.MethodGet, "/events", ""},
		{http.MethodGet, "/stream", ""},
		{http.MethodGet, "/trace", ""},
		{http.MethodGet, "/plan", ""},
		{http.MethodGet, "/children", ""},
		{http.MethodGet, "/artifacts", ""},
		{http.MethodGet, "/artifacts/example.txt", ""},
		{http.MethodGet, "/approvals", ""},
		{http.MethodPost, "/fork", "{}"},
		{http.MethodDelete, "", ""},
	} {
		t.Run(route.method+route.suffix, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			task := remediationAPITask("proposal-example", "default")
			require.NoError(t, f.kube.Create(t.Context(), task))
			require.NoError(t, f.store.SaveResult(t.Context(), task.Namespace, task.Name, []byte("example proposal result")))
			require.NoError(t, f.store.SavePlan(t.Context(), task.Namespace, task.Name, &store.PlanState{Summary: "example proposal plan"}))
			require.NoError(t, f.store.SaveArtifact(t.Context(), task.Namespace, task.Name, "example.txt", "text/plain", []byte("example proposal artifact")))
			_, err := f.store.AppendExecutionEvent(t.Context(), &store.ExecutionEvent{
				Namespace: task.Namespace, StreamType: store.ExecutionEventStreamTypeTask, StreamID: task.Name,
				TaskName: task.Name, Type: events.ExecutionEventTypeWorkerStarted,
				Severity: events.ExecutionEventSeverityInfo, ContentText: "example proposal event",
			})
			require.NoError(t, err)
			allowRemediationTaskFixture(t, f)
			code, body := f.request(t, route.method, "/api/v1/tasks/"+task.Name+route.suffix, route.body)
			require.Equal(t, http.StatusNotFound, code, body)
			for _, value := range []string{task.Spec.Prompt, "example proposal result", "example proposal plan", "example proposal artifact", "example proposal event"} {
				require.NotContains(t, body, value)
			}
			var unchanged corev1alpha1.Task
			require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(task), &unchanged))
			require.Equal(t, task.Spec.Prompt, unchanged.Spec.Prompt, "native Kubernetes access must remain unchanged")
			result, err := f.store.GetResult(t.Context(), task.Namespace, task.Name)
			require.NoError(t, err)
			require.Equal(t, "example proposal result", string(result))
		})
	}
}

func TestRemediationTaskPrivacySurvivesGateDisableAndPartialMarkers(t *testing.T) {
	for _, marker := range []string{labels.LabelCreatedBy, remediationpolicy.RunLabel, remediationpolicy.RunAnnotation, remediationpolicy.IdentityAnnotation, remediationpolicy.RequestDigestAnnotation} {
		t.Run(marker, func(t *testing.T) {
			f := newExternalAuthorizationFixture(t)
			f.server.handlers.remediationService = nil
			task := remediationAPITask("proposal-example", "default")
			task.Labels, task.Annotations = map[string]string{}, map[string]string{}
			switch marker {
			case labels.LabelCreatedBy:
				task.Labels[marker] = remediationpolicy.CreatedBy
			case remediationpolicy.RunLabel:
				task.Labels[marker] = ""
			default:
				task.Annotations[marker] = ""
			}
			require.NoError(t, f.kube.Create(t.Context(), task))
			allowRemediationTaskFixture(t, f)
			code, body := f.request(t, http.MethodGet, "/api/v1/tasks/"+task.Name, "")
			require.Equal(t, http.StatusNotFound, code, body)
			require.NotContains(t, body, task.Spec.Prompt)
		})
	}
}

func TestRemediationTaskPrivacyFiltersTasksAndChildren(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	parent := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Name: "parent-example", Namespace: "default"}}
	proposal := remediationAPITask("proposal-example", "default")
	ordinary := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Name: "ordinary-example", Namespace: "default"},
		Spec:       corev1alpha1.TaskSpec{Prompt: "example ordinary prompt"},
	}
	for _, task := range []*corev1alpha1.Task{parent, proposal, ordinary} {
		if task != parent {
			if task.Labels == nil {
				task.Labels = map[string]string{}
			}
			task.Labels[labels.LabelParentTask] = labels.SelectorValue(parent.Name)
		}
		require.NoError(t, f.kube.Create(t.Context(), task))
	}
	allowRemediationTaskFixture(t, f)
	for _, path := range []string{"/api/v1/tasks", "/api/v1/tasks/" + parent.Name + "/children"} {
		code, body := f.request(t, http.MethodGet, path, "")
		require.Equal(t, http.StatusOK, code, body)
		require.NotContains(t, body, proposal.Name)
		require.NotContains(t, body, proposal.Spec.Prompt)
		require.Contains(t, body, ordinary.Name)
		require.Contains(t, body, ordinary.Spec.Prompt)
	}
	code, body := f.request(t, http.MethodGet, "/api/v1/tasks/"+ordinary.Name, "")
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, ordinary.Spec.Prompt)
}

func TestRemediationTaskPrivacyOIDCAndContextTokenCannotBypass(t *testing.T) {
	for _, authType := range []string{AuthTypeOIDC, AuthTypeContextToken} {
		t.Run(authType, func(t *testing.T) {
			task := remediationAPITask("proposal-example", "default")
			h, app := setupTestHandlersWithObjects(task)
			app.Use(func(c fiber.Ctx) error {
				c.Locals(UserInfoContextKey, &UserInfo{AuthType: authType, Namespace: "default", Username: "example-user"})
				return c.Next()
			})
			app.Get("/api/v1/tasks/:id", h.GetTask)
			app.Get("/api/v1/tasks/:id/children", h.GetTaskChildren)
			for _, path := range []string{"/api/v1/tasks/proposal-example", "/api/v1/tasks/proposal-example/children"} {
				code, body, _ := validationHTTPRequest(t, app, http.MethodGet, path, "")
				require.Equal(t, http.StatusNotFound, code, body)
				require.NotContains(t, body, task.Spec.Prompt)
			}
		})
	}
}

func TestRemediationTaskPrivacyKeepsPrivateArtifactAuthorization(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	task := remediationAPITask("proposal-example", "default")
	require.NoError(t, f.kube.Create(t.Context(), task))
	for _, allowed := range []bool{false, true} {
		f.review = func(review *authorizationv1.SubjectAccessReview) error {
			attributes := review.Spec.ResourceAttributes
			if attributes.Resource == "remediations" {
				require.Equal(t, "core.orka.ai", attributes.Group)
				require.Equal(t, "default", attributes.Namespace)
				require.Equal(t, "artifacts", attributes.Subresource)
				require.Equal(t, "get", attributes.Verb)
				require.Equal(t, "run-current", attributes.Name)
				review.Status.Allowed = allowed
			} else {
				review.Status.Allowed = true
			}
			return nil
		}
		code, body := f.request(t, http.MethodGet, "/api/v1/tasks/"+task.Name+"/result", "")
		require.Equal(t, http.StatusNotFound, code, body)
		code, body = f.request(t, http.MethodGet, "/api/v1/remediations/run-current/artifacts/evidence.json", "")
		if allowed {
			require.Equal(t, http.StatusOK, code, body)
		} else {
			require.Equal(t, http.StatusForbidden, code, body)
		}
	}
}

func TestRemediationTaskPrivacySessionAggregates(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	proposal := remediationAPITask("proposal-example", "default")
	proposal.Spec.SessionRef = &corev1alpha1.SessionReference{Name: "a-associated-session"}
	require.NoError(t, f.kube.Create(t.Context(), proposal))
	for _, session := range []*store.SessionRecord{
		{Namespace: "default", Name: "a-associated-session", SessionType: "task", Messages: []store.SessionMessage{{Role: "user", Content: "example associated message"}}},
		{Namespace: "default", Name: "b-active-session", SessionType: "task", ActiveTask: proposal.Name, Messages: []store.SessionMessage{{Role: "user", Content: "example active message"}}},
		{Namespace: "default", Name: "c-ordinary-session", SessionType: "task", Messages: []store.SessionMessage{{Role: "user", Content: "example ordinary message"}}},
		{Namespace: "default", Name: "d-ordinary-session", SessionType: "task"},
	} {
		require.NoError(t, f.store.CreateSession(t.Context(), session))
		if len(session.Messages) > 0 {
			require.NoError(t, f.store.AppendMessages(t.Context(), session.Namespace, session.Name, session.Messages))
		}
	}
	allowRemediationTaskFixture(t, f)
	for _, path := range []string{
		"/api/v1/sessions/a-associated-session", "/api/v1/sessions/a-associated-session/events",
		"/api/v1/sessions/a-associated-session/stream", "/api/v1/sessions/b-active-session",
	} {
		code, body := f.request(t, http.MethodGet, path, "")
		require.Equal(t, http.StatusNotFound, code, body)
		require.NotContains(t, body, "example associated message")
		require.NotContains(t, body, "example active message")
	}
	code, body := f.request(t, http.MethodGet, "/api/v1/sessions?limit=1", "")
	require.Equal(t, http.StatusOK, code, body)
	require.NotContains(t, body, "a-associated-session")
	require.NotContains(t, body, "b-active-session")
	require.Contains(t, body, "c-ordinary-session")
	var page struct {
		Metadata ListMeta `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &page))
	require.Equal(t, "c-ordinary-session", page.Metadata.Continue, "cursor must not name a hidden Session")
	code, body = f.request(t, http.MethodGet, "/api/v1/sessions?limit=1&continue="+page.Metadata.Continue, "")
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, "d-ordinary-session")
	code, body = f.request(t, http.MethodGet, "/api/v1/sessions/c-ordinary-session", "")
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, "example ordinary message")
}

func TestRemediationTaskPrivacySessionEventProvenance(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	proposal := remediationAPITask("proposal-example", "default")
	require.NoError(t, f.kube.Create(t.Context(), proposal))
	require.NoError(t, f.store.CreateSession(t.Context(), &store.SessionRecord{Namespace: "default", Name: "example-session", SessionType: "task"}))
	_, err := f.store.AppendExecutionEvent(t.Context(), &store.ExecutionEvent{
		Namespace: "default", StreamType: store.ExecutionEventStreamTypeTask, StreamID: proposal.Name,
		TaskName: proposal.Name, SessionName: "example-session",
		Type: events.ExecutionEventTypeWorkerStarted, Severity: events.ExecutionEventSeverityInfo,
		ContentText: "example aggregated event",
	})
	require.NoError(t, err)
	allowRemediationTaskFixture(t, f)
	code, body := f.request(t, http.MethodGet, "/api/v1/sessions/example-session/events", "")
	require.Equal(t, http.StatusNotFound, code, body)
	require.NotContains(t, body, "example aggregated event")
}

func TestRemediationTaskPrivacySessionVisibilityFailsClosed(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	require.NoError(t, f.store.CreateSession(t.Context(), &store.SessionRecord{Namespace: "default", Name: "example-session", SessionType: "task"}))
	f.server.handlers.apiReader = interceptor.NewClient(f.kube.(client.WithWatch), interceptor.Funcs{
		List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
			return errors.New("example internal detail")
		},
	})
	allowRemediationTaskFixture(t, f)
	for _, path := range []string{"/api/v1/sessions", "/api/v1/sessions/example-session", "/api/v1/sessions/example-session/events"} {
		code, body := f.request(t, http.MethodGet, path, "")
		require.Equal(t, http.StatusServiceUnavailable, code, body)
		require.NotContains(t, body, "example internal detail")
	}
}

func TestRemediationTaskPrivacySessionNamespaceIsExact(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	proposal := remediationAPITask("proposal-example", "other")
	proposal.Spec.SessionRef = &corev1alpha1.SessionReference{Name: "example-session"}
	require.NoError(t, f.kube.Create(t.Context(), proposal))
	require.NoError(t, f.store.CreateSession(t.Context(), &store.SessionRecord{
		Namespace: "default", Name: "example-session", SessionType: "task",
	}))
	require.NoError(t, f.store.AppendMessages(t.Context(), "default", "example-session", []store.SessionMessage{{Role: "user", Content: "example message"}}))
	allowRemediationTaskFixture(t, f)
	code, body := f.request(t, http.MethodGet, "/api/v1/sessions/example-session", "")
	require.Equal(t, http.StatusOK, code, body)
	require.Contains(t, body, "example message")
}

func TestRemediationTaskPrivacyAPIToolsAndResultReader(t *testing.T) {
	clientset, _ := externalToolReviews(t, func(authorizationv1.SubjectAccessReviewSpec) (runtime.Object, error) {
		return externalToolReview(true), nil
	})
	proposal := remediationAPITask("proposal-example", externalToolNamespace)
	executor, backend, results, _ := newExternalToolExecutor(clientset, proposal,
		&corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{Name: "ordinary-example", Namespace: externalToolNamespace}},
	)
	for _, tool := range []string{"check_task_progress", "fetch_task_output", "cancel_task"} {
		result := executeExternalTool(t, executor, tool, `{"name":"proposal-example","namespace":"tool-target"}`)
		require.False(t, result.Success)
		raw, err := json.Marshal(result)
		require.NoError(t, err)
		require.NotContains(t, string(raw), proposal.Spec.Prompt)
	}
	result := executeExternalTool(t, executor, "list_tasks", `{"namespace":"tool-target"}`)
	require.True(t, result.Success)
	raw, err := json.Marshal(result.Data)
	require.NoError(t, err)
	require.NotContains(t, string(raw), proposal.Name)
	require.Contains(t, string(raw), "ordinary-example")
	require.Zero(t, backend.writes)
	require.Zero(t, results.reads)

	authorized := newExternalToolClient(backend, clientset, externalToolUser(), externalToolNamespace, "", false, nil)
	var task corev1alpha1.Task
	err = authorized.Get(t.Context(), client.ObjectKeyFromObject(proposal), &task)
	require.True(t, apierrors.IsNotFound(err))
	require.Empty(t, task.Spec.Prompt)
}
