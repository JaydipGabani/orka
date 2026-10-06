package api

import (
	"context"
	"net/http"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestDisabledRemediationDoesNotListTasksForSessionReads(t *testing.T) {
	fixture := newExternalAuthorizationFixture(t)
	fixture.server.handlers.remediationService = nil
	taskLists := 0
	fixture.server.handlers.apiReader = interceptor.NewClient(fixture.kube.(client.WithWatch), interceptor.Funcs{
		List: func(ctx context.Context, delegate client.WithWatch, list client.ObjectList, options ...client.ListOption) error {
			if _, tasks := list.(*corev1alpha1.TaskList); tasks {
				taskLists++
			}
			return delegate.List(ctx, list, options...)
		},
	})
	require.NoError(t, fixture.store.CreateSession(t.Context(), &store.SessionRecord{
		Namespace: "default", Name: "ordinary-session", SessionType: "task",
	}))
	allowRemediationTaskFixture(t, fixture)
	code, body := fixture.request(t, http.MethodGet, "/api/v1/sessions/ordinary-session", "")
	require.Equal(t, http.StatusOK, code, body)
	require.Zero(t, taskLists, "ordinary installations must not scan Task history for the disabled experiment")
}
