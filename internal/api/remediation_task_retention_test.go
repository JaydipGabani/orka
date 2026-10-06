package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemediationTaskPrivacySurvivesObjectDeletion(t *testing.T) {
	f := newExternalAuthorizationFixture(t)
	task := remediationAPITask("rm-"+strings.Repeat("a", 32)+"-checks", "default")
	require.NoError(t, f.kube.Create(t.Context(), task))
	require.NoError(t, f.store.SaveResult(t.Context(), task.Namespace, task.Name, []byte("private retained result")))
	require.NoError(t, f.kube.Delete(t.Context(), task))
	require.Error(t, f.server.handlers.checkRemediationTaskPublicAccess(t.Context(), task.Namespace, task.Name),
		"removing a proposal Task must not expose its retained result or events")
	require.NoError(t, f.server.handlers.checkRemediationTaskPublicAccess(t.Context(), task.Namespace, "ordinary-deleted-task"),
		"ordinary missing Task behavior is unchanged")
}
