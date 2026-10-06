package controllerlab

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func beforeObserverMaterial(t *testing.T, l *testLab, r Request) State {
	t.Helper()
	return l.until(t, State{}, r, func(s State) bool {
		objects := phaseObjects(s)
		return s.Phase == Preparing && s.Cursor < len(objects) &&
			sameRef(objects[s.Cursor], ref(secrets, s.ObserverNamespace, adminSecretName))
	})
}

func TestObserverAuthorizationQueriesBindActualServiceAccountAndAllSecretReads(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := beforeObserverMaterial(t, l, r)
	account := receiptFor(s, ref(serviceAccounts, s.Namespaces[0], controllerName))
	require.NotNil(t, account)
	count := 0
	secretQueries := map[string]bool{}
	l.kube.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		review := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		require.Equal(t, "system:serviceaccount:"+s.Namespaces[0]+":"+controllerName, review.Spec.User)
		require.Equal(t, string(account.Object.UID), review.Spec.UID)
		require.Equal(t, []string{"system:serviceaccounts", "system:serviceaccounts:" + s.Namespaces[0], "system:authenticated"}, review.Spec.Groups)
		attrs := review.Spec.ResourceAttributes
		require.NotNil(t, attrs)
		if attrs.Resource == "secrets" {
			require.Equal(t, s.ObserverNamespace, attrs.Namespace)
			require.NotContains(t, s.Namespaces, attrs.Namespace)
			secretQueries[attrs.Verb+"/"+attrs.Name] = true
		}
		count++
		review.Status.Denied = true
		return true, review, nil
	})
	var err error
	s, err = l.step(s, r)
	require.NoError(t, err)
	require.Equal(t, len(observerDeniedAccess(s)), count)
	require.Equal(t, map[string]bool{
		"get/" + adminSecretName: true, "list/": true, "list/" + adminSecretName: true,
		"watch/": true, "watch/" + adminSecretName: true,
	}, secretQueries)
	require.NotNil(t, receiptFor(s, ref(secrets, s.ObserverNamespace, adminSecretName)))
	r.Cancel = true
	_ = l.until(t, s, r, State.Terminal)
}

func TestObserverMaterialAndSubjectAreNotCreatedWhenEffectiveBoundaryAllowsAccess(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		resource    string
		subresource string
		verb        string
		objectName  string
	}{
		{"secret-get", "secrets", "", "get", adminSecretName},
		{"secret-list", "secrets", "", "list", ""},
		{"named-secret-list", "secrets", "", "list", adminSecretName},
		{"secret-watch", "secrets", "", "watch", ""},
		{"named-secret-watch", "secrets", "", "watch", adminSecretName},
		{"pod-create", "pods", "", "create", ""},
		{"observer-image-patch", "pods", "", "patch", serviceName},
		{"observer-exec", "pods", "exec", "create", serviceName},
		{"observer-websocket-exec", "pods", "exec", "get", serviceName},
		{"observer-ephemeral-container", "pods", "ephemeralcontainers", "update", serviceName},
		{"deployment-create", "deployments", "", "create", ""},
		{"job-create", "jobs", "", "create", ""},
		{"rolebinding-create", "rolebindings", "", "create", ""},
		{"clusterrolebinding-create", "clusterrolebindings", "", "create", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			r := l.request(Candidate)
			s := beforeObserverMaterial(t, l, r)
			l.kube.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
				review := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
				attrs := review.Spec.ResourceAttributes
				review.Status.Allowed = attrs.Resource == tc.resource && attrs.Subresource == tc.subresource &&
					attrs.Verb == tc.verb && attrs.Name == tc.objectName
				review.Status.Denied = !review.Status.Allowed
				return true, review, nil
			})
			s, err := l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Inconclusive, s.Outcome)
			require.Equal(t, Cleaning, s.Phase)
			_, err = l.kube.CoreV1().Secrets(s.ObserverNamespace).Get(context.Background(), adminSecretName, metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err))
			_, err = l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err))
			s = l.until(t, s, r, State.Terminal)
			require.Equal(t, Complete, s.Phase)
			require.Equal(t, Inconclusive, s.Outcome)
		})
	}
}

func TestUnavailableOrMismatchedAuthorizationNeverMeansDenied(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"unreachable", "evaluation-error", "mismatched-user", "mismatched-namespace", "missing-response"} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			r := l.request(Candidate)
			s := beforeObserverMaterial(t, l, r)
			l.kube.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
				review := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
				review.Status.Denied = true
				switch variant {
				case "unreachable":
					return true, nil, errors.New("authorization transport unavailable")
				case "evaluation-error":
					review.Status.EvaluationError = "untrusted diagnostic"
				case "mismatched-user":
					review.Spec.User = "system:anonymous"
				case "mismatched-namespace":
					review.Spec.ResourceAttributes.Namespace = s.Namespaces[0]
				case "missing-response":
					return true, nil, nil
				}
				return true, review, nil
			})
			s, err := l.step(s, r)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "untrusted diagnostic")
			require.Equal(t, Inconclusive, s.Outcome)
			require.Nil(t, receiptFor(s, ref(secrets, s.ObserverNamespace, adminSecretName)))
		})
	}
}

func TestInheritedSecretGrantAfterStartupInvalidatesObservation(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingWindow)
	require.Equal(t, [2]bool{true, true}, s.Evidence.InitialNormal)
	l.kube.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		review := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		review.Status.Allowed = true
		return true, review, nil
	})
	s, err := l.step(s, r)
	require.Error(t, err)
	require.Equal(t, Inconclusive, s.Outcome)
	require.Equal(t, Cleaning, s.Phase)
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Complete, s.Phase)
	require.NotEqual(t, Protected, s.Outcome)
}

func TestObserverBoundaryIsRecheckedImmediatelyBeforeSubjectLaunch(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.until(t, State{}, r, func(s State) bool {
		objects := phaseObjects(s)
		return s.Phase == InstallingController && s.Placement != nil && s.Cursor < len(objects) &&
			sameRef(objects[s.Cursor], ref(deployments, s.Namespaces[0], controllerName))
	})
	require.NotNil(t, receiptFor(s, ref(secrets, s.ObserverNamespace, adminSecretName)))
	l.kube.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		review := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		review.Status.Allowed = true
		return true, review, nil
	})
	s, err := l.step(s, r)
	require.Error(t, err)
	require.Equal(t, Inconclusive, s.Outcome)
	_, err = l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Complete, s.Phase)
}
