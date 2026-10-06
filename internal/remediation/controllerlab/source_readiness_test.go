package controllerlab

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func persistSourceCondition(t *testing.T, l *testLab, s State, status string) {
	t.Helper()
	for _, source := range sourceObjects(s) {
		if source.Resource != cloudEventSources && source.Resource != clusterEventSources {
			continue
		}
		raw, err := l.custom.Tracker().Get(source.Resource, source.Namespace, source.Name)
		require.NoError(t, err)
		object := raw.(*unstructured.Unstructured)
		require.NoError(t, unstructured.SetNestedSlice(object.Object, []any{
			map[string]any{"type": "Active", "status": status},
		}, "status", "conditions"))
		object.SetResourceVersion("source-status-" + status)
		require.NoError(t, l.custom.Tracker().Update(source.Resource, object, source.Namespace))
	}
}

func requireNoInitialFixtures(t *testing.T, l *testLab, s State) {
	t.Helper()
	for _, fixture := range fixtureObjects(s, false) {
		_, err := l.custom.Tracker().Get(fixture.Resource, fixture.Namespace, fixture.Name)
		require.True(t, apierrors.IsNotFound(err))
	}
}

func TestSourceUnknownAndFalseCanBootstrapTrustedPublishingControls(t *testing.T) {
	t.Parallel()
	for _, condition := range []string{"Unknown", "False"} {
		t.Run(condition, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			var states [3]State
			for i, role := range []Role{Original, Control, Candidate} {
				r := l.request(role)
				s := l.phase(t, r, WaitingSources)
				persistSourceCondition(t, l.testLab, s, condition)
				requireNoInitialFixtures(t, l.testLab, s)
				next, err := l.step(s, r)
				require.NoError(t, err)
				require.Equal(t, InstallingInitial, next.Phase)
				require.Equal(t, s.Deadline, next.Deadline)
				require.Equal(t, s.Evidence, next.Evidence, "source installation is not readiness or verdict evidence")
				require.Empty(t, next.Outcome)
				require.True(t, next.WindowStartedAt.IsZero())
				requireNoInitialFixtures(t, l.testLab, next)
				states[i] = l.until(t, next, r, State.Terminal)
				require.Equal(t, Complete, states[i].Phase)
				require.True(t, normalControlsComplete(states[i], false))
				require.True(t, normalControlsComplete(states[i], true))
				require.Positive(t, states[i].Evidence.HTTPCount)
			}
			require.NoError(t, Compare(states[0], states[1], states[2]))
		})
	}
}

func TestSourceConditionsAloneNeverReplacePositivePublishingObservations(t *testing.T) {
	t.Parallel()
	for _, condition := range []string{"Unknown", "False", "True"} {
		for _, role := range []Role{Original, Control, Candidate} {
			t.Run(condition+"/"+string(role), func(t *testing.T) {
				t.Parallel()
				l := newPublishingLab(t)
				l.observer.behaviors[role] = publishingBehavior{denyAll: true}
				r := l.request(role)
				s := l.phase(t, r, WaitingSources)
				persistSourceCondition(t, l.testLab, s, condition)
				s = l.until(t, s, r, func(s State) bool { return s.Phase == ObservingInitial })
				next, err := l.step(s, r)
				require.NoError(t, err)
				require.Equal(t, ObservingInitial, next.Phase)
				require.Zero(t, next.Evidence.HTTPCount)
				require.False(t, normalControlsComplete(next, false))
				require.True(t, next.WindowStartedAt.IsZero())
				l.clockMu.Lock()
				l.clock = next.Deadline
				l.clockMu.Unlock()
				next, err = l.step(next, r)
				require.NoError(t, err)
				require.Equal(t, Cleaning, next.Phase)
				require.Equal(t, Inconclusive, next.Outcome)
				next = l.until(t, next, r, State.Terminal)
				require.Equal(t, Complete, next.Phase)
				require.Equal(t, Inconclusive, next.Outcome)
				require.True(t, next.ControllerStopped)
			})
		}
	}
}

func TestSourceUnknownAndFalseStillRequireBaselineCrossReproduction(t *testing.T) {
	t.Parallel()
	for _, condition := range []string{"Unknown", "False"} {
		for _, role := range []Role{Original, Control} {
			t.Run(condition+"/"+string(role), func(t *testing.T) {
				t.Parallel()
				l := newPublishingLab(t)
				l.observer.behaviors[role] = publishingBehavior{}
				r := l.request(role)
				s := l.phase(t, r, WaitingSources)
				persistSourceCondition(t, l.testLab, s, condition)
				s = l.until(t, s, r, State.Terminal)
				require.Equal(t, Complete, s.Phase)
				require.Equal(t, NotReproduced, s.Outcome)
				require.True(t, normalControlsComplete(s, false) && normalControlsComplete(s, true))
				require.False(t, s.Evidence.CrossObserved)
			})
		}
	}
}

func TestLegacyHTTPSourceReadinessUsesObservedControlsNotCRStatus(t *testing.T) {
	t.Parallel()
	for _, condition := range []string{"Unknown", "False"} {
		t.Run(condition, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			var states [3]State
			for i, role := range []Role{Original, Control, Candidate} {
				r := l.request(role)
				s := l.phase(t, r, WaitingSources)
				persistSourceCondition(t, l, s, condition)
				states[i] = l.until(t, s, r, State.Terminal)
				require.Equal(t, Complete, states[i].Phase)
			}
			require.NoError(t, Compare(states[0], states[1], states[2]))
		})
	}
}

func TestSourceBootstrapPreservesLiveRuntimeAndExactBindings(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"runtime-not-ready", "source-spec", "auth-spec", "source-uid", "secret-uid"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, WaitingSources)
			switch mode {
			case "runtime-not-ready":
				raw, err := l.kube.Tracker().Get(pods, s.RuntimePod.Namespace, s.RuntimePod.Name)
				require.NoError(t, err)
				pod := raw.(*corev1.Pod)
				pod.Status.ContainerStatuses[0].Ready = false
				require.NoError(t, l.kube.Tracker().Update(pods, pod, pod.Namespace))
			case "source-spec", "source-uid":
				raw, err := l.custom.Tracker().Get(cloudEventSources, s.Namespaces[0], "scope-source")
				require.NoError(t, err)
				source := raw.(*unstructured.Unstructured)
				if mode == "source-uid" {
					source.SetUID("foreign-source-uid")
				} else {
					require.NoError(t, unstructured.SetNestedField(source.Object, "changed", "spec", "clusterName"))
				}
				require.NoError(t, l.custom.Tracker().Update(cloudEventSources, source, source.GetNamespace()))
			case "auth-spec":
				raw, err := l.custom.Tracker().Get(triggerAuthentications, s.Namespaces[1], publishingAuthName)
				require.NoError(t, err)
				auth := raw.(*unstructured.Unstructured)
				require.NoError(t, unstructured.SetNestedSlice(auth.Object, []any{
					map[string]any{"parameter": "accessKey", "name": "unapproved-secret", "key": "key"},
				}, "spec", "secretTargetRef"))
				require.NoError(t, l.custom.Tracker().Update(triggerAuthentications, auth, auth.GetNamespace()))
			case "secret-uid":
				raw, err := l.kube.Tracker().Get(secrets, s.Namespaces[1], canaryName)
				require.NoError(t, err)
				secret := raw.(*corev1.Secret)
				secret.UID = "foreign-secret-uid"
				require.NoError(t, l.kube.Tracker().Update(secrets, secret, secret.Namespace))
			}
			next, err := l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Inconclusive, next.Outcome)
			requireNoInitialFixtures(t, l.testLab, next)
			require.Equal(t, s.Evidence, next.Evidence)
			if mode == "source-uid" || mode == "secret-uid" {
				require.Equal(t, Quarantined, next.Phase)
			} else {
				require.Equal(t, Cleaning, next.Phase)
				next = l.until(t, next, r, State.Terminal)
				require.Equal(t, Complete, next.Phase)
			}
		})
	}
}
