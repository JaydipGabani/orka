package controllerlab

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPublishingControllerExitAndIdentityDriftNeverMeanProtection(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"exit-zero", "restart", "not-ready", "replacement", "owner", "tls-env", "tls-host", "host-network"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, ObservingWindow)
			require.NotNil(t, s.RuntimePod)
			value, err := l.kube.Tracker().Get(pods, s.RuntimePod.Namespace, s.RuntimePod.Name)
			require.NoError(t, err)
			pod := value.(*corev1.Pod)
			switch mode {
			case "exit-zero":
				pod.Status.Phase = corev1.PodSucceeded
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}
			case "restart":
				pod.Status.ContainerStatuses[0].RestartCount = 1
			case "not-ready":
				pod.Status.ContainerStatuses[0].Ready = false
			case "replacement":
				pod.UID = "replacement-runtime"
			case "owner":
				pod.OwnerReferences[0].UID = "replacement-replicaset"
			case "tls-env":
				pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{Name: "EXTRA", Value: "unapproved"})
			case "tls-host", "host-network":
				raw, err := l.kube.Tracker().Get(deployments, s.Namespaces[0], controllerName)
				require.NoError(t, err)
				d := raw.(*appsv1.Deployment)
				if mode == "tls-host" {
					d.Spec.Template.Spec.HostAliases[0].IP = "10.244.0.99"
				} else {
					d.Spec.Template.Spec.HostNetwork = true
				}
				require.NoError(t, l.kube.Tracker().Update(deployments, d, d.Namespace))
			}
			require.NoError(t, l.kube.Tracker().Update(pods, pod, pod.Namespace))
			before := l.observer.calls.Load()
			next, err := l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Inconclusive, next.Outcome)
			require.Equal(t, before, l.observer.calls.Load(), "stale observer evidence must not outlive the subject")
			if next.Phase == Cleaning {
				next = l.until(t, next, r, State.Terminal)
				require.Equal(t, Complete, next.Phase)
			} else {
				require.Equal(t, Quarantined, next.Phase)
			}
		})
	}
}

func TestPublishingMirroredRetriesAndSnapshotsAreIdempotent(t *testing.T) {
	t.Parallel()
	for _, role := range []Role{Original, Control, Candidate} {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			behavior := l.observer.behaviors[role]
			behavior.retries = 2
			l.observer.behaviors[role] = behavior
			r := l.request(role)
			s := l.phase(t, r, ObservingWindow)
			before := cloneState(s).Evidence
			require.Zero(t, s.Evidence.HTTPCount%3)
			for range 3 {
				next, err := l.step(s, r)
				require.NoError(t, err)
				require.Equal(t, before, next.Evidence)
				s = next
			}
			l.restart(t)
			s = l.until(t, s, r, State.Terminal)
			require.Equal(t, Complete, s.Phase)
			require.True(t, normalControlsComplete(s, false) && normalControlsComplete(s, true))
			if role == Candidate {
				require.Equal(t, Protected, s.Outcome)
			} else {
				require.Equal(t, Reproduced, s.Outcome)
			}
		})
	}
}

func TestPublishingObserverContinuityAndReachabilityAreMandatory(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"unreachable", "reset", "history-shrink", "prefix-edit", "saturation", "missing-tls-flag", "missing-header-flag"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, ObservingWindow)
			if mode == "unreachable" {
				l.observer.behaviors[Candidate] = publishingBehavior{unreachable: true}
			} else {
				l.observer.mutate = func(o *Observation) {
					switch mode {
					case "reset":
						o.Generation++
					case "history-shrink":
						o.HTTP = o.HTTP[:len(o.HTTP)-1]
					case "prefix-edit":
						o.HTTP[0].BodySHA256 = bytesDigest([]byte("rewritten synthetic body"))
					case "saturation":
						o.DroppedHTTP = 1
					case "missing-tls-flag", "missing-header-flag":
						for i := range o.HTTP {
							if o.HTTP[i].Route == "/events/grid-a" {
								if mode == "missing-tls-flag" {
									o.HTTP[i].TLSDataIngress = false
								} else {
									o.HTTP[i].SyntheticCredentialObserved = false
								}
								break
							}
						}
					}
				}
			}
			next, err := l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Inconclusive, next.Outcome)
			next = l.until(t, next, r, State.Terminal)
			require.Equal(t, Complete, next.Phase)
			require.Equal(t, Inconclusive, next.Outcome)
		})
	}
}

func TestPublishingStepBudgetIncludesProductionObserverOperations(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	var s State
	for range 600 {
		if s.Terminal() {
			break
		}
		before := len(l.kube.Actions()) + len(l.custom.Actions())
		snapshots := l.observer.calls.Load()
		var err error
		s, err = l.step(s, r)
		require.NoError(t, err)
		// wireObserver performs three reads; podForwardDialer adds three UID
		// checks and one port-forward upgrade, absent from the injected fake.
		transportOperations := 7 * int(l.observer.calls.Load()-snapshots)
		require.LessOrEqual(t, len(l.kube.Actions())+len(l.custom.Actions())-before+transportOperations, MaxStepClientOperations)
	}
	require.Equal(t, Protected, s.Outcome)
}

func TestPublishingCancelledContextAndConcurrentReceiptFences(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, Preparing)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := len(l.kube.Actions()) + len(l.custom.Actions())
	unchanged, err := l.adapter.Step(ctx, s, r)
	require.Error(t, err)
	require.Equal(t, s, unchanged)
	require.Equal(t, before, len(l.kube.Actions())+len(l.custom.Actions()))
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := l.adapter.Step(context.Background(), s, r)
			results <- err
		})
	}

	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else {
			var safe *Error
			require.ErrorAs(t, err, &safe)
			require.Equal(t, StoreRejected, safe.Kind)
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, createCount(l.kube.Actions()))
	s = l.journal.load(r)
	l.restart(t)
	r.Cancel = true
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Cancelled, s.Outcome)
	_, err = l.kube.CoreV1().Namespaces().Get(context.Background(), s.Namespaces[0], metav1.GetOptions{})
	require.Error(t, err)
}

func TestPublishingFinalChallengesCannotBePreplayedOrRecounted(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	owned := l.phase(t, r, ObservingWindow)
	s := cloneState(owned)
	config, err := l.kube.CoreV1().ConfigMaps(s.ObserverNamespace).Get(context.Background(), "observer-config", metav1.GetOptions{})
	require.NoError(t, err)
	raw := []byte(config.Data["config.json"])
	require.False(t, bytes.Contains(raw, []byte(s.FinalMarkerNonce)))
	for index := range 2 {
		require.False(t, bytes.Contains(raw, []byte(subject(s, index, true))))
		require.False(t, bytes.Contains(raw, []byte(fixtureObjects(s, true)[index].Name)))
	}
	observation, err := l.observer.Snapshot(context.Background(), wireTarget(t, l.testLab, s))
	require.NoError(t, err)
	var future []HTTPObservation
	for index := range 2 {
		for _, route := range []string{[]string{httpARoute, httpBRoute}[index], []string{gridARoute, gridBRoute}[index], clusterHTTPRoute} {
			record := observedEvent(s, index, true, index)
			record.Route = route
			record.TLSDataIngress = route == gridARoute || route == gridBRoute
			record.SyntheticCredentialObserved = record.TLSDataIngress
			future = append(future, record)
		}
	}
	observation.HTTP = append(observation.HTTP, future...)
	require.NoError(t, incorporate(&s, observation))
	require.False(t, normalControlsComplete(s, true), "events before fixture creation cannot count as fresh controls")
	for _, object := range fixtureObjects(s, true) {
		object.UID = "synthetic-final-receipt"
		s.Receipts = append(s.Receipts, Receipt{Object: object, IntentDigest: bytesDigest([]byte(object.Name))})
	}
	require.NoError(t, incorporate(&s, observation))
	require.False(t, normalControlsComplete(s, true), "old history cannot be recounted after fixture creation")
	observation.HTTP = append(observation.HTTP, future...)
	require.NoError(t, incorporate(&s, observation))
	require.True(t, normalControlsComplete(s, true))
	r.Cancel = true
	_ = l.until(t, owned, r, State.Terminal)
}
