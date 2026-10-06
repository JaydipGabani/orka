package controllerlab

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestNamespaceIsolationAloneDoesNotAuthorizeClusterCredential(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingInitial)
	attack := observedEvent(s, 1, false, 1)
	attack.Route = gridCredentialAttackRoute
	attack.TLSDataIngress, attack.SyntheticCredentialObserved = true, true
	l.observer.mutate = func(o *Observation) { o.HTTP = append(o.HTTP, attack) }
	next, err := l.step(s, r)
	require.NoError(t, err)
	require.False(t, next.Evidence.CrossObserved, "this attack uses a namespace-B event, not cross-namespace fanout")
	require.Equal(t, StillExposed, next.Outcome, "an explicit cluster-auth reference is not credential delegation")
	require.True(t, next.Evidence.Publishing.CredentialAttack.Observed)
	require.True(t, next.Evidence.Publishing.CredentialAttack.InitialObserved)
	next = l.until(t, next, r, State.Terminal)
	require.Equal(t, Complete, next.Phase)
}

func TestPublishingV2RejectsOldCombinedContractAndRawProof(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	require.Equal(t, Capability("keda-event-publishing-v2"), KEDAEventPublishing)
	require.Equal(t, Capability("keda-namespace-events-v1"), KEDANamespaceEvents)
	require.Equal(t, 1, r.Plan.Version)
	require.NoError(t, ValidatePlan(r.Plan))
	old := r
	old.Plan.Capability = Capability("keda-event-publishing-v1")
	old.Plan.Expected = []SemanticOutcome{NamespacedEventScope, NamespacedEventCredentialScope}
	require.Error(t, ValidatePlan(old.Plan))
	_, err := l.adapter.Step(context.Background(), State{}, old)
	var safe *Error
	require.ErrorAs(t, err, &safe)
	require.Equal(t, NeedsAdapter, safe.Kind)
	require.Empty(t, l.kube.Actions())
	require.Empty(t, l.custom.Actions())
	withoutAttack := r.Plan
	withoutAttack.Expected = old.Plan.Expected
	require.Error(t, ValidatePlan(withoutAttack))

	var current, previous [3]State
	for i, role := range []Role{Original, Control, Candidate} {
		request := l.request(role)
		current[i] = l.until(t, State{}, request, State.Terminal)
		raw, err := json.Marshal(current[i])
		require.NoError(t, err)
		var document map[string]any
		require.NoError(t, json.Unmarshal(raw, &document))
		document["capability"] = "keda-event-publishing-v1"
		document["planDigest"] = PlanDigest(old.Plan)
		evidence := document["evidence"].(map[string]any)["publishing"].(map[string]any)
		delete(evidence, "credentialAttack")
		evidence["initialClusterAuth"], evidence["finalClusterAuth"] = true, true
		raw, err = json.Marshal(document)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &previous[i]))
		require.Error(t, l.adapter.ValidateState(previous[i], request))
	}
	require.NoError(t, Compare(current[0], current[1], current[2]))
	require.Error(t, Compare(previous[0], previous[1], previous[2]))
}

func TestHeldOutFinalCredentialAttackIsIndependentOfNormalControls(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	l.observer.behaviors[Candidate] = publishingBehavior{credentialAttack: true, omitInitialCredential: true}
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingWindow)
	require.True(t, normalControlsComplete(s, false))
	require.Equal(t, CredentialAttackEvidence{}, s.Evidence.Publishing.CredentialAttack)
	require.Equal(t, credentialFinalMarkerID, eventMarkerID(s, 1, true))
	require.NotEqual(t, markerID(1, true), eventMarkerID(s, 1, true))
	config, err := l.kube.CoreV1().ConfigMaps(s.ObserverNamespace).Get(context.Background(), "observer-config", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotContains(t, config.Data["config.json"], subject(s, 1, true))
	var cfg syntheticObserverConfig
	require.NoError(t, json.Unmarshal([]byte(config.Data["config.json"]), &cfg))
	found := false
	for _, marker := range cfg.Markers {
		if marker.ID == credentialFinalMarkerID {
			found = true
			require.Equal(t, bytesDigest([]byte(subject(s, 1, true))), marker.SHA256)
			require.Empty(t, marker.Value)
		}
	}
	require.True(t, found)
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, StillExposed, s.Outcome)
	require.False(t, s.Evidence.CrossObserved)
	require.True(t, normalControlsComplete(s, true), "the same held-out event must still exercise retained normal channels")
	require.True(t, s.Evidence.Publishing.CredentialAttack.Observed)
	require.False(t, s.Evidence.Publishing.CredentialAttack.InitialObserved)
	require.True(t, s.Evidence.Publishing.CredentialAttack.FinalObserved)
}

func TestCredentialAttackChallengeCannotBeCreditedBeforeItsReceipt(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Original)
	owned := l.phase(t, r, ObservingWindow)
	s := cloneState(owned)
	observation, err := l.observer.Snapshot(context.Background(), wireTarget(t, l.testLab, s))
	require.NoError(t, err)
	future := observedEvent(s, 1, true, 1)
	future.Route, future.TLSDataIngress, future.SyntheticCredentialObserved = gridCredentialAttackRoute, true, true
	observation.HTTP = append(observation.HTTP, future)
	require.NoError(t, incorporate(&s, observation))
	require.True(t, s.Evidence.Publishing.CredentialAttack.Observed)
	require.False(t, s.Evidence.Publishing.CredentialAttack.FinalObserved)
	target := fixtureObjects(s, true)[1]
	target.UID = "synthetic-held-out-receipt"
	s.Receipts = append(s.Receipts, Receipt{Object: target, IntentDigest: bytesDigest([]byte(target.Name))})
	require.NoError(t, incorporate(&s, observation))
	require.False(t, s.Evidence.Publishing.CredentialAttack.FinalObserved, "pre-receipt history cannot be recounted")
	r.Cancel = true
	_ = l.until(t, owned, r, State.Terminal)
}

func TestClusterReferenceAttackHasNoDelegationAndRetainsLocalTAControls(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingInitial)
	attack, err := l.custom.Resource(cloudEventSources).Namespace(s.Namespaces[1]).Get(
		context.Background(), "scope-credential-attack-source", metav1.GetOptions{})
	require.NoError(t, err)
	kind, _, err := unstructured.NestedString(attack.Object, "spec", "authenticationRef", "kind")
	require.NoError(t, err)
	require.Equal(t, clusterAuthKind, kind)
	name, _, err := unstructured.NestedString(attack.Object, "spec", "authenticationRef", "name")
	require.NoError(t, err)
	require.Equal(t, globalAuthName(s), name)
	endpoint, _, err := unstructured.NestedString(attack.Object, "spec", "destination", "azureEventGridTopic", "endpoint")
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(endpoint, gridCredentialAttackRoute))
	raw, err := json.Marshal(attack.Object["spec"])
	require.NoError(t, err)
	require.NotContains(t, strings.ToLower(string(raw)), "delegat")
	for _, namespace := range s.Namespaces {
		local, err := l.custom.Resource(cloudEventSources).Namespace(namespace).Get(
			context.Background(), "scope-grid-source", metav1.GetOptions{})
		require.NoError(t, err)
		kind, _, err := unstructured.NestedString(local.Object, "spec", "authenticationRef", "kind")
		require.NoError(t, err)
		require.Equal(t, authKind, kind)
	}
	a, err := l.kube.Tracker().Get(secrets, s.Namespaces[0], canaryName)
	require.NoError(t, err)
	b, err := l.kube.Tracker().Get(secrets, s.Namespaces[1], canaryName)
	require.NoError(t, err)
	require.NotEqual(t, bytesDigest(a.(*corev1.Secret).Data["key"]), bytesDigest(b.(*corev1.Secret).Data["key"]))
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Protected, s.Outcome)
	require.Equal(t, CredentialAttackEvidence{}, s.Evidence.Publishing.CredentialAttack)
	require.True(t, normalControlsComplete(s, false) && normalControlsComplete(s, true))
}

func TestCredentialAttackObservationFailuresNeverMeanProtection(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"missing-header", "wrong-header", "missing-tls", "unreachable"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, ObservingInitial)
			behavior := publishingBehavior{credentialAttack: true}
			switch mode {
			case "missing-header":
				behavior.attackMissingHeader = true
			case "wrong-header":
				behavior.attackWrongHeader = true
			case "missing-tls":
				behavior.attackPlainTLS = true
			case "unreachable":
				behavior.unreachable = true
			}
			l.observer.behaviors[Candidate] = behavior
			next, err := l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Cleaning, next.Phase)
			require.Equal(t, Inconclusive, next.Outcome)
			next = l.until(t, next, r, State.Terminal)
			require.Equal(t, Complete, next.Phase)
			require.Equal(t, Inconclusive, next.Outcome)
		})
	}
}

func TestCredentialAttackTrafficDoesNotSubstituteForEventScopeChecks(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingInitial)
	attack := observedEvent(s, 0, false, 1)
	attack.Route, attack.TLSDataIngress, attack.SyntheticCredentialObserved = gridCredentialAttackRoute, true, true
	l.observer.mutate = func(o *Observation) { o.HTTP = append(o.HTTP, attack) }
	next, err := l.step(s, r)
	require.NoError(t, err)
	require.Equal(t, StillExposed, next.Outcome)
	require.True(t, next.Evidence.Publishing.CredentialAttack.Observed)
	require.False(t, next.Evidence.Publishing.CredentialAttack.InitialObserved, "baseline qualification specifically needs a B event")
	require.False(t, next.Evidence.CrossObserved)
	require.False(t, next.Evidence.Publishing.HTTPCrossObserved)
	require.False(t, next.Evidence.Publishing.HTTPSCrossObserved)
	next = l.until(t, next, r, State.Terminal)
	require.Equal(t, Complete, next.Phase)
}

func TestOldFinalMarkerCannotQualifyV2CredentialAttack(t *testing.T) {
	t.Parallel()
	for _, role := range []Role{Original, Control} {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(role)
			s := l.phase(t, r, ObservingWindow)
			expectedSubject := bytesDigest([]byte(subject(s, 1, true)))
			l.observer.mutate = func(o *Observation) {
				for _, record := range o.HTTP {
					if record.Route != gridCredentialAttackRoute {
						continue
					}
					for _, event := range record.CloudEvents {
						if event.Subject != nil && event.Subject.SHA256 == expectedSubject {
							event.Subject.MarkerIDs = []string{markerID(1, true)}
						}
					}
				}
			}
			s = l.until(t, s, r, State.Terminal)
			require.Equal(t, NotReproduced, s.Outcome)
			require.True(t, normalControlsComplete(s, true))
			require.True(t, s.Evidence.Publishing.CredentialAttack.InitialObserved)
			require.False(t, s.Evidence.Publishing.CredentialAttack.FinalObserved)
		})
	}
}
