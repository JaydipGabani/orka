package controllerlab

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAllFixtureBindingsAreRevalidatedThroughFinalObservation(t *testing.T) {
	t.Parallel()
	for _, phase := range []Phase{ObservingWindow, Settling} {
		for _, mode := range []string{"extra-source-spec", "auth-ref", "scale-target", "source-label", "secret-label", "trust-map-label", "source-owner"} {
			t.Run(string(phase)+"/"+mode, func(t *testing.T) {
				t.Parallel()
				l := newPublishingLab(t)
				r := l.request(Candidate)
				emulateKEDAFinalizers(t, l, r)
				s := l.phase(t, r, phase)
				target := ref(cloudEventSources, s.Namespaces[0], "scope-source")
				switch mode {
				case "auth-ref":
					target = ref(triggerAuthentications, s.Namespaces[1], publishingAuthName)
				case "scale-target":
					target = fixtureObjects(s, false)[0]
				case "secret-label":
					target = ref(secrets, s.Namespaces[1], canaryName)
				case "trust-map-label":
					target = ref(configMaps, s.Namespaces[0], observerTrustName)
				}
				var raw runtime.Object
				var err error
				if kedaFixture(target.Resource) {
					raw, err = l.custom.Tracker().Get(target.Resource, target.Namespace, target.Name)
				} else {
					raw, err = l.kube.Tracker().Get(target.Resource, target.Namespace, target.Name)
				}
				require.NoError(t, err)
				m, err := objectMetadata(raw)
				require.NoError(t, err)
				receipt := receiptFor(s, target)
				require.NotNil(t, receipt)
				annotations := m.GetAnnotations()
				annotations["subject.example/claimed-binding-digest"] = receipt.BindingDigest
				m.SetAnnotations(annotations)
				switch mode {
				case "extra-source-spec":
					require.NoError(t, unstructured.SetNestedField(raw.(*unstructured.Unstructured).Object,
						true, "spec", "unexpected"))
				case "auth-ref":
					require.NoError(t, unstructured.SetNestedSlice(raw.(*unstructured.Unstructured).Object,
						[]any{map[string]any{"name": "different-secret", "key": "key", "parameter": "accessKey"}}, "spec", "secretTargetRef"))
				case "scale-target":
					require.NoError(t, unstructured.SetNestedField(raw.(*unstructured.Unstructured).Object,
						"different-absent-target", "spec", "scaleTargetRef", "name"))
				case "source-owner":
					m.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "Namespace", Name: "foreign", UID: "foreign"}})
				default:
					m.SetLabels(map[string]string{"subject.example/extra-label": "changed"})
				}
				if kedaFixture(target.Resource) {
					require.NoError(t, l.custom.Tracker().Update(target.Resource, raw, target.Namespace))
				} else {
					require.NoError(t, l.kube.Tracker().Update(target.Resource, raw, target.Namespace))
				}
				next, err := l.step(s, r)
				require.Error(t, err)
				require.Equal(t, Inconclusive, next.Outcome)
				require.Equal(t, Cleaning, next.Phase)
				next = l.until(t, next, r, State.Terminal)
				require.Equal(t, Complete, next.Phase)
				require.Equal(t, Inconclusive, next.Outcome)
			})
		}
	}
}

func TestFixtureBindingDigestsAllowStatusAndKnownFinalizerUpdates(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingWindow)
	for i, receipt := range s.Receipts {
		if !kedaFixture(receipt.Object.Resource) {
			continue
		}
		raw, err := l.custom.Tracker().Get(receipt.Object.Resource, receipt.Object.Namespace, receipt.Object.Name)
		require.NoError(t, err)
		object := raw.(*unstructured.Unstructured)
		object.SetResourceVersion(fmt.Sprintf("new-version-%d", i))
		object.SetFinalizers([]string{kedaFinalizer})
		require.NoError(t, unstructured.SetNestedField(object.Object, "synthetic controller status", "status", "message"))
		require.NoError(t, l.custom.Tracker().Update(receipt.Object.Resource, object, receipt.Object.Namespace))
	}
	next, err := l.step(s, r)
	require.NoError(t, err)
	require.Equal(t, s.Evidence.BindingsDigest, next.Evidence.BindingsDigest)
	next = l.until(t, next, r, State.Terminal)
	require.Equal(t, Protected, next.Outcome)
}

func TestUnacknowledgedKEDACreateCannotAdoptExtraSpecFields(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, InstallingSources)
	l.journal.loseReceiptAck = true
	_, err := l.step(s, r)
	require.Error(t, err)
	s = l.journal.load(r)
	require.NotNil(t, s.Intent)
	target := s.Intent.Object
	raw, err := l.custom.Tracker().Get(target.Resource, target.Namespace, target.Name)
	require.NoError(t, err)
	object := raw.(*unstructured.Unstructured)
	require.NoError(t, unstructured.SetNestedField(object.Object, "unexpected", "spec", "extra"))
	require.NoError(t, l.custom.Tracker().Update(target.Resource, object, target.Namespace))
	l.restart(t)
	next, err := l.step(s, r)
	require.Error(t, err)
	require.Equal(t, Quarantined, next.Phase)
	require.Nil(t, receiptFor(next, target))
}

func TestPublishingMissingBindingReceiptNeverMeansProtected(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingWindow)
	for i := range s.Receipts {
		if s.Receipts[i].Object.Resource == secrets {
			s.Receipts[i].BindingDigest = ""
			break
		}
	}
	next, err := l.step(s, r)
	require.Error(t, err)
	require.Equal(t, Inconclusive, next.Outcome)
	require.Equal(t, Cleaning, next.Phase)
	next = l.until(t, next, r, State.Terminal)
	require.Equal(t, Complete, next.Phase)
}

func TestPublishingSecretUIDReplacementIsNotANameOnlyReference(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingWindow)
	secret, err := l.kube.CoreV1().Secrets(s.Namespaces[1]).Get(context.Background(), canaryName, metav1.GetOptions{})
	require.NoError(t, err)
	replacement := secret.DeepCopy()
	replacement.UID = "foreign-secret-uid"
	require.NoError(t, l.kube.Tracker().Update(secrets, replacement, replacement.Namespace))
	next, err := l.step(s, r)
	require.Error(t, err)
	require.Equal(t, Inconclusive, next.Outcome)
	require.Equal(t, Quarantined, next.Phase)
}

func TestBindingHashDoesNotTrustAnAnnotationOrDropExtraData(t *testing.T) {
	t.Parallel()
	base := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: "synthetic", Namespace: "synthetic", UID: "synthetic-uid", ResourceVersion: "1",
		Labels: map[string]string{runLabel: "synthetic"},
	}, Immutable: new(true), Data: map[string]string{"public": "synthetic value"}}
	original, err := resourceBindingDigest(base)
	require.NoError(t, err)
	changed := base.DeepCopy()
	changed.Annotations = map[string]string{"subject.example/claimed-binding-digest": original}
	changed.Data["extra"] = "not part of the frozen fixture"
	actual, err := resourceBindingDigest(changed)
	require.NoError(t, err)
	require.NotEqual(t, original, actual)
}
