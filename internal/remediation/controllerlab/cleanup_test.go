package controllerlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

func emulateKEDAFinalizers(t *testing.T, l *publishingLab, request Request) {
	t.Helper()
	l.custom.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		if kedaFixture(action.GetResource()) {
			object := action.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured)
			object.SetFinalizers([]string{kedaFinalizer})
		}
		return false, nil, nil
	})
	l.custom.PrependReactor("delete", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		if !kedaFixture(action.GetResource()) {
			return false, nil, nil
		}
		deleteAction := action.(ktesting.DeleteAction)
		raw, err := l.custom.Tracker().Get(action.GetResource(), action.GetNamespace(), deleteAction.GetName())
		if err != nil {
			return true, nil, err
		}
		object := raw.(*unstructured.Unstructured)
		if len(object.GetFinalizers()) == 0 {
			return false, nil, nil
		}
		// An actual API server retains finalizing objects. The default fake
		// tracker would otherwise conceal the cleanup dependency on KEDA.
		now := metav1.Now()
		object.SetDeletionTimestamp(&now)
		require.NoError(t, l.custom.Tracker().Update(action.GetResource(), object, action.GetNamespace()))
		return true, nil, nil
	})
	l.custom.PrependReactor("patch", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		patch := action.(ktesting.PatchAction)
		require.True(t, kedaFixture(action.GetResource()))
		require.Equal(t, types.JSONPatchType, patch.GetPatchType())
		s := l.journal.load(request)
		require.True(t, s.ControllerStopped)
		controller := receiptFor(s, ref(deployments, s.Namespaces[0], controllerName))
		require.NotNil(t, controller)
		require.True(t, controller.Deleted && controller.DeleteRequested)
		list, err := l.kube.CoreV1().Pods(s.Namespaces[0]).List(context.Background(), metav1.ListOptions{})
		require.NoError(t, err)
		require.Empty(t, list.Items, "finalizers must not be released while any subject Pod remains")
		receipt := receiptFor(s, ref(action.GetResource(), action.GetNamespace(), patch.GetName()))
		require.NotNil(t, receipt)
		require.NotNil(t, receipt.FinalizerRemoval)
		require.False(t, receipt.FinalizerRemoval.Completed)
		var operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		}
		require.NoError(t, json.Unmarshal(patch.GetPatch(), &operations))
		require.Len(t, operations, 4)
		require.Equal(t, []string{"/metadata/uid", "/metadata/resourceVersion", "/metadata/finalizers", "/metadata/finalizers"},
			[]string{operations[0].Path, operations[1].Path, operations[2].Path, operations[3].Path})
		require.Equal(t, []string{"test", "test", "test", "replace"},
			[]string{operations[0].Op, operations[1].Op, operations[2].Op, operations[3].Op})
		var uid, version string
		require.NoError(t, json.Unmarshal(operations[0].Value, &uid))
		require.NoError(t, json.Unmarshal(operations[1].Value, &version))
		require.Equal(t, string(receipt.Object.UID), uid)
		require.Equal(t, receipt.FinalizerRemoval.ResourceVersion, version)
		return false, nil, nil
	})
}

func TestCleanupOwnsKnownFinalizersWithoutControllerCooperation(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	var states [3]State
	for i, role := range []Role{Original, Control, Candidate} {
		r := l.request(role)
		// Each arm gets a fresh fake cluster so its closure binds one request.
		if i != 0 {
			l = newPublishingLab(t)
		}
		emulateKEDAFinalizers(t, l, r)
		states[i] = l.until(t, State{}, r, State.Terminal)
		require.Equal(t, Complete, states[i].Phase)
		require.True(t, states[i].ControllerStopped)
		for _, receipt := range states[i].Receipts {
			if kedaFixture(receipt.Object.Resource) {
				require.NotNil(t, receipt.FinalizerRemoval)
				require.True(t, receipt.FinalizerRemoval.Completed)
				require.NotEmpty(t, receipt.FinalizerRemoval.ResourceVersion)
			}
		}
	}
	require.NoError(t, Compare(states[0], states[1], states[2]))
}

func cancelledAfterControllerStops(t *testing.T, l *publishingLab, r Request) State {
	t.Helper()
	s := l.phase(t, r, ObservingWindow)
	r.Cancel = true
	return l.until(t, s, r, func(s State) bool { return s.ControllerStopped })
}

func TestFinalizerRemovalRecoversLostAcknowledgementsAndRaces(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"lost-patch-ack", "rv-conflict", "replaced-uid"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			emulateKEDAFinalizers(t, l, r)
			s := cancelledAfterControllerStops(t, l, r)
			r.Cancel = true
			var attempts int
			l.custom.PrependReactor("patch", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
				attempts++
				if attempts != 1 {
					return false, nil, nil
				}
				patch := action.(ktesting.PatchAction)
				raw, err := l.custom.Tracker().Get(action.GetResource(), action.GetNamespace(), patch.GetName())
				require.NoError(t, err)
				object := raw.(*unstructured.Unstructured)
				switch mode {
				case "lost-patch-ack":
					object.SetFinalizers(nil)
				case "replaced-uid":
					object.SetUID("foreign-replacement")
				}
				object.SetResourceVersion("synthetic-rv-after-race")
				require.NoError(t, l.custom.Tracker().Update(action.GetResource(), object, action.GetNamespace()))
				return true, nil, errors.New("synthetic unacknowledged patch")
			})
			next, err := l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Cleaning, next.Phase)
			require.Equal(t, Cancelled, next.Outcome)
			s = l.journal.load(r)
			require.True(t, s.ControllerStopped)
			l.restart(t)
			if mode == "replaced-uid" {
				s, err = l.step(s, r)
				require.Error(t, err)
				require.Equal(t, Quarantined, s.Phase)
				for _, action := range l.custom.Actions() {
					if deletion, ok := action.(ktesting.DeleteAction); ok {
						require.NotEqual(t, types.UID("foreign-replacement"), *deletion.GetDeleteOptions().Preconditions.UID)
					}
				}
				return
			}
			s = l.until(t, s, r, State.Terminal)
			require.Equal(t, Complete, s.Phase)
			require.Equal(t, Cancelled, s.Outcome)
		})
	}
}

func TestCleanupRefusesUnknownFinalizersAndRequiresAcceptance(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"unknown-finalizer", "authorization-revoked"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			emulateKEDAFinalizers(t, l, r)
			s := cancelledAfterControllerStops(t, l, r)
			r.Cancel = true
			target := s.Receipts[len(s.Receipts)-1].Object
			if mode == "unknown-finalizer" {
				raw, err := l.custom.Tracker().Get(target.Resource, target.Namespace, target.Name)
				require.NoError(t, err)
				object := raw.(*unstructured.Unstructured)
				object.SetFinalizers([]string{kedaFinalizer, "foreign.example/hold"})
				require.NoError(t, l.custom.Tracker().Update(target.Resource, object, target.Namespace))
			} else {
				l.journal.reject = "remove-finalizer"
			}
			before := len(l.custom.Actions())
			next, err := l.step(s, r)
			require.Error(t, err)
			if mode == "unknown-finalizer" {
				require.Equal(t, Quarantined, next.Phase)
			}
			for _, action := range l.custom.Actions()[before:] {
				require.NotEqual(t, "patch", action.GetVerb())
				require.NotEqual(t, "delete", action.GetVerb())
			}
		})
	}
}

func TestCleanupUsesReceiptedUIDDespiteSubjectMetadataChanges(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	emulateKEDAFinalizers(t, l, r)
	s := l.phase(t, r, ObservingWindow)
	for _, receipt := range s.Receipts {
		if !kedaFixture(receipt.Object.Resource) {
			continue
		}
		raw, err := l.custom.Tracker().Get(receipt.Object.Resource, receipt.Object.Namespace, receipt.Object.Name)
		require.NoError(t, err)
		object := raw.(*unstructured.Unstructured)
		object.SetLabels(map[string]string{"subject.example/changed": "true"})
		object.SetAnnotations(map[string]string{"subject.example/changed": "true"})
		object.SetOwnerReferences([]metav1.OwnerReference{{
			APIVersion: "v1", Kind: "Namespace", Name: "foreign-namespace", UID: "foreign-namespace-uid",
		}})
		require.NoError(t, l.custom.Tracker().Update(receipt.Object.Resource, object, receipt.Object.Namespace))
	}
	s, err := l.step(s, r)
	require.Error(t, err)
	require.Equal(t, Cleaning, s.Phase)
	require.Equal(t, Inconclusive, s.Outcome)
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Complete, s.Phase)
	require.Equal(t, Inconclusive, s.Outcome)
	for _, receipt := range s.Receipts {
		require.True(t, receipt.Deleted && receipt.DeleteRequested)
	}
	for _, action := range l.custom.Actions() {
		if deletion, ok := action.(ktesting.DeleteAction); ok {
			require.NotEqual(t, "foreign-namespace", deletion.GetName())
			require.True(t, slices.ContainsFunc(s.Receipts, func(r Receipt) bool {
				return r.Object.Resource == deletion.GetResource() && r.Object.Name == deletion.GetName() &&
					r.Object.UID == *deletion.GetDeleteOptions().Preconditions.UID
			}))
		}
	}
}

func TestCleanupWaitsForUnlabelledPodAbsenceBeforeFinalizers(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	emulateKEDAFinalizers(t, l, r)
	s := l.phase(t, r, ObservingWindow)
	raw, err := l.kube.Tracker().Get(pods, s.Namespaces[0], s.RuntimePod.Name)
	require.NoError(t, err)
	orphan := raw.(*corev1.Pod).DeepCopy()
	orphan.Name, orphan.UID = "unlabelled-runtime", "unlabelled-runtime-uid"
	orphan.Labels = nil
	require.NoError(t, l.kube.Tracker().Create(pods, orphan, orphan.Namespace))
	r.Cancel = true
	s = l.until(t, s, r, func(s State) bool {
		controller := receiptFor(s, ref(deployments, s.Namespaces[0], controllerName))
		return controller != nil && controller.Deleted
	})
	for range 3 {
		s, err = l.step(s, r)
		require.NoError(t, err)
		require.False(t, s.ControllerStopped)
	}
	for _, action := range l.custom.Actions() {
		require.NotEqual(t, "patch", action.GetVerb())
		require.NotEqual(t, "delete", action.GetVerb())
	}
	// The simulated kubelet/GC, not a selector-based lab delete, settles it.
	require.NoError(t, l.kube.Tracker().Delete(pods, orphan.Namespace, orphan.Name))
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Complete, s.Phase)
}

func TestTransientReplicaSetReadAndValidReplacementStillCleanUp(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"transient-rs", "missing-rs", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			emulateKEDAFinalizers(t, l, r)
			s := l.phase(t, r, ObservingWindow)
			switch mode {
			case "transient-rs", "missing-rs":
				l.kube.PrependReactor("get", "replicasets", func(action ktesting.Action) (bool, runtime.Object, error) {
					if mode == "missing-rs" {
						return true, nil, apierrors.NewNotFound(action.GetResource().GroupResource(), action.(ktesting.GetAction).GetName())
					}
					return true, nil, errors.New("synthetic temporary read outage")
				})
			case "replacement":
				object, err := l.kube.Tracker().Get(pods, s.Namespaces[0], s.RuntimePod.Name)
				require.NoError(t, err)
				pod := object.(*corev1.Pod)
				pod.UID = "replacement-with-valid-owner"
				require.NoError(t, l.kube.Tracker().Update(pods, pod, pod.Namespace))
			}
			s, err := l.step(s, r)
			var safe *Error
			require.ErrorAs(t, err, &safe)
			require.Equal(t, Infrastructure, safe.Kind)
			require.Equal(t, Cleaning, s.Phase)
			s = l.until(t, s, r, State.Terminal)
			require.Equal(t, Complete, s.Phase)
			require.Equal(t, Inconclusive, s.Outcome)
		})
	}
}

func TestCleanupFinalizerMutationIsASeparateBoundedStep(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	emulateKEDAFinalizers(t, l, r)
	s := l.phase(t, r, Cleaning)
	for !s.Terminal() {
		beforeKube, beforeCustom := len(l.kube.Actions()), len(l.custom.Actions())
		var err error
		s, err = l.step(s, r)
		require.NoError(t, err)
		mutations := 0
		for _, actions := range [][]ktesting.Action{l.kube.Actions()[beforeKube:], l.custom.Actions()[beforeCustom:]} {
			for _, action := range actions {
				if action.GetResource().Resource != "subjectaccessreviews" &&
					slices.Contains([]string{"create", "update", "patch", "delete"}, action.GetVerb()) {
					mutations++
				}
			}
		}
		require.LessOrEqual(t, mutations, 1)
	}
	require.Equal(t, Complete, s.Phase)
}

func TestControllerWrongOwnershipChainRemainsQuarantined(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingWindow)
	resource := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
	raw, err := l.kube.Tracker().Get(resource, s.Namespaces[0], "synthetic-controller-rs")
	require.NoError(t, err)
	rs := raw.(*appsv1.ReplicaSet)
	rs.OwnerReferences[0].UID = "foreign-deployment-uid"
	require.NoError(t, l.kube.Tracker().Update(resource, rs, rs.Namespace))
	next, err := l.step(s, r)
	require.Error(t, err)
	require.Equal(t, Quarantined, next.Phase)
	require.Equal(t, Inconclusive, next.Outcome)
}

func TestCleanupNamespaceMetadataDriftDoesNotChangeUIDAuthority(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingWindow)
	for _, name := range ownedNamespaces(s) {
		raw, err := l.kube.Tracker().Get(namespaces, "", name)
		require.NoError(t, err)
		m, err := meta.Accessor(raw)
		require.NoError(t, err)
		m.SetLabels(map[string]string{"changed.example/label": fmt.Sprint(true)})
		require.NoError(t, l.kube.Tracker().Update(namespaces, raw, ""))
	}
	r.Cancel = true
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Complete, s.Phase)
	require.Equal(t, Cancelled, s.Outcome)
}
