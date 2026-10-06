package controllerlab

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestCleanupFinishesGCTriggeredByChangedOwnerReferences(t *testing.T) {
	t.Parallel()
	for _, lostAck := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "lost-finalizer-ack"}[lostAck], func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			emulateKEDAFinalizers(t, l, r)
			s := l.phase(t, r, ObservingWindow)
			target := s.Receipts[len(s.Receipts)-1].Object
			raw, err := l.custom.Tracker().Get(target.Resource, target.Namespace, target.Name)
			require.NoError(t, err)
			object := raw.(*unstructured.Unstructured)
			object.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "Namespace", Name: "foreign", UID: "foreign"}})
			now := metav1.Now()
			object.SetDeletionTimestamp(&now)
			require.NoError(t, l.custom.Tracker().Update(target.Resource, object, target.Namespace))
			patches := 0
			l.custom.PrependReactor("patch", target.Resource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
				patch := action.(ktesting.PatchAction)
				if patch.GetName() != target.Name || action.GetNamespace() != target.Namespace {
					return false, nil, nil
				}
				patches++
				durable := l.journal.load(r)
				require.True(t, durable.ControllerStopped)
				receipt := receiptFor(durable, target)
				require.NotNil(t, receipt)
				require.True(t, receipt.DeleteRequested, "GC completion must have an authorized exact-UID deletion receipt")
				raw, err := l.custom.Tracker().Get(target.Resource, target.Namespace, target.Name)
				require.NoError(t, err)
				result := raw.(*unstructured.Unstructured)
				require.Equal(t, target.UID, result.GetUID())
				result.SetFinalizers(nil)
				require.NoError(t, l.custom.Tracker().Delete(target.Resource, target.Namespace, target.Name))
				if lostAck {
					return true, nil, errors.New("synthetic lost finalizer acknowledgement")
				}
				return true, result, nil
			})
			r.Cancel = true
			for range 600 {
				if s.Terminal() {
					break
				}
				next, err := l.step(s, r)
				if err != nil {
					require.True(t, lostAck)
					var safe *Error
					require.ErrorAs(t, err, &safe)
					require.Equal(t, Infrastructure, safe.Kind)
					next = l.journal.load(r)
					l.restart(t)
				}
				s = next
			}
			require.Equal(t, 1, patches)
			require.Equal(t, Complete, s.Phase)
			require.Equal(t, Cancelled, s.Outcome)
			require.True(t, receiptFor(s, target).Deleted)
		})
	}
}

func TestCleanupSettlesAlreadyAbsentReceiptedObjectWithoutAdoptingReplacement(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingWindow)
	target := s.Receipts[len(s.Receipts)-1].Object
	require.NoError(t, l.custom.Tracker().Delete(target.Resource, target.Namespace, target.Name))
	r.Cancel = true
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Complete, s.Phase)
	require.Equal(t, Cancelled, s.Outcome)
	receipt := receiptFor(s, target)
	require.True(t, receipt.Deleted && receipt.DeleteRequested)
	for _, action := range l.custom.Actions() {
		if deletion, ok := action.(ktesting.DeleteAction); ok && deletion.GetName() == target.Name {
			require.Equal(t, target.UID, *deletion.GetDeleteOptions().Preconditions.UID)
		}
	}
}
