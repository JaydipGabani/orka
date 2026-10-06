package controllerlab

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func prepareFinalizerAcceptance(t *testing.T) (*publishingLab, Request, State, ObjectRef) {
	t.Helper()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	emulateKEDAFinalizers(t, l, r)
	s := cancelledAfterControllerStops(t, l, r)
	r.Cancel = true
	return l, r, s, s.Receipts[len(s.Receipts)-1].Object
}

func durableFinalizerHooks(t *testing.T, l *publishingLab, r Request, accepted *int) Hooks {
	t.Helper()
	hooks := l.journal.hooks()
	base := hooks.Acceptance
	hooks.Acceptance = func(ctx context.Context, mutation Mutation) error {
		if mutation.Action == "remove-finalizer" {
			*accepted++
			durable := l.journal.load(r)
			require.Equal(t, Cleaning, durable.Phase)
			require.True(t, durable.ControllerStopped)
			require.Equal(t, durable.RunID, mutation.RunID)
			require.Equal(t, durable.OperationID, mutation.OperationID)
			require.Equal(t, durable.OperationDigest, mutation.OperationDigest)
			receipt := receiptFor(durable, mutation.Object)
			require.NotNil(t, receipt)
			require.Equal(t, receipt.Object, mutation.Object)
			require.NotEmpty(t, mutation.Object.UID)
			require.False(t, receipt.Deleted)
			require.True(t, kedaFixture(mutation.Object.Resource))
			require.Equal(t, kedaAPIVersion, mutation.Object.Resource.Version)
			require.NotNil(t, receipt.FinalizerRemoval, "acceptance must see the persisted intent, not a future PATCH")
			require.NotEmpty(t, receipt.FinalizerRemoval.ResourceVersion)
			require.False(t, receipt.FinalizerRemoval.Completed)
		}
		return base(ctx, mutation)
	}
	return hooks
}

func installFinalizerHooks(t *testing.T, l *publishingLab, hooks Hooks) {
	t.Helper()
	adapter, err := New(l.config, Clients{Kubernetes: l.kube, CustomResources: l.custom, Observer: l.observer}, hooks)
	require.NoError(t, err)
	adapter.now = l.adapter.now
	l.adapter = adapter
}

func finalizerPatchCount(l *publishingLab, target ObjectRef) int {
	count := 0
	for _, action := range l.custom.Actions() {
		if patch, ok := action.(ktesting.PatchAction); ok && patch.GetResource() == target.Resource &&
			patch.GetNamespace() == target.Namespace && patch.GetName() == target.Name {
			count++
		}
	}
	return count
}

func TestFinalizerAcceptanceSeesDurableIntentBeforePatch(t *testing.T) {
	t.Parallel()
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal-finish", true: "explicit-cancel"}[cancelled], func(t *testing.T) {
			t.Parallel()
			var l *publishingLab
			var r Request
			var s State
			want := Protected
			if cancelled {
				l, r, s, _ = prepareFinalizerAcceptance(t)
				want = Cancelled
			} else {
				l = newPublishingLab(t)
				r = l.request(Candidate)
				emulateKEDAFinalizers(t, l, r)
				s = l.phase(t, r, Cleaning)
				s = l.until(t, s, r, func(s State) bool { return s.ControllerStopped })
			}
			target := s.Receipts[len(s.Receipts)-1].Object
			accepted := 0
			installFinalizerHooks(t, l, durableFinalizerHooks(t, l, r, &accepted))
			raw, err := l.custom.Tracker().Get(target.Resource, target.Namespace, target.Name)
			require.NoError(t, err)
			version := raw.(*unstructured.Unstructured).GetResourceVersion()
			next, err := l.step(s, r)
			require.NoError(t, err)
			require.Equal(t, 1, accepted)
			require.Equal(t, 1, finalizerPatchCount(l, target))
			receipt := receiptFor(l.journal.load(r), target)
			require.NotNil(t, receipt.FinalizerRemoval)
			require.Equal(t, version, receipt.FinalizerRemoval.ResourceVersion)
			require.True(t, receipt.FinalizerRemoval.Completed)
			next = l.until(t, next, r, State.Terminal)
			require.Equal(t, Complete, next.Phase)
			require.Equal(t, want, next.Outcome)
		})
	}
}

func TestFinalizerPersistenceFailurePreventsAcceptanceAndPatch(t *testing.T) {
	t.Parallel()
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "write-rejected", true: "write-ack-lost"}[committed], func(t *testing.T) {
			t.Parallel()
			l, r, s, target := prepareFinalizerAcceptance(t)
			accepted := 0
			hooks := durableFinalizerHooks(t, l, r, &accepted)
			base := hooks.PersistState
			fail := true
			hooks.PersistState = func(ctx context.Context, revision uint64, next State) error {
				receipt := receiptFor(next, target)
				if fail && receipt != nil && receipt.FinalizerRemoval != nil && !receipt.FinalizerRemoval.Completed {
					fail = false
					if committed {
						require.NoError(t, base(ctx, revision, next))
					}
					return errors.New("synthetic persistence acknowledgement failure")
				}
				return base(ctx, revision, next)
			}
			installFinalizerHooks(t, l, hooks)
			_, err := l.step(s, r)
			var safe *Error
			require.ErrorAs(t, err, &safe)
			require.Equal(t, StoreRejected, safe.Kind)
			require.Zero(t, accepted)
			require.Zero(t, finalizerPatchCount(l, target))
			durable := l.journal.load(r)
			receipt := receiptFor(durable, target)
			if committed {
				require.NotNil(t, receipt.FinalizerRemoval)
				require.False(t, receipt.FinalizerRemoval.Completed)
			} else {
				require.Nil(t, receipt.FinalizerRemoval)
			}
			installFinalizerHooks(t, l, hooks)
			next, err := l.step(durable, r)
			require.NoError(t, err)
			require.Equal(t, 1, accepted)
			require.Equal(t, 1, finalizerPatchCount(l, target))
			next = l.until(t, next, r, State.Terminal)
			require.Equal(t, Complete, next.Phase)
		})
	}
}

func TestFinalizerAcceptanceRejectionRetainsIntentWithoutPatch(t *testing.T) {
	t.Parallel()
	l, r, s, target := prepareFinalizerAcceptance(t)
	accepted := 0
	hooks := durableFinalizerHooks(t, l, r, &accepted)
	installFinalizerHooks(t, l, hooks)
	l.journal.reject = "remove-finalizer"
	_, err := l.step(s, r)
	var safe *Error
	require.ErrorAs(t, err, &safe)
	require.Equal(t, StoreRejected, safe.Kind)
	require.Equal(t, 1, accepted)
	require.Zero(t, finalizerPatchCount(l, target))
	durable := l.journal.load(r)
	receipt := receiptFor(durable, target)
	require.NotNil(t, receipt.FinalizerRemoval)
	require.False(t, receipt.FinalizerRemoval.Completed)
	raw, err := l.custom.Tracker().Get(target.Resource, target.Namespace, target.Name)
	require.NoError(t, err)
	object := raw.(*unstructured.Unstructured)
	object.SetResourceVersion("changed-before-authorized-retry")
	require.NoError(t, l.custom.Tracker().Update(target.Resource, object, target.Namespace))
	l.journal.reject = ""
	installFinalizerHooks(t, l, hooks)
	next, err := l.step(durable, r)
	require.NoError(t, err)
	require.Equal(t, 2, accepted)
	require.Equal(t, 1, finalizerPatchCount(l, target))
	require.Equal(t, object.GetResourceVersion(), receiptFor(l.journal.load(r), target).FinalizerRemoval.ResourceVersion)
	next = l.until(t, next, r, State.Terminal)
	require.Equal(t, Complete, next.Phase)
}

func TestFinalizerLostPatchAckReconcilesUIDWithoutReplayingPatch(t *testing.T) {
	t.Parallel()
	l, r, s, target := prepareFinalizerAcceptance(t)
	accepted := 0
	hooks := durableFinalizerHooks(t, l, r, &accepted)
	installFinalizerHooks(t, l, hooks)
	l.custom.PrependReactor("patch", target.Resource.Resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		patch := action.(ktesting.PatchAction)
		if patch.GetName() != target.Name || patch.GetNamespace() != target.Namespace {
			return false, nil, nil
		}
		require.Equal(t, 1, accepted)
		raw, err := l.custom.Tracker().Get(target.Resource, target.Namespace, target.Name)
		require.NoError(t, err)
		object := raw.(*unstructured.Unstructured)
		require.Equal(t, target.UID, object.GetUID())
		object.SetFinalizers(nil)
		object.SetResourceVersion("patch-applied-with-lost-reply")
		require.NoError(t, l.custom.Tracker().Update(target.Resource, object, target.Namespace))
		return true, nil, errors.New("synthetic lost patch acknowledgement")
	})
	_, err := l.step(s, r)
	var safe *Error
	require.ErrorAs(t, err, &safe)
	require.Equal(t, Infrastructure, safe.Kind)
	durable := l.journal.load(r)
	require.False(t, receiptFor(durable, target).FinalizerRemoval.Completed)
	installFinalizerHooks(t, l, hooks)
	next, err := l.step(durable, r)
	require.NoError(t, err)
	require.Equal(t, 1, accepted)
	require.Equal(t, 1, finalizerPatchCount(l, target))
	require.True(t, receiptFor(l.journal.load(r), target).FinalizerRemoval.Completed)
	next = l.until(t, next, r, State.Terminal)
	require.Equal(t, Complete, next.Phase)
	require.True(t, receiptFor(next, target).Deleted)
}
