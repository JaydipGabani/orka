package service

import (
	"testing"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestFinalizerRemovalRequiresStoppedSubjectAndExactReceipt(t *testing.T) {
	object := controllerlab.ObjectRef{
		Resource:  schema.GroupVersionResource{Group: "eventing.keda.sh", Version: "v1alpha1", Resource: "cloudeventsources"},
		Namespace: "synthetic", Name: "source", UID: "source-uid",
	}
	state := controllerlab.State{Phase: controllerlab.Cleaning, ControllerStopped: true,
		Receipts: []controllerlab.Receipt{{
			Object: object, FinalizerRemoval: &controllerlab.FinalizerRemoval{ResourceVersion: "17"},
		}},
	}
	require.True(t, controllerFinalizerRemovalAuthorized(state, object))
	for _, change := range []func(*controllerlab.State){
		func(s *controllerlab.State) { s.ControllerStopped = false },
		func(s *controllerlab.State) { s.Phase = controllerlab.ObservingFinal },
		func(s *controllerlab.State) { s.Receipts = nil },
		func(s *controllerlab.State) { s.Receipts[0].Object.UID = "other-uid" },
		func(s *controllerlab.State) { s.Receipts[0].FinalizerRemoval = nil },
		func(s *controllerlab.State) { s.Receipts[0].FinalizerRemoval.Completed = true },
	} {
		changed := state
		receipt := state.Receipts[0]
		removal := *receipt.FinalizerRemoval
		receipt.FinalizerRemoval = &removal
		changed.Receipts = []controllerlab.Receipt{receipt}
		change(&changed)
		require.False(t, controllerFinalizerRemovalAuthorized(changed, object))
	}
	unrelated := object
	unrelated.Resource = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	state.Receipts[0].Object = unrelated
	require.False(t, controllerFinalizerRemovalAuthorized(state, unrelated), "the hook is not a general finalizer-removal API")
}
