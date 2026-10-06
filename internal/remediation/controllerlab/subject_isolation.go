package controllerlab

import (
	"context"

	networkingv1 "k8s.io/api/networking/v1"
)

// SubjectIsolation identifies the exact compiled controller Pod selector and
// policy set. It is trusted parent input, never part of the model-facing plan.
type SubjectIsolation struct {
	Namespace ObjectRef
	Labels    map[string]string
	Policy    ObjectRef
	Policies  []networkingv1.NetworkPolicy
}

func (a *Adapter) SubjectIsolationTarget(state State) (SubjectIsolation, error) {
	if !digestPattern.MatchString(state.OperationDigest) {
		return SubjectIsolation{}, failure(InvalidState, "subject-isolation-state-required")
	}
	namespace := receiptFor(state, ref(namespaces, "", state.Namespaces[0]))
	if namespace == nil || namespace.Object.UID == "" {
		return SubjectIsolation{}, failure(InvalidState, "subject-namespace-receipt-required")
	}
	result := SubjectIsolation{Namespace: namespace.Object, Labels: componentLabels(state, controllerName)}
	controllerPolicy := controllerObjects(state)[0]
	for _, object := range []ObjectRef{ref(networkPolicies, state.Namespaces[0], "deny-all"), controllerPolicy} {
		receipt := receiptFor(state, object)
		if receipt == nil || receipt.Object.UID == "" {
			return SubjectIsolation{}, failure(InvalidState, "subject-policy-receipt-required")
		}
		expected := a.networkPolicy(state, metadata(state, receipt.Object, receipt.IntentDigest))
		expected.UID = receipt.Object.UID
		result.Policies = append(result.Policies, *expected)
		if sameRef(object, controllerPolicy) {
			result.Policy = receipt.Object
		}
	}
	return result, nil
}

// ValidateState verifies persisted evidence without performing a mutation or
// replaying a terminal operation.
func (a *Adapter) ValidateState(state State, request Request) error {
	binding, err := a.validateRequest(request)
	if err != nil {
		return err
	}
	return a.validateState(state, request, binding)
}

// ValidateRuntime requires the subject and trusted observer to remain ready at
// evidence acceptance. A stopped controller is never evidence of protection.
func (a *Adapter) ValidateRuntime(ctx context.Context, state State) error {
	if err := a.checkPlacementRuntime(ctx, state); err != nil {
		return err
	}
	ready, err := a.runtimeReady(ctx, state)
	if err != nil {
		return err
	}
	if !ready {
		return failure(Infrastructure, "controller-not-ready-at-observation")
	}
	if publishing(state) {
		if state.RuntimePod == nil {
			return failure(InvalidState, "runtime-pod-pin-required")
		}
		pod, err := a.livePublishingRuntime(ctx, state)
		if err != nil {
			return err
		}
		if pod == nil {
			return failure(Infrastructure, "controller-not-ready-at-observation")
		}
	}
	return nil
}
