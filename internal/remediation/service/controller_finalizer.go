package service

import "github.com/orka-agents/orka/internal/remediation/controllerlab"

func controllerFinalizerRemovalAuthorized(state controllerlab.State, object controllerlab.ObjectRef) bool {
	if state.Phase != controllerlab.Cleaning || !state.ControllerStopped || object.UID == "" ||
		object.Resource.Version != "v1alpha1" {
		return false
	}
	switch object.Resource.Group {
	case "keda.sh":
		switch object.Resource.Resource {
		case "scaledobjects", "triggerauthentications", "clustertriggerauthentications":
		default:
			return false
		}
	case "eventing.keda.sh":
		if object.Resource.Resource != "cloudeventsources" && object.Resource.Resource != "clustercloudeventsources" {
			return false
		}
	default:
		return false
	}
	for _, receipt := range state.Receipts {
		if receipt.Object == object {
			return receipt.FinalizerRemoval != nil && receipt.FinalizerRemoval.ResourceVersion != "" &&
				!receipt.FinalizerRemoval.Completed && !receipt.Deleted
		}
	}
	return false
}
