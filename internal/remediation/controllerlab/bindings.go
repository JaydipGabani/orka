package controllerlab

import (
	"context"
	"encoding/json"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const kedaFinalizer = "finalizer.keda.sh"

func kedaFixture(resource schema.GroupVersionResource) bool {
	switch resource {
	case scaledObjects, cloudEventSources, clusterEventSources, triggerAuthentications, clusterAuthentications:
		return true
	default:
		return false
	}
}

func fixtureBinding(resource schema.GroupVersionResource) bool {
	return kedaFixture(resource) || resource == secrets || resource == configMaps
}

func bindingShape(object runtime.Object, withUID bool) (map[string]any, error) {
	raw, err := json.Marshal(object)
	if err != nil {
		return nil, failure(Infrastructure, "binding-encoding-unavailable")
	}
	defer clear(raw)
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		return nil, failure(Infrastructure, "binding-encoding-unavailable")
	}
	delete(result, "status")
	metadata, ok := result["metadata"].(map[string]any)
	if !ok {
		return nil, failure(Infrastructure, "binding-metadata-unavailable")
	}
	for _, key := range []string{"creationTimestamp", "resourceVersion", "generation", "managedFields", "deletionTimestamp", "deletionGracePeriodSeconds"} {
		delete(metadata, key)
	}
	if !withUID {
		delete(metadata, "uid")
	}
	if finalizers, ok := metadata["finalizers"].([]any); ok {
		remaining := make([]any, 0, len(finalizers))
		for _, value := range finalizers {
			if value != kedaFinalizer {
				remaining = append(remaining, value)
			}
		}
		if len(remaining) == 0 {
			delete(metadata, "finalizers")
		} else {
			metadata["finalizers"] = remaining
		}
	}
	return result, nil
}

func resourceBindingDigest(object runtime.Object) (string, error) {
	shape, err := bindingShape(object, true)
	if err != nil {
		return "", err
	}
	return digest(shape), nil
}

func exactKEDATemplate(desired, actual runtime.Object) bool {
	want, err := bindingShape(desired, false)
	if err != nil {
		return false
	}
	have, err := bindingShape(actual, false)
	return err == nil && reflect.DeepEqual(want, have)
}

func (a *Adapter) validateFixtureBindings(ctx context.Context, s State) (string, error) {
	bindings := make([]struct {
		Object ObjectRef
		Digest string
	}, 0, 19)
	for _, receipt := range s.Receipts {
		if !fixtureBinding(receipt.Object.Resource) {
			continue
		}
		if receipt.Deleted || receipt.DeleteRequested || !digestPattern.MatchString(receipt.BindingDigest) {
			return "", failure(Infrastructure, "fixture-binding-receipt-required")
		}
		object, err := a.get(ctx, receipt.Object)
		if err != nil {
			return "", failure(Infrastructure, "fixture-binding-unavailable")
		}
		m, err := objectMetadata(object)
		if err != nil || m.GetUID() != receipt.Object.UID {
			return "", failure(OwnershipLost, "fixture-binding-uid-changed")
		}
		current, err := resourceBindingDigest(object)
		if err != nil {
			return "", err
		}
		if m.GetDeletionTimestamp() != nil || current != receipt.BindingDigest {
			return "", failure(Infrastructure, "fixture-spec-ref-or-metadata-changed")
		}
		bindings = append(bindings, struct {
			Object ObjectRef
			Digest string
		}{receipt.Object, current})
	}
	return digest(bindings), nil
}
