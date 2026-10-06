package isolation

import (
	"context"
	"math"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (a *Adapter) create(ctx context.Context, receipt *Receipt, role string, persist ReceiptCallback) error {
	index := roleIndex(*receipt, role)
	if index < 0 {
		return &Error{Code: "invalid-resource-role"}
	}
	object := &receipt.Objects[index]
	if object.UID != "" || object.CreateAttempted {
		return &Error{Code: "create-acknowledgement-required"}
	}
	if object.Kind == podKind {
		object.ActiveDeadlineSeconds = max(1, int64(math.Ceil(receipt.Deadline.Sub(a.now()).Seconds())))
		if object.ActiveDeadlineSeconds > int64(time.Minute/time.Second) {
			return &Error{Code: "invalid-pod-deadline"}
		}
	}
	object.CreateAttempted = true
	if err := save(ctx, receipt, persist); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return &Error{Code: contextEnded}
	}
	var actual metav1.Object
	var matched bool
	switch object.Kind {
	case podKind:
		created, err := a.kube.CoreV1().Pods(object.Namespace).Create(ctx, pod(*receipt, *object), metav1.CreateOptions{})
		if err != nil {
			return &Error{Code: "pod-create-not-acknowledged"}
		}
		actual, matched = created, matchesPod(*receipt, *object, created)
	case policyKind:
		created, err := a.kube.NetworkingV1().NetworkPolicies(object.Namespace).Create(ctx, policy(*receipt, *object), metav1.CreateOptions{})
		if err != nil {
			return &Error{Code: "control-policy-create-not-acknowledged"}
		}
		actual, matched = created, matchesPolicy(*receipt, *object, created)
	default:
		return &Error{Code: "invalid-resource-kind"}
	}
	object.UID, object.ResourceVersion = actual.GetUID(), actual.GetResourceVersion()
	if err := save(ctx, receipt, persist); err != nil {
		return err
	}
	if !matched || object.UID == "" || object.ResourceVersion == "" {
		return &Error{Code: "created-resource-identity-mismatch"}
	}
	return nil
}
