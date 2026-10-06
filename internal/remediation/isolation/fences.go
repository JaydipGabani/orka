package isolation

import (
	"context"
	"maps"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (a *Adapter) verifyCleanupAnchors(ctx context.Context, receipt Receipt) error {
	cluster, err := a.kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID != receipt.Proof.ClusterUID {
		return &Error{Code: "cluster-identity-changed"}
	}
	for _, identity := range []SubjectNamespace{receipt.Proof.SubjectNamespace, receipt.Config.ControlNamespace} {
		namespace, err := a.kube.CoreV1().Namespaces().Get(ctx, identity.Name, metav1.GetOptions{})
		if err != nil || namespace.UID != identity.UID {
			return &Error{Code: "cleanup-namespace-identity-changed"}
		}
	}
	return nil
}

func (a *Adapter) verifyAnchors(ctx context.Context, receipt Receipt) error {
	cluster, err := a.kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID != receipt.Proof.ClusterUID || cluster.DeletionTimestamp != nil {
		return &Error{Code: "cluster-identity-changed"}
	}
	subject, err := a.namespace(ctx, receipt.Proof.SubjectNamespace)
	if err != nil {
		return err
	}
	control, err := a.namespace(ctx, receipt.Config.ControlNamespace)
	if err != nil {
		return err
	}
	if !maps.Equal(subject.Labels, receipt.SubjectLabels) || !maps.Equal(control.Labels, receipt.ControlLabels) {
		return &Error{Code: "namespace-labels-changed"}
	}
	return nil
}

func (a *Adapter) verifyParentPolicies(ctx context.Context, receipt Receipt) error {
	current, err := a.subjectPolicies(ctx, receipt.Proof.SubjectNamespace.Name)
	if err != nil {
		return err
	}
	if !slices.Equal(current, receipt.Proof.SubjectPolicies) {
		return &Error{Code: "subject-policy-set-changed"}
	}
	return nil
}

func (a *Adapter) verifyInventory(ctx context.Context, receipt Receipt) error {
	if err := a.verifyControlPolicies(ctx, receipt); err != nil {
		return err
	}
	for _, namespace := range []string{receipt.Proof.SubjectNamespace.Name, receipt.Config.ControlNamespace.Name} {
		if err := a.verifyPods(ctx, receipt, namespace); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) verifyControlPolicies(ctx context.Context, receipt Receipt) error {
	list, err := a.kube.NetworkingV1().NetworkPolicies(receipt.Config.ControlNamespace.Name).List(ctx, metav1.ListOptions{Limit: 3})
	if err != nil || list.Continue != "" || len(list.Items) > 2 {
		return &Error{Code: "control-policy-set-changed"}
	}
	seen := 0
	for i := range list.Items {
		actual := &list.Items[i]
		object := findObject(receipt, policyKind, actual.Namespace, actual.Name)
		if object == nil || object.UID == "" || actual.ResourceVersion != object.ResourceVersion ||
			actual.DeletionTimestamp != nil || !matchesPolicy(receipt, *object, actual) {
			return &Error{Code: "control-policy-set-changed"}
		}
		seen++
	}
	for _, object := range receipt.Objects {
		if object.Kind == policyKind && object.UID != "" {
			seen--
		}
	}
	if seen != 0 {
		return &Error{Code: "control-policy-missing"}
	}
	return nil
}

func (a *Adapter) verifyPods(ctx context.Context, receipt Receipt, namespace string) error {
	list, err := a.kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil || list.Continue != "" || len(list.Items) > 4 {
		return &Error{Code: "probe-pod-set-changed"}
	}
	seen := 0
	for i := range list.Items {
		actual := &list.Items[i]
		object := findObject(receipt, podKind, actual.Namespace, actual.Name)
		if object == nil || object.UID == "" || actual.DeletionTimestamp != nil || !matchesPod(receipt, *object, actual) {
			return &Error{Code: "probe-pod-identity-changed"}
		}
		seen++
	}
	for _, object := range receipt.Objects {
		if object.Kind == podKind && object.Namespace == namespace && object.UID != "" {
			seen--
		}
	}
	if seen != 0 {
		return &Error{Code: "probe-pod-missing"}
	}
	return nil
}

func findObject(receipt Receipt, kind, namespace, name string) *ObjectReceipt {
	for i := range receipt.Objects {
		object := &receipt.Objects[i]
		if object.Kind == kind && object.Namespace == namespace && object.Name == name {
			return object
		}
	}
	return nil
}

func roleIndex(receipt Receipt, role string) int {
	for i, object := range receipt.Objects {
		if object.Role == role {
			return i
		}
	}
	return -1
}
