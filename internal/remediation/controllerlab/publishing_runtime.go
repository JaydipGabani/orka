package controllerlab

import (
	"context"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (a *Adapter) livePublishingRuntime(ctx context.Context, s State) (*ObjectRef, error) {
	deployment := receiptFor(s, ref(deployments, s.Namespaces[0], controllerName))
	if deployment == nil || !validPlacement(s.Placement, s.OperationDigest) {
		return nil, failure(InvalidState, "runtime-deployment-receipt-required")
	}
	list, err := a.kube.CoreV1().Pods(s.Namespaces[0]).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(componentLabels(s, controllerName)).String(), Limit: 2,
	})
	if err != nil {
		return nil, failure(Infrastructure, "controller-pod-state-unavailable")
	}
	if len(list.Items) != 1 || list.Continue != "" {
		if s.RuntimePod != nil {
			return nil, failure(Infrastructure, "pinned-controller-pod-unavailable")
		}
		return nil, nil
	}
	pod := &list.Items[0]
	object := ref(pods, pod.Namespace, pod.Name)
	object.UID = pod.UID
	if pod.UID == "" {
		return nil, failure(Infrastructure, "controller-pod-identity-unavailable")
	}
	if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded ||
		len(pod.Status.ContainerStatuses) > 1 {
		return nil, failure(Infrastructure, "controller-exited-or-replaced")
	}
	if len(pod.Status.ContainerStatuses) == 1 && pod.Status.ContainerStatuses[0].RestartCount != 0 {
		return nil, failure(Infrastructure, "controller-exited-or-restarted")
	}
	if pod.Status.Phase != corev1.PodRunning || len(pod.Status.ContainerStatuses) != 1 ||
		!pod.Status.ContainerStatuses[0].Ready || pod.Status.ContainerStatuses[0].State.Running == nil {
		return nil, nil
	}
	if err := a.checkPublishingRuntimeOwner(ctx, pod, deployment.Object); err != nil {
		return nil, err
	}
	if s.RuntimePod != nil && object != *s.RuntimePod {
		return nil, failure(Infrastructure, "controller-pod-replaced")
	}
	if err := a.checkPublishingRuntimeSpec(s, pod); err != nil {
		return nil, err
	}
	return &object, nil
}

func (a *Adapter) checkPublishingRuntimeOwner(ctx context.Context, pod *corev1.Pod, deployment ObjectRef) error {
	owners := pod.OwnerReferences
	if len(owners) != 1 || owners[0].APIVersion != "apps/v1" || owners[0].Kind != "ReplicaSet" ||
		owners[0].UID == "" || owners[0].Controller == nil || !*owners[0].Controller {
		return failure(OwnershipLost, "controller-pod-owner-changed")
	}
	replicaSet, err := a.kube.AppsV1().ReplicaSets(deployment.Namespace).Get(ctx, owners[0].Name, metav1.GetOptions{})
	if err != nil {
		return failure(Infrastructure, "controller-replicaset-unavailable")
	}
	if replicaSet.UID != owners[0].UID || len(replicaSet.OwnerReferences) != 1 {
		return failure(OwnershipLost, "controller-replicaset-identity-changed")
	}
	if replicaSet.DeletionTimestamp != nil {
		return failure(Infrastructure, "controller-replicaset-terminating")
	}
	owner := replicaSet.OwnerReferences[0]
	if owner.APIVersion != "apps/v1" || owner.Kind != "Deployment" || owner.Name != deployment.Name ||
		owner.UID != deployment.UID || owner.Controller == nil || !*owner.Controller {
		return failure(OwnershipLost, "controller-deployment-owner-changed")
	}
	return nil
}

func (a *Adapter) checkPublishingRuntimeSpec(s State, pod *corev1.Pod) error {
	if pod.Namespace != s.Namespaces[0] || !publishingPodEnvelope(pod.Spec) || pod.Spec.NodeName != s.Placement.NodeName ||
		pod.Spec.ServiceAccountName != controllerName || pod.Spec.Containers[0].Name != controllerName ||
		pod.Status.ContainerStatuses[0].Name != controllerName ||
		imageContentDigest(pod.Spec.Containers[0].Image) != s.ImageDigest ||
		!imageIDMatches(pod.Status.ContainerStatuses[0].ImageID, pod.Spec.Containers[0].Image) {
		return failure(Infrastructure, "controller-runtime-binding-changed")
	}
	expected := a.controller(s, metav1.ObjectMeta{}, pod.Spec.Containers[0].Image).Spec.Template.Spec
	if !reflect.DeepEqual(pod.Spec.HostAliases, expected.HostAliases) ||
		!reflect.DeepEqual(pod.Spec.Containers[0].Env, expected.Containers[0].Env) ||
		!reflect.DeepEqual(pod.Spec.Containers[0].Command, expected.Containers[0].Command) ||
		!reflect.DeepEqual(pod.Spec.Containers[0].Args, expected.Containers[0].Args) {
		return failure(Infrastructure, "controller-tls-or-command-contract-changed")
	}
	return nil
}

func publishingPodEnvelope(spec corev1.PodSpec) bool {
	if spec.HostNetwork || spec.HostPID || spec.HostIPC || len(spec.Containers) != 1 ||
		len(spec.InitContainers) != 0 || len(spec.EphemeralContainers) != 0 ||
		spec.ShareProcessNamespace != nil && *spec.ShareProcessNamespace ||
		spec.HostUsers != nil && !*spec.HostUsers {
		return false
	}
	c := spec.Containers[0]
	return len(c.EnvFrom) == 0 && c.Lifecycle == nil && c.SecurityContext != nil &&
		(c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged) &&
		c.SecurityContext.Capabilities != nil && len(c.SecurityContext.Capabilities.Add) == 0
}

func (a *Adapter) validatePublishingRuntime(ctx context.Context, s State) error {
	if s.RuntimePod == nil {
		return failure(InvalidState, "runtime-pod-pin-required")
	}
	ready, err := a.runtimeReady(ctx, s)
	if err != nil {
		return err
	}
	if !ready {
		return failure(Infrastructure, "controller-not-ready-at-observation")
	}
	pod, err := a.livePublishingRuntime(ctx, s)
	if err != nil {
		return err
	}
	if pod == nil {
		return failure(Infrastructure, "controller-not-ready-at-observation")
	}
	return nil
}
