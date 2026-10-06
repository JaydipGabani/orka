package controllerlab

import (
	"context"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

func privateObserverIP(value string) bool {
	address, err := netip.ParseAddr(value)
	// The compiled worker binds IPv4. Other address families require a separately
	// qualified listener template, not an implicit DNS or dual-stack fallback.
	return err == nil && address.Is4() && address.IsPrivate() && address.String() == value
}

func imageIDMatches(actual, configured string) bool {
	for _, prefix := range []string{"docker-pullable://", "containerd://", "docker://", "cri-o://"} {
		actual = strings.TrimPrefix(actual, prefix)
	}
	wanted := "sha256:" + imageContentDigest(configured)
	return actual == wanted || imagePattern.MatchString(actual) && strings.HasSuffix(actual, "@"+wanted)
}

func observerExecutionMatches(pod *corev1.Pod, image, ip string) bool {
	return observerReady(pod) && privateObserverIP(ip) && pod.Status.PodIP == ip &&
		len(pod.Spec.Containers) == 1 && pod.Spec.Containers[0].Name == serviceName &&
		pod.Spec.Containers[0].Image == image && imageIDMatches(pod.Status.ContainerStatuses[0].ImageID, image)
}

func validObserverPin(s State, image string) bool {
	return privateObserverIP(s.ObserverPodIP) && s.ObserverImageDigest == imageContentDigest(image)
}

func (a *Adapter) checkObserverPin(ctx context.Context, s State) error {
	if !validObserverPin(s, a.config.ObserverImage) {
		return failure(InvalidState, "observer-endpoint-pin-required")
	}
	value, err := a.exact(ctx, s, ref(pods, s.ObserverNamespace, serviceName))
	if err != nil {
		return err
	}
	pod := value.(*corev1.Pod)
	if observerIdentityChanged(pod, a.config.ObserverImage, s.ObserverPodIP) {
		return failure(OwnershipLost, "observer-ip-or-image-changed")
	}
	if !observerExecutionMatches(pod, a.config.ObserverImage, s.ObserverPodIP) {
		return failure(Infrastructure, "observer-not-ready-or-restarted")
	}
	return nil
}

func observerIdentityChanged(pod *corev1.Pod, image, ip string) bool {
	if len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != serviceName ||
		pod.Spec.Containers[0].Image != image || pod.Status.PodIP != "" && pod.Status.PodIP != ip {
		return true
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == serviceName && status.ImageID != "" && !imageIDMatches(status.ImageID, image) {
			return true
		}
	}
	return false
}

func (a *Adapter) pinObserver(ctx context.Context, s State) (State, error) {
	if a.now().Sub(s.StartedAt) >= a.config.StartupTimeout {
		return a.finish(ctx, s, Inconclusive, "observer-readiness-deadline")
	}
	value, err := a.exact(ctx, s, ref(pods, s.ObserverNamespace, serviceName))
	if err != nil {
		return a.stop(ctx, s, err)
	}
	pod := value.(*corev1.Pod)
	if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded ||
		(len(pod.Status.ContainerStatuses) > 0 && pod.Status.ContainerStatuses[0].RestartCount != 0) {
		return a.stop(ctx, s, failure(Infrastructure, "observer-exited-or-restarted"))
	}
	if !observerReady(pod) {
		return a.save(ctx, s)
	}
	if !observerExecutionMatches(pod, a.config.ObserverImage, pod.Status.PodIP) {
		return a.stop(ctx, s, failure(OutsideScope, "observer-private-ip-and-image-proof-required"))
	}
	if s.ObserverPodIP == "" {
		s.ObserverPodIP = pod.Status.PodIP
		s.ObserverImageDigest = imageContentDigest(a.config.ObserverImage)
		return a.save(ctx, s)
	}
	if err := a.checkObserverPin(ctx, s); err != nil {
		return a.stop(ctx, s, err)
	}
	observation, err := a.snapshot(ctx, s)
	if err != nil {
		return a.stop(ctx, s, err)
	}
	if len(observation.HTTP) != 0 || len(observation.RESP) != 0 {
		return a.stop(ctx, s, failure(Infrastructure, "observer-not-fresh-before-launch"))
	}
	s.Phase = InstallingController
	return a.save(ctx, s)
}
