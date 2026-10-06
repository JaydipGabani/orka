package controllerlab

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestFixtureDestinationsUsePinnedPrivateIPsWithoutDNSEgress(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, WaitingSources)
	require.True(t, privateObserverIP(s.ObserverPodIP))
	require.Equal(t, imageContentDigest(l.config.ObserverImage), s.ObserverImageDigest)
	for _, source := range sourceObjects(s) {
		object, err := l.custom.Resource(source.Resource).Namespace(source.Namespace).Get(context.Background(), source.Name, metav1.GetOptions{})
		require.NoError(t, err)
		uri, ok, err := unstructured.NestedString(object.Object, "spec", "destination", "http", "uri")
		require.NoError(t, err)
		require.True(t, ok)
		target, err := url.Parse(uri)
		require.NoError(t, err)
		require.Equal(t, "http", target.Scheme)
		require.Equal(t, s.ObserverPodIP, target.Hostname())
		require.Equal(t, "8080", target.Port())
		require.NotNil(t, net.ParseIP(target.Hostname()))
		require.NotContains(t, uri, ".svc")
	}
	policy, err := l.kube.NetworkingV1().NetworkPolicies(s.Namespaces[0]).Get(context.Background(), "controller-egress", metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, policy.Spec.Egress, 2)
	for _, rule := range policy.Spec.Egress {
		require.Len(t, rule.Ports, 1)
		require.Equal(t, corev1.ProtocolTCP, *rule.Ports[0].Protocol)
		require.NotEqual(t, 53, rule.Ports[0].Port.IntValue())
	}
	require.Equal(t, l.config.APIServer.CIDR, policy.Spec.Egress[0].To[0].IPBlock.CIDR)
	require.Equal(t, s.ObserverNamespace, policy.Spec.Egress[1].To[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"])
	require.Equal(t, componentLabels(s, serviceName), policy.Spec.Egress[1].To[0].PodSelector.MatchLabels)
	require.Equal(t, 8080, policy.Spec.Egress[1].Ports[0].Port.IntValue())
	deployment, err := l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.NoError(t, err)
	env := deployment.Spec.Template.Spec.Containers[0].Env
	require.Contains(t, env, corev1.EnvVar{Name: "KUBERNETES_SERVICE_HOST", Value: "10.96.0.1"})
	require.Contains(t, env, corev1.EnvVar{Name: "KUBERNETES_SERVICE_PORT", Value: "443"})
	require.Contains(t, env, corev1.EnvVar{Name: "NO_PROXY", Value: "*"})
	r.Cancel = true
	_ = l.until(t, s, r, State.Terminal)
}

func TestDNSAllowConfigurationIsExplicitlyRejected(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	config := l.config
	config.DNS = EgressEndpoint{CIDR: "10.96.0.10/32", Port: 53}
	_, err := New(config, Clients{Kubernetes: l.kube, CustomResources: l.custom, Observer: l.observer}, l.journal.hooks())
	var safe *Error
	require.ErrorAs(t, err, &safe)
	require.Equal(t, OutsideScope, safe.Kind)
	require.Empty(t, l.kube.Actions())
}

func TestObserverEndpointPinIsDurableBeforeControllerLaunch(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, WaitingObserver)
	require.Empty(t, s.ObserverPodIP)
	_, err := l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	s, err = l.step(s, r)
	require.NoError(t, err)
	require.Equal(t, WaitingObserver, s.Phase)
	require.Equal(t, "10.244.0.23", s.ObserverPodIP)
	require.Equal(t, s.ObserverPodIP, l.journal.load(r).ObserverPodIP)
	require.Equal(t, imageContentDigest(l.config.ObserverImage), s.ObserverImageDigest)
	s = l.until(t, s, r, func(s State) bool { return s.Phase == WaitingRuntime })
	r.Cancel = true
	_ = l.until(t, s, r, State.Terminal)
}

func TestObserverPinRequiresPrivateIPv4AndExactImmutableImage(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"", "1.1.1.1", "169.254.169.254", "127.0.0.1", "observer.invalid", "fd00::23", "image-spec", "image-status"} {
		t.Run("reject-"+variant, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, WaitingObserver)
			pod, err := l.kube.CoreV1().Pods(s.ObserverNamespace).Get(context.Background(), serviceName, metav1.GetOptions{})
			require.NoError(t, err)
			switch variant {
			case "image-spec":
				pod.Spec.Containers[0].Image = "registry.invalid/other@sha256:" + strings.Repeat("d", 64)
			case "image-status":
				pod.Status.ContainerStatuses[0].ImageID = "sha256:" + strings.Repeat("d", 64)
			default:
				pod.Status.PodIP = variant
			}
			require.NoError(t, l.kube.Tracker().Update(pods, pod, pod.Namespace))
			s, err = l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Inconclusive, s.Outcome)
			require.Empty(t, s.ObserverPodIP)
			require.Nil(t, receiptFor(s, ref(deployments, s.Namespaces[0], controllerName)))
		})
	}
}

func TestObserverIPOrImageDriftIsNeverFollowed(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"ip-before-launch", "ip-during-observation", "image-during-observation"} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			r := l.request(Candidate)
			phase := ObservingWindow
			if variant == "ip-before-launch" {
				phase = InstallingController
			}
			s := l.phase(t, r, phase)
			pinned := s.ObserverPodIP
			pod, err := l.kube.CoreV1().Pods(s.ObserverNamespace).Get(context.Background(), serviceName, metav1.GetOptions{})
			require.NoError(t, err)
			if variant == "image-during-observation" {
				pod.Status.ContainerStatuses[0].ImageID = "sha256:" + strings.Repeat("f", 64)
			} else {
				pod.Status.PodIP = "10.244.0.99"
			}
			require.NoError(t, l.kube.Tracker().Update(pods, pod, pod.Namespace))
			s, err = l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Quarantined, s.Phase)
			require.Equal(t, Inconclusive, s.Outcome)
			require.Equal(t, pinned, s.ObserverPodIP)
		})
	}
}
