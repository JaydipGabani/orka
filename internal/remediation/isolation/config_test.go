package isolation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
)

func TestOperatorConfigFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"mutable-image", func(f *fixture) { f.config.ProbeImage = "trusted:latest" }},
		{"missing-image", func(f *fixture) { f.config.ProbeImage = "" }},
		{"oversized-timeout", func(f *fixture) { f.config.Timeout = time.Minute + time.Nanosecond }},
		{"missing-subject-uid", func(f *fixture) { f.subject.UID = "" }},
		{"missing-control-uid", func(f *fixture) { f.config.ControlNamespace.UID = "" }},
		{"same-namespace", func(f *fixture) { f.config.ControlNamespace = f.subject }},
		{"system-namespace", func(f *fixture) { f.config.ControlNamespace.Name = "kube-system" }},
		{"missing-policy-uid", func(f *fixture) { f.policy.UID = "" }},
		{"missing-policy-version", func(f *fixture) { f.policy.ResourceVersion = "" }},
		{"wrong-policy-digest", func(f *fixture) { f.policy.Digest = "sha256:" + strings.Repeat("f", 64) }},
		{"invalid-label", func(f *fixture) { f.labels["bad label"] = "value" }},
		{"reserved-label", func(f *fixture) { f.labels[endpointLabel] = "value" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			test.mutate(f)
			_, err := f.adapter().Start(context.Background(), f.config, "run-1", "operation-1", f.subject, f.labels, f.policy, f.store.persist)
			require.ErrorContains(t, err, "needs-adapter")
			require.Empty(t, mutations(f.kube))
		})
	}
	_, err := New(nil)
	require.Error(t, err)
	var nilClient *fake.Clientset
	_, err = New(nilClient)
	require.Error(t, err)
}

func TestProbePodsAreCredentialFreeResourceBoundedAndSameSelector(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool {
		return r.Phase == PositiveAfter && r.Objects[roleIndex(r, afterRole)].UID != ""
	})
	for _, object := range receipt.Objects {
		if object.Kind != podKind {
			continue
		}
		actual, err := f.kube.CoreV1().Pods(object.Namespace).Get(context.Background(), object.Name, metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, corev1.RestartPolicyNever, actual.Spec.RestartPolicy)
		require.False(t, *actual.Spec.AutomountServiceAccountToken)
		require.False(t, *actual.Spec.EnableServiceLinks)
		require.False(t, actual.Spec.HostNetwork)
		require.False(t, actual.Spec.HostPID)
		require.False(t, actual.Spec.HostIPC)
		require.True(t, *actual.Spec.SecurityContext.RunAsNonRoot)
		require.Equal(t, int64(65532), *actual.Spec.SecurityContext.RunAsUser)
		require.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, actual.Spec.SecurityContext.SeccompProfile.Type)
		require.Empty(t, actual.Spec.Volumes)
		require.Empty(t, actual.Spec.ImagePullSecrets)
		require.Empty(t, actual.Spec.InitContainers)
		require.Len(t, actual.Spec.Containers, 1)
		require.Equal(t, corev1.DNSNone, actual.Spec.DNSPolicy)
		require.LessOrEqual(t, *actual.Spec.ActiveDeadlineSeconds, int64(60))
		container := actual.Spec.Containers[0]
		require.Empty(t, container.Env)
		require.Empty(t, container.EnvFrom)
		require.Empty(t, container.VolumeMounts)
		require.True(t, *container.SecurityContext.ReadOnlyRootFilesystem)
		require.False(t, *container.SecurityContext.AllowPrivilegeEscalation)
		require.Equal(t, []corev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
		require.Equal(t, f.config.ProbeImage, container.Image)
		require.Equal(t, int64(100), container.Resources.Limits.Cpu().MilliValue())
		require.Equal(t, int64(32*1024*1024), container.Resources.Limits.Memory().Value())
		require.Equal(t, corev1.TerminationMessageReadFile, container.TerminationMessagePolicy)
		if object.Role == serverRole {
			require.Equal(t, int32(probe.Port), container.ReadinessProbe.TCPSocket.Port.IntVal)
		} else {
			require.Equal(t, receipt.Proof.SubjectSelectorLabels, actual.Labels)
			require.Equal(t, receipt.Proof.Endpoint.NodeName, actual.Spec.NodeName)
			require.Contains(t, container.Args, receipt.Proof.Endpoint.Address)
		}
		require.Equal(t, "Namespace", actual.OwnerReferences[0].Kind)
	}
	allow := receipt.Objects[roleIndex(receipt, allowRole)]
	allowPolicy, err := f.kube.NetworkingV1().NetworkPolicies(allow.Namespace).Get(context.Background(), allow.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, allowPolicy.Spec.Egress, 1)
	require.Nil(t, allowPolicy.Spec.Egress[0].To[0].IPBlock)
	require.Equal(t, int32(probe.Port), allowPolicy.Spec.Egress[0].Ports[0].Port.IntVal)
	guard := receipt.Objects[roleIndex(receipt, guardRole)]
	guardPolicy, err := f.kube.NetworkingV1().NetworkPolicies(guard.Namespace).Get(context.Background(), guard.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Empty(t, guardPolicy.Spec.Egress)
	require.Len(t, guardPolicy.Spec.Ingress[0].From, 2)
	require.Equal(t, f.subject.Name, guardPolicy.Spec.Ingress[0].From[1].NamespaceSelector.MatchLabels[namespaceNameKey])
	f.clean(receipt)
	f.noLeaks()
}

func TestPositiveEgressSelectsOnlyOwnedCanary(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool {
		return r.Objects[roleIndex(r, allowRole)].UID != ""
	})
	allow := receipt.Objects[roleIndex(receipt, allowRole)]
	actual, err := f.kube.NetworkingV1().NetworkPolicies(allow.Namespace).Get(context.Background(), allow.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, f.config.ControlNamespace.Name, actual.Namespace)
	require.Equal(t, receipt.Proof.SubjectSelectorLabels, actual.Spec.PodSelector.MatchLabels)
	require.Len(t, actual.Spec.Egress, 1)
	rule := actual.Spec.Egress[0]
	require.Len(t, rule.To, 1)
	require.Len(t, rule.Ports, 1)
	require.Equal(t, corev1.ProtocolTCP, *rule.Ports[0].Protocol)
	require.Equal(t, int32(probe.Port), rule.Ports[0].Port.IntVal)
	require.Nil(t, rule.Ports[0].EndPort)
	peer := rule.To[0]
	require.Nil(t, peer.IPBlock)
	require.NotNil(t, peer.NamespaceSelector)
	require.NotNil(t, peer.PodSelector)
	require.Equal(t, map[string]string{namespaceNameKey: receipt.Config.ControlNamespace.Name}, peer.NamespaceSelector.MatchLabels)
	require.Equal(t, map[string]string{
		endpointLabel: strings.TrimPrefix(receipt.OperationDigest, "sha256:")[:24],
	}, peer.PodSelector.MatchLabels)
	require.Empty(t, peer.NamespaceSelector.MatchExpressions)
	require.Empty(t, peer.PodSelector.MatchExpressions)

	namespaceSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
	require.NoError(t, err)
	podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
	require.NoError(t, err)
	server := receipt.Objects[roleIndex(receipt, serverRole)]
	canary, err := f.kube.CoreV1().Pods(server.Namespace).Get(context.Background(), server.Name, metav1.GetOptions{})
	require.NoError(t, err)
	for _, test := range []struct {
		name      string
		namespace string
		podLabels map[string]string
		matches   bool
	}{
		{"exact-canary", receipt.Config.ControlNamespace.Name, canary.Labels, true},
		{"same-label-other-namespace", receipt.Proof.SubjectNamespace.Name, canary.Labels, false},
		{"unrelated-namespace", "unrelated", canary.Labels, false},
		{"positive-client", receipt.Config.ControlNamespace.Name, receipt.Proof.SubjectSelectorLabels, false},
		{"unlabeled-pod", receipt.Config.ControlNamespace.Name, nil, false},
		{"other-canary-generation", receipt.Config.ControlNamespace.Name, map[string]string{endpointLabel: "other-generation"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := namespaceSelector.Matches(labels.Set{namespaceNameKey: test.namespace}) &&
				podSelector.Matches(labels.Set(test.podLabels))
			require.Equal(t, test.matches, selected)
		})
	}
	positive := pod(receipt, receipt.Objects[roleIndex(receipt, beforeRole)])
	require.Equal(t, receipt.Proof.Endpoint.Address, positive.Spec.Containers[0].Args[2])
	require.Equal(t, canary.UID, receipt.Proof.Endpoint.Pod.UID)
	subjectPolicy, err := f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Get(context.Background(), f.policy.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, f.policy, policyIdentity(subjectPolicy))
	f.clean(receipt)
	f.noLeaks()
}

func TestCleanupRetainsUIDFenceForPreviousIPBlockPolicy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool {
		return r.Objects[roleIndex(r, allowRole)].UID != ""
	})
	allow := receipt.Objects[roleIndex(receipt, allowRole)]
	previous, err := f.kube.NetworkingV1().NetworkPolicies(allow.Namespace).Get(context.Background(), allow.Name, metav1.GetOptions{})
	require.NoError(t, err)
	previous.Spec.Egress[0].To = []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "10.23.42.7/32"}}}
	_, err = f.kube.NetworkingV1().NetworkPolicies(allow.Namespace).Update(context.Background(), previous, metav1.UpdateOptions{})
	require.NoError(t, err)
	receipt = f.clean(receipt)
	require.True(t, receipt.CleanupComplete)
	require.False(t, receipt.Proof.Verified)
	f.noLeaks()
}

func TestSelectorMismatchCannotProbeDifferentSubject(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	policy, err := f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Get(context.Background(), f.policy.Name, metav1.GetOptions{})
	require.NoError(t, err)
	policy.Spec.PodSelector.MatchLabels = map[string]string{"component": "different-subject"}
	policy, err = f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Update(context.Background(), policy, metav1.UpdateOptions{})
	require.NoError(t, err)
	f.policy = policyIdentity(policy)
	_, err = f.adapter().Start(context.Background(), f.config, "run-1", "operation-1", f.subject, f.labels, f.policy, f.store.persist)
	require.ErrorContains(t, err, "subject-policy-mismatch")
}

func TestCNIStatusAnnotationsDoNotWeakenPodIntent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool { return r.Phase == PositiveBefore })
	object := receipt.Objects[roleIndex(receipt, serverRole)]
	actual, err := f.kube.CoreV1().Pods(object.Namespace).Get(context.Background(), object.Name, metav1.GetOptions{})
	require.NoError(t, err)
	actual.Annotations["cni.projectcalico.org/containerID"] = "synthetic-container"
	actual.Annotations["cni.projectcalico.org/podIP"] = "10.23.42.7/32"
	actual.Annotations["cni.projectcalico.org/podIPs"] = "10.23.42.7/32"
	require.True(t, matchesPod(receipt, object, actual))
	delete(actual.Annotations, "cni.projectcalico.org/containerID")
	actual.Annotations["k8s.v1.cni.cncf.io/networks"] = "unapproved-network"
	require.False(t, matchesPod(receipt, object, actual))
	delete(actual.Annotations, "k8s.v1.cni.cncf.io/networks")
	actual.Annotations[operationKey] = "different-operation"
	require.False(t, matchesPod(receipt, object, actual))
}
