package isolation

import (
	"maps"
	"slices"
	"strings"

	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func metadata(receipt Receipt, object ObjectReceipt) metav1.ObjectMeta {
	anchor := receipt.Config.ControlNamespace
	if object.Namespace == receipt.Proof.SubjectNamespace.Name {
		anchor = receipt.Proof.SubjectNamespace
	}
	return metav1.ObjectMeta{
		Name: object.Name, Namespace: object.Namespace,
		Annotations: map[string]string{operationKey: receipt.OperationDigest},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "v1", Kind: "Namespace", Name: anchor.Name, UID: anchor.UID, BlockOwnerDeletion: new(false),
		}},
	}
}

func owned(receipt Receipt, object ObjectReceipt, actual metav1.Object) bool {
	expected := metadata(receipt, object)
	return actual.GetName() == expected.Name && actual.GetNamespace() == expected.Namespace && actual.GetUID() != "" &&
		(object.UID == "" || object.UID == actual.GetUID()) &&
		ownedAnnotations(receipt, object, actual.GetAnnotations()) &&
		equality.Semantic.DeepEqual(actual.GetOwnerReferences(), expected.OwnerReferences)
}

func ownedAnnotations(receipt Receipt, object ObjectReceipt, annotations map[string]string) bool {
	if annotations[operationKey] != receipt.OperationDigest || len(annotations) > 4 {
		return false
	}
	for key, value := range annotations {
		if key == operationKey {
			continue
		}
		// Calico writes these observations after CNI setup. They are not
		// network-attachment or security-profile inputs; all other additions
		// remain rejected rather than trusting arbitrary admission annotations.
		if object.Kind != podKind || len(value) > 1024 ||
			!slices.Contains([]string{
				"cni.projectcalico.org/containerID", "cni.projectcalico.org/podIP", "cni.projectcalico.org/podIPs",
			}, key) {
			return false
		}
	}
	return true
}

func pod(receipt Receipt, object ObjectReceipt) *corev1.Pod {
	labels := maps.Clone(receipt.Proof.SubjectSelectorLabels)
	args := []string{"serve", "--nonce", receipt.Nonce}
	node := ""
	if object.Role == serverRole {
		labels = endpointLabels(receipt)
	} else {
		expect := probe.Reachable
		if object.Role == negativeRole {
			expect = probe.Blocked
		}
		args = []string{"connect", "--target", receipt.Proof.Endpoint.Address, "--expect", string(expect), "--nonce", receipt.Nonce}
		node = receipt.Proof.Endpoint.NodeName
	}
	p := &corev1.Pod{
		ObjectMeta: metadata(receipt, object),
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever, ActiveDeadlineSeconds: new(object.ActiveDeadlineSeconds),
			TerminationGracePeriodSeconds: new(int64(1)), NodeName: node,
			ServiceAccountName: defaultAccount, DeprecatedServiceAccount: defaultAccount, AutomountServiceAccountToken: new(false),
			EnableServiceLinks: new(false), SchedulerName: corev1.DefaultSchedulerName,
			PreemptionPolicy: new(corev1.PreemptLowerPriority), Priority: new(int32(0)),
			DNSPolicy: corev1.DNSNone, DNSConfig: &corev1.PodDNSConfig{Nameservers: []string{"127.0.0.1"}},
			OS: &corev1.PodOS{Name: corev1.Linux},
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: new(true), RunAsUser: new(int64(65532)), RunAsGroup: new(int64(65532)),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name: containerName, Image: receipt.Config.ProbeImage, ImagePullPolicy: corev1.PullIfNotPresent,
				Command: []string{"/orka-remediation-network-probe"}, Args: args,
				TerminationMessagePath: "/dev/termination-log", TerminationMessagePolicy: corev1.TerminationMessageReadFile,
				SecurityContext: &corev1.SecurityContext{
					Privileged: new(false), AllowPrivilegeEscalation: new(false), ReadOnlyRootFilesystem: new(true),
					Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("32Mi"),
					},
				},
			}},
		},
	}
	p.Labels = labels
	if object.Role == serverRole {
		p.Spec.Containers[0].Ports = []corev1.ContainerPort{{Name: "canary", ContainerPort: probe.Port, Protocol: corev1.ProtocolTCP}}
		p.Spec.Containers[0].ReadinessProbe = &corev1.Probe{
			ProbeHandler:   corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(probe.Port)}},
			TimeoutSeconds: 1, PeriodSeconds: 1, SuccessThreshold: 1, FailureThreshold: 2,
		}
	}
	return p
}

func endpointLabels(receipt Receipt) map[string]string {
	return map[string]string{endpointLabel: strings.TrimPrefix(receipt.OperationDigest, "sha256:")[:24]}
}

func policy(receipt Receipt, object ObjectReceipt) *networkingv1.NetworkPolicy {
	p := &networkingv1.NetworkPolicy{
		ObjectMeta: metadata(receipt, object),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
	port := []networkingv1.NetworkPolicyPort{{Protocol: new(corev1.ProtocolTCP), Port: new(intstr.FromInt32(probe.Port))}}
	if object.Role == guardRole {
		// Both namespaces may reach the canary's ingress. Consequently the
		// negative probe cannot mistake our own ingress policy for egress deny.
		p.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					namespaceNameKey: receipt.Config.ControlNamespace.Name,
				}},
				PodSelector: &metav1.LabelSelector{MatchLabels: maps.Clone(receipt.Proof.SubjectSelectorLabels)},
			}, {
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					namespaceNameKey: receipt.Proof.SubjectNamespace.Name,
				}},
				PodSelector: &metav1.LabelSelector{MatchLabels: maps.Clone(receipt.Proof.SubjectSelectorLabels)},
			}}, Ports: port,
		}}
		return p
	}
	p.Spec.PodSelector.MatchLabels = maps.Clone(receipt.Proof.SubjectSelectorLabels)
	p.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
	// In-cluster Pod IPs are identity-backed in CNIs such as Cilium and need
	// not match IPBlock rules. Both selectors in this peer are required (AND).
	p.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
		To: []networkingv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
				namespaceNameKey: receipt.Config.ControlNamespace.Name,
			}},
			PodSelector: &metav1.LabelSelector{MatchLabels: endpointLabels(receipt)},
		}}, Ports: port,
	}}
	return p
}

func matchesPod(receipt Receipt, object ObjectReceipt, actual *corev1.Pod) bool {
	if !owned(receipt, object, actual) {
		return false
	}
	expected := pod(receipt, object)
	if !maps.Equal(actual.Labels, expected.Labels) || !defaultTolerations(actual.Spec.Tolerations) {
		return false
	}
	spec := actual.Spec.DeepCopy()
	spec.Tolerations = nil
	if object.Role == serverRole {
		// The scheduler alone chooses the initial canary node; all three clients
		// and the subsequent parent subject must be pinned to this same node.
		spec.NodeName = ""
	}
	return equality.Semantic.DeepEqual(*spec, expected.Spec)
}

func defaultTolerations(tolerations []corev1.Toleration) bool {
	if len(tolerations) > 2 {
		return false
	}
	for _, toleration := range tolerations {
		if !slices.Contains([]string{corev1.TaintNodeNotReady, corev1.TaintNodeUnreachable}, toleration.Key) ||
			toleration.Operator != corev1.TolerationOpExists || toleration.Effect != corev1.TaintEffectNoExecute ||
			toleration.Value != "" || toleration.TolerationSeconds == nil || *toleration.TolerationSeconds != 300 {
			return false
		}
	}
	return true
}

func matchesPolicy(receipt Receipt, object ObjectReceipt, actual *networkingv1.NetworkPolicy) bool {
	return owned(receipt, object, actual) && len(actual.Labels) == 0 &&
		equality.Semantic.DeepEqual(policy(receipt, object).Spec, actual.Spec)
}
