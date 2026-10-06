package controllerlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	runLabel           = "controllerlab.orka.ai/operation"
	componentLabel     = "controllerlab.orka.ai/component"
	intentAnnotation   = "controllerlab.orka.ai/intent"
	observerPort       = int32(8443)
	observerWorkerPort = int32(8080)
	serviceName        = "observer"
	controllerName     = "controller"
	canaryName         = "synthetic-shared-key"
	adminSecretName    = "observer-private"
	controllerTLSName  = "controller-tls"
	httpScheme         = "http"
	httpsScheme        = "https"
	kedaAPIGroup       = "keda.sh"
	kedaAPIVersion     = "v1alpha1"
	getVerb            = "get"
	createVerb         = "create"
	objectNameKey      = "name"
	objectKindKey      = "kind"
	authKind           = "TriggerAuthentication"
	clusterAuthKind    = "ClusterTriggerAuthentication"
	httpARoute         = "/events/a"
	httpBRoute         = "/events/b"
	metricRoute        = "/metric"
)

var (
	namespaces             = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	secrets                = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	configMaps             = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	pods                   = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	serviceAccounts        = schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}
	deployments            = schema.GroupVersionResource{Group: appsv1.GroupName, Version: "v1", Resource: "deployments"}
	networkPolicies        = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	roles                  = schema.GroupVersionResource{Group: rbacv1.GroupName, Version: "v1", Resource: "roles"}
	roleBindings           = schema.GroupVersionResource{Group: rbacv1.GroupName, Version: "v1", Resource: "rolebindings"}
	clusterRoles           = schema.GroupVersionResource{Group: rbacv1.GroupName, Version: "v1", Resource: "clusterroles"}
	clusterRoleBindings    = schema.GroupVersionResource{Group: rbacv1.GroupName, Version: "v1", Resource: "clusterrolebindings"}
	scaledObjects          = schema.GroupVersionResource{Group: kedaAPIGroup, Version: kedaAPIVersion, Resource: "scaledobjects"}
	triggerAuthentications = schema.GroupVersionResource{Group: kedaAPIGroup, Version: kedaAPIVersion, Resource: "triggerauthentications"}
	cloudEventSources      = schema.GroupVersionResource{Group: "eventing.keda.sh", Version: kedaAPIVersion, Resource: "cloudeventsources"}
	clusterAuthentications = schema.GroupVersionResource{Group: kedaAPIGroup, Version: kedaAPIVersion, Resource: "clustertriggerauthentications"}
	clusterEventSources    = schema.GroupVersionResource{Group: "eventing.keda.sh", Version: kedaAPIVersion, Resource: "clustercloudeventsources"}
)

func ref(gvr schema.GroupVersionResource, namespace, name string) ObjectRef {
	return ObjectRef{Resource: gvr, Namespace: namespace, Name: name}
}

// KEDAClusterWatchRules is the complete operator-installed role contract.
// KEDA installs these two global informers even for exclusively namespaced
// scenarios. There is deliberately no permission to mutate global sources.
func KEDAClusterWatchRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{APIGroups: []string{clusterAuthentications.Group}, Resources: []string{clusterAuthentications.Resource}, Verbs: readVerbs()},
		{APIGroups: []string{clusterEventSources.Group}, Resources: []string{clusterEventSources.Resource}, Verbs: readVerbs()},
	}
}

func readVerbs() []string { return []string{getVerb, "list", "watch"} }

func reconciliationVerbs() []string { return []string{"update", "patch"} }

func preparation(s State) []ObjectRef {
	a, b, observer := s.Namespaces[0], s.Namespaces[1], s.ObserverNamespace
	result := []ObjectRef{
		ref(namespaces, "", a), ref(namespaces, "", b), ref(namespaces, "", observer),
		ref(networkPolicies, a, "deny-all"), ref(networkPolicies, b, "deny-all"),
		ref(networkPolicies, observer, "deny-all"),
		ref(networkPolicies, observer, "observer-ingress"),
		ref(serviceAccounts, a, controllerName),
		ref(roles, a, controllerName), ref(roles, b, controllerName),
		ref(roleBindings, a, controllerName), ref(roleBindings, b, controllerName),
		ref(clusterRoleBindings, "", a+"-watch"),
		ref(secrets, a, canaryName),
	}
	if publishing(s) {
		result = append(result, ref(secrets, b, canaryName),
			ref(clusterRoles, "", publishingRoleName(s)), ref(clusterRoleBindings, "", publishingRoleName(s)))
	}
	result = append(result, ref(secrets, observer, adminSecretName), ref(secrets, a, controllerTLSName))
	if publishing(s) {
		result = append(result, ref(configMaps, a, observerTrustName))
	}
	return append(result, ref(configMaps, observer, "observer-config"), ref(pods, observer, serviceName))
}

func controllerObjects(s State) []ObjectRef {
	return []ObjectRef{
		ref(networkPolicies, s.Namespaces[0], "controller-egress"),
		ref(deployments, s.Namespaces[0], controllerName),
	}
}

func ownedNamespaces(s State) []string {
	return []string{s.Namespaces[0], s.Namespaces[1], s.ObserverNamespace}
}

func sourceObjects(s State) []ObjectRef {
	if publishing(s) {
		return publishingSourceObjects(s)
	}
	return []ObjectRef{ref(cloudEventSources, s.Namespaces[0], "scope-source"), ref(cloudEventSources, s.Namespaces[1], "scope-source")}
}

func fixtureObjects(s State, final bool) []ObjectRef {
	round := "initial"
	if final {
		round = "final"
	}
	result := []ObjectRef{
		ref(scaledObjects, s.Namespaces[0], "scope-a-"+round),
		ref(scaledObjects, s.Namespaces[1], "scope-b-"+round),
	}
	if publishing(s) && final {
		for i := range result {
			// Future subjects are revealed only when these objects exist.
			// Seeing namespace A's challenge does not predict B's.
			result[i].Name += "-" + bytesDigest([]byte(s.FinalMarkerNonce + result[i].Namespace))[:24]
		}
	}
	return result
}

func allObjects(s State) []ObjectRef {
	result := preparation(s)
	result = append(result, controllerObjects(s)...)
	result = append(result, sourceObjects(s)...)
	result = append(result, fixtureObjects(s, false)...)
	return append(result, fixtureObjects(s, true)...)
}

func phaseObjects(s State) []ObjectRef {
	switch s.Phase {
	case Preparing:
		return preparation(s)
	case InstallingController:
		return controllerObjects(s)
	case InstallingSources:
		return sourceObjects(s)
	case InstallingInitial:
		return fixtureObjects(s, false)
	case InstallingFinal:
		return fixtureObjects(s, true)
	default:
		return nil
	}
}

func sameRef(a, b ObjectRef) bool {
	a.UID, b.UID = "", ""
	return a == b
}

func receiptFor(s State, object ObjectRef) *Receipt {
	for _, receipt := range s.Receipts {
		if sameRef(receipt.Object, object) {
			return &receipt
		}
	}
	return nil
}

func namespaceOwner(s State, object ObjectRef) []metav1.OwnerReference {
	if object.Resource == namespaces {
		return nil
	}
	namespace := object.Namespace
	if namespace == "" {
		namespace = s.Namespaces[0]
	}
	receipt := receiptFor(s, ref(namespaces, "", namespace))
	if receipt == nil {
		return nil
	}
	return []metav1.OwnerReference{{
		APIVersion: "v1", Kind: "Namespace", Name: namespace, UID: receipt.Object.UID,
	}}
}

func metadata(s State, object ObjectRef, intent string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: object.Name, Namespace: object.Namespace,
		Labels:          map[string]string{runLabel: s.OperationDigest[:40]},
		Annotations:     map[string]string{intentAnnotation: intent},
		OwnerReferences: namespaceOwner(s, object),
	}
}

func (a *Adapter) build(ctx context.Context, s State, binding ImageBinding, intent Intent, existing runtime.Object) (runtime.Object, error) {
	object := intent.Object
	m := metadata(s, object, intent.Digest)
	switch object.Resource {
	case namespaces:
		m.Labels["pod-security.kubernetes.io/enforce"] = "restricted"
		m.Labels["pod-security.kubernetes.io/audit"] = "restricted"
		return &corev1.Namespace{ObjectMeta: m}, nil
	case networkPolicies:
		if m.Name == "controller-egress" && !validObserverPin(s, a.config.ObserverImage) {
			return nil, failure(InvalidState, "observer-endpoint-pin-required")
		}
		return a.networkPolicy(s, m), nil
	case serviceAccounts:
		return &corev1.ServiceAccount{ObjectMeta: m, AutomountServiceAccountToken: new(false)}, nil
	case roles:
		rules := namespacedRules()
		if publishing(s) {
			// The public TriggerAuthentication controller maintains this exact
			// synthetic object's finalizer; no other auth object may be changed.
			rules = append(rules, rbacv1.PolicyRule{
				APIGroups: []string{kedaAPIGroup}, Resources: []string{triggerAuthentications.Resource},
				ResourceNames: []string{publishingAuthName}, Verbs: reconciliationVerbs(),
			})
		}
		return &rbacv1.Role{ObjectMeta: m, Rules: rules}, nil
	case clusterRoles:
		if !publishing(s) || m.Name != publishingRoleName(s) {
			return nil, failure(InvalidState, "unapproved-cluster-role")
		}
		return &rbacv1.ClusterRole{ObjectMeta: m, Rules: publishingClusterRules(s)}, nil
	case roleBindings:
		return &rbacv1.RoleBinding{ObjectMeta: m,
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: controllerName},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: controllerName, Namespace: s.Namespaces[0]}},
		}, nil
	case clusterRoleBindings:
		roleName := a.config.Template.ClusterWatchRole.Name
		if publishing(s) && m.Name == publishingRoleName(s) {
			roleName = publishingRoleName(s)
		}
		return &rbacv1.ClusterRoleBinding{ObjectMeta: m,
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: roleName},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: controllerName, Namespace: s.Namespaces[0]}},
		}, nil
	case secrets:
		return a.secret(s, m, existing)
	case configMaps:
		return a.configMap(ctx, s, m)
	case pods:
		return a.observerPod(s, m), nil
	case deployments:
		if !validPlacement(s.Placement, s.OperationDigest) {
			return nil, failure(InvalidState, "trusted-subject-placement-required")
		}
		return a.controller(s, m, binding.Image), nil
	case cloudEventSources, triggerAuthentications, clusterAuthentications, clusterEventSources, scaledObjects:
		return a.buildKEDAObject(s, m, object)
	}
	return nil, failure(InvalidState, "unknown-compiled-resource")
}

func (a *Adapter) buildKEDAObject(s State, m metav1.ObjectMeta, object ObjectRef) (runtime.Object, error) {
	switch object.Resource {
	case cloudEventSources:
		if !validObserverPin(s, a.config.ObserverImage) {
			return nil, failure(InvalidState, "observer-endpoint-pin-required")
		}
		if publishing(s) && m.Name != "scope-source" {
			return publishingEventSource(s, m), nil
		}
		channel := "a"
		if object.Namespace == s.Namespaces[1] {
			channel = "b"
		}
		return customObject("eventing.keda.sh/v1alpha1", "CloudEventSource", m, map[string]any{
			"clusterName": "orka-controllerlab",
			"destination": map[string]any{httpScheme: map[string]any{
				"uri": "http://" + net.JoinHostPort(s.ObserverPodIP, strconv.Itoa(int(observerWorkerPort))) + "/events/" + channel,
			}},
			"eventSubscription": map[string]any{"includedEventTypes": []any{"keda.scaledobject.failed.v1"}},
		}), nil
	case triggerAuthentications, clusterAuthentications:
		if !publishing(s) {
			return nil, failure(InvalidState, "unapproved-authentication-fixture")
		}
		kind := authKind
		if object.Resource == clusterAuthentications {
			kind = clusterAuthKind
		}
		return customObject("keda.sh/v1alpha1", kind, m, publishingAuthSpec()), nil
	case clusterEventSources:
		if !publishing(s) || !validObserverPin(s, a.config.ObserverImage) {
			return nil, failure(InvalidState, "unapproved-global-event-fixture")
		}
		return publishingEventSource(s, m), nil
	case scaledObjects:
		// A missing, run-owned target is KEDA's public event-source test pattern.
		// It produces a positive failed.v1 CloudEvent, not a workload exit code.
		if publishing(s) {
			m.Labels["scaledobject.keda.sh/name"] = m.Name
		}
		return customObject("keda.sh/v1alpha1", "ScaledObject", m, map[string]any{
			"scaleTargetRef": map[string]any{objectNameKey: "deliberately-absent"},
			"triggers": []any{map[string]any{"type": "kubernetes-workload", "metadata": map[string]any{
				"podSelector": "controllerlab.orka.ai/nonexistent=true", "value": "1", "activationValue": "3",
			}}},
		}), nil
	}
	return nil, failure(InvalidState, "unknown-compiled-resource")
}

func customObject(apiVersion, kind string, metadata metav1.ObjectMeta, spec map[string]any) *unstructured.Unstructured {
	meta, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(&metadata)
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion, objectKindKey: kind, "metadata": meta, "spec": spec,
	}}
}

func namespacedRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{APIGroups: []string{kedaAPIGroup}, Resources: []string{scaledObjects.Resource, "scaledjobs", triggerAuthentications.Resource}, Verbs: readVerbs()},
		{APIGroups: []string{cloudEventSources.Group}, Resources: []string{cloudEventSources.Resource}, Verbs: readVerbs()},
		// These writes maintain reconciliation status and finalizers on fixtures.
		{APIGroups: []string{kedaAPIGroup}, Resources: []string{scaledObjects.Resource, "scaledobjects/status", "scaledobjects/finalizers", "scaledjobs/status", "triggerauthentications/status"}, Verbs: reconciliationVerbs()},
		{APIGroups: []string{cloudEventSources.Group}, Resources: []string{cloudEventSources.Resource, "cloudeventsources/status", "cloudeventsources/finalizers"}, Verbs: reconciliationVerbs()},
		{APIGroups: []string{appsv1.GroupName}, Resources: []string{"deployments", "deployments/scale", "statefulsets", "statefulsets/scale"}, Verbs: readVerbs()},
		{APIGroups: []string{"autoscaling"}, Resources: []string{"horizontalpodautoscalers"}, Verbs: readVerbs()},
		{APIGroups: []string{""}, Resources: []string{pods.Resource}, Verbs: readVerbs()},
		// Kubernetes event recording is necessary to the same reconciliation path.
		{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{createVerb, "patch"}},
		// KEDA Secret informers may run in both watched namespaces. The observer
		// and its private material live in a THIRD, unwatched namespace.
		{APIGroups: []string{""}, Resources: []string{secrets.Resource}, Verbs: readVerbs()},
	}
}

func componentLabels(s State, component string) map[string]string {
	return map[string]string{runLabel: s.OperationDigest[:40], componentLabel: component}
}

func observerDNS(s State) string { return serviceName + "." + s.ObserverNamespace + ".svc" }

func subject(s State, index int, final bool) string {
	f := fixtureObjects(s, final)[index]
	return "/orka-controllerlab/" + f.Namespace + "/scaledobject/" + f.Name
}

func (a *Adapter) networkPolicy(s State, m metav1.ObjectMeta) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{ObjectMeta: m, Spec: networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
	}}
	tcp := corev1.ProtocolTCP
	workerPorts := []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: new(intstr.FromInt32(observerWorkerPort))}}
	if publishing(s) {
		workerPorts = append(workerPorts, networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: new(intstr.FromInt32(observerTLSPort))})
	}
	if m.Name == "controller-egress" {
		policy.Spec.PodSelector.MatchLabels = componentLabels(s, controllerName)
		policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
		policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
			To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: a.config.APIServer.CIDR}}},
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: new(intstr.FromInt32(a.config.APIServer.Port))}},
		}, {
			// Keep namespace/pod selectors as well as a pinned destination URI:
			// an old Pod IP must not become an allowed unrelated endpoint on reuse.
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					"kubernetes.io/metadata.name": s.ObserverNamespace, runLabel: s.OperationDigest[:40],
				}},
				PodSelector: &metav1.LabelSelector{MatchLabels: componentLabels(s, serviceName)},
			}},
			Ports: workerPorts,
		}}
	}
	if m.Name == "observer-ingress" {
		policy.Spec.PodSelector.MatchLabels = componentLabels(s, serviceName)
		policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
		policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": s.Namespaces[0]}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: componentLabels(s, controllerName)},
			}}, Ports: workerPorts,
		}}
	}
	return policy
}

func podSecurity() *corev1.PodSecurityContext {
	return &corev1.PodSecurityContext{
		RunAsNonRoot: new(true), RunAsUser: new(int64(65532)), RunAsGroup: new(int64(65532)),
		FSGroup: new(int64(65532)), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func containerSecurity() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: new(false), ReadOnlyRootFilesystem: new(true),
		Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
}

func secretVolume(name, secret string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{
		Secret: &corev1.SecretVolumeSource{SecretName: secret, DefaultMode: new(int32(0440))},
	}}
}

func mapVolume(name, configMap string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{
		ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: configMap}},
	}}
}

func (a *Adapter) observerPod(s State, m metav1.ObjectMeta) *corev1.Pod {
	m.Labels[componentLabel] = serviceName
	pod := &corev1.Pod{ObjectMeta: m, Spec: corev1.PodSpec{
		AutomountServiceAccountToken: new(false), EnableServiceLinks: new(false),
		SecurityContext: podSecurity(), RestartPolicy: corev1.RestartPolicyNever,
		TerminationGracePeriodSeconds: new(int64(2)),
		Containers: []corev1.Container{{
			Name: serviceName, Image: a.config.ObserverImage, ImagePullPolicy: corev1.PullIfNotPresent,
			SecurityContext: containerSecurity(), Resources: *a.config.ObserverResources.DeepCopy(),
			Args: []string{"-config", "/observer/config/config.json"},
			Ports: []corev1.ContainerPort{
				{Name: httpsScheme, ContainerPort: observerPort},
				{Name: "worker-http", ContainerPort: observerWorkerPort},
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: "private", MountPath: "/observer/private", ReadOnly: true},
				{Name: "config", MountPath: "/observer/config", ReadOnly: true},
			},
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(observerPort), Scheme: corev1.URISchemeHTTPS},
			}, PeriodSeconds: 2, TimeoutSeconds: 1},
		}},
		Volumes: []corev1.Volume{secretVolume("private", adminSecretName), mapVolume("config", "observer-config")},
	}}
	if publishing(s) {
		pod.Spec.Containers[0].Ports = append(pod.Spec.Containers[0].Ports,
			corev1.ContainerPort{Name: "worker-https", ContainerPort: observerTLSPort})
	}
	return pod
}

func (a *Adapter) controller(s State, m metav1.ObjectMeta, image string) *appsv1.Deployment {
	labels := componentLabels(s, controllerName)
	apiAddress, _ := netip.ParsePrefix(a.config.APIServer.CIDR)
	deployment := &appsv1.Deployment{ObjectMeta: m, Spec: appsv1.DeploymentSpec{
		Replicas: new(int32(1)), RevisionHistoryLimit: new(int32(0)),
		Selector: &metav1.LabelSelector{MatchLabels: labels},
		Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{
			NodeName:           s.Placement.NodeName,
			ServiceAccountName: controllerName, AutomountServiceAccountToken: new(true), EnableServiceLinks: new(false),
			SecurityContext: podSecurity(), TerminationGracePeriodSeconds: new(int64(5)),
			Containers: []corev1.Container{{
				Name: controllerName, Image: image, ImagePullPolicy: corev1.PullIfNotPresent, Command: []string{"/keda"},
				Args: []string{"--leader-elect=false", "--enable-cert-rotation=false", "--enable-webhook-patching=false",
					"--enable-prometheus-metrics=false", "--health-probe-bind-address=:8081",
					"--metrics-service-bind-address=127.0.0.1:9666", "--cert-dir=/certs"},
				Env: []corev1.EnvVar{
					{Name: "POD_NAMESPACE", Value: s.Namespaces[0]},
					{Name: "KEDA_CLUSTER_OBJECT_NAMESPACE", Value: s.Namespaces[0]},
					{Name: "WATCH_NAMESPACE", Value: strings.Join(s.Namespaces[:], ",")},
					{Name: "KUBERNETES_SERVICE_HOST", Value: apiAddress.Addr().String()},
					{Name: "KUBERNETES_SERVICE_PORT", Value: strconv.Itoa(int(a.config.APIServer.Port))},
					{Name: "NO_PROXY", Value: "*"},
					{Name: "no_proxy", Value: "*"},
				},
				SecurityContext: containerSecurity(), Resources: *a.config.Template.Resources.DeepCopy(),
				VolumeMounts: []corev1.VolumeMount{
					{Name: "certs", MountPath: "/certs", ReadOnly: true},
				},
				ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(8081)},
				}, PeriodSeconds: 2, TimeoutSeconds: 1},
			}},
			Volumes: []corev1.Volume{secretVolume("certs", controllerTLSName)},
		}},
	}}
	if publishing(s) {
		// The virtual TLS hostname is resolved only by this pinned /etc/hosts
		// entry. Go's trust store contains public fixture CA material, not keys.
		spec := &deployment.Spec.Template.Spec
		spec.HostAliases = []corev1.HostAlias{{IP: s.ObserverPodIP, Hostnames: []string{observerDNS(s)}}}
		spec.Volumes = append(spec.Volumes, mapVolume("observer-trust", observerTrustName))
		spec.Containers[0].VolumeMounts = append(spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{Name: "observer-trust", MountPath: "/observer-trust", ReadOnly: true})
		spec.Containers[0].Env = append(spec.Containers[0].Env,
			corev1.EnvVar{Name: "SSL_CERT_FILE", Value: "/observer-trust/ca.crt"},
			corev1.EnvVar{Name: "SSL_CERT_DIR", Value: "/observer-trust"})
	}
	return deployment
}

func (a *Adapter) configMap(ctx context.Context, s State, m metav1.ObjectMeta) (runtime.Object, error) {
	if publishing(s) && m.Name == observerTrustName {
		private, err := a.ownedSecret(ctx, s, ref(secrets, s.ObserverNamespace, adminSecretName))
		if err != nil {
			return nil, err
		}
		return &corev1.ConfigMap{ObjectMeta: m, Immutable: new(true),
			Data: map[string]string{"ca.crt": string(private.Data["ca.crt"])}}, nil
	}
	canary, err := a.ownedSecret(ctx, s, ref(secrets, s.Namespaces[0], canaryName))
	if err != nil {
		return nil, err
	}
	markers := []map[string]string{}
	for _, final := range []bool{false, true} {
		for index := range 2 {
			marker := map[string]string{"id": eventMarkerID(s, index, final)}
			if publishing(s) {
				marker["sha256"] = bytesDigest([]byte(subject(s, index, final)))
			} else {
				marker["value"] = subject(s, index, final)
			}
			markers = append(markers, marker)
		}
	}
	config := map[string]any{
		"schemaVersion": "v1", "runID": s.OperationDigest,
		"httpAddress": fmt.Sprintf("0.0.0.0:%d", observerPort), "respAddress": "",
		"ingressHTTPAddress":    fmt.Sprintf("0.0.0.0:%d", observerWorkerPort),
		"adminTokenFile":        "/observer/private/admin-token",
		"syntheticCanarySHA256": bytesDigest(canary.Data["key"]),
		"tls":                   map[string]string{"certFile": "/observer/private/tls.crt", "keyFile": "/observer/private/tls.key"},
		"channels":              []string{"a", "b"}, "markers": markers,
	}
	if publishing(s) {
		second, err := a.ownedSecret(ctx, s, ref(secrets, s.Namespaces[1], canaryName))
		if err != nil {
			return nil, err
		}
		config["ingressHTTPSAddress"] = fmt.Sprintf("0.0.0.0:%d", observerTLSPort)
		config["httpSetEvidence"] = true
		// Two failed events, six handlers and two fixtures can have 240
		// attempts within the observer's five-second read deadline.
		config["limits"] = map[string]int{"httpConnections": 256}
		config["channels"] = []string{"a", "b", gridAChannel, gridBChannel, gridCredentialAttackChannel, clusterHTTPChannel}
		config["channelCanaries"] = []struct {
			Channel string `json:"channel"`
			SHA256  string `json:"sha256"`
		}{
			{gridAChannel, bytesDigest(canary.Data["key"])},
			{gridBChannel, bytesDigest(second.Data["key"])},
			{gridCredentialAttackChannel, bytesDigest(canary.Data["key"])},
		}
	}
	data, err := json.Marshal(config)
	if err != nil {
		return nil, failure(Infrastructure, "observer-config-encoding")
	}
	return &corev1.ConfigMap{ObjectMeta: m, Immutable: new(true), Data: map[string]string{"config.json": string(data)}}, nil
}

func markerID(index int, final bool) string {
	round := "initial"
	if final {
		round = "final"
	}
	return fmt.Sprintf("%s-%d", round, index)
}

func eventMarkerID(s State, index int, final bool) string {
	if publishing(s) && index == 1 && final {
		return credentialFinalMarkerID
	}
	return markerID(index, final)
}

func knownRef(s State, object ObjectRef) bool {
	return slices.ContainsFunc(allObjects(s), func(expected ObjectRef) bool { return sameRef(expected, object) })
}
