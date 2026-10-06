package controllerlab

import (
	"context"
	"net"
	"reflect"
	"strconv"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	kedaPublishingCommit        = "e615440f24f6abec8b7c69bd88854cb4324e9eaa"
	observerTLSPort             = int32(9443)
	observerTrustName           = "observer-public-trust"
	publishingAuthName          = "scope-auth"
	gridAChannel                = "grid-a"
	gridBChannel                = "grid-b"
	gridCredentialAttackChannel = "grid-credential-attack"
	clusterHTTPChannel          = "cluster-http"
	gridARoute                  = "/events/" + gridAChannel
	gridBRoute                  = "/events/" + gridBChannel
	gridCredentialAttackRoute   = "/events/" + gridCredentialAttackChannel
	credentialFinalMarkerID     = "credential-final-1"
	clusterHTTPRoute            = "/events/" + clusterHTTPChannel
)

func publishing(s State) bool { return s.Capability == KEDAEventPublishing }

func publishingRoleName(s State) string { return s.Namespaces[0] + "-publishing" }

func globalAuthName(s State) string { return s.Namespaces[0] + "-auth" }

func globalSourceName(s State) string { return s.Namespaces[0] + "-events" }

func publishingSourceObjects(s State) []ObjectRef {
	return []ObjectRef{
		ref(triggerAuthentications, s.Namespaces[0], publishingAuthName),
		ref(triggerAuthentications, s.Namespaces[1], publishingAuthName),
		ref(clusterAuthentications, "", globalAuthName(s)),
		ref(cloudEventSources, s.Namespaces[0], "scope-source"),
		ref(cloudEventSources, s.Namespaces[1], "scope-source"),
		ref(cloudEventSources, s.Namespaces[0], "scope-grid-source"),
		ref(cloudEventSources, s.Namespaces[1], "scope-grid-source"),
		ref(cloudEventSources, s.Namespaces[1], "scope-credential-attack-source"),
		ref(clusterEventSources, "", globalSourceName(s)),
	}
}

func publishingAuthSpec() map[string]any {
	return map[string]any{"secretTargetRef": []any{map[string]any{
		"parameter": "accessKey", objectNameKey: canaryName, "key": "key",
	}}}
}

func publishingEventSource(s State, m metav1.ObjectMeta) *unstructured.Unstructured {
	spec := map[string]any{
		"clusterName":       "orka-controllerlab",
		"eventSubscription": map[string]any{"includedEventTypes": []any{"keda.scaledobject.failed.v1"}},
	}
	if m.Namespace == "" {
		// The pinned resolver does not resolve auth for an empty namespace.
		// ClusterCloudEventSource is therefore a legitimate HTTP broadcast
		// control, not a claim of cluster-scoped Event Grid authentication.
		spec["destination"] = map[string]any{httpScheme: map[string]any{
			"uri": "http://" + net.JoinHostPort(s.ObserverPodIP, strconv.Itoa(int(observerWorkerPort))) + clusterHTTPRoute,
		}}
		return customObject("eventing.keda.sh/v1alpha1", "ClusterCloudEventSource", m, spec)
	}
	channel := gridAChannel
	if m.Namespace == s.Namespaces[1] {
		channel = gridBChannel
	}
	authName, kind := publishingAuthName, authKind
	if m.Name == "scope-credential-attack-source" {
		// An explicit cluster-auth reference is the attack input, not delegation.
		channel, authName, kind = gridCredentialAttackChannel, globalAuthName(s), clusterAuthKind
	}
	spec["destination"] = map[string]any{"azureEventGridTopic": map[string]any{
		"endpoint": "https://" + net.JoinHostPort(observerDNS(s), strconv.Itoa(int(observerTLSPort))) + "/events/" + channel,
	}}
	spec["authenticationRef"] = map[string]any{objectNameKey: authName, objectKindKey: kind}
	return customObject("eventing.keda.sh/v1alpha1", "CloudEventSource", m, spec)
}

func publishingClusterRules(s State) []rbacv1.PolicyRule {
	// Only these two generated objects need status/finalizer writes. Read-only
	// informer access remains in the separately pinned operator watcher role.
	return []rbacv1.PolicyRule{
		{APIGroups: []string{clusterEventSources.Group},
			Resources:     []string{clusterEventSources.Resource, "clustercloudeventsources/status", "clustercloudeventsources/finalizers"},
			ResourceNames: []string{globalSourceName(s)}, Verbs: reconciliationVerbs()},
		{APIGroups: []string{clusterAuthentications.Group},
			Resources:     []string{clusterAuthentications.Resource, "clustertriggerauthentications/status"},
			ResourceNames: []string{globalAuthName(s)}, Verbs: reconciliationVerbs()},
	}
}

func (a *Adapter) checkPublishingGlobals(ctx context.Context, s State) error {
	roleRef := ref(clusterRoles, "", publishingRoleName(s))
	if receiptFor(s, roleRef) != nil {
		value, err := a.exact(ctx, s, roleRef)
		if err != nil {
			return err
		}
		role := value.(*rbacv1.ClusterRole)
		if role.AggregationRule != nil || !reflect.DeepEqual(role.Rules, publishingClusterRules(s)) {
			return failure(Infrastructure, "publishing-role-contract-changed")
		}
	}
	for _, object := range []ObjectRef{
		ref(clusterAuthentications, "", globalAuthName(s)), ref(clusterEventSources, "", globalSourceName(s)),
	} {
		list, err := a.custom.Resource(object.Resource).List(ctx, metav1.ListOptions{Limit: 2})
		if err != nil {
			return failure(Infrastructure, "global-source-isolation-unavailable")
		}
		if len(list.Items) > 1 || list.GetContinue() != "" {
			return failure(OutsideScope, "foreign-global-source-in-publishing-lab")
		}
		receipt := receiptFor(s, object)
		if len(list.Items) == 0 {
			if receipt != nil {
				return failure(Infrastructure, "owned-global-source-disappeared")
			}
			continue
		}
		item := &list.Items[0]
		if item.GetName() != object.Name || item.GetNamespace() != object.Namespace {
			return failure(OutsideScope, "foreign-global-source-in-publishing-lab")
		}
		intent := ""
		if receipt != nil {
			if receipt.Object.UID != item.GetUID() {
				return failure(OwnershipLost, "global-source-uid-changed")
			}
			intent = receipt.IntentDigest
		} else if s.Intent != nil && sameRef(s.Intent.Object, object) {
			intent = s.Intent.Digest
		}
		if intent == "" || item.GetUID() == "" {
			return failure(OwnershipLost, "foreign-global-source-in-publishing-lab")
		}
		if item.GetDeletionTimestamp() != nil || !owns(s, object, intent, item) {
			if receipt != nil {
				return failure(Infrastructure, "owned-global-source-metadata-changed")
			}
			return failure(OwnershipLost, "foreign-global-source-in-publishing-lab")
		}
		expected, err := a.build(ctx, s, ImageBinding{}, Intent{Object: object, Digest: intent}, item)
		if err != nil || !exactKEDATemplate(expected, item) {
			if receipt == nil {
				return failure(OwnershipLost, "unacknowledged-global-source-contract-changed")
			}
			return failure(Infrastructure, "global-source-contract-changed")
		}
	}
	return nil
}
