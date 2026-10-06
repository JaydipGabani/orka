package controllerlab

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (a *Adapter) get(ctx context.Context, r ObjectRef) (runtime.Object, error) {
	o := metav1.GetOptions{}
	switch r.Resource {
	case namespaces:
		return a.kube.CoreV1().Namespaces().Get(ctx, r.Name, o)
	case serviceAccounts:
		return a.kube.CoreV1().ServiceAccounts(r.Namespace).Get(ctx, r.Name, o)
	case secrets:
		return a.kube.CoreV1().Secrets(r.Namespace).Get(ctx, r.Name, o)
	case configMaps:
		return a.kube.CoreV1().ConfigMaps(r.Namespace).Get(ctx, r.Name, o)
	case pods:
		return a.kube.CoreV1().Pods(r.Namespace).Get(ctx, r.Name, o)
	case deployments:
		return a.kube.AppsV1().Deployments(r.Namespace).Get(ctx, r.Name, o)
	case roles:
		return a.kube.RbacV1().Roles(r.Namespace).Get(ctx, r.Name, o)
	case roleBindings:
		return a.kube.RbacV1().RoleBindings(r.Namespace).Get(ctx, r.Name, o)
	case clusterRoleBindings:
		return a.kube.RbacV1().ClusterRoleBindings().Get(ctx, r.Name, o)
	case clusterRoles:
		return a.kube.RbacV1().ClusterRoles().Get(ctx, r.Name, o)
	case networkPolicies:
		return a.kube.NetworkingV1().NetworkPolicies(r.Namespace).Get(ctx, r.Name, o)
	case cloudEventSources, scaledObjects, triggerAuthentications, clusterAuthentications, clusterEventSources:
		return a.custom.Resource(r.Resource).Namespace(r.Namespace).Get(ctx, r.Name, o)
	default:
		return nil, failure(InvalidState, "unapproved-resource-read")
	}
}

func (a *Adapter) create(ctx context.Context, object runtime.Object) (runtime.Object, error) {
	o := metav1.CreateOptions{}
	switch object := object.(type) {
	case *corev1.Namespace:
		return a.kube.CoreV1().Namespaces().Create(ctx, object, o)
	case *corev1.ServiceAccount:
		return a.kube.CoreV1().ServiceAccounts(object.Namespace).Create(ctx, object, o)
	case *corev1.Secret:
		return a.kube.CoreV1().Secrets(object.Namespace).Create(ctx, object, o)
	case *corev1.ConfigMap:
		return a.kube.CoreV1().ConfigMaps(object.Namespace).Create(ctx, object, o)
	case *corev1.Pod:
		return a.kube.CoreV1().Pods(object.Namespace).Create(ctx, object, o)
	case *appsv1.Deployment:
		return a.kube.AppsV1().Deployments(object.Namespace).Create(ctx, object, o)
	case *rbacv1.Role:
		return a.kube.RbacV1().Roles(object.Namespace).Create(ctx, object, o)
	case *rbacv1.RoleBinding:
		return a.kube.RbacV1().RoleBindings(object.Namespace).Create(ctx, object, o)
	case *rbacv1.ClusterRoleBinding:
		return a.kube.RbacV1().ClusterRoleBindings().Create(ctx, object, o)
	case *rbacv1.ClusterRole:
		return a.kube.RbacV1().ClusterRoles().Create(ctx, object, o)
	case *networkingv1.NetworkPolicy:
		return a.kube.NetworkingV1().NetworkPolicies(object.Namespace).Create(ctx, object, o)
	case *unstructured.Unstructured:
		var gvr schema.GroupVersionResource
		switch object.GetKind() {
		case "ScaledObject":
			gvr = scaledObjects
		case "CloudEventSource":
			gvr = cloudEventSources
		case authKind:
			gvr = triggerAuthentications
		case clusterAuthKind:
			gvr = clusterAuthentications
		case "ClusterCloudEventSource":
			gvr = clusterEventSources
		default:
			return nil, failure(InvalidState, "unapproved-custom-resource-create")
		}
		if object.GetAPIVersion() != gvr.GroupVersion().String() {
			return nil, failure(InvalidState, "unapproved-custom-resource-version")
		}
		return a.custom.Resource(gvr).Namespace(object.GetNamespace()).Create(ctx, object, o)
	default:
		return nil, failure(InvalidState, "unapproved-resource-create")
	}
}

func (a *Adapter) delete(ctx context.Context, r ObjectRef, version string) error {
	if r.UID == "" {
		return failure(OwnershipLost, "delete-requires-exact-uid")
	}
	o := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &r.UID},
		PropagationPolicy: new(metav1.DeletePropagationForeground)}
	if version != "" {
		o.Preconditions.ResourceVersion = &version
	}
	switch r.Resource {
	case namespaces:
		return a.kube.CoreV1().Namespaces().Delete(ctx, r.Name, o)
	case serviceAccounts:
		return a.kube.CoreV1().ServiceAccounts(r.Namespace).Delete(ctx, r.Name, o)
	case secrets:
		return a.kube.CoreV1().Secrets(r.Namespace).Delete(ctx, r.Name, o)
	case configMaps:
		return a.kube.CoreV1().ConfigMaps(r.Namespace).Delete(ctx, r.Name, o)
	case pods:
		return a.kube.CoreV1().Pods(r.Namespace).Delete(ctx, r.Name, o)
	case deployments:
		return a.kube.AppsV1().Deployments(r.Namespace).Delete(ctx, r.Name, o)
	case roles:
		return a.kube.RbacV1().Roles(r.Namespace).Delete(ctx, r.Name, o)
	case roleBindings:
		return a.kube.RbacV1().RoleBindings(r.Namespace).Delete(ctx, r.Name, o)
	case clusterRoleBindings:
		return a.kube.RbacV1().ClusterRoleBindings().Delete(ctx, r.Name, o)
	case clusterRoles:
		return a.kube.RbacV1().ClusterRoles().Delete(ctx, r.Name, o)
	case networkPolicies:
		return a.kube.NetworkingV1().NetworkPolicies(r.Namespace).Delete(ctx, r.Name, o)
	case cloudEventSources, scaledObjects, triggerAuthentications, clusterAuthentications, clusterEventSources:
		return a.custom.Resource(r.Resource).Namespace(r.Namespace).Delete(ctx, r.Name, o)
	default:
		return failure(InvalidState, "unapproved-resource-delete")
	}
}

func owns(s State, r ObjectRef, intent string, object metav1.Object) bool {
	if object.GetName() != r.Name || object.GetNamespace() != r.Namespace ||
		object.GetLabels()[runLabel] != s.OperationDigest[:40] ||
		object.GetAnnotations()[intentAnnotation] != intent {
		return false
	}
	expected := namespaceOwner(s, r)
	actual := object.GetOwnerReferences()
	return len(expected) == len(actual) && slices.Equal(expected, actual)
}

func (a *Adapter) checkAnchors(ctx context.Context, s State) error {
	for _, namespace := range ownedNamespaces(s) {
		receipt := receiptFor(s, ref(namespaces, "", namespace))
		if receipt == nil || receipt.Deleted {
			continue
		}
		value, err := a.kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) && receipt.DeleteRequested {
			continue
		}
		if err != nil {
			if apierrors.IsNotFound(err) {
				return failure(OwnershipLost, "namespace-anchor-unavailable")
			}
			return failure(Infrastructure, "namespace-anchor-read-unavailable")
		}
		if value == nil || value.UID != receipt.Object.UID {
			return failure(OwnershipLost, "namespace-anchor-changed")
		}
		if !owns(s, receipt.Object, receipt.IntentDigest, value) ||
			(value.DeletionTimestamp != nil && !receipt.DeleteRequested) {
			return failure(Infrastructure, "namespace-anchor-metadata-changed")
		}
	}
	return nil
}

func (a *Adapter) checkClusterRole(ctx context.Context) error {
	expected := a.config.Template.ClusterWatchRole
	role, err := a.kube.RbacV1().ClusterRoles().Get(ctx, expected.Name, metav1.GetOptions{})
	if err != nil || role.UID != expected.UID || role.AggregationRule != nil || role.DeletionTimestamp != nil ||
		!reflect.DeepEqual(role.Rules, KEDAClusterWatchRules()) {
		return failure(OutsideScope, "operator-cluster-role-contract-changed")
	}
	return nil
}

func (a *Adapter) checkNoGlobalSources(ctx context.Context) error {
	for _, gvr := range []schema.GroupVersionResource{clusterAuthentications, clusterEventSources} {
		result, err := a.custom.Resource(gvr).List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			return failure(Infrastructure, "global-source-isolation-unavailable")
		}
		if len(result.Items) != 0 || result.GetContinue() != "" {
			return failure(OutsideScope, "dedicated-empty-global-source-scope-required")
		}
	}
	return nil
}

func (a *Adapter) preflight(ctx context.Context) error {
	cluster, err := a.kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID == "" || ClusterIdentity(string(cluster.UID)) != a.config.ClusterIdentity {
		return failure(OutsideScope, "dedicated-cluster-identity-mismatch")
	}
	if err := a.checkClusterRole(ctx); err != nil {
		return err
	}
	type requiredResource struct {
		kind       string
		namespaced bool
	}
	groups := map[string]map[string]requiredResource{
		scaledObjects.GroupVersion().String(): {
			scaledObjects.Resource: {"ScaledObject", true}, "scaledjobs": {"ScaledJob", true},
			triggerAuthentications.Resource: {authKind, true},
			clusterAuthentications.Resource: {clusterAuthKind, false},
		},
		cloudEventSources.GroupVersion().String(): {
			cloudEventSources.Resource:   {"CloudEventSource", true},
			clusterEventSources.Resource: {"ClusterCloudEventSource", false},
		},
	}
	for group, required := range groups {
		resources, err := a.kube.Discovery().ServerResourcesForGroupVersion(group)
		if err != nil {
			return failure(OutsideScope, "operator-installed-crds-required")
		}
		for _, resource := range resources.APIResources {
			if expected, ok := required[resource.Name]; ok &&
				expected.namespaced == resource.Namespaced && expected.kind == resource.Kind {
				delete(required, resource.Name)
			}
		}
		if len(required) != 0 {
			return failure(OutsideScope, "required-public-crd-scope-unavailable")
		}
	}
	return a.checkNoGlobalSources(ctx)
}

// ClusterIdentity binds operator approval to the lab API server's kube-system
// Namespace UID. This shared anchor is read only and is NEVER a cleanup target.
func ClusterIdentity(uid string) string {
	return digest(struct{ Domain, UID string }{"orka.controllerlab.cluster.v1", uid})
}

// desiredMatches compares the complete written surface while allowing API
// defaulting. It never treats an annotation claiming a spec digest as the spec.
func desiredMatches(desired, actual runtime.Object) bool {
	encode := func(object runtime.Object) map[string]any {
		data, _ := json.Marshal(object)
		var result map[string]any
		_ = json.Unmarshal(data, &result)
		delete(result, "status")
		delete(result, "apiVersion")
		delete(result, "kind")
		if metadata, ok := result["metadata"].(map[string]any); ok {
			delete(metadata, "creationTimestamp")
			delete(metadata, "resourceVersion")
			delete(metadata, "uid")
			delete(metadata, "generation")
			delete(metadata, "managedFields")
			delete(metadata, "deletionTimestamp")
		}
		return result
	}
	var subset func(any, any) bool
	subset = func(want, have any) bool {
		switch want := want.(type) {
		case map[string]any:
			got, ok := have.(map[string]any)
			if !ok {
				return false
			}
			for key, value := range want {
				if !subset(value, got[key]) {
					return false
				}
			}
			return true
		case []any:
			got, ok := have.([]any)
			if !ok || len(want) != len(got) {
				return false
			}
			for i := range want {
				if !subset(want[i], got[i]) {
					return false
				}
			}
			return true
		default:
			return reflect.DeepEqual(want, have)
		}
	}
	return subset(encode(desired), encode(actual))
}

func objectMetadata(object runtime.Object) (metav1.Object, error) {
	result, err := meta.Accessor(object)
	if err != nil || result.GetUID() == "" {
		return nil, failure(OwnershipLost, "api-object-uid-required")
	}
	return result, nil
}
