package controllerlab

import (
	"context"
	"reflect"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// These are authorization queries, not persisted Kubernetes objects. Check the
// actual service-account identity, including inherited group grants: examining
// only the RoleBindings this package created cannot establish effective denial.
func (a *Adapter) checkObserverBoundary(ctx context.Context, s State) error {
	object, err := a.exact(ctx, s, ref(serviceAccounts, s.Namespaces[0], controllerName))
	if err != nil {
		return err
	}
	account := object.(*corev1.ServiceAccount)
	for _, attributes := range observerDeniedAccess(s) {
		spec := authorizationv1.SubjectAccessReviewSpec{
			User: "system:serviceaccount:" + account.Namespace + ":" + account.Name,
			UID:  string(account.UID),
			Groups: []string{
				"system:serviceaccounts", "system:serviceaccounts:" + account.Namespace, "system:authenticated",
			},
			ResourceAttributes: &attributes,
		}
		review, err := a.kube.AuthorizationV1().SubjectAccessReviews().Create(ctx,
			&authorizationv1.SubjectAccessReview{Spec: spec}, metav1.CreateOptions{})
		if err != nil || review == nil || review.Status.EvaluationError != "" || !reflect.DeepEqual(review.Spec, spec) {
			return failure(Infrastructure, "observer-authorization-check-unavailable")
		}
		if review.Status.Allowed {
			return failure(OutsideScope, "controller-can-access-observer-trust-boundary")
		}
	}
	return nil
}

func observerDeniedAccess(s State) []authorizationv1.ResourceAttributes {
	result := make([]authorizationv1.ResourceAttributes, 0, 23)
	result = append(result, authorizationv1.ResourceAttributes{
		Namespace: s.ObserverNamespace, Version: "v1", Resource: secrets.Resource, Verb: getVerb, Name: adminSecretName,
	})
	for _, verb := range []string{"list", "watch"} {
		for _, name := range []string{"", adminSecretName} {
			result = append(result, authorizationv1.ResourceAttributes{
				Namespace: s.ObserverNamespace, Version: "v1", Resource: secrets.Resource, Verb: verb, Name: name,
			})
		}
	}
	// Secret denial alone is insufficient: creating a Pod, changing its image,
	// or executing in the observer can expose a mounted key without a Secret GET.
	result = append(result, authorizationv1.ResourceAttributes{
		Namespace: s.ObserverNamespace, Version: "v1", Resource: pods.Resource, Verb: createVerb,
	})
	for _, subresource := range []string{"", "ephemeralcontainers"} {
		for _, verb := range reconciliationVerbs() {
			result = append(result, authorizationv1.ResourceAttributes{
				Namespace: s.ObserverNamespace, Version: "v1", Resource: pods.Resource,
				Subresource: subresource, Verb: verb, Name: serviceName,
			})
		}
	}
	for _, subresource := range []string{"exec", "attach"} {
		for _, verb := range []string{getVerb, createVerb} {
			result = append(result, authorizationv1.ResourceAttributes{
				Namespace: s.ObserverNamespace, Version: "v1", Resource: pods.Resource,
				Subresource: subresource, Verb: verb, Name: serviceName,
			})
		}
	}
	for _, kind := range []struct{ group, resource string }{
		{deployments.Group, deployments.Resource}, {deployments.Group, "replicasets"},
		{deployments.Group, "statefulsets"}, {deployments.Group, "daemonsets"},
		{"batch", "jobs"}, {"batch", "cronjobs"}, {"", "replicationcontrollers"},
		{roleBindings.Group, roleBindings.Resource},
	} {
		result = append(result, authorizationv1.ResourceAttributes{
			Namespace: s.ObserverNamespace, Group: kind.group, Version: "v1", Resource: kind.resource, Verb: createVerb,
		})
	}
	result = append(result, authorizationv1.ResourceAttributes{
		Group: clusterRoleBindings.Group, Version: "v1", Resource: clusterRoleBindings.Resource, Verb: createVerb,
	})
	return result
}
