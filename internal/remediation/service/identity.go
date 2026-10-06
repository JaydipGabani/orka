package service

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ActorIdentity struct {
	Username string   `json:"username"`
	UID      string   `json:"uid,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

type actorContextKey struct{}

// WithActor attaches only an identity verified by the API authentication layer.
// It is never populated from request JSON or a model-generated proposal.
func WithActor(ctx context.Context, identity ActorIdentity) context.Context {
	identity.Groups = slices.Clone(identity.Groups)
	slices.Sort(identity.Groups)
	identity.Groups = slices.Compact(identity.Groups)
	return context.WithValue(ctx, actorContextKey{}, identity)
}

func actorFromContext(ctx context.Context, username string) (ActorIdentity, error) {
	identity, exists := ctx.Value(actorContextKey{}).(ActorIdentity)
	if !exists {
		identity.Username = username
	}
	raw, err := json.Marshal(identity)
	if err != nil || len(raw) > 16<<10 || identity.Username != username || len(identity.Groups) > 128 {
		return ActorIdentity{}, ErrInvalid
	}
	return identity, nil
}

func KubernetesAuthorizer(client kubernetes.Interface) func(context.Context, string, string, ActorIdentity) error {
	return func(ctx context.Context, namespace, policy string, identity ActorIdentity) error {
		if client == nil || identity.Username == "" || identity.UID == "" {
			return ErrPolicy
		}
		if strings.HasPrefix(identity.Username, "system:serviceaccount:") {
			parts := strings.Split(identity.Username, ":")
			if len(parts) != 4 {
				return ErrPolicy
			}
			account, err := client.CoreV1().ServiceAccounts(parts[2]).Get(ctx, parts[3], metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return ErrPolicy
			}
			if err != nil {
				return ErrAuthorizationUnavailable
			}
			if string(account.UID) != identity.UID || account.DeletionTimestamp != nil {
				return ErrPolicy
			}
		}
		for _, attributes := range []*authorizationv1.ResourceAttributes{
			{Namespace: namespace, Group: corev1alpha1.GroupVersion.Group, Resource: "remediations", Verb: "create"},
			{Namespace: namespace, Group: corev1alpha1.GroupVersion.Group, Resource: "remediationpolicies", Verb: "use", Name: policy},
		} {
			review, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: identity.Username, UID: identity.UID, Groups: slices.Clone(identity.Groups), ResourceAttributes: attributes,
				},
			}, metav1.CreateOptions{})
			if err != nil || review == nil {
				return ErrAuthorizationUnavailable
			}
			if review.Status.EvaluationError != "" && !review.Status.Denied {
				return ErrAuthorizationUnavailable
			}
			if !review.Status.Allowed || review.Status.Denied {
				return ErrPolicy
			}
		}
		return nil
	}
}
