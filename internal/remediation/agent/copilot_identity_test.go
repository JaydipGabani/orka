package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediationpolicy"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestCopilotNamespaceReplacementInvalidatesIdentity(t *testing.T) {
	for _, namespace := range []string{"private-runtimes", "proxy"} {
		t.Run(namespace, func(t *testing.T) {
			adapter, kube, _, creates := copilotFixture(t)
			identity, err := adapter.Snapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			current := &corev1.Namespace{}
			if err := kube.Get(t.Context(), client.ObjectKey{Name: namespace}, current); err != nil {
				t.Fatal(err)
			}
			if err := kube.Delete(t.Context(), current); err != nil {
				t.Fatal(err)
			}
			replacement := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, UID: "replacement-namespace"}}
			if err := kube.Create(t.Context(), replacement); err != nil {
				t.Fatal(err)
			}
			_, err = adapter.Generate(t.Context(), Request{
				TaskName: "rm-" + strings.Repeat("b", 32) + "-checks", RunID: "rm-" + strings.Repeat("b", 32),
				Prompt: "synthetic", ExpectedIdentity: identity.Digest,
			})
			if !errors.Is(err, remediationpolicy.ErrIdentityChanged) || *creates != 0 {
				t.Fatal("a recreated runtime or proxy namespace retained disclosure authority", err)
			}
		})
	}
}

func TestCopilotIdentityReadFailureIsRetryableAndSanitized(t *testing.T) {
	adapter, kube, _, _ := copilotFixture(t)
	unavailable := true
	adapter.Reader = interceptor.NewClient(kube, interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch,
		key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
		if unavailable {
			return apierrors.NewServiceUnavailable("synthetic private transport diagnostic")
		}
		return c.Get(ctx, key, object, opts...)
	}})
	_, err := adapter.Snapshot(t.Context())
	if !errors.Is(err, ErrDependencyUnavailable) || strings.Contains(err.Error(), "private transport") {
		t.Fatal("a temporary read failed permanently or leaked diagnostics", err)
	}
	unavailable = false
	if _, err := adapter.Snapshot(t.Context()); err != nil {
		t.Fatal("recovered metadata reader remained blocked", err)
	}
	adapter.Config.IdentityReferences[0].Namespace = "foreign"
	if _, err := adapter.Snapshot(t.Context()); err == nil {
		t.Fatal("unrelated proxy configuration was accepted as the model boundary")
	}
}
