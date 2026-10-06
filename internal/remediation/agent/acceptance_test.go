package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type acceptanceFixture struct {
	task     *corev1alpha1.Task
	request  AcceptanceRequest
	adapter  ControllerClient
	kube     client.WithWatch
	observed func(*corev1alpha1.Task)
	readErr  error
	reads    int
	writes   int
}

func newAcceptanceFixture(t *testing.T, backend string) *acceptanceFixture {
	t.Helper()
	identity := PlanIdentity{
		Backend: backend, Namespace: "remediation-tests", AgentName: "proposal-agent",
		AgentUID: "synthetic-agent-uid", AgentGeneration: 1,
	}
	if backend == remediationpolicy.CopilotBackend {
		identity.CopilotConfigDigest = "sha256:" + strings.Repeat("d", 64)
		identity.RuntimeImage = "example.invalid/runtime@sha256:" + strings.Repeat("a", 64)
		identity.RuntimeNamespace, identity.RuntimeNamespaceUID = "proposal-runtime", "synthetic-runtime-uid"
		identity.RuntimeProfileDigest = "sha256:" + strings.Repeat("b", 64)
		identity.ProxyEndpoint, identity.ProxyNamespace = "http://proxy.fixture.invalid:8080", "proposal-proxy"
		identity.ProxyNamespaceUID, identity.ProxyIdentityDigest = "synthetic-proxy-uid", "sha256:"+strings.Repeat("c", 64)
	} else {
		identity.ProviderName, identity.ProviderUID, identity.ProviderGeneration = "proposal-provider", "synthetic-provider-uid", 1
		identity.SecretRefName, identity.SecretUID, identity.SecretResourceVersion = "proposal-reference", "synthetic-reference-uid", "1"
	}
	var err error
	identity.Digest, err = remediationpolicy.MetadataDigest(identity)
	require.NoError(t, err)
	prompt := "Use only this synthetic cleanup fixture."
	sum := sha256.Sum256([]byte(prompt))
	f := &acceptanceFixture{request: AcceptanceRequest{
		TaskName: "rm-" + strings.Repeat("a", 32) + "-checks", RunID: "rm-" + strings.Repeat("a", 32),
		PromptDigest: "sha256:" + hex.EncodeToString(sum[:]), Expected: identity,
	}}
	f.task = &corev1alpha1.Task{
		TypeMeta: metav1.TypeMeta{Kind: "Task", APIVersion: corev1alpha1.GroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{
			Name: f.request.TaskName, Namespace: identity.Namespace, UID: "synthetic-task-uid", ResourceVersion: "1", Generation: 1,
			Labels: map[string]string{
				labels.LabelCreatedBy: remediationpolicy.CreatedBy, nativeRunLabel: labels.SelectorValue(f.request.RunID),
			},
			Annotations: map[string]string{nativeRunAnnotation: f.request.RunID, nativeIdentityAnnotation: identity.Digest},
		},
		Spec:   remediationpolicy.TaskSpec(prompt, identity.AgentName),
		Status: corev1alpha1.TaskStatus{Phase: corev1alpha1.TaskPhaseSucceeded},
	}
	if backend == remediationpolicy.CopilotBackend {
		f.task.Spec = remediationpolicy.CopilotTaskSpec(prompt, identity.AgentName)
		f.task.Annotations[labels.AnnotationAgentReadOnly] = "true"
	}
	f.task.Annotations[nativeRequestAnnotation], err = remediationpolicy.RequestDigest(
		f.task.Namespace, f.task.Name, f.request.RunID, identity.Digest, f.task.Spec)
	require.NoError(t, err)
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))
	f.kube = fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&corev1alpha1.Task{}).WithObjects(f.task).Build()
	reader := interceptor.NewClient(f.kube, interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
			f.reads++
			require.IsType(t, &corev1alpha1.Task{}, object, "cleanup must not read live model configuration or credentials")
			require.Equal(t, client.ObjectKeyFromObject(f.task), key)
			if f.readErr != nil {
				return f.readErr
			}
			if err := delegate.Get(ctx, key, object, options...); err != nil {
				return err
			}
			if f.observed != nil {
				f.observed(object.(*corev1alpha1.Task))
			}
			return nil
		},
	})
	writer := interceptor.NewClient(f.kube, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			t.Error("cleanup used the cached client")
			return errors.New("cached reads are forbidden")
		},
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			f.writes++
			return errors.New("cleanup must not create Tasks")
		},
		Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
			f.writes++
			return errors.New("acceptance resolution must be read-only")
		},
		Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
			f.writes++
			return errors.New("acceptance resolution must be read-only")
		},
		SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
			f.writes++
			return errors.New("acceptance resolution must be read-only")
		},
	})
	f.adapter.Native = KubernetesClient{Reader: reader, Client: writer, Namespace: identity.Namespace, AgentName: identity.AgentName}
	return f
}

func TestResolveAcceptedUsesFrozenIdentityAndUncachedTaskOnly(t *testing.T) {
	for _, backend := range []string{"", remediationpolicy.CopilotBackend} {
		t.Run("backend="+backend, func(t *testing.T) {
			f := newAcceptanceFixture(t, backend)
			for _, resolver := range []AcceptanceResolver{
				f.adapter, f.adapter.Native,
				CopilotClient{Reader: f.adapter.Native.Reader, Namespace: f.task.Namespace, AgentName: f.request.Expected.AgentName},
			} {
				result, err := resolver.ResolveAccepted(t.Context(), f.request)
				require.NoError(t, err)
				require.Equal(t, Result{TaskName: f.task.Name, TaskUID: string(f.task.UID)}, result)
			}
			require.Equal(t, 3, f.reads)
			require.Zero(t, f.writes)
			require.Nil(t, f.adapter.Copilot, "removed inference policy must not prevent cleanup")
		})
	}
}

func TestResolveAcceptedRejectsDriftWithoutAdoptingUID(t *testing.T) {
	tests := []struct {
		name   string
		change func(*corev1alpha1.Task, *AcceptanceRequest)
		rehash bool
	}{
		{"namespace", func(task *corev1alpha1.Task, _ *AcceptanceRequest) { task.Namespace = "another-namespace" }, true},
		{"name", func(task *corev1alpha1.Task, _ *AcceptanceRequest) { task.Name += "-other" }, true},
		{"run", func(task *corev1alpha1.Task, _ *AcceptanceRequest) {
			task.Annotations[nativeRunAnnotation] = "another-run"
			task.Labels[nativeRunLabel] = labels.SelectorValue("another-run")
		}, true},
		{"identity", func(task *corev1alpha1.Task, _ *AcceptanceRequest) {
			task.Annotations[nativeIdentityAnnotation] = "sha256:" + strings.Repeat("f", 64)
		}, true},
		{"prompt", func(task *corev1alpha1.Task, _ *AcceptanceRequest) { task.Spec.Prompt = "another synthetic prompt" }, true},
		{"agent", func(task *corev1alpha1.Task, _ *AcceptanceRequest) { task.Spec.AgentRef.Name = "another-agent" }, true},
		{"request-digest", func(task *corev1alpha1.Task, _ *AcceptanceRequest) {
			task.Annotations[nativeRequestAnnotation] = "sha256:" + strings.Repeat("f", 64)
		}, false},
		{"backend", func(task *corev1alpha1.Task, _ *AcceptanceRequest) { task.Spec.Type = corev1alpha1.TaskTypeContainer }, true},
		{"replaced-uid", func(task *corev1alpha1.Task, request *AcceptanceRequest) {
			request.ExpectedTaskUID = string(task.UID)
			task.UID = "same-name-replacement"
		}, true},
		{"missing-uid", func(task *corev1alpha1.Task, _ *AcceptanceRequest) { task.UID = "" }, true},
		{"missing-version", func(task *corev1alpha1.Task, _ *AcceptanceRequest) { task.ResourceVersion = "" }, true},
		{"generation", func(task *corev1alpha1.Task, _ *AcceptanceRequest) { task.Generation = 0 }, true},
		{"owned-task", func(task *corev1alpha1.Task, _ *AcceptanceRequest) {
			task.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "unrelated", UID: "unrelated-uid"}}
		}, true},
		{"spec", func(task *corev1alpha1.Task, _ *AcceptanceRequest) {
			task.Spec.Timeout.Duration *= 2
		}, true},
		{"invalid-frozen-identity", func(_ *corev1alpha1.Task, request *AcceptanceRequest) { request.Expected.AgentUID = "changed-agent" }, true},
	}
	for _, backend := range []string{"", remediationpolicy.CopilotBackend} {
		for _, test := range tests {
			t.Run(backend+"/"+test.name, func(t *testing.T) {
				f := newAcceptanceFixture(t, backend)
				observed := f.task.DeepCopy()
				test.change(observed, &f.request)
				if test.rehash {
					digest, err := remediationpolicy.RequestDigest(observed.Namespace, observed.Name,
						observed.Annotations[nativeRunAnnotation], observed.Annotations[nativeIdentityAnnotation], observed.Spec)
					require.NoError(t, err)
					observed.Annotations[nativeRequestAnnotation] = digest
				}
				f.observed = func(task *corev1alpha1.Task) { *task = *observed.DeepCopy() }
				result, err := f.adapter.ResolveAccepted(t.Context(), f.request)
				require.ErrorIs(t, err, remediationpolicy.ErrIdentityChanged)
				require.NotErrorIs(t, err, ErrDependencyUnavailable)
				require.Equal(t, f.request.ExpectedTaskUID, result.TaskUID)
				require.Empty(t, result.Output)
				require.NotContains(t, err.Error(), observed.Spec.Prompt)
				require.Zero(t, f.writes)
			})
		}
	}
}

func TestResolveAcceptedDeletingTaskDoesNotRelaxDispatch(t *testing.T) {
	for _, backend := range []string{"", remediationpolicy.CopilotBackend} {
		t.Run("backend="+backend, func(t *testing.T) {
			f := newAcceptanceFixture(t, backend)
			f.observed = func(task *corev1alpha1.Task) {
				now := metav1.Now()
				task.DeletionTimestamp = &now
				task.Finalizers = []string{"fixture.orka.ai/cleanup"}
				if backend == "" {
					require.Error(t, remediationpolicy.ValidateTask(task))
				} else {
					require.Error(t, remediationpolicy.ValidateCopilotTask(task))
				}
			}
			result, err := f.adapter.ResolveAccepted(t.Context(), f.request)
			require.NoError(t, err)
			require.Equal(t, string(f.task.UID), result.TaskUID)
			require.ErrorIs(t, f.adapter.Cancel(t.Context(), result.TaskName, result.TaskUID), ErrCancellationPending)
			require.Zero(t, f.writes)
		})
	}
}

func TestResolveAcceptedMissingTaskRequiresDurableUID(t *testing.T) {
	f := newAcceptanceFixture(t, remediationpolicy.CopilotBackend)
	require.NoError(t, f.kube.Delete(t.Context(), f.task))
	result, err := f.adapter.ResolveAccepted(t.Context(), f.request)
	require.ErrorIs(t, err, ErrAcceptanceUnresolved)
	require.Empty(t, result.TaskUID)
	f.request.ExpectedTaskUID = string(f.task.UID)
	result, err = f.adapter.ResolveAccepted(t.Context(), f.request)
	require.NoError(t, err)
	require.Equal(t, f.request.ExpectedTaskUID, result.TaskUID)
	require.Zero(t, f.writes)
}

func TestResolveAcceptedSanitizesDependencyErrorsAndPreservesUID(t *testing.T) {
	resource := schema.GroupResource{Group: corev1alpha1.GroupVersion.Group, Resource: "tasks"}
	for _, test := range []struct {
		name      string
		err       error
		retryable bool
	}{
		{"unavailable", apierrors.NewServiceUnavailable("synthetic-api-response"), true},
		{"timeout", fmt.Errorf("synthetic-api-response: %w", apierrors.NewTimeoutError("synthetic-api-response", 1)), true},
		{"throttled", apierrors.NewTooManyRequests("synthetic-api-response", 1), true},
		{"client-timeout", fmt.Errorf("synthetic-api-response: %w", context.DeadlineExceeded), true},
		{"transport", errors.New("synthetic-api-response"), true},
		{"forbidden", apierrors.NewForbidden(resource, "synthetic", errors.New("synthetic-api-response")), false},
		{"conflict", apierrors.NewConflict(resource, "synthetic", errors.New("synthetic-api-response")), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAcceptanceFixture(t, remediationpolicy.CopilotBackend)
			f.request.ExpectedTaskUID, f.readErr = string(f.task.UID), test.err
			result, err := f.adapter.ResolveAccepted(t.Context(), f.request)
			require.Error(t, err)
			require.Equal(t, test.retryable, errors.Is(err, ErrDependencyUnavailable))
			require.NotErrorIs(t, err, ErrCancellationPending)
			require.NotContains(t, err.Error(), "synthetic-api-response")
			require.Equal(t, f.request.ExpectedTaskUID, result.TaskUID)
			require.Empty(t, result.Output)
			require.Zero(t, f.writes)
		})
	}
}
