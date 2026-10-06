package remediationpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type policyFixture struct {
	reader   client.Reader
	agent    *corev1alpha1.Agent
	provider *corev1alpha1.Provider
	task     *corev1alpha1.Task
	identity PlanIdentity
}

func newPolicyFixture(t *testing.T) *policyFixture {
	t.Helper()
	f := &policyFixture{
		agent: &corev1alpha1.Agent{
			ObjectMeta: metav1.ObjectMeta{
				Name: "proposal-agent", Namespace: "remediation-tests", UID: "agent-uid", Generation: 3,
			},
			Spec: corev1alpha1.AgentSpec{
				ProviderRef: &corev1alpha1.ProviderReference{Name: "proposal-provider"},
				Model:       &corev1alpha1.ModelConfig{Name: "reviewed-model"},
			},
		},
		provider: &corev1alpha1.Provider{
			ObjectMeta: metav1.ObjectMeta{
				Name: "proposal-provider", Namespace: "remediation-tests", UID: "provider-uid", Generation: 7,
			},
			Spec: corev1alpha1.ProviderSpec{
				Type: corev1alpha1.ProviderTypeOpenAI, BaseURL: "https://approved.invalid",
				SecretRef: corev1alpha1.ProviderSecretRef{Name: "provider-credential"},
			},
			Status: corev1alpha1.ProviderStatus{Ready: true},
		},
	}
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: f.provider.Spec.SecretRef.Name, Namespace: f.agent.Namespace, UID: "credential-uid", ResourceVersion: "42",
		},
	}).Build()
	// No Agent/Provider exists in this client. Fetching a different object
	// would validate one configuration while the caller renders another.
	f.reader = interceptor.NewClient(kube, interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
			require.IsType(t, &metav1.PartialObjectMetadata{}, object, "only Secret metadata may be read")
			require.Equal(t, "Secret", object.GetObjectKind().GroupVersionKind().Kind)
			require.Equal(t, f.provider.Spec.SecretRef.Name, key.Name)
			require.Equal(t, f.agent.Namespace, key.Namespace)
			return delegate.Get(ctx, key, object, options...)
		},
	})
	var err error
	f.identity, err = MetadataIdentity(t.Context(), f.reader, f.agent, f.provider)
	require.NoError(t, err)
	f.task = &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proposal-task", Namespace: f.agent.Namespace, UID: "task-uid", Generation: 1,
			Labels:      map[string]string{labels.LabelCreatedBy: CreatedBy, RunLabel: "case-123"},
			Annotations: map[string]string{RunAnnotation: "case-123", IdentityAnnotation: f.identity.Digest},
		},
		Spec: TaskSpec("Use this synthetic source packet only.", f.agent.Name),
	}
	digest, err := RequestDigest(f.task.Namespace, f.task.Name, "case-123", f.identity.Digest, f.task.Spec)
	require.NoError(t, err)
	f.task.Annotations[RequestDigestAnnotation] = digest
	return f
}

func TestValidateNativeDispatchUsesExactRenderObjects(t *testing.T) {
	t.Parallel()
	f := newPolicyFixture(t)
	require.NoError(t, ValidateNativeDispatch(t.Context(), f.reader, f.task, f.agent, f.provider))
	require.Equal(t, "credential-uid", f.identity.SecretUID)
	require.Equal(t, "42", f.identity.SecretResourceVersion)
	require.NoError(t, CompareIdentity(f.identity, f.identity))
	digest, err := MetadataDigest(f.identity)
	require.NoError(t, err)
	require.Equal(t, f.identity.Digest, digest)
}

func TestValidateNativeDispatchRejectsNewAndStaleRenderRevisions(t *testing.T) {
	for name, mutate := range map[string]func(*policyFixture){
		"new provider endpoint": func(f *policyFixture) {
			f.provider.Generation++
			f.provider.Spec.BaseURL = "https://unapproved.invalid"
		},
		"stale provider":    func(f *policyFixture) { f.provider.Generation-- },
		"replaced provider": func(f *policyFixture) { f.provider.UID = "replacement-provider" },
		"new agent model": func(f *policyFixture) {
			f.agent.Generation++
			f.agent.Spec.Model.Name = "unapproved-model"
		},
		"stale agent":    func(f *policyFixture) { f.agent.Generation-- },
		"replaced agent": func(f *policyFixture) { f.agent.UID = "replacement-agent" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPolicyFixture(t)
			mutate(f)
			err := ValidateNativeDispatch(t.Context(), f.reader, f.task, f.agent, f.provider)
			require.ErrorIs(t, err, ErrIdentityChanged)
			require.NotErrorIs(t, err, ErrCredentialRotated)
			require.NotContains(t, err.Error(), "unapproved")
		})
	}
}

func TestIdentityIgnoresReadinessButDispatchRequiresIt(t *testing.T) {
	t.Parallel()
	f := newPolicyFixture(t)
	f.provider.Status.Ready = false
	f.provider.Status.Message = "private-status-message"
	f.agent.Status.ActiveTasks = 99
	f.agent.ResourceVersion = "999"
	identity, err := MetadataIdentity(t.Context(), f.reader, f.agent, f.provider)
	require.NoError(t, err)
	require.Equal(t, f.identity, identity)
	err = ValidateNativeDispatch(t.Context(), f.reader, f.task, f.agent, f.provider)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private-status-message")
}

func TestCredentialRotationClassificationRequiresUnchangedConfiguration(t *testing.T) {
	for name, mutate := range map[string]func(*PlanIdentity){
		"Secret version":           func(p *PlanIdentity) { p.SecretResourceVersion = "43" },
		"Secret replacement":       func(p *PlanIdentity) { p.SecretUID = "replacement-credential" },
		"Agent changed too":        func(p *PlanIdentity) { p.SecretResourceVersion = "43"; p.AgentGeneration++ },
		"Provider changed too":     func(p *PlanIdentity) { p.SecretResourceVersion = "43"; p.ProviderGeneration++ },
		"Secret reference changed": func(p *PlanIdentity) { p.SecretRefName = "another-credential" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPolicyFixture(t)
			changed := f.identity
			mutate(&changed)
			var err error
			changed.Digest, err = MetadataDigest(changed)
			require.NoError(t, err)
			err = CompareIdentity(f.identity, changed)
			if name == "Secret version" || name == "Secret replacement" {
				require.ErrorIs(t, err, ErrCredentialRotated)
				require.NotErrorIs(t, err, ErrIdentityChanged)
			} else {
				require.ErrorIs(t, err, ErrIdentityChanged)
				require.NotErrorIs(t, err, ErrCredentialRotated)
			}
		})
	}
}

func TestMetadataDigestRejectsMissingOrTamperedIdentity(t *testing.T) {
	t.Parallel()
	f := newPolicyFixture(t)
	changed := f.identity
	changed.SecretUID = ""
	_, err := MetadataDigest(changed)
	require.Error(t, err)
	changed = f.identity
	changed.AgentGeneration++
	require.Error(t, CompareIdentity(f.identity, changed), "a changed identity cannot retain its previous digest")
	require.False(t, ValidDigest("sha256:"+strings.Repeat("A", 64)))
}

func TestValidateNativeDispatchEnforcesAgentPolicy(t *testing.T) {
	for name, mutate := range map[string]func(*corev1alpha1.Agent){
		"enabled tool": func(a *corev1alpha1.Agent) { a.Spec.Tools = []corev1alpha1.ToolReference{{Name: "file_read"}} },
		"runtime":      func(a *corev1alpha1.Agent) { a.Spec.Runtime = &corev1alpha1.AgentCLIRuntime{} },
		"coordination": func(a *corev1alpha1.Agent) { a.Spec.Coordination = &corev1alpha1.CoordinationConfig{} },
		"skill":        func(a *corev1alpha1.Agent) { a.Spec.Skills = []corev1alpha1.SkillReference{{Name: "skill"}} },
		"fallback": func(a *corev1alpha1.Agent) {
			a.Spec.Model.Fallbacks = []corev1alpha1.ModelFallback{{ProviderRef: "fallback"}}
		},
		"secret EnvFrom": func(a *corev1alpha1.Agent) { a.Spec.SecretRef = &corev1.LocalObjectReference{Name: "extra"} },
		"execution":      func(a *corev1alpha1.Agent) { a.Spec.Execution = &corev1alpha1.ExecutionSpec{} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPolicyFixture(t)
			mutate(f.agent)
			require.Error(t, ValidateNativeDispatch(t.Context(), f.reader, f.task, f.agent, f.provider))
		})
	}
	t.Run("explicitly disabled tools", func(t *testing.T) {
		t.Parallel()
		f := newPolicyFixture(t)
		f.agent.Spec.Tools = []corev1alpha1.ToolReference{{Name: "file_read", Enabled: new(false)}}
		require.NoError(t, ValidateAgent(f.agent))
	})
}

func TestValidateNativeDispatchEnforcesTaskPolicy(t *testing.T) {
	for name, mutate := range map[string]func(*corev1alpha1.Task){
		"enabled memory tools":   func(task *corev1alpha1.Task) { task.Spec.Env[0].Value = "true" },
		"enabled memory context": func(task *corev1alpha1.Task) { task.Spec.Env[1].Value = "true" },
		"extra env": func(task *corev1alpha1.Task) {
			task.Spec.Env = append(task.Spec.Env, corev1.EnvVar{Name: "EXTRA", Value: "true"})
		},
		"model override":      func(task *corev1alpha1.Task) { task.Spec.AI = &corev1alpha1.AISpec{Model: "other-model"} },
		"runtime override":    func(task *corev1alpha1.Task) { task.Spec.AgentRuntime = &corev1alpha1.AgentRuntimeSpec{} },
		"workspace":           func(task *corev1alpha1.Task) { task.Spec.Workspace = &corev1alpha1.WorkspaceConfig{} },
		"credential override": func(task *corev1alpha1.Task) { task.Spec.SecretRef = &corev1alpha1.SecretReference{Name: "extra"} },
		"unverified actor": func(task *corev1alpha1.Task) {
			task.Spec.RequestedBy = &corev1alpha1.RequestedBy{Subject: "unverified"}
		},
		"retry":                 func(task *corev1alpha1.Task) { task.Spec.RetryPolicy.MaxRetries = 1 },
		"run mismatch":          func(task *corev1alpha1.Task) { task.Labels[RunLabel] = "other-run" },
		"missing role":          func(task *corev1alpha1.Task) { delete(task.Labels, labels.LabelCreatedBy) },
		"request digest":        func(task *corev1alpha1.Task) { task.Annotations[RequestDigestAnnotation] = "wrong" },
		"empty identity":        func(task *corev1alpha1.Task) { task.Annotations[IdentityAnnotation] = "" },
		"additional annotation": func(task *corev1alpha1.Task) { task.Annotations[labels.AnnotationTransactionTokenSecret] = "extra" },
		"resource type":         func(task *corev1alpha1.Task) { task.Kind = "Agent" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPolicyFixture(t)
			mutate(f.task)
			require.Error(t, ValidateNativeDispatch(t.Context(), f.reader, f.task, f.agent, f.provider))
		})
	}
}

func TestNativeMarkersCannotBypassGuardIndependently(t *testing.T) {
	t.Parallel()
	require.False(t, IsNativeProposal(nil))
	require.False(t, IsNativeProposal(&corev1alpha1.Task{}))
	require.True(t, IsNativeProposal(&corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{
		Labels: map[string]string{labels.LabelCreatedBy: CreatedBy},
	}}))
	require.True(t, IsNativeProposal(&corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{IdentityAnnotation: ""},
	}}))
}

func TestMetadataErrorsDoNotExposeResponseContent(t *testing.T) {
	t.Parallel()
	f := newPolicyFixture(t)
	kube := fake.NewClientBuilder().Build()
	reader := interceptor.NewClient(kube, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("private-api-content")
		},
	})
	_, err := MetadataIdentity(t.Context(), reader, f.agent, f.provider)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private-api-content")
}
