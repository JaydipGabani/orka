package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/controller"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
	"github.com/orka-agents/orka/internal/workerenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type nativeResultStore struct {
	store.ResultStore
	reads int
	onGet func()
	err   error
}

func (s *nativeResultStore) GetResult(ctx context.Context, namespace, name string) ([]byte, error) {
	s.reads++
	if s.onGet != nil {
		s.onGet()
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.ResultStore.GetResult(ctx, namespace, name)
}

type nativeFixture struct {
	adapter   KubernetesClient
	kube      client.WithWatch
	scheme    *runtime.Scheme
	request   Request
	agent     *corev1alpha1.Agent
	provider  *corev1alpha1.Provider
	results   *nativeResultStore
	creates   int
	createErr error
}

func newNativeFixture(t *testing.T) *nativeFixture {
	t.Helper()
	f := &nativeFixture{
		scheme: runtime.NewScheme(),
		request: Request{
			TaskName: "native-proposal", RunID: "run-0123456789", Prompt: "Use only this synthetic source packet.",
		},
		agent: &corev1alpha1.Agent{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "remediation-tests", Name: "proposal-agent", UID: "agent-uid", Generation: 1,
			},
			Spec: corev1alpha1.AgentSpec{
				ProviderRef: &corev1alpha1.ProviderReference{Name: "proposal-provider"},
				Model:       &corev1alpha1.ModelConfig{Name: "synthetic-model"},
			},
		},
		provider: &corev1alpha1.Provider{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "remediation-tests", Name: "proposal-provider", UID: "provider-uid", Generation: 1,
			},
			Spec: corev1alpha1.ProviderSpec{
				Type: corev1alpha1.ProviderTypeOpenAI, DefaultModel: "synthetic-default",
				SecretRef: corev1alpha1.ProviderSecretRef{Name: "provider-credential", Key: "api-key"},
			},
			Status: corev1alpha1.ProviderStatus{Ready: true},
		},
	}
	require.NoError(t, corev1alpha1.AddToScheme(f.scheme))
	require.NoError(t, corev1.AddToScheme(f.scheme))
	require.NoError(t, batchv1.AddToScheme(f.scheme))
	f.kube = fake.NewClientBuilder().WithScheme(f.scheme).
		WithStatusSubresource(&corev1alpha1.Task{}, &corev1alpha1.Agent{}, &corev1alpha1.Provider{}, &batchv1.Job{}, &corev1.Pod{}).
		WithObjects(f.agent, f.provider, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: f.agent.Namespace, Name: f.provider.Spec.SecretRef.Name, UID: "provider-secret-uid", ResourceVersion: "1",
		}}).Build()
	db, err := sqlite.NewDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	f.results = &nativeResultStore{ResultStore: sqlite.NewStore(db, ":memory:")}
	f.adapter = KubernetesClient{
		Client: interceptor.NewClient(f.kube, interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return errors.New("cached reader must never be used")
			},
			Create: func(ctx context.Context, delegate client.WithWatch, object client.Object, options ...client.CreateOption) error {
				f.creates++
				object.SetUID("proposal-task-uid")
				object.SetGeneration(1)
				if err := delegate.Create(ctx, object, options...); err != nil {
					return err
				}
				return f.createErr
			},
		}),
		Reader: f.kube, Results: f.results,
		Namespace: f.agent.Namespace, AgentName: f.agent.Name, PollInterval: time.Microsecond,
	}
	snapshot, err := f.adapter.Snapshot(t.Context())
	require.NoError(t, err)
	f.request.ExpectedIdentity = snapshot.Digest
	require.NoError(t, f.results.SaveResult(t.Context(), f.agent.Namespace, f.request.TaskName, []byte(`{"summary":"synthetic"}`)))
	return f
}

func (f *nativeFixture) task(t *testing.T) *corev1alpha1.Task {
	t.Helper()
	task := &corev1alpha1.Task{}
	require.NoError(t, f.kube.Get(t.Context(), client.ObjectKey{
		Namespace: f.agent.Namespace, Name: f.request.TaskName,
	}, task))
	return task
}

func (f *nativeFixture) seed(t *testing.T, phase corev1alpha1.TaskPhase) *corev1alpha1.Task {
	t.Helper()
	task, err := f.adapter.nativeTask(f.request)
	require.NoError(t, err)
	task.UID, task.Generation = "proposal-task-uid", 1
	task.Status.Phase = phase
	require.NoError(t, f.kube.Create(t.Context(), task))
	return task
}

func (f *nativeFixture) finish(t *testing.T) {
	t.Helper()
	task := f.task(t)
	task.Status.Phase = corev1alpha1.TaskPhaseSucceeded
	require.NoError(t, f.kube.Status().Update(t.Context(), task))
}

func (f *nativeFixture) updateAgent(t *testing.T, change func(*corev1alpha1.Agent)) {
	t.Helper()
	registered := &corev1alpha1.Agent{}
	require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.agent), registered))
	change(registered)
	require.NoError(t, f.kube.Update(t.Context(), registered))
}

func (f *nativeFixture) jobBuilder() *controller.JobBuilder {
	builder := controller.NewJobBuilder(f.kube)
	builder.RemediationDispatchValidator = func(
		ctx context.Context, task *corev1alpha1.Task, registered *corev1alpha1.Agent, provider *corev1alpha1.Provider,
	) error {
		return remediationpolicy.ValidateNativeDispatch(ctx, f.adapter.Reader, task, registered, provider)
	}
	return builder
}

func TestKubernetesGenerateNativeWireAndNoAmbientMemory(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	calls := 0
	f.adapter.OnAccepted = func(_ context.Context, accepted Result) error {
		calls++
		require.Equal(t, Result{TaskName: f.request.TaskName, TaskUID: "proposal-task-uid"}, accepted)
		require.Zero(t, f.results.reads)
		f.finish(t)
		return nil
	}
	result, err := f.adapter.Generate(t.Context(), f.request)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Equal(t, 1, f.creates)
	require.Equal(t, `{"summary":"synthetic"}`, result.Output)
	task := f.task(t)
	require.Equal(t, corev1alpha1.TaskSpec{
		Type: corev1alpha1.TaskTypeAI, Prompt: f.request.Prompt,
		AgentRef:    &corev1alpha1.AgentReference{Name: f.agent.Name},
		Timeout:     &metav1.Duration{Duration: 15 * time.Minute},
		RetryPolicy: &corev1alpha1.RetryPolicy{MaxRetries: 0, BackoffMultiplier: 2},
		Env: []corev1.EnvVar{
			{Name: "ORKA_MEMORY_TOOLS_AUTO_ENABLE", Value: "false"},
			{Name: "ORKA_MEMORY_CONTEXT_ENABLED", Value: "false"},
			{Name: "ORKA_RESULT_STDOUT", Value: "true"},
		},
	}, task.Spec)
	require.Equal(t, nativeProposalOwner, task.Labels[labels.LabelCreatedBy])
	require.Equal(t, f.request.RunID, task.Labels[nativeRunLabel])
	require.Equal(t, f.request.ExpectedIdentity, task.Annotations[nativeIdentityAnnotation])
	require.True(t, validNativeDigest(task.Annotations[nativeRequestAnnotation]))

	builder := f.jobBuilder()
	builder.AIWorkerImage = "example.invalid/synthetic-worker"
	builder.ControllerURL = "http://127.0.0.1/synthetic-controller"
	job, err := builder.Build(t.Context(), task, f.agent, f.provider)
	require.NoError(t, err)
	require.Len(t, job.Spec.Template.Spec.Containers, 1)
	require.Empty(t, job.Spec.Template.Spec.InitContainers)
	worker := job.Spec.Template.Spec.Containers[0]
	require.Equal(t, []string{"--mode=ai"}, worker.Args)
	require.Empty(t, worker.EnvFrom)
	require.EqualValues(t, 0, *job.Spec.BackoffLimit)
	require.EqualValues(t, 900, *job.Spec.ActiveDeadlineSeconds)
	for key, want := range map[string]string{
		workerenv.MemoryToolsAutoEnable: "false", workerenv.MemoryContextEnabled: "false",
		workerenv.ResultStdout: "true",
		workerenv.AITools:      "", workerenv.CoordinationEnabled: "",
		workerenv.AIModel: f.agent.Spec.Model.Name, workerenv.AIPrompt: f.request.Prompt,
	} {
		matches := 0
		for _, env := range worker.Env {
			if env.Name == key {
				matches++
				require.Equal(t, want, env.Value)
				require.Nil(t, env.ValueFrom)
			}
		}
		require.Equal(t, 1, matches, "worker must receive exactly one value for %s", key)
	}
	ordinary := task.DeepCopy()
	ordinary.Spec.Env = nil
	ordinary.Labels, ordinary.Annotations = nil, nil
	ordinaryJob, err := builder.Build(t.Context(), ordinary, f.agent, f.provider)
	require.NoError(t, err)
	for _, env := range ordinaryJob.Spec.Template.Spec.Containers[0].Env {
		require.NotEqual(t, workerenv.MemoryToolsAutoEnable, env.Name, "ordinary workers keep their existing memory defaults")
		require.NotEqual(t, workerenv.MemoryContextEnabled, env.Name, "ordinary workers keep their existing memory defaults")
	}
}

func TestKubernetesRealJobBuilderRejectsRenderConfigurationDrift(t *testing.T) {
	for _, changed := range []string{"Agent", "Provider"} {
		t.Run(changed, func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			task := f.seed(t, corev1alpha1.TaskPhasePending)
			registered, provider := f.agent.DeepCopy(), f.provider.DeepCopy()
			if changed == "Agent" {
				registered.Generation++
				registered.Spec.Model.Name = "unapproved-model"
			} else {
				provider.Generation++
				provider.Spec.BaseURL = "https://unapproved.invalid"
			}
			// The uncached API still contains the old, approved configuration.
			// Re-fetching those objects instead of checking the actual render
			// arguments would incorrectly allow this Job.
			job, err := f.jobBuilder().Build(t.Context(), task, registered, provider)
			require.ErrorIs(t, err, remediationpolicy.ErrIdentityChanged)
			require.Nil(t, job)
			require.NotContains(t, err.Error(), "unapproved")
		})
	}
}

func TestKubernetesSnapshotReadsSecretMetadataOnly(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	var metadataReads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Empty(t, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		var response any
		switch {
		case strings.HasSuffix(r.URL.Path, "/agents/"+f.agent.Name):
			response = f.agent
		case strings.HasSuffix(r.URL.Path, "/providers/"+f.provider.Name):
			response = f.provider
		case strings.HasSuffix(r.URL.Path, "/secrets/"+f.provider.Spec.SecretRef.Name):
			metadataReads.Add(1)
			assert.Contains(t, r.Header.Get("Accept"), "as=PartialObjectMetadata")
			response = &metav1.PartialObjectMetadata{
				TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.agent.Namespace, Name: f.provider.Spec.SecretRef.Name, UID: "provider-secret-uid", ResourceVersion: "1",
				},
			}
		default:
			http.NotFound(w, r)
			return
		}
		assert.NoError(t, json.NewEncoder(w).Encode(response))
	}))
	defer server.Close()
	f.adapter.Reader = nativeHTTPClient(t, f.scheme, server)
	identity, err := f.adapter.Snapshot(t.Context())
	require.NoError(t, err)
	require.Equal(t, f.request.ExpectedIdentity, identity.Digest)
	require.Equal(t, "agent-uid", identity.AgentUID)
	require.Equal(t, "provider-uid", identity.ProviderUID)
	require.Equal(t, "provider-secret-uid", identity.SecretUID)
	require.Equal(t, "1", identity.SecretResourceVersion)
	require.EqualValues(t, 1, metadataReads.Load())
}

func nativeHTTPClient(t *testing.T, scheme *runtime.Scheme, server *httptest.Server) client.Client {
	t.Helper()
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{
		corev1alpha1.GroupVersion, corev1.SchemeGroupVersion, batchv1.SchemeGroupVersion,
	})
	for _, kind := range []string{"Task", "Agent", "Provider"} {
		mapper.Add(corev1alpha1.GroupVersion.WithKind(kind), meta.RESTScopeNamespace)
	}
	mapper.Add(corev1.SchemeGroupVersion.WithKind("Secret"), meta.RESTScopeNamespace)
	mapper.Add(corev1.SchemeGroupVersion.WithKind("Pod"), meta.RESTScopeNamespace)
	mapper.Add(batchv1.SchemeGroupVersion.WithKind("Job"), meta.RESTScopeNamespace)
	kube, err := client.New(&rest.Config{Host: server.URL}, client.Options{
		Scheme: scheme, Mapper: mapper, HTTPClient: server.Client(),
	})
	require.NoError(t, err)
	return kube
}

func TestKubernetesNativeAgentPolicyRejectsExtensions(t *testing.T) {
	enabled, disabled := true, false
	cases := map[string]func(*corev1alpha1.Agent){
		"implicitly enabled tool": func(a *corev1alpha1.Agent) { a.Spec.Tools = []corev1alpha1.ToolReference{{Name: "file_read"}} },
		"enabled tool": func(a *corev1alpha1.Agent) {
			a.Spec.Tools = []corev1alpha1.ToolReference{{Name: "file_read", Enabled: &enabled}}
		},
		"runtime":               func(a *corev1alpha1.Agent) { a.Spec.Runtime = &corev1alpha1.AgentCLIRuntime{} },
		"disabled coordination": func(a *corev1alpha1.Agent) { a.Spec.Coordination = &corev1alpha1.CoordinationConfig{Enabled: false} },
		"coordination":          func(a *corev1alpha1.Agent) { a.Spec.Coordination = &corev1alpha1.CoordinationConfig{Enabled: true} },
		"skill":                 func(a *corev1alpha1.Agent) { a.Spec.Skills = []corev1alpha1.SkillReference{{Name: "synthetic-skill"}} },
		"fallback": func(a *corev1alpha1.Agent) {
			a.Spec.Model.Fallbacks = []corev1alpha1.ModelFallback{{ProviderRef: "fallback"}}
		},
		"credential override": func(a *corev1alpha1.Agent) { a.Spec.SecretRef = &corev1.LocalObjectReference{Name: "override"} },
		"execution":           func(a *corev1alpha1.Agent) { a.Spec.Execution = &corev1alpha1.ExecutionSpec{} },
		"mutable prompt": func(a *corev1alpha1.Agent) {
			a.Spec.SystemPrompt = &corev1alpha1.PromptSource{ConfigMapRef: &corev1alpha1.ConfigMapKeySelector{Name: "prompt", Key: "content"}}
		},
		"no provider":     func(a *corev1alpha1.Agent) { a.Spec.ProviderRef = nil },
		"cross namespace": func(a *corev1alpha1.Agent) { a.Spec.ProviderRef.Namespace = "another-namespace" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			f.updateAgent(t, change)
			f.request.ExpectedTaskUID = "saved-uid"
			result, err := f.adapter.Generate(t.Context(), f.request)
			require.Error(t, err)
			require.Equal(t, Result{TaskName: f.request.TaskName, TaskUID: "saved-uid"}, result)
			require.Zero(t, f.creates)
		})
	}
	t.Run("all tools explicitly disabled", func(t *testing.T) {
		t.Parallel()
		f := newNativeFixture(t)
		f.updateAgent(t, func(a *corev1alpha1.Agent) {
			a.Spec.Tools = []corev1alpha1.ToolReference{{Name: "file_read", Enabled: &disabled}}
		})
		_, err := f.adapter.Snapshot(t.Context())
		require.NoError(t, err)
	})
}

func TestKubernetesIdentityFencedBeforeCreateAndBeforeResult(t *testing.T) {
	changes := map[string]func(*testing.T, *nativeFixture){
		"agent generation": func(t *testing.T, f *nativeFixture) {
			f.updateAgent(t, func(a *corev1alpha1.Agent) { a.Generation++; a.Spec.Model.Name = "changed" })
		},
		"agent replacement": func(t *testing.T, f *nativeFixture) {
			f.updateAgent(t, func(a *corev1alpha1.Agent) { a.UID = "replaced-agent-uid" })
		},
		"provider generation": func(t *testing.T, f *nativeFixture) {
			provider := &corev1alpha1.Provider{}
			require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.provider), provider))
			provider.Generation++
			require.NoError(t, f.kube.Update(t.Context(), provider))
		},
		"provider replacement": func(t *testing.T, f *nativeFixture) {
			provider := &corev1alpha1.Provider{}
			require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.provider), provider))
			provider.UID = "replaced-provider-uid"
			require.NoError(t, f.kube.Update(t.Context(), provider))
		},
		"credential version": func(t *testing.T, f *nativeFixture) {
			secret := &corev1.Secret{}
			require.NoError(t, f.kube.Get(t.Context(), client.ObjectKey{
				Namespace: f.agent.Namespace, Name: f.provider.Spec.SecretRef.Name,
			}, secret))
			secret.Labels = map[string]string{"changed": "true"}
			require.NoError(t, f.kube.Update(t.Context(), secret))
		},
	}
	for name, change := range changes {
		for _, when := range []string{"before initial read", "before create", "before result", "during result"} {
			t.Run(name+"/"+when, func(t *testing.T) {
				t.Parallel()
				f := newNativeFixture(t)
				switch when {
				case "before initial read":
					change(t, f)
				case "before create":
					first := true
					f.adapter.Reader = interceptor.NewClient(f.kube, interceptor.Funcs{
						Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
							if _, task := object.(*corev1alpha1.Task); task && first {
								first = false
								change(t, f)
							}
							return delegate.Get(ctx, key, object, options...)
						},
					})
				case "before result":
					f.seed(t, corev1alpha1.TaskPhaseSucceeded)
					f.adapter.OnAccepted = func(context.Context, Result) error { change(t, f); return nil }
				case "during result":
					f.seed(t, corev1alpha1.TaskPhaseSucceeded)
					f.results.onGet = func() { change(t, f) }
				}
				result, err := f.adapter.Generate(t.Context(), f.request)
				require.Error(t, err)
				require.Empty(t, result.Output)
				require.Zero(t, f.creates)
				if when == "before result" || when == "during result" {
					require.Equal(t, "proposal-task-uid", result.TaskUID)
				}
			})
		}
	}
}

func TestKubernetesExistingUIDMissingOrReplacedNeverCreates(t *testing.T) {
	for _, mode := range []string{"known UID missing", "uncertain create missing", "replaced UID"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			f.request.ExpectedTaskUID = "original-uid"
			if mode == "uncertain create missing" {
				f.request.ExpectedTaskUID = ""
				f.request.RequireExisting = true
			}
			if mode == "replaced UID" {
				f.seed(t, corev1alpha1.TaskPhaseSucceeded)
			}
			f.adapter.OnAccepted = func(context.Context, Result) error {
				t.Error("must not accept a missing or replaced Task")
				return nil
			}
			result, err := f.adapter.Generate(t.Context(), f.request)
			require.Error(t, err)
			require.Equal(t, f.request.ExpectedTaskUID, result.TaskUID)
			require.Empty(t, result.Output)
			require.Zero(t, f.creates)
			require.Zero(t, f.results.reads)
		})
	}
}

func TestKubernetesNativeTaskRejectsUnrequestedExecutionAndMetadata(t *testing.T) {
	changes := map[string]func(*corev1alpha1.Task){
		"prompt":      func(task *corev1alpha1.Task) { task.Spec.Prompt = "changed prompt" },
		"credentials": func(task *corev1alpha1.Task) { task.Spec.SecretRef = &corev1alpha1.SecretReference{Name: "override"} },
		"memory env":  func(task *corev1alpha1.Task) { task.Spec.Env[0].Value = "true" },
		"other env": func(task *corev1alpha1.Task) {
			task.Spec.Env = append(task.Spec.Env, corev1.EnvVar{Name: "EXTRA", Value: "true"})
		},
		"model":     func(task *corev1alpha1.Task) { task.Spec.AI = &corev1alpha1.AISpec{Model: "override"} },
		"runtime":   func(task *corev1alpha1.Task) { task.Spec.AgentRuntime = &corev1alpha1.AgentRuntimeSpec{} },
		"workspace": func(task *corev1alpha1.Task) { task.Spec.Workspace = &corev1alpha1.WorkspaceConfig{} },
		"retries":   func(task *corev1alpha1.Task) { task.Spec.RetryPolicy.MaxRetries = 1 },
		"requester": func(task *corev1alpha1.Task) {
			task.Spec.RequestedBy = &corev1alpha1.RequestedBy{Subject: "unverified"}
		},
		"UID":       func(task *corev1alpha1.Task) { task.UID = "" },
		"ownership": func(task *corev1alpha1.Task) { delete(task.Labels, labels.LabelCreatedBy) },
		"digest":    func(task *corev1alpha1.Task) { task.Annotations[nativeRequestAnnotation] = "wrong" },
		"annotation": func(task *corev1alpha1.Task) {
			task.Annotations[labels.AnnotationTransactionTokenSecret] = "unrequested"
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			task := f.seed(t, corev1alpha1.TaskPhaseSucceeded)
			change(task)
			require.NoError(t, f.kube.Update(t.Context(), task))
			result, err := f.adapter.Generate(t.Context(), f.request)
			require.Error(t, err)
			require.Empty(t, result.TaskUID, "unvalidated metadata must not become the saved identity")
			require.Empty(t, result.Output)
			require.Zero(t, f.creates)
		})
	}
}

func TestKubernetesAcceptedCheckpointFailureAndResume(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	f.adapter.OnAccepted = func(context.Context, Result) error { return errors.New("private-checkpoint-content") }
	accepted, err := f.adapter.Generate(t.Context(), f.request)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private-checkpoint-content")
	require.Equal(t, "proposal-task-uid", accepted.TaskUID)
	require.Zero(t, f.results.reads)
	require.Equal(t, 1, f.creates)
	require.NotEmpty(t, f.task(t).UID)
	f.request.ExpectedTaskUID, f.request.RequireExisting = accepted.TaskUID, true
	f.adapter.OnAccepted = func(context.Context, Result) error { f.finish(t); return nil }
	resumed, err := f.adapter.Generate(t.Context(), f.request)
	require.NoError(t, err)
	require.Equal(t, accepted.TaskUID, resumed.TaskUID)
	require.Equal(t, 1, f.creates)
}

func TestKubernetesLostCreateAcknowledgementResumesWithoutReplay(t *testing.T) {
	for _, recoveryUnavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "immediate recovery", true: "process recovery"}[recoveryUnavailable], func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			f.createErr = errors.New("private-create-response")
			if recoveryUnavailable {
				f.adapter.Reader = interceptor.NewClient(f.kube, interceptor.Funcs{
					Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
						if _, task := object.(*corev1alpha1.Task); task && f.creates > 0 {
							return errors.New("private-read-response")
						}
						return delegate.Get(ctx, key, object, options...)
					},
				})
			}
			f.adapter.OnAccepted = func(context.Context, Result) error { f.finish(t); return nil }
			result, err := f.adapter.Generate(t.Context(), f.request)
			if recoveryUnavailable {
				require.Error(t, err)
				require.Empty(t, result.TaskUID)
				require.NotContains(t, err.Error(), "private-")
				f.adapter.Reader = f.kube
				f.request.RequireExisting = true
				result, err = f.adapter.Generate(t.Context(), f.request)
			}
			require.NoError(t, err)
			require.Equal(t, "proposal-task-uid", result.TaskUID)
			require.NotEmpty(t, result.Output)
			require.Equal(t, 1, f.creates)
		})
	}
}

func TestKubernetesAlreadyCompletedAndCRDDefaultsDoNotReplay(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	task := f.seed(t, corev1alpha1.TaskPhaseSucceeded)
	priority, success, failed := int32(500), int32(3), int32(1)
	deadline := int64(100)
	task.Spec.Priority = &priority
	task.Spec.ConcurrencyPolicy = corev1alpha1.ForbidConcurrent
	task.Spec.SuccessfulRunsHistoryLimit, task.Spec.FailedRunsHistoryLimit = &success, &failed
	task.Spec.StartingDeadlineSeconds = &deadline
	require.NoError(t, f.kube.Update(t.Context(), task))
	accepted := 0
	f.adapter.OnAccepted = func(context.Context, Result) error { accepted++; return nil }
	first, err := f.adapter.Generate(t.Context(), f.request)
	require.NoError(t, err)
	f.request.ExpectedTaskUID = first.TaskUID
	second, err := f.adapter.Generate(t.Context(), f.request)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, 2, accepted)
	require.Zero(t, f.creates)
}

func TestKubernetesTaskGenerationFencedBetweenAcceptanceAndResult(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	f.seed(t, corev1alpha1.TaskPhaseSucceeded)
	f.adapter.OnAccepted = func(context.Context, Result) error {
		task := f.task(t)
		task.Generation++
		require.NoError(t, f.kube.Update(t.Context(), task))
		return nil
	}
	result, err := f.adapter.Generate(t.Context(), f.request)
	require.Error(t, err)
	require.Equal(t, "proposal-task-uid", result.TaskUID)
	require.Empty(t, result.Output)
	require.Zero(t, f.results.reads)
}

func TestKubernetesSnapshotIgnoresUnrelatedStatusUpdates(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	registered := &corev1alpha1.Agent{}
	require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.agent), registered))
	registered.Status.ActiveTasks = 1
	require.NoError(t, f.kube.Status().Update(t.Context(), registered))
	provider := &corev1alpha1.Provider{}
	require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.provider), provider))
	now := metav1.Now()
	provider.Status.LastValidated = &now
	require.NoError(t, f.kube.Status().Update(t.Context(), provider))
	identity, err := f.adapter.Snapshot(t.Context())
	require.NoError(t, err)
	require.Equal(t, f.request.ExpectedIdentity, identity.Digest)
}

func TestKubernetesReadinessOnlyGatesNewTasks(t *testing.T) {
	for _, mode := range []string{"before create", "while running", "already succeeded"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			unready := func() {
				provider := &corev1alpha1.Provider{}
				require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(f.provider), provider))
				provider.Status.Ready = false
				provider.Status.Message = "private-readiness-status"
				require.NoError(t, f.kube.Status().Update(t.Context(), provider))
			}
			switch mode {
			case "before create":
				unready()
			case "while running":
				f.seed(t, corev1alpha1.TaskPhaseRunning)
				f.adapter.OnAccepted = func(context.Context, Result) error {
					unready()
					f.finish(t)
					return nil
				}
			case "already succeeded":
				f.seed(t, corev1alpha1.TaskPhaseSucceeded)
				unready()
			}
			result, err := f.adapter.Generate(t.Context(), f.request)
			if mode == "before create" {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "private-readiness-status")
				require.Empty(t, result.Output)
			} else {
				require.NoError(t, err)
				require.Equal(t, "proposal-task-uid", result.TaskUID)
				require.NotEmpty(t, result.Output)
			}
			require.Zero(t, f.creates)
		})
	}
}

func TestKubernetesCredentialRotationIsTypedAndNeverRetries(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "resource version", true: "Secret UID"}[replacement], func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			f.seed(t, corev1alpha1.TaskPhaseRunning)
			f.adapter.OnAccepted = func(context.Context, Result) error {
				secret := &corev1.Secret{}
				require.NoError(t, f.kube.Get(t.Context(), client.ObjectKey{
					Namespace: f.agent.Namespace, Name: f.provider.Spec.SecretRef.Name,
				}, secret))
				secret.Labels = map[string]string{"rotation": "observed"}
				if replacement {
					secret.UID = "replacement-secret-uid"
				}
				require.NoError(t, f.kube.Update(t.Context(), secret))
				return nil
			}
			result, err := f.adapter.Generate(t.Context(), f.request)
			require.ErrorIs(t, err, ErrCredentialRotated)
			require.Equal(t, "proposal-task-uid", result.TaskUID)
			require.Empty(t, result.Output)
			require.Zero(t, f.creates)
			require.Zero(t, f.results.reads)
		})
	}
}

func TestKubernetesResultsBoundedAndNonempty(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty": {}, "whitespace": []byte(" \n\t"),
		"sentinel":      []byte("Prompt completed without textual output."),
		"invalid UTF-8": {0xff}, "oversized": []byte(strings.Repeat("a", maxResponseBytes+1)),
		"at limit": []byte(strings.Repeat("a", maxResponseBytes)),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			f.seed(t, corev1alpha1.TaskPhaseSucceeded)
			require.NoError(t, f.results.SaveResult(t.Context(), f.agent.Namespace, f.request.TaskName, data))
			result, err := f.adapter.Generate(t.Context(), f.request)
			require.Equal(t, "proposal-task-uid", result.TaskUID)
			if name == "at limit" {
				require.NoError(t, err)
				require.Len(t, result.Output, maxResponseBytes)
			} else {
				require.Error(t, err)
				require.Empty(t, result.Output)
			}
		})
	}
}

func TestKubernetesResultReadFencesTaskUIDSpecAndPhase(t *testing.T) {
	for _, change := range []string{"UID", "spec", "generation", "phase", "missing", "store error"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			f.seed(t, corev1alpha1.TaskPhaseSucceeded)
			f.results.onGet = func() {
				task := f.task(t)
				switch change {
				case "UID":
					task.UID = "replacement-uid"
				case "spec":
					task.Spec.Prompt = "mutated content"
				case "generation":
					task.Generation++
				case "phase":
					task.Status.Phase = corev1alpha1.TaskPhaseRunning
					require.NoError(t, f.kube.Status().Update(t.Context(), task))
					return
				case "missing":
					require.NoError(t, f.kube.Delete(t.Context(), task))
					return
				case "store error":
					f.results.err = errors.New("private-result-content")
					return
				}
				require.NoError(t, f.kube.Update(t.Context(), task))
			}
			result, err := f.adapter.Generate(t.Context(), f.request)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "private-result-content")
			require.Equal(t, "proposal-task-uid", result.TaskUID)
			require.Empty(t, result.Output)
			require.Zero(t, f.creates)
		})
	}
}

func TestKubernetesContextCancellationStopsWaitingNotTask(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.adapter.OnAccepted = func(context.Context, Result) error { cancel(); return nil }
	result, err := f.adapter.Generate(ctx, f.request)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, "proposal-task-uid", result.TaskUID)
	require.Empty(t, f.task(t).Status.Phase)
	require.Zero(t, f.results.reads)
	require.Equal(t, 1, f.creates)
}

func TestKubernetesTerminalFailuresKeepUIDWithoutReplaying(t *testing.T) {
	for _, phase := range []corev1alpha1.TaskPhase{
		corev1alpha1.TaskPhaseFailed, corev1alpha1.TaskPhaseCancelled, corev1alpha1.TaskPhaseScheduled, "unexpected",
	} {
		t.Run(string(phase), func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			task := f.seed(t, phase)
			task.Status.Message = "private-runtime-message"
			require.NoError(t, f.kube.Status().Update(t.Context(), task))
			result, err := f.adapter.Generate(t.Context(), f.request)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "private-runtime-message")
			require.Equal(t, "proposal-task-uid", result.TaskUID)
			require.Empty(t, result.Output)
			require.Zero(t, f.creates)
			require.Zero(t, f.results.reads)
		})
	}
}

func TestKubernetesCancelUsesSupportedNativePhase(t *testing.T) {
	for _, phase := range []corev1alpha1.TaskPhase{
		"", corev1alpha1.TaskPhasePending, corev1alpha1.TaskPhaseRunning, corev1alpha1.TaskPhaseSucceeded,
		corev1alpha1.TaskPhaseFailed, corev1alpha1.TaskPhaseCancelled, corev1alpha1.TaskPhaseFinalizing,
	} {
		t.Run(string(phase), func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			task := f.seed(t, phase)
			err := f.adapter.Cancel(t.Context(), task.Name, string(task.UID))
			if phase == corev1alpha1.TaskPhaseFinalizing {
				require.ErrorIs(t, err, ErrUnsupported)
				require.Equal(t, phase, f.task(t).Status.Phase)
				return
			}
			actual := f.task(t)
			switch phase {
			case "":
				require.ErrorIs(t, err, ErrCancellationPending)
				require.Empty(t, actual.Status.Phase, "status initialization must be acknowledged before cancellation")
			case corev1alpha1.TaskPhasePending, corev1alpha1.TaskPhaseRunning:
				require.ErrorIs(t, err, ErrCancellationPending)
				require.Equal(t, corev1alpha1.TaskPhaseCancelled, actual.Status.Phase)
				require.NotNil(t, actual.Status.CompletionTime)
				require.Equal(t, nativeCancellationMessage, actual.Status.Message)
				require.ErrorIs(t, f.adapter.Cancel(t.Context(), task.Name, string(task.UID)), ErrCancellationPending,
					"no Job receipt cannot prove that no dispatch is still in flight")
			case corev1alpha1.TaskPhaseCancelled:
				require.ErrorIs(t, err, ErrCancellationPending)
			default:
				require.NoError(t, err)
				require.Equal(t, phase, actual.Status.Phase)
			}
			require.Equal(t, task.Spec, actual.Spec)
			require.Zero(t, f.creates)
		})
	}
}

func TestKubernetesCancelFencesUIDAndResourceVersionOnWire(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "conflict"}[conflict], func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			task := f.seed(t, corev1alpha1.TaskPhaseRunning)
			task.ResourceVersion = "12345"
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodGet:
					assert.NoError(t, json.NewEncoder(w).Encode(task))
				case http.MethodPut:
					writes.Add(1)
					assert.True(t, strings.HasSuffix(r.URL.Path, "/tasks/"+task.Name+"/status"))
					var submitted corev1alpha1.Task
					assert.NoError(t, json.NewDecoder(r.Body).Decode(&submitted))
					assert.Equal(t, task.UID, submitted.UID)
					assert.Equal(t, "12345", submitted.ResourceVersion)
					assert.Equal(t, task.Spec, submitted.Spec)
					assert.Equal(t, corev1alpha1.TaskPhaseCancelled, submitted.Status.Phase)
					if conflict {
						w.WriteHeader(http.StatusConflict)
						assert.NoError(t, json.NewEncoder(w).Encode(metav1.Status{
							Status: metav1.StatusFailure, Reason: metav1.StatusReasonConflict, Code: http.StatusConflict,
							Message: "private-conflict-content",
						}))
						return
					}
					assert.NoError(t, json.NewEncoder(w).Encode(submitted))
				default:
					t.Error("cancellation must not create, patch, or delete resources")
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			wire := nativeHTTPClient(t, f.scheme, server)
			f.adapter.Client, f.adapter.Reader = wire, wire
			err := f.adapter.Cancel(t.Context(), task.Name, string(task.UID))
			if conflict {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "private-conflict-content")
			} else {
				require.ErrorIs(t, err, ErrCancellationPending)
			}
			require.EqualValues(t, 1, writes.Load())
			require.Error(t, f.adapter.Cancel(t.Context(), task.Name, "different-uid"))
			require.EqualValues(t, 1, writes.Load())
		})
	}
}

func (f *nativeFixture) execution(t *testing.T) (*corev1alpha1.Task, *batchv1.Job, *corev1.Pod) {
	t.Helper()
	task := f.seed(t, corev1alpha1.TaskPhaseRunning)
	task.Finalizers = []string{labels.TaskFinalizer}
	require.NoError(t, f.kube.Update(t.Context(), task))
	builder := f.jobBuilder()
	builder.AIWorkerImage = "example.invalid/synthetic-native-worker"
	job, err := builder.Build(t.Context(), task, f.agent, f.provider)
	require.NoError(t, err)
	require.NoError(t, controllerutil.SetControllerReference(task, job, f.scheme))
	job.UID, job.Status.Active = "native-job-uid", 1
	require.NoError(t, f.kube.Create(t.Context(), job))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: task.Namespace, Name: job.Name + "-pod", UID: "native-pod-uid",
			Labels: job.Spec.Template.Labels,
		},
		Spec: *job.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	require.NoError(t, controllerutil.SetControllerReference(job, pod, f.scheme))
	require.NoError(t, f.kube.Create(t.Context(), pod))
	task.Status.JobName = job.Name
	task.Status.Attempts = 1
	require.NoError(t, f.kube.Status().Update(t.Context(), task))
	return task, job, pod
}

func TestKubernetesCancelObservesRealControllerCleanupAndPodStop(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	task, job, pod := f.execution(t)
	require.ErrorIs(t, f.adapter.Cancel(t.Context(), task.Name, string(task.UID)), ErrCancellationPending)
	require.Equal(t, corev1alpha1.TaskPhaseCancelled, f.task(t).Status.Phase)
	require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(job), &batchv1.Job{}))

	deletes := 0
	reconciler := &controller.TaskReconciler{
		Scheme: f.scheme,
		Client: interceptor.NewClient(f.kube, interceptor.Funcs{
			Delete: func(ctx context.Context, delegate client.WithWatch, object client.Object, options ...client.DeleteOption) error {
				deletes++
				require.IsType(t, &batchv1.Job{}, object)
				require.Equal(t, job.Name, object.GetName())
				opts := (&client.DeleteOptions{}).ApplyOptions(options)
				require.NotNil(t, opts.PropagationPolicy)
				require.Equal(t, metav1.DeletePropagationBackground, *opts.PropagationPolicy)
				return delegate.Delete(ctx, object, options...)
			},
		}),
	}
	_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(task)})
	require.NoError(t, err)
	require.Equal(t, 1, deletes, "the production cancelled Task path must delete its Job")
	require.True(t, apierrors.IsNotFound(f.kube.Get(t.Context(), client.ObjectKeyFromObject(job), &batchv1.Job{})))
	require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), pod))
	require.Equal(t, corev1.PodRunning, pod.Status.Phase)
	require.ErrorIs(t, f.adapter.Cancel(t.Context(), task.Name, string(task.UID)), ErrCancellationPending,
		"background Job deletion does not prove the model process stopped")

	pod.Labels = nil
	require.NoError(t, f.kube.Update(t.Context(), pod))
	require.ErrorIs(t, f.adapter.Cancel(t.Context(), task.Name, string(task.UID)), ErrCancellationPending,
		"removed labels do not hide a still-running Job-owned Pod")
	require.NoError(t, f.kube.Delete(t.Context(), pod, client.Preconditions{UID: &pod.UID}))
	require.NoError(t, f.adapter.Cancel(t.Context(), task.Name, string(task.UID)))
	_, err = reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(task)})
	require.NoError(t, err)
	jobs := &batchv1.JobList{}
	require.NoError(t, f.kube.List(t.Context(), jobs, client.InNamespace(task.Namespace)))
	require.Empty(t, jobs.Items, "a cancelled Task must not replay after observed shutdown")
}

func TestKubernetesCancelStopsJobCreatedBeforeBindingAcknowledgement(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	task, job, pod := f.execution(t)
	task.Status.Phase, task.Status.JobName = corev1alpha1.TaskPhaseCancelled, ""
	require.NoError(t, f.kube.Status().Update(t.Context(), task))
	pod.Labels = nil
	require.NoError(t, f.kube.Update(t.Context(), pod))
	deletes := 0
	f.adapter.Client = interceptor.NewClient(f.kube, interceptor.Funcs{
		Delete: func(ctx context.Context, delegate client.WithWatch, object client.Object, options ...client.DeleteOption) error {
			deletes++
			require.IsType(t, &batchv1.Job{}, object)
			opts := (&client.DeleteOptions{}).ApplyOptions(options)
			require.NotNil(t, opts.Preconditions)
			require.Equal(t, job.UID, *opts.Preconditions.UID)
			require.Equal(t, job.ResourceVersion, *opts.Preconditions.ResourceVersion)
			require.Equal(t, metav1.DeletePropagationForeground, *opts.PropagationPolicy)
			return delegate.Delete(ctx, object, options...)
		},
	})
	require.ErrorIs(t, f.adapter.Cancel(t.Context(), task.Name, string(task.UID)), ErrCancellationPending)
	require.Equal(t, 1, deletes)
	require.True(t, apierrors.IsNotFound(f.kube.Get(t.Context(), client.ObjectKeyFromObject(job), &batchv1.Job{})))
	require.ErrorIs(t, f.adapter.Cancel(t.Context(), task.Name, string(task.UID)), ErrCancellationPending,
		"the real worker's immutable TaskUID env keeps an unlabelled, unbound Pod observable after Job deletion")
	require.Equal(t, 1, deletes, "the adapter must never delete the Pod directly")
	pod.Status.Phase = corev1.PodSucceeded
	require.NoError(t, f.kube.Status().Update(t.Context(), pod))
	require.NoError(t, f.adapter.Cancel(t.Context(), task.Name, string(task.UID)))
}

func TestKubernetesCancelRejectsForeignJobBeforeStatusMutation(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	task, job, _ := f.execution(t)
	job.OwnerReferences[0].UID = "foreign-task-uid"
	require.NoError(t, f.kube.Update(t.Context(), job))
	require.Error(t, f.adapter.Cancel(t.Context(), task.Name, string(task.UID)))
	require.Equal(t, corev1alpha1.TaskPhaseRunning, f.task(t).Status.Phase)
	current := &batchv1.Job{}
	require.NoError(t, f.kube.Get(t.Context(), client.ObjectKeyFromObject(job), current))
	require.Equal(t, job.UID, current.UID)
}

func TestKubernetesCancelRevalidatesTaskUIDAfterShutdownObservation(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	task, job, pod := f.execution(t)
	task.Status.Phase = corev1alpha1.TaskPhaseCancelled
	require.NoError(t, f.kube.Status().Update(t.Context(), task))
	require.NoError(t, f.kube.Delete(t.Context(), job, client.Preconditions{UID: &job.UID}))
	require.NoError(t, f.kube.Delete(t.Context(), pod, client.Preconditions{UID: &pod.UID}))
	reads := 0
	f.adapter.Reader = interceptor.NewClient(f.kube, interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
			if err := delegate.Get(ctx, key, object, options...); err != nil {
				return err
			}
			if observed, ok := object.(*corev1alpha1.Task); ok {
				reads++
				if reads == 2 {
					observed.UID = "replacement-task-uid"
				}
			}
			return nil
		},
	})
	err := f.adapter.Cancel(t.Context(), task.Name, string(task.UID))
	require.Equal(t, 2, reads)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrCancellationPending)
	require.Contains(t, err.Error(), "UID changed")
}

func TestKubernetesCancelJobDeletionPreconditionsOnWire(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "replaced Job"}[conflict], func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			task, job, pod := f.execution(t)
			task.Status.Phase = corev1alpha1.TaskPhaseCancelled
			var deletes atomic.Int32
			codecs := serializer.NewCodecFactory(f.scheme)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Contains(t, r.URL.Path, "/namespaces/"+task.Namespace+"/")
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodDelete {
					deletes.Add(1)
					assert.True(t, strings.HasSuffix(r.URL.Path, "/jobs/"+job.Name))
					var options metav1.DeleteOptions
					data, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
					assert.NoError(t, err)
					assert.NoError(t, runtime.DecodeInto(codecs.UniversalDeserializer(), data, &options))
					assert.Equal(t, &metav1.Preconditions{UID: &job.UID, ResourceVersion: &job.ResourceVersion}, options.Preconditions)
					assert.Equal(t, new(metav1.DeletePropagationForeground), options.PropagationPolicy)
					if conflict {
						w.WriteHeader(http.StatusConflict)
						assert.NoError(t, json.NewEncoder(w).Encode(metav1.Status{
							Status: metav1.StatusFailure, Reason: metav1.StatusReasonConflict, Code: http.StatusConflict,
							Message: "private-job-conflict",
						}))
					} else {
						assert.NoError(t, json.NewEncoder(w).Encode(metav1.Status{Status: metav1.StatusSuccess}))
					}
					return
				}
				assert.Equal(t, http.MethodGet, r.Method)
				switch {
				case strings.HasSuffix(r.URL.Path, "/tasks/"+task.Name):
					assert.NoError(t, json.NewEncoder(w).Encode(task))
				case strings.HasSuffix(r.URL.Path, "/jobs"):
					assert.NoError(t, json.NewEncoder(w).Encode(&batchv1.JobList{Items: []batchv1.Job{*job}}))
				case strings.HasSuffix(r.URL.Path, "/pods"):
					assert.NoError(t, json.NewEncoder(w).Encode(&corev1.PodList{Items: []corev1.Pod{*pod}}))
				default:
					t.Error("unexpected cancellation resource access")
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			wire := nativeHTTPClient(t, f.scheme, server)
			f.adapter.Client, f.adapter.Reader = wire, wire
			err := f.adapter.Cancel(t.Context(), task.Name, string(task.UID))
			require.ErrorIs(t, err, ErrCancellationPending)
			require.NotContains(t, err.Error(), "private-job-conflict")
			require.EqualValues(t, 1, deletes.Load())
		})
	}
}

func TestKubernetesRequestValidationPreservesSavedUID(t *testing.T) {
	for name, mutate := range map[string]func(*nativeFixture){
		"no reader":        func(f *nativeFixture) { f.adapter.Reader = nil },
		"no writer":        func(f *nativeFixture) { f.adapter.Client = nil },
		"no store":         func(f *nativeFixture) { f.adapter.Results = nil },
		"namespace":        func(f *nativeFixture) { f.adapter.Namespace = "" },
		"agent":            func(f *nativeFixture) { f.adapter.AgentName = "" },
		"task":             func(f *nativeFixture) { f.request.TaskName = "../bad" },
		"prompt":           func(f *nativeFixture) { f.request.Prompt = " \n" },
		"oversized prompt": func(f *nativeFixture) { f.request.Prompt = strings.Repeat("p", maxPromptBytes+1) },
		"repository":       func(f *nativeFixture) { f.request.Repository = "https://github.com/synthetic/repository" },
		"commit":           func(f *nativeFixture) { f.request.Commit = strings.Repeat("a", 40) },
		"runtime override": func(f *nativeFixture) { f.request.MaxTurns = 1 },
		"identity":         func(f *nativeFixture) { f.request.ExpectedIdentity = "invalid" },
		"run":              func(f *nativeFixture) { f.request.RunID = "../bad" },
		"poll interval":    func(f *nativeFixture) { f.adapter.PollInterval = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newNativeFixture(t)
			f.request.ExpectedTaskUID = "saved-uid"
			mutate(f)
			result, err := f.adapter.Generate(t.Context(), f.request)
			require.Error(t, err)
			require.Equal(t, "saved-uid", result.TaskUID)
			require.Empty(t, result.Output)
			require.Zero(t, f.creates)
		})
	}
}

func TestKubernetesReadErrorsAreContentFree(t *testing.T) {
	t.Parallel()
	f := newNativeFixture(t)
	f.request.ExpectedTaskUID = "saved-uid"
	f.adapter.Reader = interceptor.NewClient(f.kube, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return apierrors.NewInvalid(schema.GroupKind{Kind: "Task"}, "private-error-content", nil)
		},
	})
	result, err := f.adapter.Generate(t.Context(), f.request)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private-error-content")
	require.Equal(t, types.UID("saved-uid"), types.UID(result.TaskUID))
	require.Zero(t, f.creates)
}
