package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	"github.com/orka-agents/orka/internal/remediation/provenance"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type controllerTestBuilder struct {
	pipelineEnvironment
	baseline     provenance.Recipe
	cancelled    atomic.Int32
	blockBuild   chan struct{}
	buildBlocked atomic.Bool
}

func (b *controllerTestBuilder) FreezeBuildPlan(binding environment.Bind, capability, contract string) (environment.Plan, error) {
	plan := environment.Plan{Version: 1, Bind: binding, ExternalObservation: &environment.ExternalObservation{
		Capability: capability, ContractDigest: contract,
	}}
	plan.Bind.ChecksDigest = environment.ChecksDigest(plan)
	return plan, nil
}

func (b *controllerTestBuilder) Build(ctx context.Context, request environment.BuildRequest) (environment.BuildResult, error) {
	if b.blockBuild != nil && b.buildBlocked.CompareAndSwap(false, true) {
		close(b.blockBuild)
		<-ctx.Done()
		return environment.BuildResult{}, ctx.Err()
	}
	result, err := b.pipelineEnvironment.Build(ctx, request)
	if err != nil {
		return result, err
	}
	result.Baseline, result.Built = b.baseline, b.baseline
	if request.Role == environment.Candidate {
		result.Built.ContentDigest = Digest(append([]byte("candidate-recipe:"), request.Patch...))
		result.Built.OrderedPatches = append(append([]provenance.Patch{}, b.baseline.OrderedPatches...), provenance.Patch{
			Path: "candidate.patch", Digest: request.PatchDigest, InputDigest: request.PatchDigest, Source: b.baseline.UpstreamSource, Strip: 1,
		})
	}
	result.OriginalRecipeDigest = result.Baseline.ContentDigest
	result.BuildRecipeDigest = result.Built.ContentDigest
	result.MetadataDigest, result.WorkerEvidenceDigest = Digest([]byte("image-metadata")), Digest([]byte("worker-attestation"))
	return result, nil
}

func (b *controllerTestBuilder) CancelBuild(context.Context, string, string, environment.Plan) error {
	b.cancelled.Add(1)
	return nil
}

type controllerTestFactory struct{ adapter *controllerExecutionAdapter }

func (f controllerTestFactory) Select(context.Context, Policy, investigate.Plan) (AdapterSelection, ExecutionAdapter, error) {
	return f.adapter.selection, f.adapter, nil
}
func (f controllerTestFactory) Resume(context.Context, Policy, AdapterSelection) (ExecutionAdapter, error) {
	return f.adapter, nil
}

type controllerTestModel struct{ pipelineModel }

func (m controllerTestModel) Generate(ctx context.Context, request modelagent.Request) (modelagent.Result, error) {
	if !strings.Contains(request.Prompt, "independent controller observation plan") {
		return m.pipelineModel.Generate(ctx, request)
	}
	if previous, found := m.owner.tasks[request.TaskName]; found {
		if !request.RequireExisting || previous.TaskUID != request.ExpectedTaskUID {
			return modelagent.Result{}, ErrUnknown
		}
		return previous, nil
	}
	m.owner.calls++
	proposal := controllerCheckProposal{
		Version: 1, Capability: controllerlab.KEDANamespaceEvents,
		Actors:   []controllerlab.ActorAccess{controllerlab.NamespaceAEventSource, controllerlab.NamespaceBEventSource},
		Expected: []controllerlab.SemanticOutcome{controllerlab.NamespacedEventScope},
	}
	raw, err := json.Marshal(proposal)
	if err != nil {
		return modelagent.Result{}, err
	}
	result := modelagent.Result{TaskName: request.TaskName, TaskUID: fmt.Sprintf("controller-check-%d", m.owner.calls), Output: string(raw)}
	m.owner.tasks[request.TaskName] = result
	return result, m.accepted(ctx, result)
}

type controllerTestFixture struct {
	t             *testing.T
	service       *Service
	store         *sqlite.Store
	pipeline      *Pipeline
	adapter       *controllerExecutionAdapter
	builder       *controllerTestBuilder
	models        *pipelineModels
	kube          *kubefake.Clientset
	custom        *dynamicfake.FakeDynamicClient
	sequence      atomic.Int32
	afterState    func(context.Context, controllerlab.State) error
	beforeState   func(*controllerlab.State)
	onCreate      func(runtime.Object)
	leakCandidate bool
	statesMu      sync.Mutex
	states        map[string]controllerlab.State
}

func newControllerFixture(t *testing.T) *controllerTestFixture {
	t.Helper()
	target := source.Target{
		Repository: source.Repository{URL: "https://github.com/kedacore/keda", Owner: "kedacore", Name: "keda", DefaultBranch: "main"},
		Ref:        "v2.17.1", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40),
	}
	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("256Mi")},
	}
	config := ControllerAdapterConfig{
		ClusterUID: "dedicated-cluster", ProbeImage: "registry.invalid/probe@sha256:" + strings.Repeat("d", 64),
		Controller: controllerlab.Config{
			DedicatedClusterApproved: true, ClusterIdentity: controllerlab.ClusterIdentity("dedicated-cluster"),
			NamespacePrefix: "service-lab",
			Template: controllerlab.ControllerRuntimeTemplate{
				Family: "keda-v2", RecipeID: "synthetic-keda", Source: controllerlab.BoundSource{Repository: target.Repository.URL, Commit: target.Commit},
				Resources: resources, ClusterWatchRole: controllerlab.ObjectRef{
					Resource: schema.GroupVersionResource{Group: rbacv1.GroupName, Version: "v1", Resource: "clusterroles"},
					Name:     "approved-watch", UID: "watch-role-uid",
				},
			},
			ObserverImage: "registry.invalid/observer@sha256:" + strings.Repeat("b", 64), ObserverResources: resources,
			APIServer:      controllerlab.EgressEndpoint{CIDR: "10.96.0.1/32", Port: 443},
			StartupTimeout: 90 * time.Second, ObservationWindow: 10 * time.Second, TailWindow: 2 * time.Second, OperationTimeout: 10 * time.Second,
		},
	}
	binding := environment.Bind{
		SourceTarget: environment.SourceTarget{Repository: target.Repository.URL, Commit: target.Commit},
		Recipe: environment.RecipeIdentity{
			ID: config.Controller.Template.RecipeID, Repository: "https://github.com/example/recipes",
			Commit: strings.Repeat("c", 40), Path: "recipe.yaml", ContentDigest: Digest([]byte("approved-recipe")),
			Target: "distro/container", Platform: "linux/amd64",
			FrontendImage: "registry.invalid/frontend@sha256:" + strings.Repeat("8", 64), WorkerImage: "registry.invalid/worker@sha256:" + strings.Repeat("9", 64),
		},
	}
	original := environment.Subject{Role: environment.PublishedOriginal, Image: "example.invalid/subject@sha256:" + strings.Repeat("1", 64)}
	frontend := provenance.ImageIdentity{Reference: binding.Recipe.FrontendImage, Digest: "sha256:" + strings.Repeat("8", 64)}
	baseline := provenance.Recipe{
		SchemaVersion: 1, RecipeRepository: binding.Recipe.Repository, RecipeCommit: binding.Recipe.Commit, Path: binding.Recipe.Path,
		ContentDigest: binding.Recipe.ContentDigest, BaseInputsDigest: Digest([]byte("fixed-inputs")), UpstreamSource: "source",
		UpstreamRepoURL: target.Repository.URL, UpstreamCommit: target.Commit, Version: "2.17.1", Revision: "1",
		Target: binding.Recipe.Target, Platform: binding.Recipe.Platform, Frontend: frontend, FrontendSyntax: frontend,
		ObservedOriginalImage: provenance.ImageIdentity{Reference: original.Image, Digest: "sha256:" + strings.Repeat("1", 64)},
		EvidenceStatus:        provenance.EvidencePartial, RecipeMappingStatus: provenance.MappingUnknown, UpstreamCommitStatus: provenance.SourceUnverified,
		OrderedPatches: []provenance.Patch{{Path: "vendor.patch", Digest: Digest([]byte("vendor-patch")), InputDigest: Digest([]byte("vendor-input")), Source: "source", Strip: 1}},
	}
	require.NoError(t, provenance.Compare(baseline, baseline))
	builder := &controllerTestBuilder{baseline: baseline}
	kube := kubefake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: config.ClusterUID}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "qualified-node", UID: "qualified-node-uid"}, Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: config.Controller.Template.ClusterWatchRole.Name, UID: config.Controller.Template.ClusterWatchRole.UID}, Rules: controllerlab.KEDAClusterWatchRules()},
	)
	kube.Discovery().(*discoveryfake.FakeDiscovery).Resources = []*metav1.APIResourceList{
		{GroupVersion: "keda.sh/v1alpha1", APIResources: []metav1.APIResource{
			{Name: "scaledobjects", Kind: "ScaledObject", Namespaced: true}, {Name: "scaledjobs", Kind: "ScaledJob", Namespaced: true},
			{Name: "triggerauthentications", Kind: "TriggerAuthentication", Namespaced: true}, {Name: "clustertriggerauthentications", Kind: "ClusterTriggerAuthentication"},
		}},
		{GroupVersion: "eventing.keda.sh/v1alpha1", APIResources: []metav1.APIResource{
			{Name: "cloudeventsources", Kind: "CloudEventSource", Namespaced: true}, {Name: "clustercloudeventsources", Kind: "ClusterCloudEventSource"},
		}},
	}
	custom := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}:                     "ScaledObjectList",
		{Group: "keda.sh", Version: "v1alpha1", Resource: "clustertriggerauthentications"}:     "ClusterTriggerAuthenticationList",
		{Group: "eventing.keda.sh", Version: "v1alpha1", Resource: "cloudeventsources"}:        "CloudEventSourceList",
		{Group: "eventing.keda.sh", Version: "v1alpha1", Resource: "clustercloudeventsources"}: "ClusterCloudEventSourceList",
	})
	f := &controllerTestFixture{t: t, kube: kube, custom: custom, builder: builder, states: map[string]controllerlab.State{}}
	kube.PrependReactor("create", "*", f.create)
	custom.PrependReactor("create", "*", f.create)
	kube.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		review := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		review.Status.Denied = true
		return true, review, nil
	})
	kube.PrependReactor("delete", "*", f.uidDelete(kube.Tracker()))
	custom.PrependReactor("delete", "*", f.uidDelete(custom.Tracker()))
	f.adapter = &controllerExecutionAdapter{
		ExecutionAdapter: builder, builder: builder, config: config, kube: kube,
		selection: AdapterSelection{
			Name: "synthetic", Kind: controllerAdapterKind, Binding: binding, Original: original,
			Capabilities: []string{string(controllerlab.KEDANamespaceEvents)},
		},
		newLab: func(config controllerlab.Config, hooks controllerlab.Hooks) (*controllerlab.Adapter, error) {
			persist := hooks.PersistState
			hooks.PersistState = func(ctx context.Context, expected uint64, next controllerlab.State) error {
				if f.beforeState != nil {
					f.beforeState(&next)
				}
				if err := persist(ctx, expected, next); err != nil {
					return err
				}
				f.statesMu.Lock()
				f.states[next.OperationID] = next
				f.statesMu.Unlock()
				if f.afterState != nil {
					return f.afterState(ctx, next)
				}
				return nil
			}
			return controllerlab.New(config, controllerlab.Clients{Kubernetes: kube, CustomResources: custom, Observer: f}, hooks)
		},
	}
	models := &pipelineModels{t: t, target: target, tasks: map[string]modelagent.Result{}}
	f.models = models
	pipeline := &Pipeline{Source: pipelineSource{target: target}, Environments: controllerTestFactory{adapter: f.adapter}, PollInterval: 5 * time.Millisecond,
		Agents: func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
			return controllerTestModel{pipelineModel{owner: models, accepted: accepted}}
		},
	}
	f.pipeline = pipeline
	path := filepath.Join(t.TempDir(), "controller-service.db")
	db, err := sqlite.NewDB(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	f.store = sqlite.NewStore(db, path)
	cipher, err := sqlite.NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("k", 32)))
	require.NoError(t, err)
	require.NoError(t, f.store.SetAgentExecutionSnapshotCipher(cipher))
	f.service, err = New(t.Context(), Config{Namespace: "testing", Store: f.store, Processor: pipeline, Lease: 2 * time.Second, Policies: []Policy{{
		Version: 1, Name: "approved", Namespace: "testing", AgentName: "proposer", Repositories: []string{target.Repository.URL},
		Adapters:           []AdapterPolicy{{Name: "synthetic", Kind: controllerAdapterKind, Repositories: []string{target.Repository.URL}, Configuration: json.RawMessage(`{"fixture":true}`)}},
		MaxDurationSeconds: 120, MaxCandidates: 2, MaxModelCalls: 8,
	}}})
	require.NoError(t, err)
	return f
}

func (f *controllerTestFixture) create(action ktesting.Action) (bool, runtime.Object, error) {
	object := action.(ktesting.CreateAction).GetObject()
	metadata, err := meta.Accessor(object)
	require.NoError(f.t, err)
	id := f.sequence.Add(1)
	metadata.SetUID(types.UID(fmt.Sprintf("uid-%d", id)))
	metadata.SetResourceVersion(fmt.Sprint(id))
	now := time.Now().UTC()
	metadata.SetCreationTimestamp(metav1.NewTime(now))
	switch value := object.(type) {
	case *corev1.Namespace:
		if value.Labels == nil {
			value.Labels = map[string]string{}
		}
		value.Labels["kubernetes.io/metadata.name"] = value.Name
		value.Status.Phase = corev1.NamespaceActive
	case *corev1.Pod:
		name := value.Spec.Containers[0].Name
		if name == "observer" {
			value.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.0.23", ContainerStatuses: []corev1.ContainerStatus{{
				Name: name, Ready: true, ImageID: value.Spec.Containers[0].Image, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}}}
		} else {
			f.readyProbe(value, now)
		}
	case *appsv1.Deployment:
		value.Status = appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
	case *unstructured.Unstructured:
		if value.GetKind() == "CloudEventSource" {
			value.Object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Active", "status": "True"}}}
		}
	}
	if f.onCreate != nil {
		f.onCreate(object)
	}
	return false, nil, nil
}

func (f *controllerTestFixture) readyProbe(pod *corev1.Pod, now time.Time) {
	image := pod.Spec.Containers[0].Image
	if strings.HasSuffix(pod.Name, "-canary") {
		pod.Spec.NodeName = "qualified-node"
		pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.0.24",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "probe", Ready: true, Image: image, ImageID: image,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(now)}}}},
		}
		return
	}
	started := now.Truncate(time.Second)
	finished := started
	result := probe.Result{Reachable: true, NonceMatched: true, FailureClass: probe.None}
	if strings.HasSuffix(pod.Name, "-denied") {
		result = probe.Result{FailureClass: probe.DialTimeout}
		finished = started.Add(time.Second)
	}
	if strings.HasSuffix(pod.Name, "-after") {
		started = started.Add(time.Second)
		finished = started
	}
	raw, err := json.Marshal(result)
	require.NoError(f.t, err)
	pod.Status = corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "probe", Image: image, ImageID: image, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			Reason: "Completed", StartedAt: metav1.NewTime(started), FinishedAt: metav1.NewTime(finished), Message: string(raw),
		}},
	}}}
}

func (f *controllerTestFixture) uidDelete(tracker ktesting.ObjectTracker) ktesting.ReactionFunc {
	return func(action ktesting.Action) (bool, runtime.Object, error) {
		deletion := action.(ktesting.DeleteAction)
		object, err := tracker.Get(action.GetResource(), action.GetNamespace(), deletion.GetName())
		if err != nil {
			return true, nil, err
		}
		actual, err := meta.Accessor(object)
		require.NoError(f.t, err)
		preconditions := deletion.GetDeleteOptions().Preconditions
		if preconditions == nil || preconditions.UID == nil || *preconditions.UID != actual.GetUID() {
			return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), deletion.GetName(), errors.New("UID mismatch"))
		}
		return false, nil, nil
	}
}

func (f *controllerTestFixture) Snapshot(_ context.Context, target controllerlab.ObserverTarget) (controllerlab.Observation, error) {
	f.statesMu.Lock()
	var state controllerlab.State
	for _, saved := range f.states {
		if saved.OperationDigest == target.OperationDigest {
			state = saved
		}
	}
	f.statesMu.Unlock()
	result := controllerlab.Observation{SchemaVersion: "v1", RunID: target.OperationDigest, Generation: 1,
		HTTP: []controllerlab.HTTPObservation{}, RESP: []controllerlab.RESPObservation{},
	}
	gvr := schema.GroupVersionResource{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}
	for _, round := range []string{"initial", "final"} {
		for i, namespace := range state.Namespaces {
			name := fmt.Sprintf("scope-%s-%s", []string{"a", "b"}[i], round)
			if _, err := f.custom.Tracker().Get(gvr, namespace, name); err != nil {
				continue
			}
			event := controllerlab.HTTPObservation{Route: []string{"/events/a", "/events/b"}[i], BodySHA256: strings.Repeat("0", 64), MarkerIDs: []string{},
				CloudEvents: []controllerlab.CloudEventEvidence{{
					Subject: &controllerlab.FieldEvidence{SHA256: strings.TrimPrefix(Digest([]byte("/orka-controllerlab/"+namespace+"/scaledobject/"+name)), "sha256:"), MarkerIDs: []string{fmt.Sprintf("%s-%d", round, i)}},
					Source:  &controllerlab.FieldEvidence{SHA256: strings.TrimPrefix(Digest([]byte("/orka-controllerlab/"+state.Namespaces[0]+"/keda")), "sha256:"), MarkerIDs: []string{}},
				}},
			}
			result.HTTP = append(result.HTTP, event)
			if i == 0 && (state.Role != controllerlab.Candidate || f.leakCandidate) {
				event.Route = "/events/b"
				result.HTTP = append(result.HTTP, event)
			}
		}
	}
	return result, nil
}

func (f *controllerTestFixture) submit(mode Mode) *store.RemediationRun {
	f.t.Helper()
	request := requestFixture()
	request.Mode = mode
	request.Report = json.RawMessage(`{"title":"Synthetic controller report","problem":"Namespace events cross boundaries","versions":["2.17.1"],"restricted":false}`)
	status, _, err := f.service.Submit(f.t.Context(), "testing", "caller", request)
	require.NoError(f.t, err)
	run, err := f.store.GetRemediationRun(f.t.Context(), "testing", status.ID)
	require.NoError(f.t, err)
	return run
}
