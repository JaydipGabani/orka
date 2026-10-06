package controllerlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

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

type memoryJournal struct {
	mu             sync.Mutex
	states         map[string]State
	mutations      []Mutation
	reject         string
	loseReceiptAck bool
}

func journalKey(run, operation string) string { return run + "/" + operation }

func (j *memoryJournal) hooks() Hooks {
	return Hooks{
		Acceptance: func(_ context.Context, m Mutation) error {
			j.mu.Lock()
			defer j.mu.Unlock()
			if m.Action == j.reject {
				return errors.New("rejected")
			}
			j.mutations = append(j.mutations, m)
			return nil
		},
		PersistState: func(_ context.Context, revision uint64, s State) error {
			j.mu.Lock()
			defer j.mu.Unlock()
			key := journalKey(s.RunID, s.OperationID)
			previous := j.states[key]
			if previous.Revision != revision || s.Revision != revision+1 {
				return errors.New("conflict")
			}
			if j.loseReceiptAck && len(s.Receipts) > len(previous.Receipts) {
				j.loseReceiptAck = false
				return errors.New("write unavailable")
			}
			j.states[key] = cloneState(s)
			return nil
		},
	}
}

func (j *memoryJournal) load(r Request) State {
	j.mu.Lock()
	defer j.mu.Unlock()
	return cloneState(j.states[journalKey(r.RunID, r.OperationID)])
}

type syntheticObserver struct {
	mu             sync.Mutex
	journal        *memoryJournal
	custom         *dynamicfake.FakeDynamicClient
	omitInitial    bool
	omitFinal      bool
	candidateLeak  bool
	noOriginalLeak bool
	unreachable    bool
	mutate         func(*Observation)
}

func (o *syntheticObserver) Snapshot(_ context.Context, target ObserverTarget) (Observation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.unreachable {
		return Observation{}, errors.New("observer unreachable")
	}
	o.journal.mu.Lock()
	var state State
	for _, candidate := range o.journal.states {
		if candidate.OperationDigest == target.OperationDigest {
			state = cloneState(candidate)
		}
	}
	o.journal.mu.Unlock()
	result := Observation{SchemaVersion: "v1", RunID: target.OperationDigest, Generation: 1, HTTP: []HTTPObservation{}, RESP: []RESPObservation{}}
	if state.Version == 0 {
		return result, nil
	}
	cross := state.Role != Candidate && !o.noOriginalLeak || state.Role == Candidate && o.candidateLeak
	for _, final := range []bool{false, true} {
		for index, object := range fixtureObjects(state, final) {
			if _, err := o.custom.Tracker().Get(object.Resource, object.Namespace, object.Name); err != nil {
				continue
			}
			if !final && o.omitInitial || final && o.omitFinal {
				continue
			}
			result.HTTP = append(result.HTTP, observedEvent(state, index, final, index))
			if cross && index == 0 {
				result.HTTP = append(result.HTTP, observedEvent(state, index, final, 1))
			}
		}
	}
	if o.mutate != nil {
		o.mutate(&result)
	}
	return result, nil
}

func observedEvent(s State, index int, final bool, destination int) HTTPObservation {
	return HTTPObservation{
		Route: []string{"/events/a", "/events/b"}[destination], BodySHA256: bytesDigest(nil), MarkerIDs: []string{},
		CloudEvents: []CloudEventEvidence{{
			Subject: &FieldEvidence{SHA256: bytesDigest([]byte(subject(s, index, final))), MarkerIDs: []string{eventMarkerID(s, index, final)}},
			Source:  &FieldEvidence{SHA256: bytesDigest([]byte("/orka-controllerlab/" + s.Namespaces[0] + "/keda")), MarkerIDs: []string{}},
		}},
	}
}

type testLab struct {
	adapter  *Adapter
	kube     *kubefake.Clientset
	custom   *dynamicfake.FakeDynamicClient
	observer *syntheticObserver
	journal  *memoryJournal
	config   Config
	clockMu  sync.Mutex
	clock    time.Time
}

func newTestLab(t *testing.T) *testLab {
	t.Helper()
	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("256Mi")},
	}
	source := BoundSource{Repository: "https://github.com/kedacore/keda", Commit: strings.Repeat("a", 40)}
	config := Config{
		DedicatedClusterApproved: true, ClusterIdentity: ClusterIdentity("dedicated-cluster"), NamespacePrefix: "synthetic-lab",
		Template: ControllerRuntimeTemplate{
			Family: "keda-v2", RecipeID: "public-keda-v1", Source: source, Resources: resources,
			ClusterWatchRole: ObjectRef{Resource: clusterRoles, Name: "operator-approved-keda-watch", UID: "approved-watch-role"},
		},
		ObserverImage: "registry.invalid/trusted-observer@sha256:" + strings.Repeat("b", 64), ObserverResources: resources,
		APIServer:      EgressEndpoint{CIDR: "10.96.0.1/32", Port: 443},
		StartupTimeout: 90 * time.Second, ObservationWindow: 10 * time.Second, TailWindow: 2 * time.Second, OperationTimeout: time.Second,
	}
	for index, role := range []Role{Original, Control, Candidate} {
		config.Bindings = append(config.Bindings, ImageBinding{
			ID: string(role), Role: role, Source: source, RecipeID: config.Template.RecipeID,
			Image:          "registry.invalid/keda@sha256:" + strings.Repeat(fmt.Sprint(index+1), 64),
			EvidenceDigest: strings.Repeat("e", 64),
		})
	}
	kube := kubefake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "dedicated-cluster"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: config.Template.ClusterWatchRole.Name, UID: config.Template.ClusterWatchRole.UID}, Rules: KEDAClusterWatchRules()},
	)
	kube.Discovery().(*discoveryfake.FakeDiscovery).Resources = []*metav1.APIResourceList{
		{GroupVersion: "keda.sh/v1alpha1", APIResources: []metav1.APIResource{
			{Name: "scaledobjects", Kind: "ScaledObject", Namespaced: true}, {Name: "scaledjobs", Kind: "ScaledJob", Namespaced: true},
			{Name: "triggerauthentications", Kind: "TriggerAuthentication", Namespaced: true}, {Name: "clustertriggerauthentications", Kind: "ClusterTriggerAuthentication", Namespaced: false},
		}},
		{GroupVersion: "eventing.keda.sh/v1alpha1", APIResources: []metav1.APIResource{
			{Name: "cloudeventsources", Kind: "CloudEventSource", Namespaced: true}, {Name: "clustercloudeventsources", Kind: "ClusterCloudEventSource", Namespaced: false},
		}},
	}
	custom := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scaledObjects: "ScaledObjectList", cloudEventSources: "CloudEventSourceList",
		clusterAuthentications: "ClusterTriggerAuthenticationList", clusterEventSources: "ClusterCloudEventSourceList",
	})
	journal := &memoryJournal{states: map[string]State{}}
	lab := &testLab{kube: kube, custom: custom, journal: journal, config: config, clock: time.Now().UTC()}
	lab.observer = &syntheticObserver{journal: journal, custom: custom}
	var uidMu sync.Mutex
	var nextUID int
	create := func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject()
		accessor, err := meta.Accessor(object)
		require.NoError(t, err)
		uidMu.Lock()
		nextUID++
		accessor.SetUID(types.UID(fmt.Sprintf("synthetic-uid-%d", nextUID)))
		accessor.SetResourceVersion(fmt.Sprint(nextUID))
		uidMu.Unlock()
		switch value := object.(type) {
		case *corev1.Pod:
			value.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.0.23", ContainerStatuses: []corev1.ContainerStatus{{
				Name: serviceName, Ready: true, ImageID: value.Spec.Containers[0].Image,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}}}
		case *appsv1.Deployment:
			value.Status = appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
		case *unstructured.Unstructured:
			if value.GetKind() == "CloudEventSource" || value.GetKind() == "ClusterCloudEventSource" {
				value.Object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Active", "status": "Unknown"}}}
			}
		}
		return false, nil, nil
	}
	kube.PrependReactor("create", "*", create)
	custom.PrependReactor("create", "*", create)
	kube.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		review := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		review.Status.Denied = true
		return true, review, nil
	})
	uidDelete := func(tracker ktesting.ObjectTracker) ktesting.ReactionFunc {
		return func(action ktesting.Action) (bool, runtime.Object, error) {
			deletion := action.(ktesting.DeleteAction)
			options := deletion.GetDeleteOptions()
			require.NotNil(t, options.Preconditions)
			require.NotNil(t, options.Preconditions.UID)
			require.Equal(t, metav1.DeletePropagationForeground, *options.PropagationPolicy)
			object, err := tracker.Get(deletion.GetResource(), deletion.GetNamespace(), deletion.GetName())
			if err != nil {
				return true, nil, err
			}
			accessor, err := meta.Accessor(object)
			require.NoError(t, err)
			if accessor.GetUID() != *options.Preconditions.UID {
				return true, nil, apierrors.NewConflict(deletion.GetResource().GroupResource(), deletion.GetName(), errors.New("UID mismatch"))
			}
			require.NotNil(t, options.Preconditions.ResourceVersion)
			if accessor.GetResourceVersion() != *options.Preconditions.ResourceVersion {
				return true, nil, apierrors.NewConflict(deletion.GetResource().GroupResource(), deletion.GetName(), errors.New("resource version mismatch"))
			}
			return false, nil, nil
		}
	}
	kube.PrependReactor("delete", "*", uidDelete(kube.Tracker()))
	custom.PrependReactor("delete", "*", uidDelete(custom.Tracker()))
	lab.newAdapter(t)
	return lab
}

func (l *testLab) newAdapter(t *testing.T) {
	t.Helper()
	adapter, err := New(l.config, Clients{Kubernetes: l.kube, CustomResources: l.custom, Observer: l.observer}, l.journal.hooks())
	require.NoError(t, err)
	adapter.now = func() time.Time {
		l.clockMu.Lock()
		defer l.clockMu.Unlock()
		return l.clock
	}
	l.adapter = adapter
}

func (l *testLab) request(role Role) Request {
	return Request{
		RunID: "public-source-case", OperationID: string(role), BindingID: string(role),
		Plan: Plan{Version: Version, Capability: KEDANamespaceEvents, BoundSource: l.config.Template.Source, RecipeID: l.config.Template.RecipeID,
			Actors: []ActorAccess{NamespaceAEventSource, NamespaceBEventSource}, Expected: []SemanticOutcome{NamespacedEventScope}},
	}
}

func (l *testLab) step(s State, r Request) (State, error) {
	l.clockMu.Lock()
	l.clock = l.clock.Add(time.Second)
	l.clockMu.Unlock()
	if s.Phase == WaitingPlacement && r.Placement == nil {
		r.Placement = syntheticPlacement(s)
	}
	return l.adapter.Step(context.Background(), s, r)
}

func syntheticPlacement(s State) *SubjectPlacement {
	return &SubjectPlacement{
		OperationDigest: s.OperationDigest, NodeName: "synthetic-qualified-node",
		ProofDigest: digest(struct{ Domain, Operation string }{"unit-only-isolation-proof", s.OperationDigest}),
	}
}

func (l *testLab) until(t *testing.T, s State, r Request, stop func(State) bool) State {
	t.Helper()
	for range 600 {
		if stop(s) {
			return s
		}
		next, err := l.step(s, r)
		require.NoError(t, err)
		s = next
	}
	require.FailNow(t, "bounded fake-client scenario did not settle")
	return s
}

func (l *testLab) phase(t *testing.T, r Request, p Phase) State {
	t.Helper()
	return l.until(t, State{}, r, func(s State) bool { return s.Phase == p })
}

func TestDeclarativeThreeWayNamespaceEventScenario(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	states := make([]State, 0, 3)
	for _, role := range []Role{Original, Control, Candidate} {
		r := l.request(role)
		state := l.until(t, State{}, r, State.Terminal)
		require.Equal(t, Complete, state.Phase)
		states = append(states, state)
		for _, receipt := range state.Receipts {
			require.True(t, receipt.Deleted && receipt.DeleteRequested)
			require.NotEmpty(t, receipt.Object.UID)
			if receipt.Object.Namespace != "" {
				require.Contains(t, ownedNamespaces(state), receipt.Object.Namespace)
			}
		}
	}
	require.NoError(t, Compare(states[0], states[1], states[2]))
	legacy := states[2]
	legacy.ObserverNamespace = legacy.Namespaces[1]
	require.Error(t, Compare(states[0], states[1], legacy))
	require.Equal(t, Reproduced, states[0].Outcome)
	require.Equal(t, Reproduced, states[1].Outcome)
	require.Equal(t, Protected, states[2].Outcome)
	require.False(t, states[2].WindowStartedAt.IsZero())
	require.False(t, states[2].TailStartedAt.IsZero())
	require.GreaterOrEqual(t, states[2].TailStartedAt.Sub(states[2].WindowStartedAt), l.config.ObservationWindow)
	for _, action := range l.kube.Actions() {
		if action.GetVerb() == "create" || action.GetVerb() == "delete" {
			require.NotEqual(t, "clusterroles", action.GetResource().Resource)
			require.NotEqual(t, "customresourcedefinitions", action.GetResource().Resource)
		}
	}
	_, err := l.kube.RbacV1().ClusterRoles().Get(context.Background(), l.config.Template.ClusterWatchRole.Name, metav1.GetOptions{})
	require.NoError(t, err)
}

func TestNormalControlsAndReproductionAreMandatory(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		role      Role
		configure func(*syntheticObserver)
		outcome   Outcome
	}{
		{"missing-initial-control", Candidate, func(o *syntheticObserver) { o.omitInitial = true }, Inconclusive},
		{"missing-late-control", Candidate, func(o *syntheticObserver) { o.omitFinal = true }, Inconclusive},
		{"positive-original-required", Original, func(o *syntheticObserver) { o.noOriginalLeak = true }, NotReproduced},
		{"still-exposed-candidate", Candidate, func(o *syntheticObserver) { o.candidateLeak = true }, StillExposed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			tc.configure(l.observer)
			s := l.until(t, State{}, l.request(tc.role), State.Terminal)
			require.Equal(t, Complete, s.Phase)
			require.Equal(t, tc.outcome, s.Outcome)
		})
	}
}

func TestObserverFailureNeverMeansProtected(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"unreachable", "reset", "prefix-edit", "dropped", "truncated", "wrong-run", "missing-state"} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, ObservingWindow)
			l.observer.unreachable = variant == "unreachable"
			l.observer.mutate = func(o *Observation) {
				switch variant {
				case "reset":
					o.Generation++
				case "prefix-edit":
					o.HTTP[0].BodySHA256 = strings.Repeat("f", 64)
				case "dropped":
					o.DroppedHTTP = 1
				case "truncated":
					o.HTTP[0].CloudEventsTruncated = true
				case "wrong-run":
					o.RunID = "other-run"
				case "missing-state":
					o.HTTP = nil
				}
			}
			s, err := l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Inconclusive, s.Outcome)
			require.Equal(t, Cleaning, s.Phase)
			s = l.until(t, s, r, State.Terminal)
			require.Equal(t, Inconclusive, s.Outcome)
		})
	}
}

func TestPersistedIntentRecoversUnacknowledgedCreation(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, Preparing)
	l.journal.loseReceiptAck = true
	_, err := l.step(s, r)
	var safe *Error
	require.ErrorAs(t, err, &safe)
	require.Equal(t, StoreRejected, safe.Kind)
	s = l.journal.load(r)
	require.NotNil(t, s.Intent)
	require.Empty(t, s.Receipts)
	created, err := l.kube.CoreV1().Namespaces().Get(context.Background(), s.Namespaces[0], metav1.GetOptions{})
	require.NoError(t, err)
	l.newAdapter(t)
	before := createCount(l.kube.Actions())
	s, err = l.step(s, r)
	require.NoError(t, err)
	require.Nil(t, s.Intent)
	require.Len(t, s.Receipts, 1)
	require.Equal(t, created.UID, s.Receipts[0].Object.UID)
	require.Equal(t, before, createCount(l.kube.Actions()))
	r.Cancel = true
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Complete, s.Phase)
	require.Equal(t, Cancelled, s.Outcome)
}

func createCount(actions []ktesting.Action) int {
	count := 0
	for _, action := range actions {
		if action.GetVerb() == "create" && action.GetResource().Resource != "subjectaccessreviews" {
			count++
		}
	}
	return count
}

func TestCancellationRecoversPendingIntentWithoutCreatingMissingObjects(t *testing.T) {
	t.Parallel()
	for _, created := range []bool{false, true} {
		t.Run(fmt.Sprint(created), func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, Preparing)
			if created {
				l.journal.loseReceiptAck = true
			} else {
				l.kube.PrependReactor("create", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("transport failure")
				})
			}
			_, err := l.step(s, r)
			require.Error(t, err)
			s = l.journal.load(r)
			require.NotNil(t, s.Intent)
			before := createCount(l.kube.Actions())
			r.Cancel = true
			s = l.until(t, s, r, State.Terminal)
			if created {
				require.Equal(t, Cancelled, s.Outcome)
				require.Equal(t, Complete, s.Phase)
			} else {
				require.Equal(t, Inconclusive, s.Outcome)
				require.Equal(t, Quarantined, s.Phase)
				require.NotNil(t, s.Intent)
			}
			require.Equal(t, before, createCount(l.kube.Actions()))
		})
	}
}

func TestCancellationRetainsIntentUntilLateCreateCanBeUIDDeleted(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, Preparing)
	failFirst := true
	l.kube.PrependReactor("create", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		if failFirst {
			failFirst = false
			return true, nil, errors.New("acknowledgement unavailable")
		}
		return false, nil, nil
	})
	_, err := l.step(s, r)
	require.Error(t, err)
	s = l.journal.load(r)
	require.NotNil(t, s.Intent)
	r.Cancel = true
	s, err = l.step(s, r)
	require.NoError(t, err)
	s, err = l.step(s, r)
	require.NoError(t, err)
	require.Equal(t, Cleaning, s.Phase)
	require.NotNil(t, s.Intent)
	late, err := l.adapter.build(context.Background(), s, l.config.Bindings[2], *s.Intent, nil)
	require.NoError(t, err)
	created, err := l.kube.CoreV1().Namespaces().Create(context.Background(), late.(*corev1.Namespace), metav1.CreateOptions{})
	require.NoError(t, err)
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Complete, s.Phase)
	require.Equal(t, Cancelled, s.Outcome)
	require.Len(t, s.Receipts, 1)
	require.Equal(t, created.UID, s.Receipts[0].Object.UID)
	require.True(t, s.Receipts[0].Deleted)
}

func TestUIDReplacementAndUnanchoredObjectsAreQuarantined(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"namespace", "observer", "preexisting"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			r := l.request(Candidate)
			var s State
			if kind == "preexisting" {
				s = l.phase(t, r, Preparing)
				require.NoError(t, l.kube.Tracker().Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: s.Namespaces[0], UID: "foreign"}}))
			} else {
				s = l.phase(t, r, WaitingRuntime)
				target := ref(namespaces, "", s.Namespaces[0])
				if kind == "observer" {
					target = ref(pods, s.ObserverNamespace, serviceName)
				}
				object, err := l.kube.Tracker().Get(target.Resource, target.Namespace, target.Name)
				require.NoError(t, err)
				m, err := meta.Accessor(object)
				require.NoError(t, err)
				m.SetUID("replacement")
				require.NoError(t, l.kube.Tracker().Update(target.Resource, object, target.Namespace))
				r.Cancel = true
				s, err = l.step(s, r)
				require.NoError(t, err)
			}
			var err error
			for range 30 {
				s, err = l.step(s, r)
				if err != nil {
					break
				}
			}
			require.Error(t, err)
			require.Equal(t, Quarantined, s.Phase)
			require.Equal(t, Inconclusive, s.Outcome)
			for _, action := range l.kube.Actions() {
				if deletion, ok := action.(ktesting.DeleteAction); ok {
					require.NotEqual(t, types.UID("replacement"), *deletion.GetDeleteOptions().Preconditions.UID)
					require.NotEqual(t, types.UID("foreign"), *deletion.GetDeleteOptions().Preconditions.UID)
				}
			}
		})
	}
}

func TestTerminalTombstoneAndStaleRevisionPreventReplay(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.until(t, State{}, r, State.Terminal)
	count := len(l.kube.Actions())
	_, err := l.step(s, r)
	require.Error(t, err)
	_, err = l.step(State{}, r)
	require.Error(t, err)
	require.Equal(t, count, len(l.kube.Actions()))
	require.Equal(t, Complete, l.journal.load(r).Phase)
}

func TestAcceptanceIsRequiredBeforeEveryKubernetesMutation(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, Preparing)
	l.journal.reject = "create"
	_, err := l.step(s, r)
	require.Error(t, err)
	require.Zero(t, createCount(l.kube.Actions()))
	l.journal.reject = ""
	s = l.until(t, s, r, func(s State) bool { return s.Phase == WaitingRuntime })
	r.Cancel = true
	s, err = l.step(s, r)
	require.NoError(t, err)
	l.journal.reject = "delete"
	_, err = l.step(s, r)
	require.Error(t, err)
	for _, action := range l.kube.Actions() {
		require.NotEqual(t, "delete", action.GetVerb())
	}
}

func TestOperatorScopeAndPlanAdmission(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	for _, capability := range []Capability{KEDARedisAuth, "arbitrary-controller", "http-exact-v1"} {
		r := l.request(Candidate)
		r.Plan.Capability = capability
		_, err := l.adapter.Step(context.Background(), State{}, r)
		var safe *Error
		require.ErrorAs(t, err, &safe)
		require.Equal(t, NeedsAdapter, safe.Kind)
	}
	r := l.request(Candidate)
	r.Plan.Expected = []SemanticOutcome{"managed-aks-policy"}
	_, err := l.adapter.Step(context.Background(), State{}, r)
	var safe *Error
	require.ErrorAs(t, err, &safe)
	require.Equal(t, OutsideScope, safe.Kind)
	require.Empty(t, l.kube.Actions())
	require.Equal(t, []Capability{KEDANamespaceEvents, KEDAEventPublishing}, SupportedCapabilities())
	for _, input := range []string{
		`{"version":1,"Version":1}`, `{"version":1,"credential":"not-permitted"}`,
		`{"version":1} {}`, `{"version":1,"actors":["namespace-a-event-source"],"actors":[]}`,
	} {
		_, err := DecodePlan(strings.NewReader(input))
		require.Error(t, err)
	}
	data, err := json.Marshal(l.request(Candidate).Plan)
	require.NoError(t, err)
	parsed, err := DecodePlan(strings.NewReader(string(data)))
	require.NoError(t, err)
	require.Equal(t, PlanDigest(l.request(Candidate).Plan), PlanDigest(parsed))
}

func TestGlobalObjectsAndUnapprovedClusterRoleFailClosed(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"cluster-identity", "wildcard-role", "global-secret-role", "global-event-source", "missing-crd"} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			switch variant {
			case "cluster-identity":
				l.config.ClusterIdentity = ClusterIdentity("different-cluster")
				l.newAdapter(t)
			case "wildcard-role":
				role, err := l.kube.RbacV1().ClusterRoles().Get(context.Background(), l.config.Template.ClusterWatchRole.Name, metav1.GetOptions{})
				require.NoError(t, err)
				role.Rules[0].Verbs = []string{"*"}
				require.NoError(t, l.kube.Tracker().Update(clusterRoles, role, ""))
			case "global-secret-role":
				role, err := l.kube.RbacV1().ClusterRoles().Get(context.Background(), l.config.Template.ClusterWatchRole.Name, metav1.GetOptions{})
				require.NoError(t, err)
				role.Rules = append(role.Rules, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: readVerbs()})
				require.NoError(t, l.kube.Tracker().Update(clusterRoles, role, ""))
			case "global-event-source":
				value := customObject("eventing.keda.sh/v1alpha1", "ClusterCloudEventSource", metav1.ObjectMeta{Name: "foreign-source", UID: "foreign"}, map[string]any{})
				require.NoError(t, l.custom.Tracker().Create(clusterEventSources, value, ""))
			case "missing-crd":
				l.kube.Discovery().(*discoveryfake.FakeDiscovery).Resources = nil
			}
			r := l.request(Candidate)
			s, err := l.step(State{}, r)
			require.NoError(t, err)
			s, err = l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Inconclusive, s.Outcome)
			require.Zero(t, createCount(l.kube.Actions()))
		})
	}
}

func TestFixedRBACAndSecretBoundaries(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, WaitingRuntime)
	require.NotContains(t, s.Namespaces, s.ObserverNamespace)
	require.NotEmpty(t, s.ObserverNamespace)
	admin, err := l.kube.CoreV1().Secrets(s.ObserverNamespace).Get(context.Background(), adminSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	canary, err := l.kube.CoreV1().Secrets(s.Namespaces[0]).Get(context.Background(), canaryName, metav1.GetOptions{})
	require.NoError(t, err)
	require.False(t, string(admin.Data["admin-token"]) == string(canary.Data["key"]))
	stateBytes, err := json.Marshal(s)
	require.NoError(t, err)
	for _, raw := range [][]byte{admin.Data["admin-token"], admin.Data["tls.key"], canary.Data["key"]} {
		require.False(t, strings.Contains(string(stateBytes), string(raw)))
	}
	cm, err := l.kube.CoreV1().ConfigMaps(s.ObserverNamespace).Get(context.Background(), "observer-config", metav1.GetOptions{})
	require.NoError(t, err)
	var observerConfig map[string]any
	require.NoError(t, json.Unmarshal([]byte(cm.Data["config.json"]), &observerConfig))
	require.True(t, observerConfig["syntheticCanarySHA256"] == bytesDigest(canary.Data["key"]))
	require.Equal(t, "0.0.0.0:8080", observerConfig["ingressHTTPAddress"])
	require.Equal(t, "0.0.0.0:8443", observerConfig["httpAddress"])
	_, unexpectedAlias := observerConfig["workerHTTPAddress"]
	require.False(t, unexpectedAlias)
	require.False(t, strings.Contains(cm.Data["config.json"], string(canary.Data["key"])))
	require.False(t, strings.Contains(cm.Data["config.json"], string(admin.Data["admin-token"])))
	for _, namespace := range s.Namespaces {
		role, err := l.kube.RbacV1().Roles(namespace).Get(context.Background(), controllerName, metav1.GetOptions{})
		require.NoError(t, err)
		secretRead := false
		for _, rule := range role.Rules {
			require.NotContains(t, rule.Verbs, "*")
			require.NotContains(t, rule.Resources, "*")
			require.NotContains(t, rule.APIGroups, "*")
			require.NotContains(t, rule.Resources, "pods/exec")
			require.NotContains(t, rule.Resources, "pods/portforward")
			require.NotContains(t, rule.Resources, "roles")
			for _, r := range rule.Resources {
				if r == "secrets" {
					secretRead = true
					require.Equal(t, readVerbs(), rule.Verbs)
				}
			}
		}
		require.True(t, secretRead)
	}
	observerRoles, err := l.kube.RbacV1().Roles(s.ObserverNamespace).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, observerRoles.Items)
	observerBindings, err := l.kube.RbacV1().RoleBindings(s.ObserverNamespace).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, observerBindings.Items)
	deployment, err := l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, len(deployment.Spec.Template.Spec.Containers))
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		require.Nil(t, volume.HostPath)
		if volume.Secret != nil {
			require.NotEqual(t, adminSecretName, volume.Secret.SecretName)
		}
	}
	require.NotContains(t, deployment.Spec.Template.Spec.Containers[0].Command, "sh")
	require.Contains(t, deployment.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{Name: "WATCH_NAMESPACE", Value: strings.Join(s.Namespaces[:], ",")})
	require.NotContains(t, deployment.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{Name: "WATCH_NAMESPACE", Value: s.ObserverNamespace})
	pod, err := l.kube.CoreV1().Pods(s.ObserverNamespace).Get(context.Background(), serviceName, metav1.GetOptions{})
	require.NoError(t, err)
	require.False(t, *pod.Spec.AutomountServiceAccountToken)
	require.Equal(t, []string{"-config", "/observer/config/config.json"}, pod.Spec.Containers[0].Args)
	r.Cancel = true
	_ = l.until(t, s, r, State.Terminal)
}

func TestBodyMarkerIsNotSemanticCloudEventEvidence(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	s := l.phase(t, l.request(Candidate), ObservingInitial)
	event := observedEvent(s, 0, false, 1)
	event.CloudEvents[0].Subject.SHA256 = strings.Repeat("d", 64)
	event.MarkerIDs = []string{"initial-0"}
	err := incorporate(&s, Observation{SchemaVersion: "v1", RunID: s.OperationDigest, Generation: 1, HTTP: []HTTPObservation{event}, RESP: []RESPObservation{}})
	require.NoError(t, err)
	require.False(t, s.Evidence.CrossObserved)
	require.Equal(t, [2]bool{}, s.Evidence.InitialNormal)
}

func TestConcurrentStaleStepsHaveOneDurableWinner(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	start := l.phase(t, r, Preparing)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := l.adapter.Step(context.Background(), start, r)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, createCount(l.kube.Actions()))
	durable := l.journal.load(r)
	require.Len(t, durable.Receipts, 1)
	require.NotEqual(t, Quarantined, durable.Phase)
}

func TestStepClientOperationBudgetAndProcessExitAreNotEvidence(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	var s State
	for range 50 {
		if s.Phase == WaitingRuntime {
			break
		}
		before := len(l.kube.Actions()) + len(l.custom.Actions())
		var err error
		s, err = l.step(s, r)
		require.NoError(t, err)
		require.LessOrEqual(t, len(l.kube.Actions())+len(l.custom.Actions())-before, MaxStepClientOperations)
	}
	require.Equal(t, WaitingRuntime, s.Phase)
	pod, err := l.kube.CoreV1().Pods(s.ObserverNamespace).Get(context.Background(), serviceName, metav1.GetOptions{})
	require.NoError(t, err)
	pod.Status.Phase = corev1.PodSucceeded
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}
	require.NoError(t, l.kube.Tracker().Update(pods, pod, pod.Namespace))
	s, err = l.step(s, r)
	require.Error(t, err)
	require.Equal(t, Inconclusive, s.Outcome)
	require.Equal(t, [2]bool{}, s.Evidence.InitialNormal)
}
