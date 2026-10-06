package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	runtimeisolation "github.com/orka-agents/orka/internal/remediation/isolation"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func newControllerLeaseFixture(t *testing.T, publishing bool, clusterUID ...types.UID) (*controllerTestFixture, *Session, *pipelineState, ExecutionPlan) {
	t.Helper()
	fixture := newControllerFixture(t)
	legacy := fixture.adapter.config
	if len(clusterUID) != 0 {
		legacy.ClusterUID = clusterUID[0]
		legacy.Controller.ClusterIdentity = controllerlab.ClusterIdentity(string(clusterUID[0]))
		cluster, err := fixture.kube.CoreV1().Namespaces().Get(t.Context(), "kube-system", metav1.GetOptions{})
		require.NoError(t, err)
		cluster.UID = clusterUID[0]
		require.NoError(t, fixture.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), cluster, ""))
	}
	legacy.BuildEnvironment.BuildJobs = &environment.BuildJobsConfig{Namespace: "controller-builds"}
	legacy.BuildEnvironment.Kubernetes = &environment.KubernetesConfig{}
	publisher := legacy
	publisher.Capability, publisher.Controller.EnableEventPublishing = controllerlab.KEDAEventPublishing, true
	publisher.Controller.Template.Source.Commit = "e615440f24f6abec8b7c69bd88854cb4324e9eaa"
	fixture.adapter.config, fixture.adapter.selection.Name = legacy, "legacy"
	if publishing {
		fixture.adapter.config, fixture.adapter.selection.Name = publisher, "publishing"
	}
	fixture.adapter.selection.ClusterExclusive = true
	fixture.adapter.selection.Capabilities = []string{string(selectedControllerCapability(fixture.adapter.config))}
	fixture.adapter.selection.Binding.SourceTarget.Commit = fixture.adapter.config.Controller.Template.Source.Commit
	config := fixture.service.config
	policy := config.Policies[0]
	policy.Adapters = nil
	for _, entry := range []struct {
		name   string
		config ControllerAdapterConfig
	}{{"legacy", legacy}, {"publishing", publisher}} {
		raw, err := json.Marshal(entry.config)
		require.NoError(t, err)
		policy.Adapters = append(policy.Adapters, AdapterPolicy{
			Name: entry.name, Kind: controllerAdapterKind, Repositories: policy.Repositories, Configuration: raw,
		})
	}
	config.Policies = []Policy{policy}
	var err error
	fixture.service, err = New(t.Context(), config)
	require.NoError(t, err)
	submitted := fixture.submit(Validate)
	run, err := fixture.store.ClaimNextRemediationRun(t.Context(), submitted.Namespace, "lease-worker", time.Now(), time.Minute)
	require.NoError(t, err)
	require.NotNil(t, run)
	session := &Session{store: fixture.store, run: run, owner: run.ClaimOwner, epoch: run.ClaimEpoch}
	var admitted pipelineState
	require.NoError(t, json.Unmarshal(run.StateJSON, &admitted))
	subject := fixture.adapter.selection.Original
	state := &pipelineState{
		Version: Version, Stage: "lease-tests", Selection: &fixture.adapter.selection, Models: map[string]modelOperation{},
		ModelIdentity: admitted.ModelIdentity, Original: executionOperation{ID: "original", Role: subject.Role, Subject: &subject},
	}
	controller := controllerlab.Plan{
		Version: 1, Capability: selectedControllerCapability(fixture.adapter.config),
		BoundSource: fixture.adapter.config.Controller.Template.Source, RecipeID: fixture.adapter.config.Controller.Template.RecipeID,
		Actors:   []controllerlab.ActorAccess{controllerlab.NamespaceAEventSource, controllerlab.NamespaceBEventSource},
		Expected: controllerExpectedOutcomes(selectedControllerCapability(fixture.adapter.config)),
	}
	plan, err := fixture.adapter.freezePlan(controller)
	require.NoError(t, err)
	state.Checks, err = fixture.pipeline.putJSON(t.Context(), session, "lease-checks", plan)
	require.NoError(t, err)
	require.NoError(t, fixture.pipeline.save(t.Context(), session, state, state.Stage))
	require.NoError(t, fixture.kube.Tracker().Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: legacy.BuildEnvironment.BuildJobs.Namespace, UID: "build-namespace", ResourceVersion: "1",
	}}))
	installControllerLeaseAPI(t, fixture.kube)
	return fixture, session, state, plan
}

// client-go's tracker does not allocate server identities or enforce deletion
// preconditions. These reactors retain the real tracker and implement those API
// semantics, including AlreadyExists, stale RV conflicts, and finalization.
func installControllerLeaseAPI(t *testing.T, kube *kubefake.Clientset) {
	t.Helper()
	var mu sync.Mutex
	var revision uint64
	nextIdentity := func(lease *coordinationv1.Lease, create bool) {
		revision++
		if create {
			lease.UID = types.UID(fmt.Sprintf("lease-uid-%d", revision))
		}
		lease.ResourceVersion = fmt.Sprint(revision)
	}
	kube.PrependReactor("create", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		object := action.(ktesting.CreateAction).GetObject().(*coordinationv1.Lease).DeepCopy()
		if _, err := kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource("namespaces"), "", action.GetNamespace()); err != nil {
			return true, nil, err
		}
		nextIdentity(object, true)
		if err := kube.Tracker().Create(action.GetResource(), object, action.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, object.DeepCopy(), nil
	})
	kube.PrependReactor("update", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		object := action.(ktesting.UpdateAction).GetObject().(*coordinationv1.Lease).DeepCopy()
		stored, err := kube.Tracker().Get(action.GetResource(), action.GetNamespace(), object.Name)
		if err != nil {
			return true, nil, err
		}
		current := stored.(*coordinationv1.Lease)
		if object.UID != current.UID || object.ResourceVersion != current.ResourceVersion {
			return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), object.Name, errors.New("stale lease identity"))
		}
		nextIdentity(object, false)
		if object.DeletionTimestamp != nil && len(object.Finalizers) == 0 {
			return true, object, kube.Tracker().Delete(action.GetResource(), action.GetNamespace(), object.Name)
		}
		return true, object, kube.Tracker().Update(action.GetResource(), object, action.GetNamespace())
	})
	kube.PrependReactor("delete", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		deletion := action.(ktesting.DeleteAction)
		stored, err := kube.Tracker().Get(action.GetResource(), action.GetNamespace(), deletion.GetName())
		if err != nil {
			return true, nil, err
		}
		current := stored.(*coordinationv1.Lease)
		preconditions := deletion.GetDeleteOptions().Preconditions
		if preconditions == nil || preconditions.UID == nil || preconditions.ResourceVersion == nil ||
			*preconditions.UID != current.UID || *preconditions.ResourceVersion != current.ResourceVersion {
			return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), current.Name, errors.New("lease precondition failed"))
		}
		if len(current.Finalizers) != 0 {
			current.DeletionTimestamp = new(metav1.Now())
			nextIdentity(current, false)
			return true, nil, kube.Tracker().Update(action.GetResource(), current, action.GetNamespace())
		}
		return true, nil, kube.Tracker().Delete(action.GetResource(), action.GetNamespace(), deletion.GetName())
	})
}

func reloadControllerLeaseState(t *testing.T, session *Session) *pipelineState {
	t.Helper()
	current, err := session.Current(t.Context())
	require.NoError(t, err)
	var state pipelineState
	require.NoError(t, json.Unmarshal(current.StateJSON, &state))
	return &state
}

func controllerLeaseActions(kube *kubefake.Clientset, verb string) int {
	count := 0
	for _, action := range kube.Actions() {
		if action.GetResource().Resource == "leases" && action.GetVerb() == verb {
			count++
		}
	}
	return count
}

func TestControllerLeasePublishingAndLegacySerializeBeforeLab(t *testing.T) {
	t.Parallel()
	first, firstSession, firstState, firstPlan := newControllerLeaseFixture(t, true)
	second, secondSession, secondState, secondPlan := newControllerLeaseFixture(t, false)
	second.kube, second.adapter.kube, second.custom = first.kube, first.kube, first.custom
	var labs atomic.Int32
	for _, fixture := range []*controllerTestFixture{first, second} {
		fixture.adapter.newLab = func(config controllerlab.Config, hooks controllerlab.Hooks) (*controllerlab.Adapter, error) {
			labs.Add(1)
			persist := hooks.PersistState
			hooks.PersistState = func(ctx context.Context, revision uint64, next controllerlab.State) error {
				if err := persist(ctx, revision, next); err != nil {
					return err
				}
				if fixture.afterState != nil {
					return fixture.afterState(ctx, next)
				}
				return nil
			}
			return controllerlab.New(config, controllerlab.Clients{
				Kubernetes: first.kube, CustomResources: first.custom, Observer: fixture,
			}, hooks)
		}
	}
	started := make(chan struct{})
	var paused atomic.Bool
	first.afterState = func(ctx context.Context, next controllerlab.State) error {
		if next.Phase == controllerlab.Preparing && len(next.Receipts) != 0 && paused.CompareAndSwap(false, true) {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := first.pipeline.executeController(ctx, firstSession, firstSession.run, first.adapter, firstPlan, firstState, &firstState.Original, nil)
		done <- err
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("first run failed before creating its owned namespace: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("first run did not enter the lab")
	}
	before := len(first.kube.Actions())
	for range 2 {
		_, err := second.pipeline.executeController(t.Context(), secondSession, secondSession.run, second.adapter, secondPlan, secondState, &secondState.Original, nil)
		require.ErrorIs(t, err, ErrRetryable)
		require.Nil(t, secondState.Original.Controller)
		require.False(t, secondState.Original.Intent)
	}
	require.EqualValues(t, 1, labs.Load(), "waiting runs must not even construct the lab")
	require.Zero(t, second.models.calls, "lease contention must not trigger model retries")
	for _, action := range first.kube.Actions()[before:] {
		require.Equal(t, "get", action.GetVerb(), "the waiting run must not create resources")
	}
	require.ErrorIs(t, first.pipeline.releaseControllerLease(t.Context(), firstSession, firstState), ErrUnknown)
	cancel()
	require.Error(t, <-done)
	require.NoError(t, first.pipeline.cancelController(t.Context(), firstSession, firstSession.run, first.service.config.Policies[0], firstState))
	require.True(t, firstState.Original.Cleaned)
	require.True(t, firstState.ControllerLease.Released)
	require.Equal(t, 1, controllerLeaseActions(first.kube, "delete"))

	secondStarted := make(chan struct{})
	ctx, cancelSecond := context.WithCancel(t.Context())
	defer cancelSecond()
	var secondPaused atomic.Bool
	second.afterState = func(ctx context.Context, next controllerlab.State) error {
		if next.Phase == controllerlab.Preparing && len(next.Receipts) != 0 && secondPaused.CompareAndSwap(false, true) {
			close(secondStarted)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	go func() {
		_, err := second.pipeline.executeController(ctx, secondSession, secondSession.run, second.adapter, secondPlan, secondState, &secondState.Original, nil)
		done <- err
	}()
	select {
	case <-secondStarted:
	case err := <-done:
		t.Fatalf("second run failed after lease release: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("second run did not enter the lab after release")
	}
	require.NotEqual(t, firstState.ControllerLease.UID, secondState.ControllerLease.UID)
	cancelSecond()
	require.Error(t, <-done)
	require.NoError(t, second.pipeline.cancelController(t.Context(), secondSession, secondSession.run, second.service.config.Policies[0], secondState))
	require.True(t, secondState.ControllerLease.Released)
	require.Equal(t, 2, controllerLeaseActions(first.kube, "create"))
}

func TestControllerLeaseRestartKeepsRunOwnershipAcrossWorkerEpochs(t *testing.T) {
	t.Parallel()
	fixture, session, state, _ := newControllerLeaseFixture(t, true)
	require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
	original := *state.ControllerLease
	current, err := session.Current(t.Context())
	require.NoError(t, err)
	reclaimed, err := fixture.store.ClaimNextRemediationRun(t.Context(), current.Namespace, "new-worker", current.ClaimUntil.Add(time.Millisecond), time.Minute)
	require.NoError(t, err)
	require.NotNil(t, reclaimed)
	restarted := &Session{store: fixture.store, run: reclaimed, owner: reclaimed.ClaimOwner, epoch: reclaimed.ClaimEpoch}
	saved := reloadControllerLeaseState(t, restarted)
	require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), restarted, saved))
	require.Equal(t, original, *saved.ControllerLease)
	require.ErrorIs(t, fixture.adapter.ensureControllerLease(t.Context(), session, state), ErrClaimLost)
	require.ErrorIs(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state), ErrClaimLost)
	require.Equal(t, 1, controllerLeaseActions(fixture.kube, "create"))
	require.Zero(t, controllerLeaseActions(fixture.kube, "update"))
	require.NoError(t, fixture.pipeline.releaseControllerLease(t.Context(), restarted, saved))
	require.True(t, saved.ControllerLease.Released)
	require.ErrorIs(t, fixture.adapter.ensureControllerLease(t.Context(), restarted, saved), ErrUnknown)
	require.Equal(t, 1, controllerLeaseActions(fixture.kube, "create"))
}

func TestControllerLeaseConcurrentCreateHasOneWinner(t *testing.T) {
	t.Parallel()
	first, firstSession, firstState, _ := newControllerLeaseFixture(t, true)
	second, secondSession, secondState, _ := newControllerLeaseFixture(t, false)
	second.kube, second.adapter.kube = first.kube, first.kube
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, run := range []struct {
		fixture *controllerTestFixture
		session *Session
		state   *pipelineState
	}{{first, firstSession, firstState}, {second, secondSession, secondState}} {
		go func() {
			<-start
			results <- run.fixture.adapter.ensureControllerLease(t.Context(), run.session, run.state)
		}()
	}
	close(start)
	a, b := <-results, <-results
	if a == nil {
		require.ErrorIs(t, b, ErrRetryable)
	} else {
		require.ErrorIs(t, a, ErrRetryable)
		require.NoError(t, b)
	}
	leases, err := first.kube.CoordinationV1().Leases("controller-builds").List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, leases.Items, 1)
	if firstState.ControllerLease.UID != "" {
		require.NoError(t, first.pipeline.releaseControllerLease(t.Context(), firstSession, firstState))
		require.NoError(t, second.adapter.ensureControllerLease(t.Context(), secondSession, secondState))
	} else {
		require.NoError(t, second.pipeline.releaseControllerLease(t.Context(), secondSession, secondState))
		require.NoError(t, first.adapter.ensureControllerLease(t.Context(), firstSession, firstState))
	}
}

func TestControllerLeaseContentionDoesNotRepeatPipelineModelWork(t *testing.T) {
	t.Parallel()
	first, firstSession, firstState, _ := newControllerLeaseFixture(t, true)
	second, secondSession, _, _ := newControllerLeaseFixture(t, false)
	second.kube, second.adapter.kube = first.kube, first.kube
	require.NoError(t, first.adapter.ensureControllerLease(t.Context(), firstSession, firstState))
	require.ErrorIs(t, second.pipeline.Run(t.Context(), secondSession), ErrRetryable)
	calls := second.models.calls
	require.Positive(t, calls, "source/model work may run before lab acquisition")
	require.ErrorIs(t, second.pipeline.Run(t.Context(), secondSession), ErrRetryable)
	require.Equal(t, calls, second.models.calls, "waiting for another holder must not repeat completed model stages")
	require.Equal(t, 1, controllerLeaseActions(first.kube, "create"))
	for _, action := range first.kube.Actions() {
		if action.GetVerb() == "create" {
			require.Equal(t, "leases", action.GetResource().Resource)
		}
	}
	state := reloadControllerLeaseState(t, secondSession)
	require.Nil(t, state.Original.Controller)
	require.NoError(t, first.pipeline.releaseControllerLease(t.Context(), firstSession, firstState))
	require.NoError(t, second.adapter.ensureControllerLease(t.Context(), secondSession, state))
}

func TestControllerLeaseDifferentClustersAndLegacyOnlyRemainIndependent(t *testing.T) {
	t.Run("different-clusters", func(t *testing.T) {
		t.Parallel()
		first, firstSession, firstState, _ := newControllerLeaseFixture(t, true, "cluster-one")
		second, secondSession, secondState, _ := newControllerLeaseFixture(t, true, "cluster-two")
		require.NoError(t, first.adapter.ensureControllerLease(t.Context(), firstSession, firstState))
		require.NoError(t, second.adapter.ensureControllerLease(t.Context(), secondSession, secondState))
		require.NotEqual(t, firstState.ControllerLease.Name, secondState.ControllerLease.Name)
		require.NoError(t, first.pipeline.releaseControllerLease(t.Context(), firstSession, firstState))
		require.NoError(t, second.adapter.verifyControllerLease(t.Context(), secondSession, secondState, false))
		require.Zero(t, controllerLeaseActions(second.kube, "delete"))
	})
	t.Run("legacy-only", func(t *testing.T) {
		t.Parallel()
		first, firstSession, firstState := controllerSessionFixture(t)
		second, secondSession, secondState := controllerSessionFixture(t)
		second.adapter.kube = first.kube
		require.NoError(t, first.adapter.ensureControllerLease(t.Context(), firstSession, firstState))
		require.NoError(t, second.adapter.ensureControllerLease(t.Context(), secondSession, secondState))
		require.Nil(t, firstState.ControllerLease)
		require.Nil(t, secondState.ControllerLease)
		require.Zero(t, controllerLeaseActions(first.kube, "get"))
		require.Zero(t, controllerLeaseActions(first.kube, "create"))
		require.Equal(t, 2, first.service.config.Workers, "cluster coordination must not disable worker fairness")
	})
}

func TestControllerLeaseNeverStealsExpiredForeignHolder(t *testing.T) {
	t.Parallel()
	fixture, session, state, _ := newControllerLeaseFixture(t, false)
	expected := expectedControllerLease(session.run, fixture.adapter.config)
	foreign := controllerLeaseObject(expected)
	foreign.Spec.HolderIdentity = new("foreign-run")
	foreign.Spec.LeaseDurationSeconds = new(int32(1))
	foreign.Spec.RenewTime = new(metav1.NewMicroTime(time.Now().Add(-24 * time.Hour)))
	created, err := fixture.kube.CoordinationV1().Leases(expected.Namespace).Create(t.Context(), foreign, metav1.CreateOptions{})
	require.NoError(t, err)
	creates := controllerLeaseActions(fixture.kube, "create")
	for range 3 {
		require.ErrorIs(t, fixture.adapter.ensureControllerLease(t.Context(), session, state), ErrRetryable)
	}
	require.Equal(t, creates, controllerLeaseActions(fixture.kube, "create"))
	require.Zero(t, controllerLeaseActions(fixture.kube, "update"))
	require.NoError(t, fixture.pipeline.cancelControllerLease(t.Context(), session, state))
	require.True(t, state.ControllerLease.Released)
	actual, err := fixture.kube.CoordinationV1().Leases(expected.Namespace).Get(t.Context(), expected.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, created, actual, "cancelling a waiting run must not delete the holder")
	require.Zero(t, controllerLeaseActions(fixture.kube, "delete"))
}

func TestControllerLeaseMissingReplacementAndChangedBindingFailClosed(t *testing.T) {
	for _, change := range []string{"missing", "uid", "holder", "binding", "resource-version", "cluster"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			fixture, session, state, _ := newControllerLeaseFixture(t, true)
			require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
			receipt := *state.ControllerLease
			resource := coordinationv1.SchemeGroupVersion.WithResource("leases")
			actual, err := fixture.kube.CoordinationV1().Leases(receipt.Namespace).Get(t.Context(), receipt.Name, metav1.GetOptions{})
			require.NoError(t, err)
			switch change {
			case "missing":
				require.NoError(t, fixture.kube.Tracker().Delete(resource, receipt.Namespace, receipt.Name))
			case "uid":
				actual.UID = "replacement-lease"
			case "holder":
				actual.Spec.HolderIdentity = new("different-holder")
			case "binding":
				actual.Annotations[controllerLeaseBinding] = Digest([]byte("different-binding"))
			case "resource-version":
				actual.ResourceVersion = "replacement-revision"
			case "cluster":
				actual.Annotations[controllerLeaseCluster] = Digest([]byte("different-cluster"))
			}
			if change != "missing" {
				require.NoError(t, fixture.kube.Tracker().Update(resource, actual, receipt.Namespace))
			}
			require.ErrorIs(t, fixture.adapter.ensureControllerLease(t.Context(), session, state), ErrUnknown)
			require.ErrorIs(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state), ErrUnknown)
			require.False(t, state.ControllerLease.Released)
			require.Equal(t, 1, controllerLeaseActions(fixture.kube, "create"))
			require.Zero(t, controllerLeaseActions(fixture.kube, "delete"))
		})
	}
}

func TestControllerLeaseAmbiguousCreateReconcilesOnlyExactBinding(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		t.Run(fmt.Sprint(delayed), func(t *testing.T) {
			t.Parallel()
			fixture, session, state, _ := newControllerLeaseFixture(t, true)
			var accepted *coordinationv1.Lease
			fixture.kube.PrependReactor("create", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
				accepted = action.(ktesting.CreateAction).GetObject().(*coordinationv1.Lease).DeepCopy()
				accepted.UID, accepted.ResourceVersion = "accepted-lease", "42"
				if !delayed {
					require.NoError(t, fixture.kube.Tracker().Create(action.GetResource(), accepted, action.GetNamespace()))
				}
				return true, nil, io.ErrUnexpectedEOF
			})
			require.ErrorIs(t, fixture.adapter.ensureControllerLease(t.Context(), session, state), ErrRetryable)
			require.True(t, state.ControllerLease.CreateAttempted)
			require.Empty(t, state.ControllerLease.UID)
			if delayed {
				for range 3 {
					require.ErrorIs(t, fixture.adapter.ensureControllerLease(t.Context(), session, state), ErrRetryable)
					require.ErrorIs(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state), ErrUnknown)
				}
				require.NoError(t, fixture.kube.Tracker().Create(coordinationv1.SchemeGroupVersion.WithResource("leases"), accepted, accepted.Namespace))
			}
			state = reloadControllerLeaseState(t, session)
			require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
			require.Equal(t, accepted.UID, state.ControllerLease.UID)
			require.Equal(t, 1, controllerLeaseActions(fixture.kube, "create"))
			require.NoError(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state))
			require.True(t, state.ControllerLease.Released)
		})
	}
}

func TestControllerLeaseQuarantinedOrUnprovenCleanupKeepsHolder(t *testing.T) {
	for _, change := range []string{"active", "quarantined", "intent", "receipt", "proof", "proof-object", "control", "foreign-run"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			fixture, session, state, _ := newControllerLeaseFixture(t, false)
			require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
			state.Original.Intent, state.Original.Cleaned = true, true
			state.Original.Controller = &controllerOperation{
				RunID: session.run.ID, InputDigest: session.run.InputDigest, OperationID: "original",
				State: controllerlab.State{
					Version: 1, Revision: 1, Phase: controllerlab.Complete, RunID: session.run.ID, OperationID: "original",
					Receipts: []controllerlab.Receipt{{Object: controllerlab.ObjectRef{
						Resource: schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, Name: "observed", UID: "namespace-uid",
					}, DeleteRequested: true, Deleted: true}},
				},
			}
			controller := state.Original.Controller
			require.True(t, controllerLeaseOperationsClean(session.run, state), "the unmodified cleanup fixture must be valid")
			switch change {
			case "active":
				state.Original.Cleaned = false
			case "quarantined":
				controller.State.Phase = controllerlab.Quarantined
			case "intent":
				controller.State.Intent = &controllerlab.Intent{Object: controllerlab.ObjectRef{Name: "unknown-write"}}
			case "receipt":
				controller.State.Receipts[0].Deleted = false
			case "proof":
				controller.Isolation = &runtimeisolation.Receipt{CleanupComplete: false}
			case "proof-object":
				controller.Control = &controllerNamespace{UID: "proof-namespace", DeleteRequested: true, Deleted: true}
				controller.Isolation = &runtimeisolation.Receipt{
					RunID: session.run.ID, OperationID: "controller-original", Phase: runtimeisolation.Complete, CleanupComplete: true,
					Objects: []runtimeisolation.ObjectReceipt{{CreateAttempted: true, Deleted: true}},
				}
			case "control":
				controller.Control = &controllerNamespace{Name: "proof-namespace", UID: "proof-namespace", DeleteRequested: true}
			case "foreign-run":
				controller.State.RunID = "another-run"
			}
			require.NoError(t, fixture.pipeline.save(t.Context(), session, state, state.Stage))
			require.ErrorIs(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state), ErrUnknown)
			require.False(t, state.ControllerLease.Released)
			require.NoError(t, fixture.adapter.verifyControllerLease(t.Context(), session, state, true))
			require.Zero(t, controllerLeaseActions(fixture.kube, "delete"))
		})
	}
}

type controllerLeaseStoreFault struct {
	store.RemediationRunStore
	beforeUpdate func(store.RemediationUpdate) error
}

func (s controllerLeaseStoreFault) UpdateRemediationRun(ctx context.Context, namespace, id, owner string, epoch, revision uint64, update store.RemediationUpdate, now time.Time) (*store.RemediationRun, error) {
	if s.beforeUpdate != nil {
		if err := s.beforeUpdate(update); err != nil {
			return nil, err
		}
	}
	return s.RemediationRunStore.UpdateRemediationRun(ctx, namespace, id, owner, epoch, revision, update, now)
}

func TestControllerLeaseCheckpointsBeforeEffectsAndRecoversAcceptedUID(t *testing.T) {
	for _, failAt := range []string{"intent", "create", "accepted", "delete"} {
		t.Run(failAt, func(t *testing.T) {
			t.Parallel()
			fixture, session, state, _ := newControllerLeaseFixture(t, true)
			if failAt == "delete" {
				require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
			}
			session.store = controllerLeaseStoreFault{RemediationRunStore: fixture.store, beforeUpdate: func(update store.RemediationUpdate) error {
				var next pipelineState
				require.NoError(t, json.Unmarshal(update.StateJSON, &next))
				lease := next.ControllerLease
				if lease != nil && (failAt == "intent" || (failAt == "create" && lease.CreateAttempted) ||
					(failAt == "accepted" && lease.UID != "") || (failAt == "delete" && lease.DeleteRequested)) {
					return ErrRetryable
				}
				return nil
			}}
			if failAt == "delete" {
				require.ErrorIs(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state), ErrRetryable)
				require.Zero(t, controllerLeaseActions(fixture.kube, "delete"))
			} else {
				require.ErrorIs(t, fixture.adapter.ensureControllerLease(t.Context(), session, state), ErrRetryable)
				if failAt == "accepted" {
					require.Equal(t, 1, controllerLeaseActions(fixture.kube, "create"))
					require.Empty(t, state.ControllerLease.UID)
				} else {
					require.Zero(t, controllerLeaseActions(fixture.kube, "create"))
				}
			}
			session.store = fixture.store
			state = reloadControllerLeaseState(t, session)
			require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
			require.Equal(t, 1, controllerLeaseActions(fixture.kube, "create"))
			require.NoError(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state))
		})
	}
}

func TestControllerLeaseDeleteUsesExactUIDAndResourceVersion(t *testing.T) {
	t.Parallel()
	fixture, session, state, _ := newControllerLeaseFixture(t, true)
	require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
	receipt := *state.ControllerLease
	changed := false
	fixture.kube.PrependReactor("delete", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		if !changed {
			changed = true
			stored, err := fixture.kube.Tracker().Get(action.GetResource(), action.GetNamespace(), receipt.Name)
			require.NoError(t, err)
			lease := stored.(*coordinationv1.Lease)
			lease.ResourceVersion = "changed-between-read-and-delete"
			require.NoError(t, fixture.kube.Tracker().Update(action.GetResource(), lease, action.GetNamespace()))
		}
		return false, nil, nil
	})
	require.ErrorIs(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state), ErrUnknown)
	require.True(t, state.ControllerLease.DeleteRequested)
	require.False(t, state.ControllerLease.Released)
	actual, err := fixture.kube.CoordinationV1().Leases(receipt.Namespace).Get(t.Context(), receipt.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, receipt.UID, actual.UID)
	require.NotEqual(t, receipt.ResourceVersion, actual.ResourceVersion)
}

func TestControllerLeaseFinalizationAndLaterHolderDoNotPermitReplay(t *testing.T) {
	t.Parallel()
	fixture, session, state, _ := newControllerLeaseFixture(t, true)
	fixture.kube.PrependReactor("create", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		action.(ktesting.CreateAction).GetObject().(*coordinationv1.Lease).Finalizers = []string{"fixture.invalid/hold"}
		return false, nil, nil
	})
	require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
	require.ErrorIs(t, fixture.pipeline.cancelControllerLease(t.Context(), session, state), ErrCleanupPending)
	require.True(t, state.ControllerLease.DeleteRequested)
	require.True(t, state.ControllerLease.DeleteAccepted)
	require.False(t, state.ControllerLease.Released)
	state = reloadControllerLeaseState(t, session)
	require.ErrorIs(t, fixture.pipeline.cancelControllerLease(t.Context(), session, state), ErrCleanupPending)
	require.Equal(t, 1, controllerLeaseActions(fixture.kube, "delete"))
	leases := fixture.kube.CoordinationV1().Leases(state.ControllerLease.Namespace)
	terminating, err := leases.Get(t.Context(), state.ControllerLease.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, terminating.DeletionTimestamp)
	terminating.Finalizers = nil
	_, err = leases.Update(t.Context(), terminating, metav1.UpdateOptions{})
	require.NoError(t, err)
	later := controllerLeaseObject(*state.ControllerLease)
	later.Spec.HolderIdentity = new("later-run")
	later.Annotations[controllerLeaseBinding] = Digest([]byte("later-run-binding"))
	later, err = leases.Create(t.Context(), later, metav1.CreateOptions{})
	require.NoError(t, err)
	require.NoError(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state))
	require.True(t, state.ControllerLease.Released)
	before := len(fixture.kube.Actions())
	require.NoError(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state))
	require.Equal(t, before, len(fixture.kube.Actions()), "a released tombstone must not touch a later holder")
	actual, err := leases.Get(t.Context(), later.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, later, actual)
	require.Equal(t, 1, controllerLeaseActions(fixture.kube, "delete"))
}

func TestControllerLeaseDeleteACKLossWithSuccessorStillCompletes(t *testing.T) {
	for _, terminal := range []string{store.RemediationPhaseSucceeded, store.RemediationPhaseCancelled} {
		t.Run(terminal, func(t *testing.T) {
			t.Parallel()
			first, firstSession, firstState, _ := newControllerLeaseFixture(t, true)
			second, secondSession, secondState, _ := newControllerLeaseFixture(t, false)
			second.kube, second.adapter.kube = first.kube, first.kube
			require.NoError(t, first.adapter.ensureControllerLease(t.Context(), firstSession, firstState))
			receipt := *firstState.ControllerLease
			require.True(t, controllerLeaseOperationsClean(firstSession.run, firstState))
			firstSession.store = controllerLeaseStoreFault{RemediationRunStore: first.store, beforeUpdate: func(update store.RemediationUpdate) error {
				var next pipelineState
				require.NoError(t, json.Unmarshal(update.StateJSON, &next))
				if next.ControllerLease != nil && next.ControllerLease.DeleteAccepted {
					return ErrRetryable
				}
				return nil
			}}
			require.ErrorIs(t, first.pipeline.releaseControllerLease(t.Context(), firstSession, firstState), ErrRetryable)
			firstSession.store = first.store
			firstState = reloadControllerLeaseState(t, firstSession)
			require.True(t, firstState.ControllerLease.DeleteRequested)
			require.False(t, firstState.ControllerLease.DeleteAccepted)
			require.False(t, firstState.ControllerLease.Released)
			require.Equal(t, receipt.UID, firstState.ControllerLease.UID)
			require.Equal(t, receipt.ResourceVersion, firstState.ControllerLease.ResourceVersion)
			leases := first.kube.CoordinationV1().Leases(receipt.Namespace)
			_, err := leases.Get(t.Context(), receipt.Name, metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err), "the exact UID/RV delete must commit before its acknowledgement is lost")
			require.Equal(t, 1, controllerLeaseActions(first.kube, "delete"))

			require.NoError(t, second.adapter.ensureControllerLease(t.Context(), secondSession, secondState))
			successor, err := leases.Get(t.Context(), receipt.Name, metav1.GetOptions{})
			require.NoError(t, err)
			require.NotEqual(t, receipt.UID, successor.UID)
			require.NotEqual(t, receipt.ResourceVersion, successor.ResourceVersion)
			require.Equal(t, secondState.ControllerLease.UID, successor.UID)

			if terminal == store.RemediationPhaseSucceeded {
				require.NoError(t, first.pipeline.complete(t.Context(), firstSession, firstState, "lease-release-recovered"))
			} else {
				current, err := first.store.CancelRemediationRun(t.Context(), firstSession.run.Namespace, firstSession.run.ID, time.Now())
				require.NoError(t, err)
				require.NoError(t, first.service.settle(t.Context(), firstSession, current, context.Canceled))
			}
			finished, err := first.store.GetRemediationRun(t.Context(), firstSession.run.Namespace, firstSession.run.ID)
			require.NoError(t, err)
			require.Equal(t, terminal, finished.Phase)
			var saved pipelineState
			require.NoError(t, json.Unmarshal(finished.StateJSON, &saved))
			require.True(t, saved.ControllerLease.Released)
			require.False(t, saved.ControllerLease.DeleteAccepted, "successor observation must not invent a delete acknowledgement")
			actual, err := leases.Get(t.Context(), receipt.Name, metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, successor, actual, "releasing the previous holder must not mutate its successor")
			require.Equal(t, 1, controllerLeaseActions(first.kube, "delete"))
			require.Equal(t, 2, controllerLeaseActions(first.kube, "create"))
			require.NoError(t, second.adapter.verifyControllerLease(t.Context(), secondSession, secondState, false))
		})
	}
}

func TestControllerLeaseRevisionCASProtectsCreateAndDelete(t *testing.T) {
	for _, deleting := range []bool{false, true} {
		t.Run(fmt.Sprint(deleting), func(t *testing.T) {
			t.Parallel()
			fixture, session, state, _ := newControllerLeaseFixture(t, true)
			if deleting {
				require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
			}
			var changed bool
			session.store = controllerLeaseStoreFault{RemediationRunStore: fixture.store, beforeUpdate: func(update store.RemediationUpdate) error {
				var next pipelineState
				require.NoError(t, json.Unmarshal(update.StateJSON, &next))
				lease := next.ControllerLease
				if changed || lease == nil || (!deleting && !lease.CreateAttempted) || (deleting && !lease.DeleteRequested) {
					return nil
				}
				changed = true
				current, err := fixture.store.GetRemediationRun(t.Context(), session.run.Namespace, session.run.ID)
				require.NoError(t, err)
				_, err = fixture.store.UpdateRemediationRun(t.Context(), current.Namespace, current.ID, session.owner, session.epoch, current.Revision,
					store.RemediationUpdate{Phase: current.Phase, Reason: current.Reason, StateJSON: current.StateJSON}, time.Now())
				require.NoError(t, err)
				return nil
			}}
			if deleting {
				require.Error(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state))
				require.Zero(t, controllerLeaseActions(fixture.kube, "delete"))
			} else {
				require.Error(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
				require.Zero(t, controllerLeaseActions(fixture.kube, "create"))
			}
			require.True(t, changed)
		})
	}
}

func TestControllerLeasePersistedReceiptRequiredBeforePreflight(t *testing.T) {
	t.Parallel()
	fixture, session, state, plan := newControllerLeaseFixture(t, true)
	var labCalls atomic.Int32
	construct := fixture.adapter.newLab
	fixture.adapter.newLab = func(config controllerlab.Config, hooks controllerlab.Hooks) (*controllerlab.Adapter, error) {
		labCalls.Add(1)
		return construct(config, hooks)
	}
	fixture.kube.PrependReactor("create", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		saved := reloadControllerLeaseState(t, session)
		require.NotNil(t, saved.ControllerLease)
		require.True(t, saved.ControllerLease.CreateAttempted, "intent must be durable before the API write")
		require.Empty(t, saved.ControllerLease.UID)
		actual := action.(ktesting.CreateAction).GetObject().(*coordinationv1.Lease)
		require.Equal(t, saved.ControllerLease.BindingDigest, actual.Annotations[controllerLeaseBinding])
		return false, nil, nil
	})
	session.store = controllerLeaseStoreFault{RemediationRunStore: fixture.store, beforeUpdate: func(update store.RemediationUpdate) error {
		var next pipelineState
		require.NoError(t, json.Unmarshal(update.StateJSON, &next))
		if next.ControllerLease != nil && next.ControllerLease.UID != "" {
			return ErrRetryable
		}
		return nil
	}}
	_, err := fixture.pipeline.executeController(t.Context(), session, session.run, fixture.adapter, plan, state, &state.Original, nil)
	require.ErrorIs(t, err, ErrRetryable)
	require.Equal(t, 1, controllerLeaseActions(fixture.kube, "create"))
	require.Zero(t, labCalls.Load(), "an uncheckpointed Lease response is not lab admission")
	require.Nil(t, state.Original.Controller)
	for _, action := range fixture.kube.Actions() {
		if action.GetVerb() == "create" {
			require.Equal(t, "leases", action.GetResource().Resource)
		}
	}
}

func TestControllerLeaseAcceptedIdentityAndTombstoneCannotRollBack(t *testing.T) {
	t.Parallel()
	fixture, session, state, _ := newControllerLeaseFixture(t, true)
	require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
	accepted := *state.ControllerLease
	for _, change := range []func(*controllerClusterLease){
		func(next *controllerClusterLease) { next.UID, next.ResourceVersion = "", "" },
		func(next *controllerClusterLease) { next.UID = "replacement-lease" },
		func(next *controllerClusterLease) { next.ResourceVersion = "replacement-revision" },
		func(next *controllerClusterLease) { next.RunID = "other-run" },
		func(next *controllerClusterLease) { next.InputDigest = Digest([]byte("other-input")) },
	} {
		next := accepted
		change(&next)
		require.ErrorIs(t, fixture.adapter.checkpointControllerLease(t.Context(), session, state, next, true), ErrUnknown)
		require.Equal(t, accepted, *state.ControllerLease)
	}
	require.NoError(t, fixture.pipeline.releaseControllerLease(t.Context(), session, state))
	require.ErrorIs(t, fixture.adapter.checkpointControllerLease(t.Context(), session, state, accepted, true), ErrUnknown)
	require.True(t, state.ControllerLease.Released)
}

func TestControllerLeaseCancellationRecoversAmbiguousUIDWithoutReplay(t *testing.T) {
	t.Parallel()
	fixture, session, state, _ := newControllerLeaseFixture(t, true)
	fixture.kube.PrependReactor("create", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		lease := action.(ktesting.CreateAction).GetObject().(*coordinationv1.Lease).DeepCopy()
		lease.UID, lease.ResourceVersion = "accepted-without-response", "3"
		require.NoError(t, fixture.kube.Tracker().Create(action.GetResource(), lease, action.GetNamespace()))
		return true, nil, io.ErrUnexpectedEOF
	})
	require.ErrorIs(t, fixture.adapter.ensureControllerLease(t.Context(), session, state), ErrRetryable)
	require.Empty(t, state.ControllerLease.UID)
	_, err := fixture.store.CancelRemediationRun(t.Context(), session.run.Namespace, session.run.ID, time.Now())
	require.NoError(t, err)
	require.ErrorIs(t, fixture.adapter.ensureControllerLease(t.Context(), session, state), context.Canceled)
	require.NoError(t, fixture.pipeline.cancelControllerLease(t.Context(), session, state))
	require.True(t, state.ControllerLease.Released)
	require.EqualValues(t, "accepted-without-response", state.ControllerLease.UID)
	require.Equal(t, 1, controllerLeaseActions(fixture.kube, "create"))
	require.Equal(t, 1, controllerLeaseActions(fixture.kube, "delete"))
}

func TestControllerLeaseContentContainsOnlyHashAndIdentity(t *testing.T) {
	t.Parallel()
	fixture, session, state, _ := newControllerLeaseFixture(t, true)
	require.NoError(t, fixture.adapter.ensureControllerLease(t.Context(), session, state))
	actual, err := fixture.kube.CoordinationV1().Leases(state.ControllerLease.Namespace).Get(t.Context(), state.ControllerLease.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Nil(t, actual.Spec.LeaseDurationSeconds)
	require.Nil(t, actual.Spec.RenewTime)
	require.Empty(t, actual.OwnerReferences)
	require.Equal(t, strings.TrimPrefix(state.ControllerLease.BindingDigest, "sha256:"), *actual.Spec.HolderIdentity)
	raw, err := json.Marshal(actual)
	require.NoError(t, err)
	require.NotContains(t, string(raw), session.run.ID)
	require.NotContains(t, string(raw), fixture.adapter.config.Controller.Template.Source.Repository)
	require.NotContains(t, string(raw), session.owner)
	require.Len(t, actual.Annotations, 2)
}
