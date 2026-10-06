package controller

import (
	"context"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func reservedBoundCleanupTask(t *testing.T, ctx context.Context, control store.DurableControlStore, kube client.Client, pool *corev1alpha1.RuntimePool, fence store.ControllerEpochFence) *corev1alpha1.Task {
	t.Helper()
	task := runtimePoolRetirementTask(t, pool, "bound-cancelled")
	task.Spec.SessionRef = nil
	task.Status.Phase = corev1alpha1.TaskPhaseCancelled
	task.Status.Execution.State = corev1alpha1.TaskExecutionStateReserved
	task.Status.Execution.Outcome = ""
	task.Status.Execution.ControllerEpoch = fence.Epoch
	task.Status.Execution.RuntimeSessionUID = taskRuntimeSessionUID(task)
	task.Status.Delivery = nil
	task.Labels = map[string]string{acpRuntimeTaskPoolLabel: pool.Name}
	task.CreationTimestamp = metav1.NewTime(time.Now().UTC().Add(-time.Minute))
	require.NoError(t, kube.Create(ctx, task))
	attempt, err := control.CreatePromptAttempt(ctx, &store.PromptAttempt{
		Key: store.PromptAttemptKey{
			Namespace: task.Namespace, TaskUID: string(task.UID), Attempt: 1, PromptID: task.Status.Execution.PromptID,
		},
		RequestDigest: task.Status.Execution.RequestDigest,
		BindingDigest: task.Status.AgentExecutionBinding.BindingDigest, SnapshotDigest: task.Status.AgentExecutionBinding.Snapshot.Digest,
	}, fence)
	require.NoError(t, err)
	for _, next := range []store.PromptExecutionState{
		store.PromptExecutionReserved, store.PromptExecutionSessionStarting,
		store.PromptExecutionPlanned, store.PromptExecutionSubmitting,
	} {
		attempt, err = control.TransitionPromptAttemptExecution(ctx, store.PromptAttemptExecutionTransition{
			ID: attempt.ID, Fence: fence, ExpectedVersion: attempt.Version, ExpectedState: attempt.ExecutionState,
			NewState: next, OperationID: "cancel-fixture-" + string(next),
			OperationDigest: store.CanonicalBytesDigest([]byte(next)), UpdatedAt: time.Now().UTC(),
			RuntimeInstanceID: task.Status.Execution.RuntimeInstanceID,
			SessionUID:        task.Status.Execution.RuntimeSessionUID, SessionLeaseGeneration: 1,
		})
		require.NoError(t, err)
	}
	_, err = control.RecoverPromptAttemptPreSubmission(ctx, store.PromptAttemptPreSubmissionRecovery{
		ID: attempt.ID, Fence: fence, ExpectedVersion: attempt.Version, ExpectedState: attempt.ExecutionState,
		ProvenNotAccepted: true, PreserveBindings: true, OperationID: "zero-write-requeue",
		OperationDigest: store.CanonicalBytesDigest([]byte("zero-write-requeue")), RecoveredAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	return task
}

func TestACPBlockedReservedCleanupDoesNotStarveAdmissionOrIdlePools(t *testing.T) {
	for _, scenario := range []string{"missing-pool", "replaced-instance"} {
		t.Run(scenario, func(t *testing.T) {
			f := newExternalACPDispatchFixtureWithOptions(t, "external-v2", testAgentRuntimeMCPPolicy(),
				externalACPDispatchFixtureOptions{contextTimeout: 30 * time.Second})
			fence, err := f.epochs.CurrentFence(f.ctx)
			require.NoError(t, err)
			healthy := f.queueTask(t, "independent-work", "independent-work-uid", "synthetic independent work", nil)
			pool := runtimePoolTestObject(1)
			pool.Namespace, pool.Name, pool.UID = defaultNS, "blocked-pool", "blocked-pool-uid"
			pool.Status.ActiveInstance = &corev1alpha1.RuntimePoolActiveInstanceStatus{
				RuntimeInstanceID: "old-instance.old-boot", BootID: "old-boot", ControllerEpoch: fence.Epoch,
				ProfileDigest: pool.Spec.Runtime.Profile.Digest,
			}
			blocked := reservedBoundCleanupTask(t, f.ctx, f.controlStore, f.client, pool, fence)
			if scenario == "replaced-instance" {
				pool.Status.ActiveInstance.RuntimeInstanceID = "replacement-instance.replacement-boot"
				require.NoError(t, f.client.Create(f.ctx, pool))
			}
			idle := &corev1alpha1.RuntimePool{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: defaultNS, Name: "unrelated-idle-pool",
					Annotations: map[string]string{acpRuntimeLastDemandAnnotation: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)},
				},
				Spec: corev1alpha1.RuntimePoolSpec{DesiredReplicas: 1},
			}
			require.NoError(t, f.client.Create(f.ctx, idle))
			f.dispatcher.sem = make(chan struct{}, 1)
			f.dispatcher.active = make(map[types.UID]struct{})
			f.dispatcher.IdlePoolTTL = time.Minute
			ctx, cancel := context.WithCancel(f.ctx)
			defer func() {
				cancel()
				require.Eventually(t, func() bool { return !f.dispatcher.isActive(healthy.UID) },
					5*time.Second, 10*time.Millisecond, "the admitted worker must leave before its fixture closes")
			}()
			err = f.dispatcher.dispatchOnce(ctx)
			require.ErrorIs(t, err, store.ErrConflict, "the blocked Task must still surface its proof error")
			attemptID, err := promptAttemptIDFromTask(healthy)
			require.NoError(t, err)
			admitted, err := f.controlStore.GetPromptAttempt(f.ctx, attemptID)
			require.NoError(t, err)
			require.Contains(t, []store.PromptExecutionState{
				store.PromptExecutionReserved, store.PromptExecutionSessionStarting, store.PromptExecutionPlanned,
				store.PromptExecutionSubmitting, store.PromptExecutionAccepted, store.PromptExecutionRunning,
				store.PromptExecutionSettling, store.PromptExecutionSucceeded,
			}, admitted.ExecutionState, "one unproven cleanup must not prevent a separate attempt's durable admission")
			require.Equal(t, string(healthy.UID), admitted.Key.TaskUID)
			current := &corev1alpha1.Task{}
			require.NoError(t, f.client.Get(f.ctx, client.ObjectKeyFromObject(blocked), current))
			require.Equal(t, corev1alpha1.TaskExecutionStateReserved, current.Status.Execution.State)
			require.Empty(t, current.Status.Execution.RuntimeSessionCleanupDigest, "unrelated progress must not mint retirement proof")
			require.NoError(t, f.client.Get(f.ctx, client.ObjectKeyFromObject(idle), idle))
			require.Zero(t, idle.Spec.DesiredReplicas, "an unproven cleanup must not starve idle-pool maintenance")
		})
	}
}

func TestACPReservedCleanupWaitsWithoutHistoricalEpochAuthority(t *testing.T) {
	f := newACPRuntimePoolRestartFixture(t, false)
	fence, err := f.dispatcher.Epochs.CurrentFence(f.ctx)
	require.NoError(t, err)
	pool := runtimePoolTestGetPool(t, f.pools, f.pool)
	task := reservedBoundCleanupTask(t, f.ctx, f.control, f.pools.Client, &pool, fence)
	complete, err := f.dispatcher.cleanupRecoveredTaskScopedRuntimeSession(f.ctx, task)
	require.NoError(t, err)
	require.False(t, complete)
	require.Empty(t, task.Status.Execution.RuntimeSessionCleanupDigest)
	f.runtime.mu.Lock()
	defer f.runtime.mu.Unlock()
	require.Zero(t, f.runtime.deleteCalls)
	require.Zero(t, f.runtime.promptCalls)
}

func TestACPHistoricalCleanupDoesNotChangeSessionRecoveryPolicy(t *testing.T) {
	f := newACPRuntimePoolRestartFixture(t, false)
	require.NoError(t, f.dispatcher.recoverStaleAttempts(f.ctx))
	task := f.currentTask(t)
	task.Spec.SessionRef = &corev1alpha1.SessionReference{Name: "continued-session"}
	task.Spec.Workspace = &corev1alpha1.WorkspaceConfig{Intent: corev1alpha1.WorkspaceIntentWrite}
	require.NoError(t, f.pools.Update(f.ctx, task))
	complete, err := f.dispatcher.cleanupRecoveredTaskScopedRuntimeSession(f.ctx, task)
	require.NoError(t, err)
	require.False(t, complete)
	f.runtime.mu.Lock()
	defer f.runtime.mu.Unlock()
	require.Zero(t, f.runtime.deleteCalls, "standalone retirement must not choose a Session abandonment policy")
}

func TestACPSessionWriteCleanupKeepsItsExistingInstanceLossPolicy(t *testing.T) {
	for _, scenario := range []string{"missing-pool", "missing-instance", "replaced-instance"} {
		for _, scope := range []string{"standalone", "session-task", "session-deletion"} {
			t.Run(scenario+"/"+scope, func(t *testing.T) {
				f := newACPRuntimePoolRestartFixture(t, false)
				pool := runtimePoolTestGetPool(t, f.pools, f.pool)
				task := runtimePoolRetirementTask(t, &pool, "legacy-write")
				task.Spec.Workspace = &corev1alpha1.WorkspaceConfig{Intent: corev1alpha1.WorkspaceIntentWrite}
				if scope == "standalone" {
					task.Spec.SessionRef = nil
				}
				require.NoError(t, f.pools.Create(f.ctx, task))
				f.dispatcher.APIReader = interceptor.NewClient(f.pools.Client.(client.WithWatch), interceptor.Funcs{
					Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
						if _, ok := object.(*corev1alpha1.RuntimePool); ok && scenario == "missing-pool" {
							return apierrors.NewNotFound(schema.GroupResource{Group: corev1alpha1.GroupVersion.Group, Resource: "runtimepools"}, key.Name)
						}
						if err := delegate.Get(ctx, key, object, options...); err != nil {
							return err
						}
						if observed, ok := object.(*corev1alpha1.RuntimePool); ok {
							if scenario == "missing-instance" {
								observed.Status.ActiveInstance = nil
							} else {
								observed.Status.ActiveInstance.RuntimeInstanceID = "replacement-instance.replacement-boot"
							}
						}
						return nil
					},
				})
				var sessionCleanup *sessionRuntimeCleanupFence
				if scope == "session-deletion" {
					sessionCleanup = &sessionRuntimeCleanupFence{}
				}
				complete, err := f.dispatcher.reconcileRecoveredRuntimeSession(f.ctx, task, task.UID, true, sessionCleanup)
				current := &corev1alpha1.Task{}
				require.NoError(t, f.pools.Get(f.ctx, client.ObjectKeyFromObject(task), current))
				if scope == "session-task" {
					require.NoError(t, err)
					require.True(t, complete)
					require.NotEmpty(t, current.Status.Execution.RuntimeSessionCleanupDigest)
				} else {
					require.ErrorIs(t, err, store.ErrConflict)
					require.False(t, complete)
					require.Empty(t, current.Status.Execution.RuntimeSessionCleanupDigest)
				}
				var pods corev1.PodList
				require.NoError(t, f.pools.List(f.ctx, &pods))
				require.Len(t, pods.Items, 1, "these read-only identity cases must not mutate runtime Pods")
			})
		}
	}
}
