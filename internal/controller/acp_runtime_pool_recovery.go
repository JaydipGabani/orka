package controller

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/orka-agents/orka/internal/store"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// runtimePoolCleanupAuthority separates the current durable cleanup owner from
// the surviving supervisor's immutable startup epoch. It cannot admit work,
// renew a prompt, or change that epoch: only exact retirement is authorized.
type runtimePoolCleanupAuthority struct {
	controller store.ControllerEpochFence
	task       *corev1alpha1.Task
	taskUID    types.UID
	pool       *corev1alpha1.RuntimePool
	pod        *corev1.Pod
	auth       *corev1.Secret
	fence      harnessv2.Fence
	abandon    bool
}

const runtimePoolFinalizePublicationOperation = "finalize_runtime_session_publication"

//nolint:gocyclo // Keep the frozen Pod, credential, profile, and epoch checks in one cleanup authority boundary.
func (d *ACPDispatcher) runtimePoolRetirementClient(
	ctx context.Context,
	task *corev1alpha1.Task,
	taskUID types.UID,
	pool *corev1alpha1.RuntimePool,
	owner store.ControllerEpochFence,
) (*harnessv2.Client, *runtimePoolCleanupAuthority, error) {
	authority := &runtimePoolCleanupAuthority{controller: owner, task: task.DeepCopy(), taskUID: taskUID, pool: pool.DeepCopy()}
	if err := authority.validatePool(pool); err != nil {
		return nil, nil, err
	}
	attempt, err := d.validateRuntimePoolCleanupTask(ctx, task, taskUID, pool)
	if err != nil {
		return nil, nil, err
	}
	authority.abandon = attempt.ExecutionState != store.PromptExecutionSucceeded ||
		attempt.DeliveryState == store.PromptDeliveryConflict || attempt.DeliveryState == store.PromptDeliveryCancelledBeforePublish
	active := pool.Status.ActiveInstance
	pod := &corev1.Pod{}
	if err := d.APIReader.Get(ctx, client.ObjectKey{Namespace: active.PodNamespace, Name: active.PodName}, pod); err != nil {
		return nil, nil, fmt.Errorf("read retirement RuntimePool Pod: %w", err)
	}
	if string(pod.UID) != active.PodUID || pod.Status.PodIP != active.PodAddress ||
		pod.Labels[runtimePoolUIDLabel] != string(pool.UID) {
		return nil, nil, fmt.Errorf("%w: retirement RuntimePool Pod identity changed", store.ErrConflict)
	}
	deployed, cfg, err := runtimePoolValidationTargetFromTemplate(pool, corev1.PodTemplateSpec{ObjectMeta: pod.ObjectMeta, Spec: pod.Spec})
	if err != nil {
		return nil, nil, err
	}
	if cfg.controllerEpoch != active.ControllerEpoch || deployed.Generation > pool.Generation ||
		deployed.Spec.Runtime.Profile.Digest != pool.Spec.Runtime.Profile.Digest ||
		pod.Spec.Containers[0].Image != pool.Spec.Runtime.Image ||
		runtimePoolLiteralEnvironment(pod.Spec.Containers[0].Env)["ORKA_ACP_RUNTIME_POOL_UID"] != string(pool.UID) {
		return nil, nil, fmt.Errorf("%w: retirement RuntimePool template fence changed", store.ErrConflict)
	}
	auth, err := d.runtimeAuthSecret(ctx, pool)
	if err != nil {
		return nil, nil, err
	}
	mounted := false
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == runtimePoolAuthVolume && volume.Secret != nil && volume.Secret.SecretName == auth.Name {
			mounted = true
		}
	}
	if !mounted || auth.UID == "" || auth.ResourceVersion == "" || !auth.DeletionTimestamp.IsZero() ||
		len(auth.Data[runtimePoolControllerTokenKey]) < 32 || len(auth.Data[runtimePoolCapabilitySecretKey]) < harnessv2.MinCapabilitySecretBytes {
		return nil, nil, fmt.Errorf("%w: retirement RuntimePool mounted authentication is unavailable", store.ErrConflict)
	}
	authority.pod, authority.auth = pod.DeepCopy(), auth.DeepCopy()
	authority.fence = harnessv2.Fence{
		RuntimeInstanceID: harnessv2.RuntimeInstanceID(active.RuntimeInstanceID), SupervisorBootID: harnessv2.SupervisorBootID(active.BootID),
		ControllerEpoch: uint64(cfg.controllerEpoch), RuntimePoolUID: harnessv2.RuntimePoolUID(pool.UID),
		RuntimePoolGeneration: uint64(deployed.Generation), RuntimeProfileDigest: harnessv2.ProfileDigest(active.ProfileDigest),
		ProfileDigestSchemaVersion: harnessv2.ProfileDigestSchemaVersion,
		RuntimeSessionUID:          harnessv2.RuntimeSessionUID(task.Status.Execution.RuntimeSessionUID),
		RuntimeSessionGeneration:   uint64(task.Status.Execution.RuntimeSessionGeneration),
	}
	var runtimeClient *harnessv2.Client
	runtimeClient, err = harnessv2.NewClient(exactPodEndpoint(active.PodAddress),
		harnessv2.WithControllerBearerToken(strings.TrimSpace(string(auth.Data[runtimePoolControllerTokenKey]))),
		harnessv2.WithOperationCapabilitySecret(auth.Data[runtimePoolCapabilitySecretKey]),
		harnessv2.WithStatusCapabilityBinding(harnessv2.StatusCapabilityBinding{
			RuntimeProfileDigest: authority.fence.RuntimeProfileDigest, RuntimeInstanceID: authority.fence.RuntimeInstanceID,
		}),
		harnessv2.WithBeforeMutation(func(checkCtx context.Context, operation string) error {
			switch operation {
			case externalRuntimeDeleteSessionOperation, runtimePoolFinalizePublicationOperation:
			default:
				return fmt.Errorf("%w: RuntimePool client permits retirement only", store.ErrConflict)
			}
			if err := authority.revalidate(checkCtx, d); err != nil {
				return err
			}
			status, err := runtimeClient.Status(checkCtx)
			if err != nil {
				return err
			}
			if err := validateSessionRuntimeCleanupStatus(authority.fence, status); err != nil {
				return err
			}
			// Authentication can outlive leadership or credential ownership
			// while status is in flight. Recheck after that network boundary.
			return authority.revalidate(checkCtx, d)
		}),
	)
	if err != nil {
		return nil, nil, err
	}
	capabilities, err := runtimeClient.Capabilities(ctx)
	if err != nil {
		return nil, nil, err
	}
	status, err := runtimeClient.Status(ctx)
	if err != nil {
		return nil, nil, err
	}
	observed, err := validateRuntimePoolProbeForRollout(deployed, cfg, pod,
		RuntimePoolProbeResult{Capabilities: *capabilities, Status: *status}, time.Now().UTC())
	if err != nil {
		return nil, nil, err
	}
	if !runtimePoolRolloutActiveInstanceMatches(active, observed) {
		return nil, nil, fmt.Errorf("%w: authenticated retirement RuntimePool boot changed", store.ErrConflict)
	}
	if err := authority.revalidate(ctx, d); err != nil {
		return nil, nil, err
	}
	return runtimeClient, authority, nil
}

func (a *runtimePoolCleanupAuthority) validatePool(pool *corev1alpha1.RuntimePool) error {
	expected, active := a.pool.Status.ActiveInstance, pool.Status.ActiveInstance
	if pool.UID != a.pool.UID || pool.Spec.ExecutionWorkspace != nil ||
		active == nil || expected == nil || active.ControllerEpoch < 1 || active.ControllerEpoch > a.controller.Epoch ||
		!runtimePoolRolloutActiveInstanceMatches(expected, active) || active.PodAddress != expected.PodAddress ||
		pool.Spec.Runtime.Profile.Digest != a.pool.Spec.Runtime.Profile.Digest ||
		(active.ControllerEpoch < a.controller.Epoch &&
			pool.Status.AdmissionState != corev1alpha1.RuntimePoolAdmissionClosed && pool.Status.AdmissionState != corev1alpha1.RuntimePoolAdmissionDraining) {
		return fmt.Errorf("%w: RuntimePool retirement requires its frozen boot and closed historical admission", store.ErrConflict)
	}
	return nil
}

//nolint:gocyclo // Every field of the durable attempt and frozen Task must agree before historical cleanup is authorized.
func (d *ACPDispatcher) validateRuntimePoolCleanupTask(
	ctx context.Context, task *corev1alpha1.Task, taskUID types.UID, pool *corev1alpha1.RuntimePool,
) (*store.PromptAttempt, error) {
	binding, execution := executionBinding(task, corev1alpha1.AgentRuntimeContractHarnessV2), task.Status.Execution
	active := pool.Status.ActiveInstance
	if task.Spec.SessionRef != nil || binding == nil || execution == nil || binding.Backend != corev1alpha1.AgentExecutionBackendRuntimePool ||
		binding.Task.UID != taskUID || binding.RuntimeProfileDigest != pool.Spec.Runtime.Profile.Digest ||
		execution.RuntimePoolName != pool.Name || execution.RuntimePoolUID != string(pool.UID) ||
		execution.AgentRuntimeName != "" || execution.AgentRuntimeUID != "" || active == nil ||
		execution.RuntimeInstanceID != active.RuntimeInstanceID || execution.RuntimeSessionSupervisorBootID != active.BootID ||
		execution.RuntimeSessionUID == "" || execution.RuntimeSessionGeneration < 1 ||
		(execution.RuntimeSessionProfileDigest != "" && execution.RuntimeSessionProfileDigest != active.ProfileDigest) {
		return nil, fmt.Errorf("%w: standalone Task cleanup identity is incomplete", store.ErrConflict)
	}
	digest, err := canonicalAgentExecutionBindingDigest(*binding)
	if err != nil || digest != binding.BindingDigest {
		return nil, fmt.Errorf("%w: Task cleanup binding failed integrity verification", store.ErrConflict)
	}
	attemptID, err := promptAttemptIDFromTaskUID(task, taskUID)
	if err != nil {
		return nil, err
	}
	attempt, err := d.Store.GetPromptAttempt(ctx, attemptID)
	if err != nil {
		return nil, err
	}
	if attempt.ID != attemptID || attempt.Key.Namespace != task.Namespace || attempt.Key.TaskUID != string(taskUID) ||
		attempt.Key.Attempt != int64(execution.Attempt) || attempt.Key.PromptID != execution.PromptID ||
		attempt.BindingDigest != binding.BindingDigest || attempt.SnapshotDigest != binding.Snapshot.Digest ||
		attempt.RequestDigest != execution.RequestDigest || attempt.RuntimeInstanceID != execution.RuntimeInstanceID ||
		attempt.SessionUID != execution.RuntimeSessionUID || attempt.SessionLeaseGeneration != execution.RuntimeSessionGeneration ||
		!store.IsTerminalPromptExecutionState(attempt.ExecutionState) || !store.IsTerminalPromptDeliveryState(attempt.DeliveryState) {
		return nil, fmt.Errorf("%w: RuntimePool retirement requires the exact durably settled attempt", store.ErrConflict)
	}
	return attempt, nil
}

func (a *runtimePoolCleanupAuthority) revalidate(ctx context.Context, d *ACPDispatcher) error {
	if err := requireAgentRuntimeRecoveryFence(ctx, d.Store, a.controller); err != nil {
		return err
	}
	task := &corev1alpha1.Task{}
	if err := d.APIReader.Get(ctx, client.ObjectKeyFromObject(a.task), task); err != nil {
		return err
	}
	if task.UID != a.task.UID || task.Status.Execution == nil ||
		task.Status.Execution.PromptID != a.task.Status.Execution.PromptID ||
		task.Status.Execution.Attempt != a.task.Status.Execution.Attempt ||
		sessionRuntimeCleanupIdentityForExecution(task.Status.Execution) != sessionRuntimeCleanupIdentityForExecution(a.task.Status.Execution) {
		return fmt.Errorf("%w: Task cleanup owner changed", store.ErrConflict)
	}
	pool := &corev1alpha1.RuntimePool{}
	if err := d.APIReader.Get(ctx, client.ObjectKeyFromObject(a.pool), pool); err != nil {
		return err
	}
	if err := a.validatePool(pool); err != nil {
		return err
	}
	if _, err := d.validateRuntimePoolCleanupTask(ctx, task, a.taskUID, pool); err != nil {
		return err
	}
	pod := &corev1.Pod{}
	if err := d.APIReader.Get(ctx, client.ObjectKeyFromObject(a.pod), pod); err != nil {
		return err
	}
	if pod.UID != a.pod.UID || pod.Status.PodIP != a.pod.Status.PodIP ||
		pod.Labels[runtimePoolUIDLabel] != string(pool.UID) || !reflect.DeepEqual(pod.Spec, a.pod.Spec) {
		return fmt.Errorf("%w: RuntimePool Pod changed before cleanup", store.ErrConflict)
	}
	auth, err := d.runtimeAuthSecret(ctx, pool)
	if err != nil {
		return err
	}
	if auth.UID != a.auth.UID || auth.ResourceVersion != a.auth.ResourceVersion || !auth.DeletionTimestamp.IsZero() ||
		!bytes.Equal(auth.Data[runtimePoolControllerTokenKey], a.auth.Data[runtimePoolControllerTokenKey]) ||
		!bytes.Equal(auth.Data[runtimePoolCapabilitySecretKey], a.auth.Data[runtimePoolCapabilitySecretKey]) {
		return fmt.Errorf("%w: RuntimePool authentication changed before cleanup", store.ErrConflict)
	}
	return nil
}

func (a *runtimePoolCleanupAuthority) recordCleanup(ctx context.Context, d *ACPDispatcher) error {
	if err := a.revalidate(ctx, d); err != nil {
		return err
	}
	return agentRuntimeRecoveryGuard(ctx, d.Store, a.controller, func(writeCtx context.Context) error {
		return d.markTaskScopedRuntimeSessionCleanupComplete(writeCtx, a.task, a.taskUID,
			string(a.fence.RuntimeInstanceID), string(a.fence.RuntimeSessionUID), int64(a.fence.RuntimeSessionGeneration))
	})
}

func (d *ACPDispatcher) standaloneRuntimePoolRetirementReady(ctx context.Context, task *corev1alpha1.Task, taskUID types.UID) (bool, error) {
	if task.Spec.SessionRef != nil {
		return false, nil
	}
	attemptID, err := promptAttemptIDFromTaskUID(task, taskUID)
	if err != nil {
		return false, err
	}
	attempt, err := d.Store.GetPromptAttempt(ctx, attemptID)
	if err != nil {
		return false, err
	}
	return store.IsTerminalPromptExecutionState(attempt.ExecutionState) && store.IsTerminalPromptDeliveryState(attempt.DeliveryState), nil
}
