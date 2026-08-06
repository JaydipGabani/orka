/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

// AgentExecutionControlReconciler drives the durable, revisioned backend
// admission modes. Every effective-mode transition increments the backend's
// modeRevision; enabled reaches drain-only only through the serialized closing
// barrier: new binding admission stops (the binding stage reads the effective
// mode uncached and rejects anything but enabled), then repeated uncached Task
// inventory passes must produce an identical closure digest with no unsettled
// pre-closing work before the cutoff is declared and admissionClosedAt is
// recorded. Recreating the control object is not a mode transition; binding
// verification pins the control UID and voids admission on recreation.
type AgentExecutionControlReconciler struct {
	client.Client
	APIReader client.Reader
	Recorder  record.EventRecorder
	// ClosurePasses and ClosureInterval bound the inventory proof.
	ClosurePasses   int
	ClosureInterval time.Duration
}

// +kubebuilder:rbac:groups=core.orka.ai,resources=agentexecutioncontrols,verbs=get;list;watch
// +kubebuilder:rbac:groups=core.orka.ai,resources=agentexecutioncontrols/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.orka.ai,resources=agentexecutionpolicies,verbs=get;list;watch

// SetupWithManager registers the reconciler.
func (r *AgentExecutionControlReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.AgentExecutionControl{}).
		Named("agentexecutioncontrol").
		Complete(r)
}

// Reconcile converges observed backend modes toward the desired modes.
func (r *AgentExecutionControlReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	control := &corev1alpha1.AgentExecutionControl{}
	if err := r.Get(ctx, req.NamespacedName, control); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if control.Name != corev1alpha1.AgentExecutionControlName {
		// CEL enforces the singleton name; ignore anything else defensively.
		return ctrl.Result{}, nil
	}

	if control.Status.Backends == nil {
		return ctrl.Result{}, r.updateStatus(ctx, control, func(status *corev1alpha1.AgentExecutionControlStatus) {
			status.ObservedGeneration = control.Generation
			status.Backends = &corev1alpha1.AgentExecutionBackendsStatus{
				V1: initialBackendStatus(control.Spec.Backends.V1.DesiredMode),
				V2: initialBackendStatus(control.Spec.Backends.V2.DesiredMode),
			}
		})
	}

	requeue := ctrl.Result{}
	v1Result, err := r.reconcileBackend(ctx, control, "v1", control.Spec.Backends.V1.DesiredMode, control.Status.Backends.V1,
		func(status *corev1alpha1.AgentExecutionControlStatus, backend corev1alpha1.AgentExecutionBackendStatus) {
			status.Backends.V1 = backend
		})
	if err != nil {
		return ctrl.Result{}, err
	}
	mergeRequeue(&requeue, v1Result)
	// Re-read after a possible v1 status write so the v2 CAS sees fresh state.
	if err := r.Get(ctx, req.NamespacedName, control); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if control.Status.Backends == nil {
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	v2Result, err := r.reconcileBackend(ctx, control, "v2", control.Spec.Backends.V2.DesiredMode, control.Status.Backends.V2,
		func(status *corev1alpha1.AgentExecutionControlStatus, backend corev1alpha1.AgentExecutionBackendStatus) {
			status.Backends.V2 = backend
		})
	if err != nil {
		return ctrl.Result{}, err
	}
	mergeRequeue(&requeue, v2Result)

	if control.Status.ObservedGeneration != control.Generation {
		if err := r.updateStatus(ctx, control, func(status *corev1alpha1.AgentExecutionControlStatus) {
			status.ObservedGeneration = control.Generation
		}); err != nil {
			return ctrl.Result{}, err
		}
	}
	return requeue, nil
}

func initialBackendStatus(desired corev1alpha1.AgentExecutionDesiredMode) corev1alpha1.AgentExecutionBackendStatus {
	// A backend bootstraps directly into its desired mode only when no
	// admission could have happened yet (fresh status).
	return corev1alpha1.AgentExecutionBackendStatus{
		EffectiveMode: effectiveModeFor(desired),
		ModeRevision:  1,
	}
}

func effectiveModeFor(desired corev1alpha1.AgentExecutionDesiredMode) corev1alpha1.AgentExecutionEffectiveMode {
	switch desired {
	case corev1alpha1.AgentExecutionModeEnabled:
		return corev1alpha1.AgentExecutionEffectiveModeEnabled
	case corev1alpha1.AgentExecutionModeDrainOnly:
		return corev1alpha1.AgentExecutionEffectiveModeDrainOnly
	default:
		return corev1alpha1.AgentExecutionEffectiveModeDisabled
	}
}

//nolint:gocyclo // The mode transition table is clearer in one place.
func (r *AgentExecutionControlReconciler) reconcileBackend(
	ctx context.Context,
	control *corev1alpha1.AgentExecutionControl,
	backendName string,
	desired corev1alpha1.AgentExecutionDesiredMode,
	current corev1alpha1.AgentExecutionBackendStatus,
	apply func(*corev1alpha1.AgentExecutionControlStatus, corev1alpha1.AgentExecutionBackendStatus),
) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("backend", backendName)
	target := effectiveModeFor(desired)
	publishModeRevision(backendName, current)

	switch {
	case current.EffectiveMode == target:
		return ctrl.Result{}, nil

	case current.EffectiveMode == corev1alpha1.AgentExecutionEffectiveModeEnabled &&
		(target == corev1alpha1.AgentExecutionEffectiveModeDrainOnly || target == corev1alpha1.AgentExecutionEffectiveModeDisabled):
		// Step 1 of the closing barrier: stop new binding admission.
		next := current
		next.EffectiveMode = corev1alpha1.AgentExecutionEffectiveModeClosing
		next.ModeRevision = current.ModeRevision + 1
		log.Info("backend admission entering closing barrier", "modeRevision", next.ModeRevision)
		r.Recorder.Eventf(control, corev1.EventTypeNormal, "AdmissionClosing",
			"%s backend admission is closing at revision %d", backendName, next.ModeRevision)
		return ctrl.Result{RequeueAfter: time.Second}, r.updateStatus(ctx, control,
			func(status *corev1alpha1.AgentExecutionControlStatus) { apply(status, next) })

	case current.EffectiveMode == corev1alpha1.AgentExecutionEffectiveModeClosing:
		if target == corev1alpha1.AgentExecutionEffectiveModeEnabled {
			// The operator reopened admission before the cutoff completed.
			next := current
			next.EffectiveMode = corev1alpha1.AgentExecutionEffectiveModeEnabled
			next.ModeRevision = current.ModeRevision + 1
			return ctrl.Result{}, r.updateStatus(ctx, control,
				func(status *corev1alpha1.AgentExecutionControlStatus) { apply(status, next) })
		}
		digest, proven, err := r.proveClosure(ctx, backendName, current.ModeRevision)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !proven {
			return ctrl.Result{RequeueAfter: r.closureInterval()}, nil
		}
		next := current
		next.EffectiveMode = target
		next.ModeRevision = current.ModeRevision + 1
		next.AdmissionClosedAt = new(metav1.Now())
		next.CutoffInventoryDigest = digest
		log.Info("backend admission cutoff proven", "modeRevision", next.ModeRevision, "cutoffInventoryDigest", digest)
		r.Recorder.Eventf(control, corev1.EventTypeNormal, "AdmissionClosed",
			"%s backend admission closed at revision %d with cutoff inventory %s", backendName, next.ModeRevision, digest)
		return ctrl.Result{}, r.updateStatus(ctx, control,
			func(status *corev1alpha1.AgentExecutionControlStatus) { apply(status, next) })

	default:
		// drain-only <-> disabled, or reopening to enabled: a direct revisioned
		// transition. Reopening clears the recorded cutoff.
		next := current
		next.EffectiveMode = target
		next.ModeRevision = current.ModeRevision + 1
		if target == corev1alpha1.AgentExecutionEffectiveModeEnabled {
			next.AdmissionClosedAt = nil
			next.CutoffInventoryDigest = ""
		}
		return ctrl.Result{}, r.updateStatus(ctx, control,
			func(status *corev1alpha1.AgentExecutionControlStatus) { apply(status, next) })
	}
}

func publishModeRevision(backendName string, backend corev1alpha1.AgentExecutionBackendStatus) {
	contract := string(corev1alpha1.AgentRuntimeContractHarnessV2)
	if backendName == "v1" {
		contract = string(corev1alpha1.AgentRuntimeContractHarnessV1)
	}
	agentExecutionModeRevision.DeletePartialMatch(prometheus.Labels{"contract_version": contract})
	agentExecutionModeRevision.WithLabelValues(contract, string(backend.EffectiveMode)).Set(float64(backend.ModeRevision))
}

func (r *AgentExecutionControlReconciler) closureInterval() time.Duration {
	if r.ClosureInterval > 0 {
		return r.ClosureInterval
	}
	return 5 * time.Second
}

// proveClosure performs repeated identical uncached Task inventory passes: the
// cutoff is effective only when no unsettled pre-closing work appears and the
// inventory is stable across passes. The binding stage already rejects new
// bindings while the backend is not enabled, and every binding pins the
// admitted mode revision, so a binding carrying the closing or a later
// revision can never exist.
func (r *AgentExecutionControlReconciler) proveClosure(
	ctx context.Context,
	backendName string,
	closingRevision int64,
) (string, bool, error) {
	passes := max(r.ClosurePasses, 2)
	contract := corev1alpha1.AgentRuntimeContractHarnessV2
	if backendName == "v1" {
		contract = corev1alpha1.AgentRuntimeContractHarnessV1
	}
	var previousDigest string
	for pass := range passes {
		digest, unsettled, err := r.inventoryPass(ctx, contract)
		if err != nil {
			return "", false, err
		}
		if unsettled > 0 {
			logf.FromContext(ctx).Info("closure blocked by unsettled pre-cutoff work",
				"backend", backendName, "closingRevision", closingRevision, "unsettled", unsettled)
			return "", false, nil
		}
		if pass > 0 && digest != previousDigest {
			return "", false, nil
		}
		previousDigest = digest
		if pass < passes-1 {
			select {
			case <-ctx.Done():
				return "", false, ctx.Err()
			case <-time.After(r.closureInterval()):
			}
		}
	}
	return previousDigest, true, nil
}

// inventoryPass counts unsettled Tasks bound to the backend contract and
// digests the complete inventory.
func (r *AgentExecutionControlReconciler) inventoryPass(
	ctx context.Context,
	contract corev1alpha1.AgentRuntimeContractVersion,
) (string, int, error) {
	tasks := &corev1alpha1.TaskList{}
	if err := r.APIReader.List(ctx, tasks); err != nil {
		return "", 0, fmt.Errorf("uncached task inventory: %w", err)
	}
	inventory := map[string]string{}
	unsettled := 0
	for i := range tasks.Items {
		task := &tasks.Items[i]
		if task.Spec.Type != corev1alpha1.TaskTypeAgent {
			continue
		}
		binding := task.Status.AgentExecutionBinding
		if binding == nil || binding.ContractVersion != contract {
			continue
		}
		state := string(task.Status.Phase)
		if !taskPhaseTerminal(task.Status.Phase) || !task.DeletionTimestamp.IsZero() {
			unsettled++
			state += "/unsettled"
		}
		inventory[string(task.UID)] = binding.BindingDigest + "/" + state
	}
	digest, err := acpDomainDigest("mode-cutoff-inventory", inventory)
	if err != nil {
		return "", 0, err
	}
	return digest, unsettled, nil
}

func mergeRequeue(into *ctrl.Result, from ctrl.Result) {
	if from.RequeueAfter > 0 && (into.RequeueAfter == 0 || from.RequeueAfter < into.RequeueAfter) {
		into.RequeueAfter = from.RequeueAfter
	}
}

// PublishOwnership mirrors the held ownership fence set into the control
// object's status; the ownership runnable calls it after each renewal cycle.
func (r *AgentExecutionControlReconciler) PublishOwnership(
	ctx context.Context,
	leaseNamespace, leaseName string,
	leaseUID types.UID,
	controllerEpoch int64,
	fences []corev1alpha1.AgentExecutionLegacyLeaseFence,
) error {
	control := &corev1alpha1.AgentExecutionControl{}
	err := r.Get(ctx, types.NamespacedName{
		Namespace: corev1alpha1.AgentExecutionControlNamespace,
		Name:      corev1alpha1.AgentExecutionControlName,
	}, control)
	if err != nil {
		return client.IgnoreNotFound(err)
	}
	return r.updateStatus(ctx, control, func(status *corev1alpha1.AgentExecutionControlStatus) {
		status.Ownership = &corev1alpha1.AgentExecutionOwnershipStatus{
			LeaseNamespace: leaseNamespace, LeaseName: leaseName, UID: leaseUID,
			ControllerEpoch: controllerEpoch, LegacyLeaseFences: fences,
		}
	})
}

func (r *AgentExecutionControlReconciler) updateStatus(
	ctx context.Context,
	control *corev1alpha1.AgentExecutionControl,
	mutate func(*corev1alpha1.AgentExecutionControlStatus),
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &corev1alpha1.AgentExecutionControl{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: control.Namespace, Name: control.Name}, current); err != nil {
			return err
		}
		mutate(&current.Status)
		return r.Status().Update(ctx, current)
	})
}
