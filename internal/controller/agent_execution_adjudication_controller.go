/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

// AgentExecutionAdjudicationReconciler applies admin-authored adjudications:
// it fences each decision to the exact observed subject and evidence, appends
// the immutable subject-side resolution reference exactly once, and never
// clears or rewrites the original quarantine, no-execution, or blocked-state
// evidence. Actions are one-way and never authorize replay or protocol
// mutation; route-aware finalization consumes only an Applied adjudication
// referenced by the subject-side record.
//
// Session-side resolution references ride the existing blocked-session
// automatic recovery (ReconcileSessionControl); Task-side references are
// appended here.
type AgentExecutionAdjudicationReconciler struct {
	client.Client
	APIReader client.Reader
	Recorder  record.EventRecorder
}

// +kubebuilder:rbac:groups=core.orka.ai,resources=agentexecutionadjudications,verbs=get;list;watch
// +kubebuilder:rbac:groups=core.orka.ai,resources=agentexecutionadjudications/status,verbs=get;update;patch

// SetupWithManager registers the reconciler.
func (r *AgentExecutionAdjudicationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.AgentExecutionAdjudication{}).
		Named("agentexecutionadjudication").
		Complete(r)
}

// Reconcile drives one adjudication to a terminal application state.
func (r *AgentExecutionAdjudicationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	adjudication := &corev1alpha1.AgentExecutionAdjudication{}
	if err := r.Get(ctx, req.NamespacedName, adjudication); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	switch adjudication.Status.State {
	case corev1alpha1.AgentExecutionAdjudicationApplied,
		corev1alpha1.AgentExecutionAdjudicationRejected,
		corev1alpha1.AgentExecutionAdjudicationSuperseded:
		return ctrl.Result{}, nil
	}
	if adjudication.Spec.ExpiresAt != nil && time.Now().After(adjudication.Spec.ExpiresAt.Time) {
		return ctrl.Result{}, r.finish(ctx, adjudication, corev1alpha1.AgentExecutionAdjudicationRejected,
			"adjudication expired before application")
	}

	// Uncached subject read: the decision is fenced to the exact observed
	// subject version and evidence.
	task := &corev1alpha1.Task{}
	err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: adjudication.Namespace, Name: adjudication.Spec.TaskRef.Name}, task)
	if apierrors.IsNotFound(err) {
		return ctrl.Result{}, r.finish(ctx, adjudication, corev1alpha1.AgentExecutionAdjudicationRejected,
			"subject task no longer exists")
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if task.UID != adjudication.Spec.TaskRef.UID {
		return ctrl.Result{}, r.finish(ctx, adjudication, corev1alpha1.AgentExecutionAdjudicationRejected,
			"subject task UID does not match; a same-name recreation never satisfies an old identity")
	}
	if task.ResourceVersion != adjudication.Spec.ExpectedState.SubjectResourceVersion {
		// A changed subject version means new evidence may exist.
		if existing := task.Status.AgentExecutionResolutionRef; existing != nil &&
			existing.AdjudicationUID == adjudication.UID {
			// Our own earlier application changed the version: converge idempotently.
			return ctrl.Result{}, r.finishApplied(ctx, adjudication, task, existing)
		}
		return ctrl.Result{}, r.finish(ctx, adjudication, corev1alpha1.AgentExecutionAdjudicationSuperseded,
			fmt.Sprintf("subject resourceVersion %s no longer matches expected %s",
				task.ResourceVersion, adjudication.Spec.ExpectedState.SubjectResourceVersion))
	}
	if message, ok := r.verifyEvidence(adjudication, task); !ok {
		return ctrl.Result{}, r.finish(ctx, adjudication, corev1alpha1.AgentExecutionAdjudicationSuperseded, message)
	}
	if existing := task.Status.AgentExecutionResolutionRef; existing != nil {
		if existing.AdjudicationUID == adjudication.UID {
			return ctrl.Result{}, r.finishApplied(ctx, adjudication, task, existing)
		}
		return ctrl.Result{}, r.finish(ctx, adjudication, corev1alpha1.AgentExecutionAdjudicationRejected,
			fmt.Sprintf("subject already carries resolution %s from adjudication %s; conflicting adjudications are rejected",
				existing.ResolutionDigest, existing.AdjudicationName))
	}

	operationID := fmt.Sprintf("adjudication-%s-rv%s", adjudication.UID, task.ResourceVersion)
	operationDigest, err := acpDomainDigest("adjudication-operation", map[string]string{
		"adjudicationUID": string(adjudication.UID),
		"action":          string(adjudication.Spec.Action),
		"subjectUID":      string(task.UID),
		"subjectRV":       task.ResourceVersion,
		"evidenceClosure": adjudication.Spec.ExpectedState.EvidenceClosureWatermark,
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	resolution := corev1alpha1.AgentExecutionResolutionRef{
		AdjudicationName: adjudication.Name,
		AdjudicationUID:  adjudication.UID,
		Action:           adjudication.Spec.Action,
		OperationDigest:  operationDigest,
		AppliedAt:        metav1.Now(),
	}
	resolutionDigest, err := acpDomainDigest("adjudication-resolution", map[string]string{
		"adjudicationUID": string(adjudication.UID),
		"operationDigest": operationDigest,
		"action":          string(adjudication.Spec.Action),
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	resolution.ResolutionDigest = resolutionDigest

	// CAS-append against the exact verified subject version; the optimistic
	// lock guarantees a concurrent subject change supersedes instead of
	// applying against unseen evidence.
	base := task.DeepCopy()
	task.Status.AgentExecutionResolutionRef = resolution.DeepCopy()
	if err := r.Status().Patch(ctx, task, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
		if apierrors.IsConflict(err) {
			log.Info("subject changed while applying adjudication; re-evaluating")
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	r.Recorder.Eventf(task, corev1.EventTypeNormal, "AgentExecutionAdjudicationApplied",
		"adjudication %s applied action %s (resolution %s)", adjudication.Name, adjudication.Spec.Action, resolutionDigest)
	if err := r.updateStatus(ctx, adjudication, func(status *corev1alpha1.AgentExecutionAdjudicationStatus) {
		status.State = corev1alpha1.AgentExecutionAdjudicationApplied
		status.OperationID = operationID
		status.OperationDigest = operationDigest
		status.ResolutionRefDigest = resolutionDigest
		status.ResultingSubjectResourceVersion = task.ResourceVersion
		status.ObservedAt = new(metav1.Now())
		status.Message = ""
	}); err != nil {
		return ctrl.Result{}, err
	}
	agentExecutionAdjudicationsTotal.WithLabelValues(string(adjudication.Spec.Action), "Applied").Inc()
	r.Recorder.Eventf(adjudication, corev1.EventTypeNormal, "Applied",
		"applied %s to task %s at resourceVersion %s", adjudication.Spec.Action, task.Name, task.ResourceVersion)
	return ctrl.Result{}, nil
}

// verifyEvidence fences the decision to the exact immutable evidence records.
func (r *AgentExecutionAdjudicationReconciler) verifyEvidence(
	adjudication *corev1alpha1.AgentExecutionAdjudication,
	task *corev1alpha1.Task,
) (string, bool) {
	if adjudication.Spec.QuarantineDigest != "" {
		quarantine := task.Status.AgentExecutionQuarantine
		if quarantine == nil {
			return "subject has no quarantine record for the supplied quarantine digest", false
		}
		digest, err := acpDomainDigest("quarantine-record", quarantine)
		if err != nil || digest != adjudication.Spec.QuarantineDigest {
			return "quarantine evidence digest no longer matches the immutable record", false
		}
	}
	return "", true
}

func (r *AgentExecutionAdjudicationReconciler) finishApplied(
	ctx context.Context,
	adjudication *corev1alpha1.AgentExecutionAdjudication,
	task *corev1alpha1.Task,
	resolution *corev1alpha1.AgentExecutionResolutionRef,
) error {
	return r.updateStatus(ctx, adjudication, func(status *corev1alpha1.AgentExecutionAdjudicationStatus) {
		status.State = corev1alpha1.AgentExecutionAdjudicationApplied
		status.OperationDigest = resolution.OperationDigest
		status.ResolutionRefDigest = resolution.ResolutionDigest
		status.ResultingSubjectResourceVersion = task.ResourceVersion
		if status.ObservedAt == nil {
			status.ObservedAt = new(metav1.Now())
		}
	})
}

func (r *AgentExecutionAdjudicationReconciler) finish(
	ctx context.Context,
	adjudication *corev1alpha1.AgentExecutionAdjudication,
	state corev1alpha1.AgentExecutionAdjudicationState,
	message string,
) error {
	observedAt := new(metav1.Now())
	if err := r.updateStatus(ctx, adjudication, func(status *corev1alpha1.AgentExecutionAdjudicationStatus) {
		status.State = state
		status.Message = message
		status.ObservedAt = observedAt
	}); err != nil {
		return err
	}
	agentExecutionAdjudicationsTotal.WithLabelValues(string(adjudication.Spec.Action), string(state)).Inc()
	r.Recorder.Eventf(adjudication, corev1.EventTypeWarning, string(state), "%s", message)
	return nil
}

func (r *AgentExecutionAdjudicationReconciler) updateStatus(
	ctx context.Context,
	adjudication *corev1alpha1.AgentExecutionAdjudication,
	mutate func(*corev1alpha1.AgentExecutionAdjudicationStatus),
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &corev1alpha1.AgentExecutionAdjudication{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: adjudication.Namespace, Name: adjudication.Name}, current); err != nil {
			return err
		}
		mutate(&current.Status)
		return r.Status().Update(ctx, current)
	})
}

//go:fix inline
