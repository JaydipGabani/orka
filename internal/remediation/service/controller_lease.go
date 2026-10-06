package service

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/orka-agents/orka/internal/store"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	controllerLeaseBinding = "remediation.orka.ai/controller-lease-binding"
	controllerLeaseCluster = "remediation.orka.ai/controller-lease-cluster"
)

// A run owns the lab, not a worker epoch. There is deliberately no expiration,
// renewal, owner reference, or takeover: an old controller or a delayed create
// can outlive both a worker claim and a process.
type controllerClusterLease struct {
	Version         int       `json:"version"`
	ClusterUID      types.UID `json:"clusterUID"`
	Namespace       string    `json:"namespace"`
	Name            string    `json:"name"`
	RunID           string    `json:"runID"`
	InputDigest     string    `json:"inputDigest"`
	BindingDigest   string    `json:"bindingDigest"`
	CreateAttempted bool      `json:"createAttempted"`
	UID             types.UID `json:"uid,omitempty"`
	ResourceVersion string    `json:"resourceVersion,omitempty"`
	DeleteRequested bool      `json:"deleteRequested"`
	DeleteAccepted  bool      `json:"deleteAccepted"`
	Released        bool      `json:"released"`
}

func expectedControllerLease(run *store.RemediationRun, config ControllerAdapterConfig) controllerClusterLease {
	namespace := config.BuildEnvironment.BuildJobs.Namespace
	cluster := Digest([]byte(config.ClusterUID))
	binding := jsonIdentity(struct {
		Domain, RunNamespace, RunID, InputDigest, PolicyDigest, Namespace string
		ClusterUID                                                        types.UID
	}{"orka.remediation.controller-lease.v1", run.Namespace, run.ID, run.InputDigest, run.PolicyDigest, namespace, config.ClusterUID})
	return controllerClusterLease{
		Version: 1, ClusterUID: config.ClusterUID, Namespace: namespace,
		Name:  "orka-controllerlab-" + strings.TrimPrefix(cluster, "sha256:")[:40],
		RunID: run.ID, InputDigest: run.InputDigest, BindingDigest: binding,
	}
}

func controllerLeaseObject(receipt controllerClusterLease) *coordinationv1.Lease {
	holder := strings.TrimPrefix(receipt.BindingDigest, "sha256:")
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: receipt.Namespace, Name: receipt.Name,
			Annotations: map[string]string{
				controllerLeaseBinding: receipt.BindingDigest,
				controllerLeaseCluster: Digest([]byte(receipt.ClusterUID)),
			},
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder},
	}
}

func controllerLeaseMatches(actual *coordinationv1.Lease, receipt controllerClusterLease) bool {
	expected := controllerLeaseObject(receipt)
	return actual != nil && actual.Name == receipt.Name && actual.Namespace == receipt.Namespace &&
		actual.UID != "" && actual.ResourceVersion != "" && (receipt.UID == "" || actual.UID == receipt.UID) &&
		len(actual.OwnerReferences) == 0 && reflect.DeepEqual(actual.Spec, expected.Spec) &&
		actual.Annotations[controllerLeaseBinding] == expected.Annotations[controllerLeaseBinding] &&
		actual.Annotations[controllerLeaseCluster] == expected.Annotations[controllerLeaseCluster]
}

func controllerLeaseCurrent(ctx context.Context, session *Session, state *pipelineState, cleanup bool) (*store.RemediationRun, pipelineState, error) {
	current, err := session.Current(ctx)
	if err != nil {
		return nil, pipelineState{}, err
	}
	if !cleanup && (current.CancelRequested || !time.Now().Before(current.Deadline) ||
		current.Phase == store.RemediationPhaseCancelling || store.IsRemediationTerminalPhase(current.Phase)) {
		return nil, pipelineState{}, context.Canceled
	}
	var durable pipelineState
	if json.Unmarshal(current.StateJSON, &durable) != nil || durable.Version != Version ||
		!reflect.DeepEqual(durable.Selection, state.Selection) || !reflect.DeepEqual(durable.ControllerLease, state.ControllerLease) {
		return nil, pipelineState{}, ErrUnknown
	}
	return current, durable, nil
}

func (a *controllerExecutionAdapter) validateControllerLease(run *store.RemediationRun, state *pipelineState) error {
	if !a.selection.ClusterExclusive || state.Selection == nil || !reflect.DeepEqual(*state.Selection, a.selection) ||
		!validControllerClusterUID(a.config.ClusterUID) || !validControllerLeaseNamespace(a.config) {
		return ErrInvalid
	}
	if state.ControllerLease == nil {
		return nil
	}
	receipt := *state.ControllerLease
	expected := expectedControllerLease(run, a.config)
	expected.CreateAttempted, expected.UID, expected.ResourceVersion = receipt.CreateAttempted, receipt.UID, receipt.ResourceVersion
	expected.DeleteRequested, expected.Released = receipt.DeleteRequested, receipt.Released
	expected.DeleteAccepted = receipt.DeleteAccepted
	if receipt != expected || (receipt.UID == "") != (receipt.ResourceVersion == "") ||
		(receipt.UID != "" && !receipt.CreateAttempted) || (receipt.DeleteRequested && receipt.UID == "") ||
		(receipt.DeleteAccepted && !receipt.DeleteRequested) ||
		(receipt.Released && receipt.CreateAttempted && !receipt.DeleteRequested) {
		return ErrUnknown
	}
	return nil
}

func (a *controllerExecutionAdapter) validateControllerLeasePolicy(run *store.RemediationRun, state *pipelineState) error {
	if err := a.validateControllerLease(run, state); err != nil {
		return err
	}
	var policy Policy
	if json.Unmarshal(run.PolicyJSON, &policy) != nil || Digest(run.PolicyJSON) != run.PolicyDigest {
		return ErrInvalid
	}
	clusters, err := controllerCoordinatedClusters(policy)
	if err != nil {
		return err
	}
	if namespace, exclusive := clusters[a.config.ClusterUID]; !exclusive || namespace != a.config.BuildEnvironment.BuildJobs.Namespace {
		return ErrInvalid
	}
	for _, configured := range policy.Adapters {
		if configured.Name == a.selection.Name && configured.Kind == controllerAdapterKind {
			config, err := decodeControllerPolicy(configured)
			if err != nil || !reflect.DeepEqual(config, a.config) {
				return ErrInvalid
			}
			return nil
		}
	}
	return ErrInvalid
}

// Read the lease and its CAS revision together. Merge into that durable state,
// not the caller's possibly stale operation receipts or settlement fields.
func (a *controllerExecutionAdapter) checkpointControllerLease(ctx context.Context, session *Session, state *pipelineState, next controllerClusterLease, cleanup bool) error {
	current, durable, err := controllerLeaseCurrent(ctx, session, state, cleanup)
	if err != nil {
		return err
	}
	if !controllerLeaseTransitionAllowed(durable.ControllerLease, next) {
		return ErrUnknown
	}
	durable.ControllerLease = &next
	if err := a.validateControllerLease(current, &durable); err != nil {
		return err
	}
	if (next.DeleteRequested || next.Released) && !controllerLeaseOperationsClean(current, &durable) {
		return ErrUnknown
	}
	raw, err := marshalControllerPipeline(current.StateJSON, &durable)
	if err != nil {
		return err
	}
	if _, err := session.store.UpdateRemediationRun(ctx, current.Namespace, current.ID, session.owner, session.epoch, current.Revision,
		store.RemediationUpdate{Phase: current.Phase, Reason: current.Reason, StateJSON: raw}, time.Now().UTC()); err != nil {
		return err
	}
	state.ControllerLease = &next
	return nil
}

func controllerLeaseTransitionAllowed(previous *controllerClusterLease, next controllerClusterLease) bool {
	if previous == nil {
		return !next.CreateAttempted && next.UID == "" && !next.DeleteRequested && !next.DeleteAccepted && !next.Released
	}
	if previous.Released {
		return *previous == next
	}
	// Once accepted, neither the server identity nor a cleanup receipt can be
	// rolled back by a stale caller to authorize another create.
	return (previous.UID == "" || (next.UID == previous.UID && next.ResourceVersion == previous.ResourceVersion)) &&
		(previous.CreateAttempted || next.UID == "") &&
		(!previous.DeleteRequested || next.DeleteRequested) && (!previous.DeleteAccepted || next.DeleteAccepted)
}

func (a *controllerExecutionAdapter) prepareControllerLease(ctx context.Context, session *Session, state *pipelineState, operation *executionOperation) error {
	if operation.Observation != nil {
		// A final checkpoint may be retried after release. Reading retained,
		// cleaned observations must not reacquire the lab.
		return nil
	}
	return a.ensureControllerLease(ctx, session, state)
}

func (a *controllerExecutionAdapter) verifyControllerLab(ctx context.Context, session *Session, state *pipelineState, cleanup bool) error {
	if err := a.verifyControllerLease(ctx, session, state, cleanup); err != nil {
		return err
	}
	return a.verifyControllerCluster(ctx)
}

func (a *controllerExecutionAdapter) ensureControllerLease(ctx context.Context, session *Session, state *pipelineState) error {
	if !a.selection.ClusterExclusive {
		if state.ControllerLease != nil || (state.Selection != nil && state.Selection.ClusterExclusive) {
			return ErrInvalid
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	current, _, err := controllerLeaseCurrent(ctx, session, state, false)
	if err != nil {
		return err
	}
	if err := a.validateControllerLeasePolicy(current, state); err != nil {
		return err
	}
	if err := a.verifyControllerCluster(ctx); err != nil {
		return err
	}
	if state.ControllerLease == nil {
		if err := a.checkpointControllerLease(ctx, session, state, expectedControllerLease(current, a.config), false); err != nil {
			return err
		}
	}
	receipt := *state.ControllerLease
	if receipt.DeleteRequested || receipt.Released {
		return ErrUnknown
	}
	leases := a.kube.CoordinationV1().Leases(receipt.Namespace)
	actual, err := leases.Get(ctx, receipt.Name, metav1.GetOptions{})
	if err == nil {
		return a.acceptControllerLease(ctx, session, state, actual)
	}
	if !apierrors.IsNotFound(err) {
		return ErrRetryable
	}
	if receipt.UID != "" {
		return ErrUnknown
	}
	if receipt.CreateAttempted {
		// The original API write may still arrive. Neither elapsed time nor
		// NotFound proves rejection or permits replay.
		return ErrRetryable
	}
	receipt.CreateAttempted = true
	if err := a.checkpointControllerLease(ctx, session, state, receipt, false); err != nil {
		return err
	}
	if _, _, err := controllerLeaseCurrent(ctx, session, state, false); err != nil {
		return err
	}
	actual, err = leases.Create(ctx, controllerLeaseObject(receipt), metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) || definitiveControllerNamespaceRejection(err) {
			receipt.CreateAttempted = false
			ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			if err := a.checkpointControllerLease(ack, session, state, receipt, true); err != nil {
				return err
			}
		}
		return ErrRetryable
	}
	if !controllerLeaseMatches(actual, receipt) || actual.DeletionTimestamp != nil {
		return ErrUnknown
	}
	receipt.UID, receipt.ResourceVersion = actual.UID, actual.ResourceVersion
	ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := a.checkpointControllerLease(ack, session, state, receipt, true); err != nil {
		return err
	}
	return a.verifyControllerLease(ctx, session, state, false)
}

func (a *controllerExecutionAdapter) acceptControllerLease(ctx context.Context, session *Session, state *pipelineState, actual *coordinationv1.Lease) error {
	receipt := *state.ControllerLease
	if !controllerLeaseMatches(actual, receipt) || actual.DeletionTimestamp != nil {
		if receipt.UID == "" && !receipt.CreateAttempted {
			return ErrRetryable
		}
		return ErrUnknown
	}
	if receipt.UID != "" {
		if receipt.ResourceVersion != actual.ResourceVersion {
			return ErrUnknown
		}
		return nil
	}
	if !receipt.CreateAttempted {
		return ErrUnknown
	}
	receipt.UID, receipt.ResourceVersion = actual.UID, actual.ResourceVersion
	return a.checkpointControllerLease(ctx, session, state, receipt, false)
}

func (a *controllerExecutionAdapter) verifyControllerLease(ctx context.Context, session *Session, state *pipelineState, cleanup bool) error {
	if !a.selection.ClusterExclusive {
		if state.ControllerLease != nil || (state.Selection != nil && state.Selection.ClusterExclusive) {
			return ErrInvalid
		}
		return nil
	}
	current, _, err := controllerLeaseCurrent(ctx, session, state, cleanup)
	if err != nil {
		return err
	}
	if err := a.validateControllerLease(current, state); err != nil {
		return err
	}
	receipt := state.ControllerLease
	if receipt == nil || receipt.UID == "" || receipt.DeleteRequested || receipt.Released {
		return ErrUnknown
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	actual, err := a.kube.CoordinationV1().Leases(receipt.Namespace).Get(ctx, receipt.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return ErrUnknown
	}
	if err != nil {
		return ErrRetryable
	}
	if !controllerLeaseMatches(actual, *receipt) || actual.DeletionTimestamp != nil || actual.ResourceVersion != receipt.ResourceVersion {
		return ErrUnknown
	}
	return nil
}
