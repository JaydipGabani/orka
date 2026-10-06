package service

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	runtimeisolation "github.com/orka-agents/orka/internal/remediation/isolation"
	"github.com/orka-agents/orka/internal/store"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func controllerLeaseOperations(state *pipelineState) []*executionOperation {
	operations := make([]*executionOperation, 0, 2+len(state.Attempts))
	operations = append(operations, &state.Original, &state.Control)
	for i := range state.Attempts {
		operations = append(operations, &state.Attempts[i].Operation)
	}
	return operations
}

func controllerLeaseOperationsClean(run *store.RemediationRun, state *pipelineState) bool {
	for _, operation := range controllerLeaseOperations(state) {
		if !controllerLeaseOperationClean(run, operation) {
			return false
		}
	}
	return true
}

func controllerLeaseOperationClean(run *store.RemediationRun, operation *executionOperation) bool {
	if !operation.Cleaned && (operation.Intent || operation.BuildIntent || operation.Controller != nil) {
		return false
	}
	controller := operation.Controller
	if controller == nil {
		return !operation.Intent && operation.Observation == nil && operation.Receipt == nil
	}
	if controller.RunID != run.ID || controller.InputDigest != run.InputDigest || controller.OperationID != operation.ID ||
		!controllerNamespaceClean(controller) {
		return false
	}
	observed := controller.State
	if observed.Version == 0 {
		return reflect.DeepEqual(observed, controllerlab.State{}) &&
			controller.Control == nil && controller.Isolation == nil && controller.Proof == nil && operation.Observation == nil
	}
	if observed.Version != controllerlab.Version || observed.Revision == 0 || observed.Phase != controllerlab.Complete || observed.Intent != nil ||
		observed.RunID != run.ID || observed.OperationID != operation.ID {
		return false
	}
	for _, receipt := range observed.Receipts {
		if receipt.Object.UID == "" || !receipt.DeleteRequested || !receipt.Deleted {
			return false
		}
	}
	return controllerLeaseProofClean(controller)
}

func controllerLeaseProofClean(controller *controllerOperation) bool {
	if controller.Proof != nil && (controller.Isolation == nil || controller.Control == nil) {
		return false
	}
	if proof := controller.Isolation; proof != nil {
		if !proof.CleanupComplete || proof.Phase != runtimeisolation.Complete ||
			proof.RunID != controller.RunID || proof.OperationID != "controller-"+controller.OperationID || controller.Control == nil {
			return false
		}
		for _, object := range proof.Objects {
			if !object.Deleted || (object.CreateAttempted && (object.UID == "" || !object.DeleteRequested)) {
				return false
			}
		}
	}
	return true
}

// Call before marking terminal success, and after failed/cancelled controller
// cleanup. A released tombstone remains in the private run state: it never
// authorizes reacquisition, and retries never inspect or delete a later holder.
func (p *Pipeline) releaseControllerLease(ctx context.Context, session *Session, state *pipelineState) error {
	if state.ControllerLease == nil {
		if state.Selection != nil && state.Selection.ClusterExclusive {
			for _, operation := range controllerLeaseOperations(state) {
				if operation.Controller != nil || operation.Intent {
					return ErrUnknown
				}
			}
		}
		return nil
	}
	current, durable, err := controllerLeaseCurrent(ctx, session, state, true)
	if err != nil {
		return err
	}
	if !controllerLeaseOperationsClean(current, &durable) || durable.Selection == nil {
		return ErrUnknown
	}
	for _, operation := range controllerLeaseOperations(&durable) {
		if operation.BuildNoEffect == nil {
			continue
		}
		checks, err := loadExecutionPlan(ctx, session, durable.Checks)
		if err != nil {
			return err
		}
		plan, err := checks.buildPlan()
		if err != nil {
			return err
		}
		if err := validateBuildNoEffect(current, plan, &durable, operation); err != nil {
			return err
		}
	}
	var policy Policy
	if json.Unmarshal(current.PolicyJSON, &policy) != nil || Digest(current.PolicyJSON) != current.PolicyDigest {
		return ErrInvalid
	}
	execution, err := p.cleanupExecutionAdapter(ctx, policy, *durable.Selection)
	if err != nil {
		return err
	}
	adapter, ok := execution.(*controllerExecutionAdapter)
	if !ok {
		return ErrInvalid
	}
	if err := adapter.validateControllerLeasePolicy(current, &durable); err != nil {
		return err
	}
	return adapter.releaseControllerLease(ctx, session, state)
}

func (a *controllerExecutionAdapter) releaseControllerLease(ctx context.Context, session *Session, state *pipelineState) error {
	receipt := *state.ControllerLease
	if receipt.Released {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := a.verifyControllerCluster(ctx); err != nil {
		return err
	}
	if !receipt.CreateAttempted {
		receipt.Released = true
		return a.checkpointControllerLease(ctx, session, state, receipt, true)
	}
	leases := a.kube.CoordinationV1().Leases(receipt.Namespace)
	actual, err := leases.Get(ctx, receipt.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if receipt.UID == "" || !receipt.DeleteRequested {
			return ErrUnknown
		}
		receipt.Released = true
		return a.checkpointControllerLease(ctx, session, state, receipt, true)
	}
	if err != nil {
		return ErrRetryable
	}
	if controllerLeaseSuperseded(receipt, actual.UID) {
		receipt.Released = true
		return a.checkpointControllerLease(ctx, session, state, receipt, true)
	}
	if !controllerLeaseMatches(actual, receipt) {
		return ErrUnknown
	}
	if actual.DeletionTimestamp != nil {
		if !receipt.DeleteRequested {
			return ErrUnknown
		}
		return ErrRetryable
	}
	if receipt.UID == "" {
		receipt.UID, receipt.ResourceVersion = actual.UID, actual.ResourceVersion
		if err := a.checkpointControllerLease(ctx, session, state, receipt, true); err != nil {
			return err
		}
	}
	if receipt.ResourceVersion != actual.ResourceVersion {
		return ErrUnknown
	}
	if !receipt.DeleteRequested {
		receipt.DeleteRequested = true
		if err := a.checkpointControllerLease(ctx, session, state, receipt, true); err != nil {
			return err
		}
	}
	if _, _, err := controllerLeaseCurrent(ctx, session, state, true); err != nil {
		return err
	}
	err = leases.Delete(ctx, receipt.Name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &receipt.UID, ResourceVersion: &receipt.ResourceVersion},
	})
	if apierrors.IsConflict(err) {
		return ErrUnknown
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return ErrRetryable
	}
	if err == nil && !receipt.DeleteAccepted {
		receipt.DeleteAccepted = true
		if err := a.checkpointControllerLease(ctx, session, state, receipt, true); err != nil {
			return err
		}
	}
	// A delete can still be finalizing. Observe its absence or a successor UID
	// after the durable delete intent, without touching that later holder.
	actual, err = leases.Get(ctx, receipt.Name, metav1.GetOptions{})
	deleted := apierrors.IsNotFound(err) || (err == nil && controllerLeaseSuperseded(receipt, actual.UID))
	if !deleted {
		return ErrRetryable
	}
	receipt.Released = true
	return a.checkpointControllerLease(ctx, session, state, receipt, true)
}

// DeleteRequested is durable only after every owned operation is clean.
// A successor at this exact key proves the known UID is gone even when
// the delete acknowledgement was lost before it could be checkpointed.
func controllerLeaseSuperseded(receipt controllerClusterLease, observedUID types.UID) bool {
	return receipt.DeleteRequested && receipt.UID != "" && observedUID != receipt.UID
}
