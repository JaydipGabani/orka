package service

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	runtimeisolation "github.com/orka-agents/orka/internal/remediation/isolation"
	"github.com/orka-agents/orka/internal/store"
	"k8s.io/apimachinery/pkg/types"
)

type controllerNamespace struct {
	Name            string    `json:"name"`
	UID             types.UID `json:"uid,omitempty"`
	IntentDigest    string    `json:"intentDigest"`
	CreateAttempted bool      `json:"createAttempted"`
	DeleteRequested bool      `json:"deleteRequested"`
	Deleted         bool      `json:"deleted"`
}

type controllerOperation struct {
	RunID       string                     `json:"runID"`
	InputDigest string                     `json:"inputDigest"`
	OperationID string                     `json:"operationID"`
	State       controllerlab.State        `json:"state"`
	Control     *controllerNamespace       `json:"control,omitempty"`
	Isolation   *runtimeisolation.Receipt  `json:"isolation,omitempty"`
	Proof       *store.RemediationArtifact `json:"proof,omitempty"`
	NodeUID     types.UID                  `json:"nodeUID,omitempty"`
}

func cloneControllerOperation(value *controllerOperation) controllerOperation {
	raw, _ := json.Marshal(value)
	var result controllerOperation
	_ = json.Unmarshal(raw, &result)
	return result
}

func pipelineOperation(state *pipelineState, id string) *executionOperation {
	if state.Original.ID == id {
		return &state.Original
	}
	if state.Control.ID == id {
		return &state.Control
	}
	for i := range state.Attempts {
		if state.Attempts[i].Operation.ID == id {
			return &state.Attempts[i].Operation
		}
	}
	return nil
}

// Use the revision read alongside the nested controller state, not a later
// independently refreshed revision: that is the CAS boundary for both engines.
func checkpointControllerOperation(ctx context.Context, session *Session, state *pipelineState, operation *executionOperation, expected, next controllerOperation, cleanup bool) error {
	current, err := controllerAcceptance(ctx, session, operation, cleanup)
	if err != nil {
		return err
	}
	if next.RunID != current.ID || next.InputDigest != current.InputDigest || next.OperationID != operation.ID {
		return ErrInvalid
	}
	var durable pipelineState
	if json.Unmarshal(current.StateJSON, &durable) != nil {
		return ErrInvalid
	}
	stored := pipelineOperation(&durable, operation.ID)
	if stored == nil || stored.Controller == nil || stored.Role != operation.Role ||
		!reflect.DeepEqual(stored.Subject, operation.Subject) || !reflect.DeepEqual(stored.Build, operation.Build) {
		return ErrUnknown
	}
	if reflect.DeepEqual(*stored.Controller, next) {
		operation.Controller = &next
		return nil
	}
	if !reflect.DeepEqual(*stored.Controller, expected) {
		return ErrUnknown
	}
	previous := operation.Controller
	operation.Controller = &next
	raw, err := marshalControllerPipeline(current.StateJSON, state)
	if err != nil {
		operation.Controller = previous
		return err
	}
	_, err = session.store.UpdateRemediationRun(ctx, current.Namespace, current.ID, session.owner, session.epoch, current.Revision,
		store.RemediationUpdate{Phase: current.Phase, Reason: current.Reason, StateJSON: raw}, time.Now().UTC())
	if err != nil {
		operation.Controller = previous
	}
	return err
}

func marshalControllerPipeline(existing json.RawMessage, state *pipelineState) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(existing, &fields) != nil {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, ErrInvalid
	}
	var changed map[string]json.RawMessage
	if json.Unmarshal(raw, &changed) != nil {
		return nil, ErrInvalid
	}
	maps.Copy(fields, changed)
	raw, err = json.Marshal(fields)
	if err != nil || len(raw) > store.RemediationMaxStateBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}

func controllerAcceptance(ctx context.Context, session *Session, operation *executionOperation, cleanup bool) (*store.RemediationRun, error) {
	current, err := session.Current(ctx)
	if err != nil {
		return nil, err
	}
	if operation.Controller == nil || operation.Controller.RunID != current.ID ||
		operation.Controller.OperationID != operation.ID || operation.Controller.InputDigest != current.InputDigest {
		return nil, ErrInvalid
	}
	if !cleanup && (current.CancelRequested || !time.Now().Before(current.Deadline) ||
		current.Phase == store.RemediationPhaseCancelling) {
		return nil, context.Canceled
	}
	return current, nil
}

func controllerHooks(session *Session, state *pipelineState, operation *executionOperation, cleanup bool) controllerlab.Hooks {
	return controllerlab.Hooks{
		Acceptance: func(ctx context.Context, mutation controllerlab.Mutation) error {
			current, err := controllerAcceptance(ctx, session, operation, cleanup)
			if err != nil {
				return err
			}
			if mutation.RunID != current.ID || mutation.OperationID != operation.ID ||
				(operation.Controller.State.Version != 0 && mutation.OperationDigest != operation.Controller.State.OperationDigest) ||
				(cleanup && mutation.Action != "delete" && mutation.Action != "remove-finalizer") {
				return ErrInvalid
			}
			if mutation.Action == "remove-finalizer" && !controllerFinalizerRemovalAuthorized(operation.Controller.State, mutation.Object) {
				return ErrInvalid
			}
			return nil
		},
		PersistState: func(ctx context.Context, expectedRevision uint64, next controllerlab.State) error {
			expected := cloneControllerOperation(operation.Controller)
			if expected.State.Revision != expectedRevision || next.Revision != expectedRevision+1 ||
				next.RunID != expected.RunID || next.OperationID != expected.OperationID {
				return ErrUnknown
			}
			updated := cloneControllerOperation(&expected)
			updated.State = next
			return checkpointControllerOperation(ctx, session, state, operation, expected, updated, cleanup)
		},
	}
}
