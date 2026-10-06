package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/store"
)

func hasUnsubmittedModelProof(operation modelOperation, requireExisting bool, result modelagent.Result, err error) bool {
	return errors.Is(err, modelagent.ErrNotSubmitted) && operation.UID == "" && !requireExisting &&
		result.TaskUID == "" && result.Output == "" && (result.TaskName == "" || result.TaskName == operation.Name)
}

// Only a fresh, synchronous Generate returning ErrNotSubmitted authorizes this
// checkpoint. A missing Task cannot prove no effect after an uncertain Create.
func clearUnsubmittedModelIntent(ctx context.Context, session *Session, state *pipelineState, key string, expected modelOperation) error {
	if !expected.Intent || expected.Name == "" || expected.UID != "" || expected.Output != nil || expected.Retired {
		return ErrUnknown
	}
	checkpoint, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	next := expected
	next.Intent = false
	for range 3 {
		current, err := session.Current(checkpoint)
		if err != nil {
			return modelCleanupStoreFailure(err)
		}
		var durable pipelineState
		if json.Unmarshal(current.StateJSON, &durable) != nil || durable.Version != Version {
			return ErrInvalid
		}
		stored, found := durable.Models[key]
		if !found || (!reflect.DeepEqual(stored, expected) && !reflect.DeepEqual(stored, next)) {
			return ErrUnknown
		}
		// An acceptance callback may have saved its immutable receipt before
		// failing to checkpoint the UID. Never discard that evidence.
		if _, _, err := session.Read(checkpoint, modelReceiptName(expected.Name)); !errors.Is(err, store.ErrNotFound) {
			if err == nil {
				return ErrUnknown
			}
			return modelCleanupStoreFailure(err)
		}
		if reflect.DeepEqual(stored, next) {
			*state = durable
			return nil
		}
		durable.Models[key] = next
		raw, err := withoutModelIntent(current.StateJSON, key)
		if err != nil {
			return err
		}
		_, err = session.store.UpdateRemediationRun(checkpoint, current.Namespace, current.ID, session.owner, session.epoch, current.Revision,
			store.RemediationUpdate{Phase: current.Phase, Reason: current.Reason, StateJSON: raw, ApprovalDigest: current.ApprovalDigest}, time.Now().UTC())
		if err == nil {
			*state = durable
			return nil
		}
		if !errors.Is(err, store.ErrConflict) {
			return modelCleanupStoreFailure(err)
		}
	}
	return ErrRetryable
}

func withoutModelIntent(existing json.RawMessage, key string) (json.RawMessage, error) {
	var fields, models, operation map[string]json.RawMessage
	if json.Unmarshal(existing, &fields) != nil || fields == nil ||
		json.Unmarshal(fields["models"], &models) != nil || models == nil ||
		json.Unmarshal(models[key], &operation) != nil || operation == nil {
		return nil, ErrInvalid
	}
	// Change only this bit; opaque state and resource fences must survive a
	// cancellation checkpoint, including fields unknown to this worker.
	operation["intent"] = json.RawMessage("false")
	var err error
	models[key], err = json.Marshal(operation)
	if err != nil {
		return nil, ErrInvalid
	}
	fields["models"], err = json.Marshal(models)
	if err != nil {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(fields)
	if err != nil || len(raw) > store.RemediationMaxStateBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}
