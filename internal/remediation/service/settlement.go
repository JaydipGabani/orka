package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	maxSettlementAttempts    = store.RemediationMaxCleanupAttempts
	maxSettlementDuration    = store.RemediationMaxCleanupDuration
	quarantinedCleanupReason = store.RemediationReasonCleanupQuarantined
)

type settlement = store.RemediationCleanup

func (s *Service) settle(ctx context.Context, session *Session, current *store.RemediationRun, runErr error) error {
	var pending settlement
	if current.Cleanup != nil {
		pending = *current.Cleanup
	} else {
		var legacy struct {
			Settlement settlement `json:"settlement"`
		}
		if json.Unmarshal(current.StateJSON, &legacy) != nil {
			return ErrInvalid
		}
		pending = legacy.Settlement
	}
	if pending.StartedAt.IsZero() {
		pending.StartedAt = time.Now().UTC()
	}
	switch {
	case current.CancelRequested:
		pending.Phase, pending.Reason = store.RemediationPhaseCancelled, ""
	case !time.Now().Before(current.Deadline):
		pending.Phase, pending.Reason = store.RemediationPhaseTimedOut, "deadline-exceeded"
	case pending.Phase == "":
		pending.Phase, pending.Reason = failureState(runErr)
	}
	// Persist the wall-clock budget before calling cleanup. These bounded
	// columns remain writable even when ordinary JSON/artifact quota is full.
	current, err := session.store.BeginRemediationCleanupAttempt(ctx, current.Namespace, current.ID, session.owner, session.epoch,
		current.Revision, pending, time.Now().UTC())
	if err != nil {
		return err
	}
	if current.Reason == quarantinedCleanupReason {
		log.FromContext(ctx).Error(ErrUnknown, "remediation cleanup quarantined; operator reconciliation required",
			"namespace", current.Namespace, "runID", current.ID)
		return nil
	}
	pending = *current.Cleanup
	remaining := time.Until(pending.StartedAt.Add(maxSettlementDuration))
	if pending.RecoveryEpoch == session.epoch {
		remaining = 30 * time.Second
	}
	cleanup, cancel := context.WithTimeout(ctx, min(30*time.Second, remaining))
	cleanupErr := s.config.Processor.Cancel(cleanup, session)
	cancel()
	if ctx.Err() != nil {
		return nil
	}
	current, err = session.Current(ctx)
	if err != nil {
		return err
	}
	switch {
	case current.CancelRequested:
		pending.Phase, pending.Reason = store.RemediationPhaseCancelled, ""
	case !time.Now().Before(current.Deadline):
		pending.Phase, pending.Reason = store.RemediationPhaseTimedOut, "deadline-exceeded"
	}
	if cleanupErr != nil && !errors.Is(cleanupErr, ErrCleanupPending) {
		pending.Attempts++
	}
	// Cleanup may checkpoint new effect identities. Merge only into that fresh
	// revision so a concurrent cancellation or receipt cannot be overwritten.
	_, err = session.store.UpdateRemediationCleanup(ctx, current.Namespace, current.ID, session.owner, session.epoch,
		current.Revision, pending, cleanupErr == nil, time.Now().UTC())
	return err
}
