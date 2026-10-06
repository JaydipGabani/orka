package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/orka-agents/orka/internal/store"
)

type Session struct {
	store store.RemediationRunStore
	run   *store.RemediationRun
	owner string
	epoch uint64
}

func (s *Session) Current(ctx context.Context) (*store.RemediationRun, error) {
	run, err := s.store.GetRemediationRun(ctx, s.run.Namespace, s.run.ID)
	if err != nil {
		return nil, err
	}
	if run.ClaimOwner != s.owner || run.ClaimEpoch != s.epoch || !time.Now().Before(run.ClaimUntil) {
		return nil, ErrClaimLost
	}
	return run, nil
}

func (s *Session) Checkpoint(ctx context.Context, phase, reason string, state json.RawMessage, approval string) error {
	current, err := s.Current(ctx)
	if err != nil {
		return err
	}
	_, err = s.store.UpdateRemediationRun(ctx, current.Namespace, current.ID, s.owner, s.epoch, current.Revision,
		store.RemediationUpdate{Phase: phase, Reason: reason, StateJSON: state, ApprovalDigest: approval}, time.Now().UTC())
	return err
}

func (s *Session) Put(ctx context.Context, name, mediaType string, data []byte) (*store.RemediationArtifact, error) {
	return s.store.PutRemediationArtifact(ctx, s.run.Namespace, s.run.ID, s.owner, s.epoch, name, mediaType, data, time.Now().UTC())
}

func (s *Session) Read(ctx context.Context, name string) (*store.RemediationArtifact, []byte, error) {
	return s.store.GetRemediationArtifact(ctx, s.run.Namespace, s.run.ID, name)
}
