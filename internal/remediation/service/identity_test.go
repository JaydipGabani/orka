package service

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/orka-agents/orka/internal/store"
)

func TestQueuedAuthorizationRevocationPreventsExecution(t *testing.T) {
	var ran, cleaned atomic.Bool
	service, _ := testService(t, processorFunc{
		run:    func(context.Context, *Session) error { ran.Store(true); return nil },
		cancel: func(context.Context, *Session) error { cleaned.Store(true); return nil },
	})
	allowed := true
	service.config.Authorize = func(context.Context, string, string, ActorIdentity) error {
		if !allowed {
			return ErrPolicy
		}
		return nil
	}
	run, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	allowed = false
	if err := service.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, err := service.Get(t.Context(), "testing", run.ID)
	if err != nil || ran.Load() || !cleaned.Load() || status.Phase != store.RemediationPhaseCancelled {
		t.Fatal("revoked caller authority was used for new execution", status, err)
	}
}
