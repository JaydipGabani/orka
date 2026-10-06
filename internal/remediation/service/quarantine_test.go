package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
)

func TestCleanupQuarantineStopsRepeatedEffectsAndDoesNotClaimDrain(t *testing.T) {
	effects := 0
	service, storage := testService(t, processorFunc{
		run:    func(context.Context, *Session) error { effects++; return errors.New("failed execution") },
		cancel: func(context.Context, *Session) error { effects++; return errors.New("unsettled cleanup") },
	})
	run, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := storage.ClaimNextRemediationRun(t.Context(), "testing", service.owner, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(map[string]any{"version": Version, "settlement": settlement{
		Phase: store.RemediationPhaseFailed, Reason: "execution-failed", Attempts: maxSettlementAttempts,
		StartedAt: time.Now().Add(-time.Minute),
	}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := storage.UpdateRemediationRun(t.Context(), "testing", run.ID, service.owner, claimed.ClaimEpoch, claimed.Revision,
		store.RemediationUpdate{Phase: store.RemediationPhaseCancelling, StateJSON: state}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.process(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	status, err := service.Get(t.Context(), "testing", run.ID)
	if err != nil || status.Reason != quarantinedCleanupReason || status.Phase != store.RemediationPhaseCancelling || effects != 0 {
		t.Fatal("quarantine re-executed effects or claimed cancellation", status, effects, err)
	}
	if err := service.RunOnce(t.Context()); err != nil || effects != 0 {
		t.Fatal("quarantined work automatically retried", err)
	}
	drain, err := service.Drain(t.Context())
	if err != nil || drain.Complete || drain.Quarantined != 1 {
		t.Fatal("quarantined resources were treated as drained", drain, err)
	}
}
