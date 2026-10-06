package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
)

func TestFailedWorkRetriesOnlyCleanup(t *testing.T) {
	runs, cleanups := 0, 0
	service, _ := testService(t, processorFunc{
		run: func(context.Context, *Session) error { runs++; return errors.New("synthetic failure") },
		cancel: func(context.Context, *Session) error {
			cleanups++
			if cleanups == 1 {
				return errors.New("synthetic cleanup pending")
			}
			return nil
		},
	})
	run, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending, err := service.Get(t.Context(), "testing", run.ID)
	if err != nil || pending.Phase != store.RemediationPhaseCancelling || pending.CancelRequested {
		t.Fatal("failed work did not record a non-user cleanup settlement", pending, err)
	}
	time.Sleep(service.config.Lease + 20*time.Millisecond)
	if err := service.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	completed, err := service.Get(t.Context(), "testing", run.ID)
	if err != nil || completed.Phase != store.RemediationPhaseFailed || runs != 1 || cleanups != 2 {
		t.Fatal("settlement replayed pipeline work or lost the failure", completed, runs, cleanups, err)
	}
}
