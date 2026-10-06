package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/orka-agents/orka/internal/store"
)

func TestSettlementPreservesCleanupCheckpoints(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		phase string
	}{
		{"complete", nil, store.RemediationPhaseFailed},
		{"pending", errors.New("cleanup still pending"), store.RemediationPhaseCancelling},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, storage := testService(t, processorFunc{
				run: func(context.Context, *Session) error { return errors.New("execution failed") },
				cancel: func(ctx context.Context, session *Session) error {
					if err := session.Checkpoint(ctx, store.RemediationPhaseCancelling, "",
						json.RawMessage(`{"stage":"cleanup-progress","resourceUID":"synthetic-exact-uid","resourceDeleted":true}`), ""); err != nil {
						return err
					}
					return test.err
				},
			})
			status, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
			if err != nil {
				t.Fatal(err)
			}
			if err := service.RunOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			run, err := storage.GetRemediationRun(t.Context(), "testing", status.ID)
			if err != nil {
				t.Fatal(err)
			}
			var state struct {
				Stage           string `json:"stage"`
				ResourceUID     string `json:"resourceUID"`
				ResourceDeleted bool   `json:"resourceDeleted"`
			}
			if err := json.Unmarshal(run.StateJSON, &state); err != nil {
				t.Fatal(err)
			}
			if run.Phase != test.phase || state.Stage != "cleanup-progress" ||
				state.ResourceUID != "synthetic-exact-uid" || !state.ResourceDeleted {
				t.Fatal("settlement overwrote newly recorded cleanup state")
			}
			if test.err == nil && run.Cleanup != nil {
				t.Fatal("completed cleanup retained a retry marker")
			}
			if test.err != nil && (run.Cleanup == nil || run.Cleanup.Attempts != 1) {
				t.Fatal("pending cleanup lost its bounded retry marker")
			}
		})
	}
}
