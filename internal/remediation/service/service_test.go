package service

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
)

type processorFunc struct {
	run    func(context.Context, *Session) error
	cancel func(context.Context, *Session) error
}

func (p processorFunc) Run(ctx context.Context, session *Session) error {
	if p.run != nil {
		return p.run(ctx, session)
	}
	return session.Checkpoint(ctx, store.RemediationPhaseSucceeded, "", json.RawMessage(`{"complete":true}`), "")
}

func (p processorFunc) Cancel(ctx context.Context, session *Session) error {
	if p.cancel != nil {
		return p.cancel(ctx, session)
	}
	return nil
}

func testService(t *testing.T, processor Processor) (*Service, *sqlite.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "service.db")
	database, err := sqlite.NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	storage := sqlite.NewStore(database, path)
	cipher, err := sqlite.NewAgentExecutionSnapshotCipher([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAgentExecutionSnapshotCipher(cipher); err != nil {
		t.Fatal(err)
	}
	config := Config{Namespace: "testing", Store: storage, Processor: processor, Lease: 300 * time.Millisecond,
		Policies: []Policy{{
			Version: 1, Name: "approved", Namespace: "testing", AgentName: "proposer",
			Repositories: []string{"https://github.com/example/project"},
			Adapters: []AdapterPolicy{{
				Name: "synthetic", Kind: "http-workload", Repositories: []string{"https://github.com/example/project"},
				Configuration: json.RawMessage(`{"fixture":true}`),
			}},
			MaxDurationSeconds: 120, MaxCandidates: 2, MaxModelCalls: 8,
		}},
	}
	service, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	return service, storage
}

func requestFixture() Request {
	return Request{
		RequestID: "client-request", Mode: Generate,
		Report: json.RawMessage(`{"title":"Synthetic report","problem":"A synthetic value is accepted","restricted":false}`),
	}
}

func TestServiceSubmissionIdempotencyAndNamespace(t *testing.T) {
	service, _ := testService(t, processorFunc{})
	original, created, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	if err != nil || !created || original.Phase != store.RemediationPhaseQueued {
		t.Fatal(original, created, err)
	}
	again, created, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	if err != nil || created || again.ID != original.ID {
		t.Fatal("exact request was not idempotent", again, created, err)
	}
	if _, _, err := service.Submit(t.Context(), "testing", "different-caller", requestFixture()); !errors.Is(err, store.ErrConflict) {
		t.Fatal("another caller started parallel work on the same source", err)
	}
	different := requestFixture()
	different.Report = json.RawMessage(`{"title":"Another synthetic report","problem":"Another value is accepted","restricted":false}`)
	other, otherCreated, err := service.Submit(t.Context(), "testing", "different-caller", different)
	if err != nil || !otherCreated || other.ID == original.ID {
		t.Fatal("client keys were not scoped by caller identity", err)
	}
	if _, err := service.Get(t.Context(), "foreign", original.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("cross-namespace read succeeded", err)
	}
}

func TestServiceSurvivesSubmissionClientDisconnect(t *testing.T) {
	service, _ := testService(t, processorFunc{})
	caller, cancel := context.WithCancel(t.Context())
	run, _, err := service.Submit(caller, "testing", "caller", requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := service.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, err := service.Get(t.Context(), "testing", run.ID)
	if err != nil || status.Phase != store.RemediationPhaseSucceeded {
		t.Fatal("client disconnect stopped durable processing", status, err)
	}
	if err := service.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestServiceCancellationStopsWorkAndSettlesCleanup(t *testing.T) {
	started := make(chan struct{})
	var cleaned atomic.Bool
	service, _ := testService(t, processorFunc{
		run: func(ctx context.Context, _ *Session) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
		cancel: func(context.Context, *Session) error {
			cleaned.Store(true)
			return nil
		},
	})
	run, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- service.RunOnce(t.Context()) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start")
	}
	if _, err := service.Cancel(t.Context(), "testing", run.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker ignored cancellation")
	}
	status, err := service.Get(t.Context(), "testing", run.ID)
	if err != nil || status.Phase != store.RemediationPhaseCancelled || !cleaned.Load() {
		t.Fatal("cancellation did not settle resources", status, err)
	}
}

func TestServiceApprovalRequiresExactPlan(t *testing.T) {
	plan := Digest([]byte("frozen plan"))
	service, _ := testService(t, processorFunc{
		run: func(ctx context.Context, session *Session) error {
			run, err := session.Current(ctx)
			if err != nil {
				return err
			}
			if run.ApprovedDigest != plan {
				if err := session.Checkpoint(ctx, store.RemediationPhaseNeedsApproval, "confirm-plan", nil, plan); err != nil {
					return err
				}
				return ErrAwaitApproval
			}
			return session.Checkpoint(ctx, store.RemediationPhaseSucceeded, "", nil, "")
		},
	})
	run, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(t.Context(), "testing", run.ID, Digest([]byte("wrong")), "caller"); err == nil {
		t.Fatal("wrong plan was approved")
	}
	if _, err := service.Approve(t.Context(), "testing", run.ID, plan, "caller"); err != nil {
		t.Fatal(err)
	}
	if err := service.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, err := service.Get(t.Context(), "testing", run.ID)
	if err != nil || status.Phase != store.RemediationPhaseSucceeded {
		t.Fatal(status, err)
	}
}

func TestDecodeRequestRejectsUnsafeShapes(t *testing.T) {
	for _, raw := range []string{
		`{"requestID":"r","requestId":"s","incident":"123"}`,
		`{"requestID":"r","incident":"123","driver":"/bin/sh"}`,
		`{"requestID":"r","incident":"123","report":{}}`,
		`{"requestID":"r","mode":"verify","incident":"123"}`,
		`{"requestID":"r","incident":"123","patch":"private-marker"}`,
		`{"requestID":"r","incident":"https://unexpected.example/123"}`,
	} {
		if _, err := DecodeRequest([]byte(raw)); err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatal("unsafe request accepted or reflected", err)
		}

	}
}
