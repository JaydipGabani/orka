package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
)

func TestPipelineRestartAfterAcceptedModelDoesNotReplay(t *testing.T) {
	target := source.Target{
		Repository: source.Repository{URL: "https://github.com/example/project", Owner: "example", Name: "project", DefaultBranch: "main"},
		Ref:        "v1.2.3", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40),
	}
	models := &pipelineModels{t: t, target: target, tasks: make(map[string]modelagent.Result), pauseFirst: make(chan struct{})}
	executor := &pipelineEnvironment{selection: AdapterSelection{
		Name: "synthetic", Capabilities: []string{environment.HTTPExact},
		Binding:  environment.Bind{SourceTarget: environment.SourceTarget{Repository: target.Repository.URL, Commit: target.Commit}},
		Original: environment.Subject{Role: environment.PublishedOriginal, Image: "example.invalid/subject@sha256:" + strings.Repeat("1", 64)},
	}}
	pipeline := &Pipeline{Source: pipelineSource{target: target}, Environments: executor,
		Agents: func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
			return pipelineModel{owner: models, accepted: accepted}
		}}
	first, _ := testService(t, pipeline)
	request := requestFixture()
	request.Report = json.RawMessage(`{"title":"Synthetic bug","problem":"Invalid requests are accepted","versions":["1.2.3"],"restricted":false}`)
	run, _, err := first.Submit(t.Context(), "testing", "caller", request)
	if err != nil {
		t.Fatal(err)
	}
	server, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- first.RunOnce(server) }()
	select {
	case <-models.pauseFirst:
	case <-time.After(5 * time.Second):
		t.Fatal("model acceptance was not persisted")
	}
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server shutdown did not stop the active wait")
	}
	time.Sleep(first.config.Lease + 20*time.Millisecond)
	second, err := New(t.Context(), first.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, err := second.Get(t.Context(), "testing", run.ID)
	if err != nil || status.Phase != store.RemediationPhaseSucceeded || models.calls != 5 {
		t.Fatalf("restart duplicated accepted work or lost progress: %+v calls=%d err=%v", status, models.calls, err)
	}
}

func TestServiceSlowRunDoesNotBlockOtherSubmissions(t *testing.T) {
	started := make(chan struct{})
	service, _ := testService(t, processorFunc{run: func(ctx context.Context, session *Session) error {
		run, err := session.Current(ctx)
		if err != nil {
			return err
		}
		var request StoredRequest
		if err := json.Unmarshal(run.RequestJSON, &request); err != nil {
			return err
		}
		if request.ClientRequestID == "slow" {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
		return session.Checkpoint(ctx, store.RemediationPhaseSucceeded, "", nil, "")
	}})
	service.config.Interval = 10 * time.Millisecond
	request := requestFixture()
	request.RequestID = "slow"
	if _, _, err := service.Submit(t.Context(), "testing", "caller", request); err != nil {
		t.Fatal(err)
	}
	server, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- service.Start(server) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("scheduler did not shut down")
		}
	})
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("slow run did not start")
	}
	request.RequestID = "fast"
	request.Report = json.RawMessage(`{"title":"Independent synthetic report","problem":"A different value is accepted","restricted":false}`)
	run, _, err := service.Submit(t.Context(), "testing", "caller", request)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		status, err := service.Get(t.Context(), "testing", run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if status.Phase == store.RemediationPhaseSucceeded {
			break
		}
		select {
		case <-deadline:
			t.Fatal("one model wait starved another accepted run")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
