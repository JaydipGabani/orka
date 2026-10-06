package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

type retryExecutionEnvironment struct {
	pipelineEnvironment
	t                *testing.T
	buildError       error
	observeError     error
	buildSubmissions int
	buildRequests    []environment.BuildRequest
	cancelled        int
	cancelledBuilds  int
	buildAccepted    bool
}

func (e *retryExecutionEnvironment) Select(context.Context, Policy, investigate.Plan) (AdapterSelection, ExecutionAdapter, error) {
	return e.selection, e, nil
}

func (e *retryExecutionEnvironment) Resume(context.Context, Policy, AdapterSelection) (ExecutionAdapter, error) {
	return e, nil
}

func (e *retryExecutionEnvironment) Build(ctx context.Context, request environment.BuildRequest) (environment.BuildResult, error) {
	e.buildRequests = append(e.buildRequests, request)
	if !e.buildAccepted {
		require.False(e.t, request.RequireExisting)
		e.buildAccepted = true
		e.buildSubmissions++
	} else {
		require.True(e.t, request.RequireExisting, "polling must resume the accepted build, not create another")
	}
	if e.buildError != nil {
		err := e.buildError
		e.buildError = nil
		return environment.BuildResult{}, err
	}
	return e.pipelineEnvironment.Build(ctx, request)
}

func (e *retryExecutionEnvironment) Observe(ctx context.Context, receipt environment.Receipt) (environment.Observation, error) {
	if e.observeError != nil {
		err := e.observeError
		e.observeError = nil
		return environment.Observation{Receipt: receipt, Phase: environment.Cleaning}, err
	}
	return e.pipelineEnvironment.Observe(ctx, receipt)
}

func (e *retryExecutionEnvironment) Cancel(context.Context, environment.Receipt) error {
	e.cancelled++
	return nil
}

func (e *retryExecutionEnvironment) CancelBuild(context.Context, string, string, environment.Plan) error {
	e.cancelledBuilds++
	return nil
}

func TestPipelineRetryableExecutionPreservesHealthyEffects(t *testing.T) {
	for _, stage := range []string{"build", "observation-cleanup"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			target := source.Target{
				Repository: source.Repository{URL: "https://github.com/example/project", Owner: "example", Name: "project", DefaultBranch: "main"},
				Ref:        "v1.2.3", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40),
			}
			models := &pipelineModels{t: t, target: target, tasks: make(map[string]modelagent.Result)}
			adapter := &retryExecutionEnvironment{t: t, pipelineEnvironment: pipelineEnvironment{selection: AdapterSelection{
				Name: "synthetic", Capabilities: []string{environment.HTTPExact},
				Binding:  environment.Bind{SourceTarget: environment.SourceTarget{Repository: target.Repository.URL, Commit: target.Commit}},
				Original: environment.Subject{Role: environment.PublishedOriginal, Image: "example.invalid/subject@sha256:" + strings.Repeat("1", 64)},
			}}}
			failure := &environment.Error{Kind: environment.Infrastructure, Code: "durable-build-api-or-cleanup-unavailable", Retryable: true}
			if stage == "build" {
				adapter.buildError = fmt.Errorf("polling: %w", failure)
			} else {
				failure.Code = "cleanup-pending"
				adapter.observeError = failure
			}
			pipeline := &Pipeline{Source: pipelineSource{target: target}, Environments: adapter,
				Agents: func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
					return pipelineModel{owner: models, accepted: accepted}
				}}
			service, storage := testService(t, pipeline)
			request := requestFixture()
			request.Mode = Validate
			request.Report = json.RawMessage(`{"title":"Synthetic retry case","problem":"Invalid requests are accepted","versions":["1.2.3"],"restricted":false}`)
			run, _, err := service.Submit(t.Context(), "testing", "caller", request)
			require.NoError(t, err)
			require.NoError(t, service.RunOnce(t.Context()))
			current, err := storage.GetRemediationRun(t.Context(), "testing", run.ID)
			require.NoError(t, err)
			require.Equal(t, store.RemediationPhaseRunning, current.Phase)
			require.Equal(t, "waiting-for-infrastructure", current.Reason)
			require.Zero(t, adapter.cancelled)
			require.Zero(t, adapter.cancelledBuilds)
			modelCalls := models.calls
			timer := time.NewTimer(time.Until(current.ClaimUntil) + 20*time.Millisecond)
			defer timer.Stop()
			select {
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			case <-timer.C:
			}
			require.NoError(t, service.RunOnce(t.Context()))
			current, err = storage.GetRemediationRun(t.Context(), "testing", run.ID)
			require.NoError(t, err)
			require.Equal(t, store.RemediationPhaseSucceeded, current.Phase, current.Reason)
			require.Zero(t, adapter.cancelled)
			require.Zero(t, adapter.cancelledBuilds)
			require.Equal(t, 1, adapter.buildSubmissions)
			require.Equal(t, 2, adapter.starts)
			require.Equal(t, modelCalls, models.calls)
			if stage == "build" {
				require.Len(t, adapter.buildRequests, 2)
				require.True(t, adapter.buildRequests[1].RequireExisting)
			}
		})
	}
}

func TestClassifyExecutionHonorsTypedRetryability(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"cleanup", &environment.Error{Kind: environment.Infrastructure, Code: "cleanup-pending", Retryable: true}, ErrRetryable},
		{"uncertain-poll", &environment.Error{Kind: environment.Unknown, Code: "poll-unavailable", Retryable: true}, ErrRetryable},
		{"permanent-infrastructure", &environment.Error{Kind: environment.Infrastructure, Code: "failed"}, ErrUnknown},
		{"configuration", &environment.Error{Kind: environment.NeedsAdapter, Code: "unsupported"}, ErrNeedsAdapter},
		{"cancel", errors.Join(context.Canceled, &environment.Error{Kind: environment.Infrastructure, Retryable: true}), context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, classifyExecution(fmt.Errorf("wrapped: %w", tc.err)), tc.want)
		})
	}
}

type retryRetireClient struct {
	disclosureModelClient
	retireCalls *int
	failures    *[]error
}

func (c retryRetireClient) Retire(context.Context, string, string) error {
	*c.retireCalls++
	if len(*c.failures) == 0 {
		return nil
	}
	failure := (*c.failures)[0]
	*c.failures = (*c.failures)[1:]
	return failure
}

func TestPipelineRetireRetriesDependencyWithoutModelReplay(t *testing.T) {
	t.Parallel()
	pipeline, session, state, policy, _, generated := disclosurePipelineFixture(t, `{}`)
	retired := 0
	failures := []error{fmt.Errorf("retire read: %w", modelagent.ErrDependencyUnavailable), modelagent.ErrCancellationPending}
	pipeline.Agents = func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
		return retryRetireClient{
			disclosureModelClient: disclosureModelClient{accepted: accepted, output: `{}`, calls: generated},
			retireCalls:           &retired, failures: &failures,
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	request := modelagent.Request{TaskName: "retry-retirement", Prompt: "Return one bounded proposal."}
	_, err := pipeline.generate(ctx, session, session.run, policy, state, request)
	require.NoError(t, err)
	key := Digest([]byte(request.TaskName + "\x00" + request.Prompt))
	require.True(t, state.Models[key].Retired)
	require.NotNil(t, state.Models[key].Output)
	require.Equal(t, 3, retired)
	require.Equal(t, 1, *generated)
	_, err = pipeline.generate(ctx, session, session.run, policy, state, request)
	require.NoError(t, err)
	require.Equal(t, 1, *generated)
	require.Equal(t, 3, retired)
}
