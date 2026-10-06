package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/stretchr/testify/require"
)

type dependencyModelClient struct {
	disclosureModelClient
	snapshotError error
	generateError error
	acceptedFirst bool
	requests      *[]modelagent.Request
}

func (c dependencyModelClient) Snapshot(ctx context.Context) (modelagent.PlanIdentity, error) {
	if c.snapshotError != nil {
		return modelagent.PlanIdentity{}, c.snapshotError
	}
	return c.disclosureModelClient.Snapshot(ctx)
}

func (c dependencyModelClient) Generate(ctx context.Context, request modelagent.Request) (modelagent.Result, error) {
	*c.requests = append(*c.requests, request)
	if c.generateError != nil {
		if c.acceptedFirst {
			if err := c.accepted(ctx, modelagent.Result{TaskName: request.TaskName, TaskUID: "synthetic-task-uid"}); err != nil {
				return modelagent.Result{}, err
			}
		}
		return modelagent.Result{}, c.generateError
	}
	return c.disclosureModelClient.Generate(ctx, request)
}

func TestControllerModelDependencyRetryPreservesSubmissionFences(t *testing.T) {
	for _, tc := range []struct {
		name            string
		snapshotError   error
		generateError   error
		accepted        bool
		requireExisting bool
	}{
		{name: "snapshot", snapshotError: fmt.Errorf("identity read: %w", modelagent.ErrDependencyUnavailable)},
		{name: "provider-snapshot", snapshotError: modelagent.ErrProviderNotReady},
		{name: "before-create", generateError: errors.Join(modelagent.ErrNotSubmitted, modelagent.ErrDependencyUnavailable)},
		{name: "after-acceptance", generateError: modelagent.ErrDependencyUnavailable, accepted: true, requireExisting: true},
		{name: "uncertain-create", generateError: modelagent.ErrDependencyUnavailable, requireExisting: true},
		{name: "provider-before-create", generateError: errors.Join(modelagent.ErrNotSubmitted, modelagent.ErrProviderNotReady)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pipeline, session, state, policy, _, calls := disclosurePipelineFixture(t, `{}`)
			snapshotError, generateError := tc.snapshotError, tc.generateError
			var requests []modelagent.Request
			pipeline.Agents = func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
				return dependencyModelClient{
					disclosureModelClient: disclosureModelClient{accepted: accepted, output: `{}`, calls: calls},
					snapshotError:         snapshotError, generateError: generateError, acceptedFirst: tc.accepted, requests: &requests,
				}
			}
			request := modelagent.Request{TaskName: "dependency-retry", Prompt: "Return one declarative check plan."}
			key := Digest([]byte(request.TaskName + "\x00" + request.Prompt))
			result, err := pipeline.generate(t.Context(), session, session.run, policy, state, request)
			require.ErrorIs(t, err, ErrRetryable)
			require.Empty(t, result.Output)
			if tc.snapshotError != nil {
				require.Empty(t, requests)
				require.Zero(t, state.ModelCalls)
				require.Empty(t, state.Models)
			} else {
				require.Equal(t, 1, state.ModelCalls)
				require.Equal(t, tc.requireExisting, state.Models[key].Intent)
			}
			if tc.accepted {
				require.Equal(t, "synthetic-task-uid", result.TaskUID)
				require.Equal(t, result.TaskUID, state.Models[key].UID)
			}
			snapshotError, generateError = nil, nil
			_, err = pipeline.generate(t.Context(), session, session.run, policy, state, request)
			require.NoError(t, err)
			retry := requests[len(requests)-1]
			require.Equal(t, tc.requireExisting, retry.RequireExisting)
			if tc.accepted {
				require.Equal(t, "synthetic-task-uid", retry.ExpectedTaskUID)
			}
			require.Equal(t, 1, state.ModelCalls, "retry must not consume another logical model operation")
			require.Equal(t, 1, *calls)
			require.True(t, state.Models[key].Retired)
		})
	}
}
