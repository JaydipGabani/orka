package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

type admissionTestProcessor struct {
	processorFunc
	admission func(context.Context, string, Policy) (json.RawMessage, error)
}

func (p *admissionTestProcessor) AdmissionState(ctx context.Context, namespace string, policy Policy) (json.RawMessage, error) {
	return p.admission(ctx, namespace, policy)
}

func TestServiceSubmissionFreezesAdmissionStateAtomically(t *testing.T) {
	expected := json.RawMessage(`{"version":1,"modelIdentity":{"agentUID":"synthetic-agent-uid","providerUID":"synthetic-provider-uid"}}`)
	snapshots := 0
	processor := &admissionTestProcessor{admission: func(_ context.Context, namespace string, policy Policy) (json.RawMessage, error) {
		snapshots++
		require.Equal(t, "testing", namespace)
		require.Equal(t, "approved", policy.Name)
		return expected, nil
	}}
	service, storage := testService(t, processor)
	request := requestFixture()
	status, created, err := service.Submit(t.Context(), "testing", "caller", request)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, 1, snapshots)
	run, err := storage.GetRemediationRun(t.Context(), "testing", status.ID)
	require.NoError(t, err)
	require.Equal(t, expected, run.StateJSON)
	require.Equal(t, store.RemediationPhaseQueued, run.Phase)
	require.Empty(t, run.Intake)
	intake, err := storage.ReadRemediationIntake(t.Context(), "testing", status.ID)
	require.NoError(t, err)
	require.Equal(t, []byte(request.Report), intake)
}

func TestServiceExactReplayDoesNotRequireCurrentAdmissionDependencies(t *testing.T) {
	snapshots, authorizations := 0, 0
	frozen := json.RawMessage(`{"version":1,"modelIdentity":{"agentUID":"original-synthetic-agent"}}`)
	processor := &admissionTestProcessor{admission: func(context.Context, string, Policy) (json.RawMessage, error) {
		snapshots++
		return frozen, nil
	}}
	service, storage := testService(t, processor)
	service.config.Authorize = func(context.Context, string, string, ActorIdentity) error {
		authorizations++
		return nil
	}
	request := requestFixture()
	accepted, created, err := service.Submit(t.Context(), "testing", "caller", request)
	require.NoError(t, err)
	require.True(t, created)
	original, err := storage.GetRemediationRun(t.Context(), "testing", accepted.ID)
	require.NoError(t, err)
	processor.admission = func(context.Context, string, Policy) (json.RawMessage, error) {
		snapshots++
		return nil, fmt.Errorf("snapshot unavailable: %w", ErrRetryable)
	}
	currentPolicy := service.policies["approved"]
	currentPolicy.MaxDurationSeconds++
	service.policies["approved"] = currentPolicy
	replay, created, err := service.Submit(t.Context(), "testing", "caller", request)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, accepted, replay)
	require.Equal(t, 1, snapshots, "an exact replay must not consult a replaced or unavailable account")
	require.Equal(t, 2, authorizations, "current authorization still applies to replays")
	stored, err := storage.GetRemediationRun(t.Context(), "testing", accepted.ID)
	require.NoError(t, err)
	require.Equal(t, original, stored, "current server policy must not replace a frozen accepted policy")

	changed := request
	changed.Mode = Validate
	_, _, err = service.Submit(t.Context(), "testing", "caller", changed)
	require.ErrorIs(t, err, store.ErrDuplicateMismatch)
	changed = request
	changed.Report = json.RawMessage(`{"title":"Different synthetic input","restricted":false}`)
	_, _, err = service.Submit(t.Context(), "testing", "caller", changed)
	require.ErrorIs(t, err, store.ErrDuplicateMismatch)
	require.Equal(t, 1, snapshots)
	service.config.Authorize = func(context.Context, string, string, ActorIdentity) error { return ErrPolicy }
	_, _, err = service.Submit(t.Context(), "testing", "caller", request)
	require.ErrorIs(t, err, ErrPolicy, "replay is not an authorization bypass")
}

func TestServiceAdmissionFailureLeavesNoRunnableOrIntakeRecord(t *testing.T) {
	for _, failure := range []error{ErrPolicy, fmt.Errorf("snapshot unavailable: %w", ErrRetryable)} {
		t.Run(failure.Error(), func(t *testing.T) {
			processor := &admissionTestProcessor{admission: func(context.Context, string, Policy) (json.RawMessage, error) {
				return nil, failure
			}}
			service, storage := testService(t, processor)
			status, created, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
			require.ErrorIs(t, err, failure)
			require.False(t, created)
			require.Empty(t, status.ID)
			counts, err := storage.CountRemediationRuns(t.Context(), "testing")
			require.NoError(t, err)
			require.Zero(t, counts.Active)
			require.Zero(t, counts.RetainedIntakes)
			runs, err := storage.ListRemediationRuns(t.Context(), "testing", 100)
			require.NoError(t, err)
			require.Empty(t, runs)
			processor.admission = func(context.Context, string, Policy) (json.RawMessage, error) {
				return json.RawMessage(`{"version":1,"modelIdentity":{"agentUID":"synthetic-agent"}}`), nil
			}
			_, created, err = service.Submit(t.Context(), "testing", "caller", requestFixture())
			require.NoError(t, err, "failed admission must not leave a source reservation")
			require.True(t, created)
		})
	}
}

func TestServiceAdmissionRejectsMalformedStateAndKeepsGenericProcessorsCompatible(t *testing.T) {
	for name, state := range map[string]json.RawMessage{
		"empty": nil, "null": json.RawMessage(`null`), "array": json.RawMessage(`[]`),
		"trailing":  json.RawMessage(`{} {}`),
		"oversized": json.RawMessage(`{"padding":"` + strings.Repeat("x", store.RemediationMaxStateBytes) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			processor := &admissionTestProcessor{admission: func(context.Context, string, Policy) (json.RawMessage, error) {
				return state, nil
			}}
			service, storage := testService(t, processor)
			_, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
			require.ErrorIs(t, err, ErrPolicy)
			counts, err := storage.CountRemediationRuns(t.Context(), "testing")
			require.NoError(t, err)
			require.Zero(t, counts.Active)
			require.Zero(t, counts.RetainedIntakes)
		})
	}
	service, storage := testService(t, processorFunc{})
	status, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	require.NoError(t, err)
	run, err := storage.GetRemediationRun(t.Context(), "testing", status.ID)
	require.NoError(t, err)
	require.Equal(t, json.RawMessage(`{}`), run.StateJSON)
}

func TestServiceAdmissionFailureRechecksConcurrentExactReplay(t *testing.T) {
	processor := &admissionTestProcessor{}
	service, storage := testService(t, processor)
	config := service.config
	config.Processor = &admissionTestProcessor{admission: func(context.Context, string, Policy) (json.RawMessage, error) {
		return json.RawMessage(`{"version":1,"modelIdentity":{"agentUID":"synthetic-winning-agent"}}`), nil
	}}
	other, err := New(t.Context(), config)
	require.NoError(t, err)
	var winner Status
	processor.admission = func(ctx context.Context, _ string, _ Policy) (json.RawMessage, error) {
		var created bool
		var err error
		winner, created, err = other.Submit(ctx, "testing", "caller", requestFixture())
		require.NoError(t, err)
		require.True(t, created)
		return nil, errors.Join(ErrRetryable, errors.New("synthetic dependency outage"))
	}
	replay, created, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, winner, replay)
	counts, err := storage.CountRemediationRuns(t.Context(), "testing")
	require.NoError(t, err)
	require.EqualValues(t, 1, counts.Active)
	require.EqualValues(t, 1, counts.RetainedIntakes)
}
