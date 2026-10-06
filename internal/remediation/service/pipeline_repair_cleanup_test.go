package service

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type repairCleanupBuilder struct {
	*controllerTestBuilder
	cancelError               error
	cancelCalls               int
	failedBuildSettled        bool
	nextBuildBeforeSettlement bool
}

func (b *repairCleanupBuilder) Build(ctx context.Context, request environment.BuildRequest) (environment.BuildResult, error) {
	if request.OperationID == "candidate-1" && !b.failedBuildSettled {
		b.nextBuildBeforeSettlement = true
	}
	return b.controllerTestBuilder.Build(ctx, request)
}

func (b *repairCleanupBuilder) CancelBuild(ctx context.Context, runID, operationID string, plan environment.Plan) error {
	b.cancelCalls++
	if b.cancelError != nil {
		return b.cancelError
	}
	if operationID == "candidate-0" {
		b.failedBuildSettled = true
	}
	return b.controllerTestBuilder.CancelBuild(ctx, runID, operationID, plan)
}

func newExclusiveRepairFixture(t *testing.T) (*controllerTestFixture, *repairCleanupBuilder) {
	t.Helper()
	f := newControllerFixture(t)
	legacy := f.adapter.config
	legacy.BuildEnvironment.BuildJobs = &environment.BuildJobsConfig{Namespace: "controller-builds"}
	legacy.BuildEnvironment.Kubernetes = &environment.KubernetesConfig{}
	publishing := legacy
	publishing.Capability, publishing.Controller.EnableEventPublishing = controllerlab.KEDAEventPublishing, true
	publishing.Controller.Template.Source.Commit = "e615440f24f6abec8b7c69bd88854cb4324e9eaa"
	f.adapter.config, f.adapter.selection.ClusterExclusive = legacy, true
	config := f.service.config
	policy := config.Policies[0]
	policy.Adapters = nil
	for _, entry := range []struct {
		name   string
		config ControllerAdapterConfig
	}{{f.adapter.selection.Name, legacy}, {"unused-publishing", publishing}} {
		raw, err := json.Marshal(entry.config)
		require.NoError(t, err)
		policy.Adapters = append(policy.Adapters, AdapterPolicy{
			Name: entry.name, Kind: controllerAdapterKind, Repositories: policy.Repositories, Configuration: raw,
		})
	}
	config.Policies = []Policy{policy}
	var err error
	f.service, err = New(t.Context(), config)
	require.NoError(t, err)
	require.NoError(t, f.kube.Tracker().Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "controller-builds", UID: "build-namespace", ResourceVersion: "1",
	}}))
	installControllerLeaseAPI(t, f.kube)
	builder := &repairCleanupBuilder{controllerTestBuilder: f.builder}
	f.adapter.ExecutionAdapter, f.adapter.builder = builder, builder
	return f, builder
}

func TestControllerRepairSettlesRejectedBuildBeforeNextCandidateAndSuccess(t *testing.T) {
	f, builder := newExclusiveRepairFixture(t)
	run := f.submit(Generate)
	require.NoError(t, f.service.RunOnce(t.Context()))
	completed, err := f.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseSucceeded, completed.Phase, completed.Reason)
	var state pipelineState
	require.NoError(t, json.Unmarshal(completed.StateJSON, &state))
	require.Len(t, state.Attempts, 2)
	require.Contains(t, string(state.Attempts[0].Feedback), "candidate-build-failed")
	require.True(t, state.Attempts[0].Operation.BuildIntent)
	require.True(t, state.Attempts[0].Operation.Cleaned)
	require.True(t, builder.failedBuildSettled)
	require.False(t, builder.nextBuildBeforeSettlement)
	require.Equal(t, 1, builder.cancelCalls)
	require.Equal(t, 3, builder.builds)
	require.Equal(t, 5, f.models.calls)
	require.True(t, state.ControllerLease.Released)
	require.Nil(t, completed.Cleanup)
	require.Equal(t, "verified", state.Stage)
	require.Equal(t, 1, controllerLeaseActions(f.kube, "delete"))
	_, patch, err := f.store.GetRemediationArtifact(t.Context(), run.Namespace, run.ID, "candidate.patch")
	require.NoError(t, err)
	require.Equal(t, state.Attempts[1].Patch.Digest, Digest(patch))
}

func TestControllerRepairWaitsForRejectedBuildSettlementWithoutAnotherProposal(t *testing.T) {
	f, builder := newExclusiveRepairFixture(t)
	builder.cancelError = &environment.Error{Kind: environment.Infrastructure, Code: "synthetic-cleanup-pending", Retryable: true}
	run := f.submit(Generate)
	require.NoError(t, f.service.RunOnce(t.Context()))
	waiting, err := f.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseRunning, waiting.Phase)
	var state pipelineState
	require.NoError(t, json.Unmarshal(waiting.StateJSON, &state))
	require.Len(t, state.Attempts, 1)
	require.False(t, state.Attempts[0].Operation.Cleaned)
	require.False(t, state.ControllerLease.Released)
	require.False(t, builder.nextBuildBeforeSettlement)
	require.Equal(t, 2, builder.builds)
	require.Equal(t, 4, f.models.calls)
	require.Equal(t, 1, builder.cancelCalls)
	require.Zero(t, controllerLeaseActions(f.kube, "delete"))
	require.Nil(t, waiting.Cleanup, "a pending repair barrier is not run cancellation")
	builder.cancelError = nil
	timer := time.NewTimer(time.Until(waiting.ClaimUntil) + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-t.Context().Done():
		require.FailNow(t, "context ended before the repair retry", t.Context().Err())
	case <-timer.C:
	}
	require.NoError(t, f.service.RunOnce(t.Context()))
	completed, err := f.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseSucceeded, completed.Phase, completed.Reason)
	require.Equal(t, 2, builder.cancelCalls)
	require.Equal(t, 3, builder.builds, "the rejected build must not be replayed")
	require.Equal(t, 5, f.models.calls, "the recorded proposal must not be regenerated")
	require.False(t, builder.nextBuildBeforeSettlement)
	require.NoError(t, json.Unmarshal(completed.StateJSON, &state))
	require.True(t, state.ControllerLease.Released)
}

func TestRejectedBuildSettlementDoesNotClaimRuntimeCleanup(t *testing.T) {
	for _, mutate := range []struct {
		name   string
		change func(*executionOperation)
	}{
		{"role", func(operation *executionOperation) { operation.Role = environment.RebuiltControl }},
		{"subject", func(operation *executionOperation) { operation.Subject = &environment.Subject{} }},
		{"intent", func(operation *executionOperation) { operation.Intent = true }},
		{"controller", func(operation *executionOperation) { operation.Controller = &controllerOperation{} }},
		{"receipt", func(operation *executionOperation) { operation.Receipt = &environment.Receipt{} }},
		{"observation", func(operation *executionOperation) { operation.Observation = &store.RemediationArtifact{} }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			f, session, state, checks := newControllerLeaseFixture(t, false)
			builder := &repairCleanupBuilder{controllerTestBuilder: f.builder}
			operation := executionOperation{ID: "candidate-0", Role: environment.Candidate, BuildIntent: true}
			mutate.change(&operation)
			require.ErrorIs(t, f.pipeline.settleRejectedBuild(t.Context(), session, checks, builder, state, &operation), ErrUnknown)
			require.False(t, operation.Cleaned)
			require.Zero(t, builder.cancelCalls)
		})
	}
}

func TestRejectedBuildSettlementPreservesLegacyHTTPBackend(t *testing.T) {
	f, session, state, checks := newControllerLeaseFixture(t, false)
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0o700))
	legacy, err := environment.New(environment.Config{OutputRoot: root, SyntheticScope: "legacy-http"})
	require.NoError(t, err)
	plan, err := checks.buildPlan()
	require.NoError(t, err)
	plan.ExternalObservation = nil
	plan.Bind.ChecksDigest = environment.ChecksDigest(plan)
	require.Error(t, legacy.CancelBuild(t.Context(), session.run.ID, "candidate-0", plan),
		"the real local backend has no durable BuildJobs cancellation receipt")
	httpChecks := ExecutionPlan{Binding: plan.Bind, HTTP: &plan}
	operation := executionOperation{ID: "candidate-0", Role: environment.Candidate, BuildIntent: true}
	require.NoError(t, f.pipeline.settleRejectedBuild(t.Context(), session, httpChecks, legacy, state, &operation))
	require.False(t, operation.Cleaned, "the controller-only barrier must not fabricate HTTP cleanup evidence")
}
