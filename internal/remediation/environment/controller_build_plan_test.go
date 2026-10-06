//go:build linux

package environment

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestControllerExternalBuildPlanDoesNotAuthorizeHTTPExecution(t *testing.T) {
	t.Parallel()
	fixture := newJobFixture(t, true)
	fixture.config.Repositories[0].CheckCapabilities = []string{"keda-namespace-events-v1"}
	adapter, err := newAdapter(fixture.config)
	require.NoError(t, err)
	adapter.kube = fixture.kube
	binding := fixture.plans[0].Bind
	binding.ChecksDigest = ""
	contract := "sha256:" + strings.Repeat("7", 64)
	plan, err := adapter.FreezeBuildPlan(binding, "keda-namespace-events-v1", contract)
	require.NoError(t, err)
	require.Equal(t, contract, plan.ExternalObservation.ContractDigest)
	require.Empty(t, plan.Resources)
	require.Empty(t, plan.Checks)
	require.Equal(t, ChecksDigest(plan), plan.Bind.ChecksDigest)
	_, err = adapter.FreezePlan(plan)
	require.Error(t, err)
	_, err = adapter.Start(t.Context(), Request{
		RunID: "controller-run", OperationID: "original", Plan: plan,
		Subject: Subject{Role: PublishedOriginal, Image: fixture.config.Repositories[0].Recipes[0].OriginalImage},
	})
	require.Error(t, err)
	require.Empty(t, fixture.kube.Actions())

	built, err := adapter.Build(t.Context(), BuildRequest{
		RunID: "controller-build", OperationID: "control", Role: RebuiltControl, Plan: plan,
	})
	require.NoError(t, err)
	require.Equal(t, plan.Bind, built.Bind)
	require.Equal(t, RebuiltControl, built.Subject.Role)
	require.NotEmpty(t, built.Subject.BuildID)
	require.Equal(t, int64(1), fixture.buildCount.Load())
}

func TestControllerExternalBuildPlanRejectsWeakenedContracts(t *testing.T) {
	t.Parallel()
	fixture := newJobFixture(t, true)
	fixture.config.Repositories[0].CheckCapabilities = []string{"keda-namespace-events-v1"}
	adapter, err := newAdapter(fixture.config)
	require.NoError(t, err)
	adapter.kube = fixture.kube
	binding := fixture.plans[0].Bind
	binding.ChecksDigest = ""
	digest := "sha256:" + strings.Repeat("7", 64)
	for _, capability := range []string{"", HTTPExact, "keda-redis-auth-v1"} {
		_, err := adapter.FreezeBuildPlan(binding, capability, digest)
		require.Error(t, err)
	}
	_, err = adapter.FreezeBuildPlan(binding, "keda-namespace-events-v1", "unverified")
	require.Error(t, err)
	plan, err := adapter.FreezeBuildPlan(binding, "keda-namespace-events-v1", digest)
	require.NoError(t, err)
	plan.Checks = fixture.plans[0].Checks
	plan.Bind.ChecksDigest = ChecksDigest(plan)
	_, err = adapter.Build(t.Context(), BuildRequest{
		RunID: "controller-build", OperationID: "control", Role: RebuiltControl, Plan: plan,
	})
	require.Error(t, err)
	require.Empty(t, fixture.kube.Actions())
	adapter.config.BuildJobs = nil
	_, err = adapter.FreezeBuildPlan(binding, "keda-namespace-events-v1", digest)
	require.Error(t, err)
}
