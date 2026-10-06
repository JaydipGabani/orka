package controller

import (
	"testing"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/stretchr/testify/require"
)

func TestRuntimePoolAdmitsOnlyRestrictedSingleSessionRemediationProfile(t *testing.T) {
	pool := runtimePoolTestObject(1)
	profile, err := runtimePoolHarnessProfile(pool.Spec.Runtime.Profile)
	require.NoError(t, err)
	profile.ProviderKind = "copilot"
	profile.ResourceClass = remediationpolicy.CopilotResourceClass
	profile.ToolPolicyDigest, err = harnessv2.CanonicalRuntimeToolPolicyDigest([]string{}, nil, false)
	require.NoError(t, err)
	profile.MCPConfigurationDigest, err = harnessv2.CanonicalMCPConfigurationDigest([]string{})
	require.NoError(t, err)
	digest, err := harnessv2.CanonicalProfileDigest(profile)
	require.NoError(t, err)
	pool.Spec.Runtime.Profile = RuntimePoolProfileFromPlan(ACPRuntimePlan{Profile: profile, Digest: digest})
	pool.Spec.Capacity = &corev1alpha1.RuntimePoolCapacitySpec{MaxResidentSessions: 1, MaxRunningPrompts: 1}
	got, _, err := validateRuntimePoolProfile(pool)
	require.NoError(t, err)
	require.Equal(t, profile, got)
	require.Equal(t, runtimePoolResourceRequirements("standard"),
		runtimePoolResourceRequirements(remediationpolicy.CopilotResourceClass))
	for _, change := range []func(*corev1alpha1.RuntimePool){
		func(p *corev1alpha1.RuntimePool) { p.Spec.Capacity.MaxResidentSessions = 2 },
		func(p *corev1alpha1.RuntimePool) { p.Spec.Capacity = nil },
		func(p *corev1alpha1.RuntimePool) { p.Spec.Runtime.Profile.ProviderKind = "codex" },
		func(p *corev1alpha1.RuntimePool) {
			p.Spec.Runtime.Profile.WorkspaceIntent = corev1alpha1.WorkspaceIntentWrite
		},
		func(p *corev1alpha1.RuntimePool) {
			p.Spec.Runtime.Profile.ToolPolicyDigest = pool.Spec.Runtime.Profile.AgentConfigurationDigest
		},
		func(p *corev1alpha1.RuntimePool) { p.Spec.Runtime.Profile.ResourceClass = "unapproved" },
	} {
		changed := pool.DeepCopy()
		change(changed)
		_, _, err := validateRuntimePoolProfile(changed)
		require.Error(t, err)
	}
	_, _, err = validateRuntimePoolProfile(runtimePoolTestObject(1))
	require.NoError(t, err, "ordinary runtime profile behavior must stay unchanged")
}
