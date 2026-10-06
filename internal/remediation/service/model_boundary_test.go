package service

import (
	"context"
	"strings"
	"testing"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/stretchr/testify/require"
)

type boundaryModelClient struct {
	disclosureModelClient
	identity modelagent.PlanIdentity
}

func (c boundaryModelClient) Snapshot(context.Context) (modelagent.PlanIdentity, error) {
	return c.identity, nil
}

func TestModelSubmissionHonorsFrozenBackendAndConfiguration(t *testing.T) {
	config := modelagent.CopilotConfig{
		Image:            "example.invalid/copilot@sha256:" + strings.Repeat("a", 64),
		RuntimeNamespace: "private-runtime", ProxyNamespace: "proxy",
		ProxyEndpoint: "http://approved-proxy.proxy.svc:8080",
		IdentityReferences: []modelagent.CopilotIdentityReference{
			{Kind: "ConfigMap", Namespace: "proxy", Name: "route"}, {Kind: "Secret", Namespace: "proxy", Name: "approved-account"},
		},
	}
	configDigest, err := config.Digest()
	require.NoError(t, err)
	approved := modelagent.PlanIdentity{
		Backend: remediationpolicy.CopilotBackend, Digest: Digest([]byte("approved-model-identity")),
		CopilotConfigDigest: configDigest, RuntimeImage: config.Image, RuntimeNamespace: config.RuntimeNamespace,
		ProxyEndpoint: config.ProxyEndpoint, ProxyNamespace: config.ProxyNamespace,
	}
	changed := config
	changed.IdentityReferences = append([]modelagent.CopilotIdentityReference(nil), config.IdentityReferences...)
	changed.IdentityReferences[1].Name = "different-account"
	changedDigest, err := changed.Digest()
	require.NoError(t, err)
	for _, test := range []struct {
		name       string
		backend    string
		identity   modelagent.PlanIdentity
		configHash string
		cached     bool
		allowed    bool
	}{
		{"unchanged-copilot", remediationpolicy.CopilotBackend, approved, "", false, true},
		{"copilot-to-native", remediationpolicy.CopilotBackend, modelagent.PlanIdentity{Digest: Digest([]byte("native"))}, "", false, false},
		{"native-to-copilot", "native-ai", approved, "", false, false},
		{"native-identity-drift", "native-ai", modelagent.PlanIdentity{Digest: Digest([]byte("different-native-account"))}, "", false, false},
		{"account-reference-changed", remediationpolicy.CopilotBackend, approved, changedDigest, false, false},
		{"cached-unapproved-identity", remediationpolicy.CopilotBackend, approved, changedDigest, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			pipeline, session, state, policy, _, calls := disclosurePipelineFixture(t, `{}`)
			policy.ProposalBackend = test.backend
			policy.AllowRestrictedModel = true
			if test.backend == remediationpolicy.CopilotBackend {
				policy.Copilot = &config
				state.ModelIdentity = &approved
			}
			actual := test.identity
			if test.configHash != "" {
				actual.CopilotConfigDigest = test.configHash
			}
			if test.cached {
				state.ModelIdentity = &actual
			}
			pipeline.Agents = func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
				return boundaryModelClient{
					disclosureModelClient: disclosureModelClient{accepted: accepted, output: `{}`, calls: calls},
					identity:              actual,
				}
			}

			_, err := pipeline.generate(t.Context(), session, session.run, policy, state, modelagent.Request{
				TaskName: "frozen-boundary-check", Prompt: "Synthetic restricted technical content.",
			})
			if test.allowed {
				require.NoError(t, err)
				require.Equal(t, 1, *calls)
				require.Equal(t, 1, state.ModelCalls)
			} else {
				require.ErrorIs(t, err, ErrNeedsInput)
				require.Zero(t, *calls, "unapproved boundary received a model submission")
				require.Zero(t, state.ModelCalls)
			}
		})
	}
}
