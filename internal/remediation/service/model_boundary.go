package service

import (
	"context"
	"encoding/json"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediationpolicy"
)

// AdmissionState freezes the exact account and routing resources before a run
// is accepted, including runs that wait in the queue before their first prompt.
func (p *Pipeline) AdmissionState(ctx context.Context, namespace string, policy Policy) (json.RawMessage, error) {
	if p.Agents == nil {
		return nil, ErrPolicy
	}
	identity, err := p.Agents(namespace, policy.AgentName, nil).Snapshot(ctx)
	if err != nil {
		return nil, modelDependencyFailure(err, ErrPolicy)
	}
	if !matchesApprovedModelBoundary(policy, identity) {
		return nil, ErrPolicy
	}
	raw, err := json.Marshal(pipelineState{Version: Version, ModelIdentity: &identity})
	if err != nil {
		return nil, ErrInvalid
	}
	return raw, nil
}

func matchesApprovedModelBoundary(policy Policy, identity modelagent.PlanIdentity) bool {
	switch policy.ProposalBackend {
	case "", remediationpolicy.NativeBackend:
		return identity.Backend == "" || identity.Backend == remediationpolicy.NativeBackend
	case remediationpolicy.CopilotBackend:
		if policy.Copilot == nil || identity.Backend != remediationpolicy.CopilotBackend {
			return false
		}
		digest, err := policy.Copilot.Digest()
		return err == nil && digest == identity.CopilotConfigDigest &&
			identity.RuntimeImage == policy.Copilot.Image && identity.RuntimeNamespace == policy.Copilot.RuntimeNamespace &&
			identity.ProxyEndpoint == policy.Copilot.ProxyEndpoint && identity.ProxyNamespace == policy.Copilot.ProxyNamespace
	default:
		return false
	}
}
