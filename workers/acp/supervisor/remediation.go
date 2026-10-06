package supervisor

import (
	"strconv"

	"github.com/orka-agents/orka/internal/acp"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/orka-agents/orka/internal/remediationpolicy"
)

func restrictRemediationProvider(profile harnessv2.RuntimeProfile, provider ProviderProfile) (ProviderProfile, error) {
	if profile.ResourceClass != remediationpolicy.CopilotResourceClass {
		return provider, nil
	}
	if err := remediationpolicy.ValidateCopilotProfile(profile); err != nil {
		return ProviderProfile{}, err
	}
	original := provider.EnvironmentForSession
	provider.EnvironmentForSession = func(request harnessv2.CreateRuntimeSessionRequest, paths acp.SessionPaths, proxy ProviderProxyBinding) (map[string]string, error) {
		values, err := original(request, paths, proxy)
		if err != nil {
			return nil, err
		}
		values["COPILOT_OFFLINE"] = strconv.FormatBool(true)
		return values, nil
	}
	return provider, nil
}
