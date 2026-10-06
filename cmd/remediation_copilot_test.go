package main

import (
	"strings"
	"testing"

	remediationagent "github.com/orka-agents/orka/internal/remediation/agent"
)

func TestRemediationCopilotBoundaryRejectsControllerRouteDrift(t *testing.T) {
	configured := remediationagent.CopilotConfig{
		Image:            "example.invalid/copilot@sha256:" + strings.Repeat("a", 64),
		RuntimeNamespace: "private-runtime", ProxyNamespace: "proxy",
		ProxyEndpoint: "http://approved-proxy.proxy.svc:8080",
	}
	options := remediationOptions{
		ACPRuntimeEnabled: true, ACPRuntimeNamespace: configured.RuntimeNamespace,
		CopilotRuntimeImage: configured.Image, ProviderProxyBaseURL: configured.ProxyEndpoint,
		ProviderProxyNamespace: configured.ProxyNamespace,
	}
	if err := validateRemediationCopilotBoundary(options, &configured); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*remediationOptions){
		"endpoint":          func(o *remediationOptions) { o.ProviderProxyBaseURL = "http://other.proxy.svc:8080" },
		"proxy namespace":   func(o *remediationOptions) { o.ProviderProxyNamespace = "other" },
		"runtime namespace": func(o *remediationOptions) { o.ACPRuntimeNamespace = "ordinary-runtimes" },
		"runtime image": func(o *remediationOptions) {
			o.CopilotRuntimeImage = "example.invalid/copilot@sha256:" + strings.Repeat("b", 64)
		},
		"disabled": func(o *remediationOptions) { o.ACPRuntimeEnabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			changed := options
			mutate(&changed)
			if err := validateRemediationCopilotBoundary(changed, &configured); err == nil {
				t.Fatal("controller and policy model boundaries diverged")
			}
		})
	}
}
