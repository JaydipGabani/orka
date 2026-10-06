package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/acp"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/orka-agents/orka/internal/remediationpolicy"
)

func TestRemediationCopilotIsOfflineDenyAllAndSingleSession(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"controller", "provider", "capability"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(strings.Repeat(name, 16)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tools, err := harnessv2.CanonicalRuntimeToolPolicyDigest([]string{}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	mcp, err := harnessv2.CanonicalMCPConfigurationDigest([]string{})
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		EnvPodUID: "pod", EnvSupervisorBootID: "boot", EnvControllerEpoch: "1", EnvRuntimePoolUID: "pool",
		EnvRuntimePoolGeneration: "1", EnvProvider: "copilot", EnvModel: "model", EnvWorkspaceIntent: "read",
		EnvAgentConfigurationDigest: testDigest("agent"), EnvToolPolicyDigest: tools,
		EnvApprovalPolicyDigest: testDigest("approval"), EnvMCPConfigurationDigest: mcp,
		EnvProxyCredentialRole: "provider-inference", EnvProxyCredentialScope: "model:model",
		EnvResourceClass:       remediationpolicy.CopilotResourceClass,
		EnvControllerTokenFile: filepath.Join(directory, "controller"), EnvProviderTokenFile: filepath.Join(directory, "provider"),
		EnvCapabilitySecretFile: filepath.Join(directory, "capability"),
		EnvMCPBrokerURL:         "http://orka-controller.orka-system.svc:8080", EnvTrustNamespace: "private",
		EnvSessionBaseDir: filepath.Join(directory, "sessions"), EnvFirstSessionUID: "20000", EnvLastSessionUID: "20010", EnvSessionGID: "20000",
	} {
		t.Setenv(name, value)
	}
	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Capabilities.Limits.MaxResidentSessions != 1 || cfg.Capabilities.Limits.MaxConcurrentPrompts != 1 {
		t.Fatal("private remediation profile was not isolated to one runtime session")
	}
	env, err := cfg.Provider.EnvironmentForSession(harnessv2.CreateRuntimeSessionRequest{}, acp.SessionPaths{Home: filepath.Join(directory, "home")}, ProviderProxyBinding{BaseURL: "http://127.0.0.1:1234", Credential: "session-capability"})
	if err != nil {
		t.Fatal(err)
	}
	if env["COPILOT_OFFLINE"] != "true" || env["COPILOT_PROVIDER_BEARER_TOKEN"] != "session-capability" ||
		env["GITHUB_TOKEN"] != "" || env["GH_TOKEN"] != "" || env["COPILOT_GITHUB_TOKEN"] != "" {
		t.Fatal("private Copilot inherited external credentials or telemetry authority")
	}
	t.Setenv(EnvToolPolicyDigest, testDigest("unrestricted"))
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("remediation resource class accepted a non-deny-all profile")
	}
}
