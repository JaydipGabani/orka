package supervisor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/orka-agents/orka/internal/acp"
	"github.com/orka-agents/orka/internal/artifactcap"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
)

const (
	providerKindCodex            = "codex"
	providerKindClaude           = "claude"
	providerKindCopilot          = "copilot"
	providerToolBash             = "Bash"
	providerToolEdit             = "Edit"
	providerToolGlob             = "Glob"
	providerToolGrep             = "Grep"
	providerToolRead             = "Read"
	providerToolWebFetch         = "WebFetch"
	providerToolWebSearch        = "WebSearch"
	providerToolWrite            = "Write"
	EnvListenAddress             = "ORKA_ACP_LISTEN_ADDRESS"
	EnvRuntimeInstanceID         = "ORKA_ACP_RUNTIME_INSTANCE_ID"
	EnvSupervisorBootID          = "ORKA_ACP_SUPERVISOR_BOOT_ID"
	EnvPodUID                    = "ORKA_ACP_POD_UID"
	EnvControllerEpoch           = "ORKA_ACP_CONTROLLER_EPOCH"
	EnvRuntimePoolUID            = "ORKA_ACP_RUNTIME_POOL_UID"
	EnvRuntimePoolGeneration     = "ORKA_ACP_RUNTIME_POOL_GENERATION"
	EnvProvider                  = "ORKA_ACP_PROVIDER"
	EnvModel                     = "ORKA_ACP_MODEL"
	EnvWorkspaceIntent           = "ORKA_ACP_WORKSPACE_INTENT"
	EnvAgentConfigurationDigest  = "ORKA_ACP_AGENT_CONFIGURATION_DIGEST"
	EnvToolPolicyDigest          = "ORKA_ACP_TOOL_POLICY_DIGEST"
	EnvApprovalPolicyDigest      = "ORKA_ACP_APPROVAL_POLICY_DIGEST"
	EnvMCPConfigurationDigest    = "ORKA_ACP_MCP_CONFIGURATION_DIGEST"
	EnvProxyCredentialRole       = "ORKA_ACP_PROXY_CREDENTIAL_ROLE"
	EnvProxyCredentialScope      = "ORKA_ACP_PROXY_CREDENTIAL_SCOPE"
	EnvResourceClass             = "ORKA_ACP_RESOURCE_CLASS"
	EnvProviderProxyBaseURL      = "ORKA_ACP_PROVIDER_PROXY_BASE_URL"
	EnvProviderTokenFile         = "ORKA_ACP_PROVIDER_TOKEN_FILE"
	EnvArtifactAPIURL            = "ORKA_ACP_ARTIFACT_API_URL"
	EnvWorkspaceArtifactMaxBytes = "ORKA_ACP_WORKSPACE_MAX_ARTIFACT_BYTES"
	EnvMCPBrokerURL              = "ORKA_ACP_MCP_BROKER_URL"
	EnvTrustNamespace            = "ORKA_ACP_TRUST_NAMESPACE"
	EnvControllerTokenFile       = "ORKA_ACP_CONTROLLER_TOKEN_FILE"
	EnvCapabilitySecretFile      = "ORKA_ACP_CAPABILITY_SECRET_FILE"
	EnvSessionBaseDir            = "ORKA_ACP_SESSION_BASE_DIR"
	EnvFirstSessionUID           = "ORKA_ACP_FIRST_SESSION_UID"
	EnvLastSessionUID            = "ORKA_ACP_LAST_SESSION_UID"
	EnvSessionGID                = "ORKA_ACP_SESSION_GID"

	// Codex ACP can flush buffered token/tool updates in short bursts above the
	// generic protocol default. Keep a bounded runtime-specific ceiling that the
	// supervisor advertises and the controller then enforces symmetrically.
	runtimeCodexMaxUpdateEventsPerSecond = 1000

	// Publisher workspace artifacts are inbound runtime materialization inputs,
	// while workspace deltas are outbound runtime artifacts. Keep independently
	// bounded defaults and configure the inbound limit from Publisher capability
	// propagation instead of conflating it with the delta capability.
	defaultWorkspaceArtifactDownloadBytes int64 = artifactcap.DefaultWorkspaceArtifactMaxBytes
	defaultWorkspaceDeltaUploadBytes      int64 = 100 << 20
)

func LoadConfigFromEnv() (Config, error) {
	providerKind := requiredEnv(EnvProvider)
	model := requiredEnv(EnvModel)
	intent := harnessv2.WorkspaceIntent(requiredEnv(EnvWorkspaceIntent))
	profile := harnessv2.RuntimeProfile{
		ACPProfile:               harnessv2.ACPProfileV1,
		ProviderKind:             providerKind,
		Model:                    model,
		AgentConfigurationDigest: requiredEnv(EnvAgentConfigurationDigest),
		ToolPolicyDigest:         requiredEnv(EnvToolPolicyDigest),
		ApprovalPolicyDigest:     requiredEnv(EnvApprovalPolicyDigest),
		MCPConfigurationDigest:   requiredEnv(EnvMCPConfigurationDigest),
		WorkspaceIntent:          intent,
		ProxyCredentialRole:      requiredEnv(EnvProxyCredentialRole),
		ProxyCredentialScope:     requiredEnv(EnvProxyCredentialScope),
		ResourceClass:            envDefault(EnvResourceClass, "standard"),
	}
	providerBaseURL := envDefault(EnvProviderProxyBaseURL, defaultProxyBaseURL())
	provider, err := providerProfile(providerKind, model, intent)
	if err != nil {
		return Config{}, err
	}
	profile.AdapterDigests = providerAdapterDigests(providerKind)
	if err := profile.Validate(); err != nil {
		return Config{}, fmt.Errorf("runtime profile: %w", err)
	}
	profileDigest, err := harnessv2.CanonicalProfileDigest(profile)
	if err != nil {
		return Config{}, err
	}
	limits := defaultProtocolLimits(providerKind)
	controllerEpoch, err := parsePositiveUint(EnvControllerEpoch, requiredEnv(EnvControllerEpoch))
	if err != nil {
		return Config{}, err
	}
	poolGeneration, err := parsePositiveUint(EnvRuntimePoolGeneration, requiredEnv(EnvRuntimePoolGeneration))
	if err != nil {
		return Config{}, err
	}
	firstUID, err := parsePositiveInt(EnvFirstSessionUID, envDefault(EnvFirstSessionUID, "20000"))
	if err != nil {
		return Config{}, err
	}
	lastUID, err := parsePositiveInt(EnvLastSessionUID, envDefault(EnvLastSessionUID, "29999"))
	if err != nil {
		return Config{}, err
	}
	firstGID, err := parsePositiveInt(EnvSessionGID, envDefault(EnvSessionGID, "20000"))
	if err != nil {
		return Config{}, err
	}
	allocator, err := acp.NewUIDAllocator(firstUID, lastUID, firstGID)
	if err != nil {
		return Config{}, err
	}
	controllerToken, err := readRequiredSecretFile(EnvControllerTokenFile)
	if err != nil {
		return Config{}, err
	}
	capabilitySecret, err := readRequiredSecretFile(EnvCapabilitySecretFile)
	if err != nil {
		return Config{}, err
	}
	workspaceMaterializer := EmptyWorkspaceMaterializer()
	var artifactUploader ArtifactUploader
	if artifactAPIURL := strings.TrimSpace(os.Getenv(EnvArtifactAPIURL)); artifactAPIURL != "" {
		authorizationProvider, providerErr := NewBrokerArtifactAuthorizationProvider(
			artifactAPIURL, requiredEnv(EnvTrustNamespace), controllerToken, []byte(capabilitySecret),
		)
		if providerErr != nil {
			return Config{}, providerErr
		}
		maxWorkspaceArtifactBytes, limitErr := workspaceArtifactDownloadLimitFromEnv()
		if limitErr != nil {
			return Config{}, limitErr
		}
		artifactClient, clientErr := newArtifactClient(
			artifactAPIURL, nil, authorizationProvider, artifactClientLimits{
				MaxDownloadBytes: maxWorkspaceArtifactBytes,
				MaxUploadBytes:   limits.MaxWorkspaceDeltaBytes,
			},
		)
		if clientErr != nil {
			return Config{}, clientErr
		}
		workspaceMaterializer, clientErr = NewRemoteWorkspaceMaterializer(artifactClient, WorkspaceMaterializerLimits{})
		if clientErr != nil {
			return Config{}, clientErr
		}
		artifactUploader, clientErr = NewRemoteArtifactUploader(artifactClient)
		if clientErr != nil {
			return Config{}, clientErr
		}
	}
	mcpBrokerURL := strings.TrimSpace(os.Getenv(EnvMCPBrokerURL))
	if mcpBrokerURL == "" {
		mcpBrokerURL = strings.TrimSpace(os.Getenv(EnvArtifactAPIURL))
	}
	mcpBroker, err := NewControllerMCPBrokerClient(
		mcpBrokerURL, requiredEnv(EnvTrustNamespace), controllerToken, []byte(capabilitySecret),
	)
	if err != nil {
		return Config{}, err
	}
	providerToken, err := readRequiredSecretFile(EnvProviderTokenFile)
	if err != nil {
		return Config{}, err
	}
	bootID := strings.TrimSpace(os.Getenv(EnvSupervisorBootID))
	if bootID == "" {
		bootID = uuid.NewString()
	}
	runtimeInstanceID := strings.TrimSpace(os.Getenv(EnvRuntimeInstanceID))
	if runtimeInstanceID == "" {
		podUID := requiredEnv(EnvPodUID)
		runtimeInstanceID = podUID + "." + bootID
	}
	capabilities := harnessv2.CapabilitiesResponse{
		Protocol: harnessv2.ProtocolVersion, Transport: "http+ndjson", ACPVersion: harnessv2.ACPProfileV1,
		RuntimeProfileDigest: profileDigest, ProfileDigestSchemaVersion: harnessv2.ProfileDigestSchemaVersion,
		AdapterDigests: profile.AdapterDigests, Limits: limits, SupportsDrain: true, SupportsPublicationFinalization: true,
		SupportsAgentSessionConfiguration: true,
		Provider: harnessv2.ProviderCapabilities{
			ProviderKinds: []string{providerKind}, Models: []string{model}, SupportsPermissions: true,
			SupportsCancel: true, SupportsTools: true, SupportsImages: true,
			SupportsEmbeddedResources: true,
		},
		WorkspaceGovernance: harnessv2.StrictWorkspaceGovernanceCapabilities(),
	}
	cfg := Config{
		ListenAddress: envDefault(EnvListenAddress, ":8080"),
		Fence: harnessv2.Fence{
			RuntimeInstanceID: harnessv2.RuntimeInstanceID(runtimeInstanceID),
			SupervisorBootID:  harnessv2.SupervisorBootID(bootID), ControllerEpoch: controllerEpoch,
			RuntimePoolUID: harnessv2.RuntimePoolUID(requiredEnv(EnvRuntimePoolUID)), RuntimePoolGeneration: poolGeneration,
			RuntimeProfileDigest: profileDigest, ProfileDigestSchemaVersion: harnessv2.ProfileDigestSchemaVersion,
		},
		Capabilities: capabilities, Provider: provider,
		ControllerBearerToken: controllerToken, CapabilitySecret: []byte(capabilitySecret), RequireCapabilities: true,
		SessionBaseDir: envDefault(EnvSessionBaseDir, "/sessions"), UIDAllocator: allocator,
		ProviderProxy: ProviderProxyConfig{
			UpstreamBaseURL: providerUpstreamBaseURL(providerKind, providerBaseURL), UpstreamBearerToken: providerToken,
			ProviderKind: providerKind, Model: model,
		},
		MCPBroker:             mcpBroker,
		WorkspaceMaterializer: workspaceMaterializer,
		ArtifactUploader:      artifactUploader,
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func providerAdapterDigests(provider string) map[string]string {
	schema := "sha256:" + acp.ACPSchemaSHA256
	switch provider {
	case providerKindCodex:
		return map[string]string{
			"codex-acp":             "sha256:" + acp.CodexACPTarSHA256,
			"codex-acp-orka-patch":  "sha256:" + acp.CodexACPOrkaPatchSHA256,
			"codex-acp-orka-dist":   "sha256:" + acp.CodexACPOrkaDistSHA256,
			"codex-cli-linux-amd64": "sha256:" + acp.CodexCLILinuxX64SHA256,
			"codex-cli-linux-arm64": "sha256:" + acp.CodexCLILinuxARM64SHA256,
			"acp-schema":            schema,
		}
	case providerKindClaude:
		return map[string]string{
			"claude-agent-acp":        "sha256:" + acp.ClaudeACPTarSHA256,
			"claude-code-linux-amd64": "sha256:" + acp.ClaudeSDKLinuxX64SHA256,
			"claude-code-linux-arm64": "sha256:" + acp.ClaudeSDKLinuxARM64SHA256,
			"acp-schema":              schema,
		}
	case providerKindCopilot:
		return map[string]string{
			"copilot-cli-linux-amd64": "sha256:" + acp.CopilotCLILinuxX64SHA256,
			"copilot-cli-linux-arm64": "sha256:" + acp.CopilotCLILinuxARM64SHA256,
			"acp-schema":              schema,
		}
	default:
		return nil
	}
}

var providerNativeToolNames = []string{
	providerToolBash, providerToolEdit, providerToolGlob, providerToolGrep,
	providerToolRead, providerToolWebFetch, providerToolWebSearch, providerToolWrite,
}

type providerNativePolicy struct {
	unrestricted bool
	allowed      map[string]struct{}
}

func (p providerNativePolicy) allows(name string) bool {
	_, ok := p.allowed[name]
	return ok
}

func providerSessionPolicy(
	request harnessv2.CreateRuntimeSessionRequest,
	provider string,
	model string,
) (providerNativePolicy, error) {
	if request.AgentConfiguration == nil {
		return providerNativePolicy{}, fmt.Errorf("agent session configuration is required")
	}
	if err := request.MCPConfiguration.ValidateProfile(request.Profile); err != nil {
		return providerNativePolicy{}, fmt.Errorf("MCP policy configuration: %w", err)
	}
	if err := request.AgentConfiguration.ValidateProfileOrLegacy(request.Profile, request.MCPConfiguration.ToolPolicy.AllowBash); err != nil {
		return providerNativePolicy{}, fmt.Errorf("agent session configuration: %w", err)
	}
	if request.Profile.ProviderKind != provider || request.AgentConfiguration.ProviderKind != provider ||
		request.Profile.Model != model || request.AgentConfiguration.Model != model {
		return providerNativePolicy{}, fmt.Errorf("provider session configuration does not match runtime profile")
	}
	toolPolicy := request.MCPConfiguration.ToolPolicy
	unrestricted := len(toolPolicy.AllowedToolNames) == 0 && len(toolPolicy.DisallowedToolNames) == 0 && toolPolicy.AllowBash
	policy := providerNativePolicy{unrestricted: unrestricted, allowed: make(map[string]struct{}, len(providerNativeToolNames))}
	for _, descriptor := range toolPolicy.Tools {
		if descriptor.Source != harnessv2.MCPToolSourceProviderNative {
			continue
		}
		name, ok := canonicalProviderNativeToolName(descriptor.Name)
		if !ok {
			return providerNativePolicy{}, fmt.Errorf("provider-native tool %q is not supported by the %s projection", descriptor.Name, provider)
		}
		if _, duplicate := policy.allowed[name]; duplicate {
			return providerNativePolicy{}, fmt.Errorf("provider-native tool %q is duplicated after canonicalization", descriptor.Name)
		}
		policy.allowed[name] = struct{}{}
	}
	return policy, nil
}

func canonicalProviderNativeToolName(value string) (string, bool) {
	for _, name := range providerNativeToolNames {
		if strings.EqualFold(value, name) {
			return name, true
		}
	}
	return "", false
}

func providerNativePolicyLists(policy providerNativePolicy) ([]string, []string) {
	allowed := make([]string, 0, len(providerNativeToolNames))
	disallowed := make([]string, 0, len(providerNativeToolNames))
	for _, name := range providerNativeToolNames {
		if policy.allows(name) {
			allowed = append(allowed, name)
		} else {
			disallowed = append(disallowed, name)
		}
	}
	return allowed, disallowed
}

func codexSessionProjection(
	request harnessv2.CreateRuntimeSessionRequest,
	_ acp.SessionPaths,
	proxy ProviderProxyBinding,
	model string,
) (ProviderSessionProjection, error) {
	policy, err := providerSessionPolicy(request, providerKindCodex, model)
	if err != nil {
		return ProviderSessionProjection{}, err
	}
	if !policy.unrestricted {
		return ProviderSessionProjection{}, fmt.Errorf("codex ACP runtime cannot exactly enforce provider-native tool restrictions")
	}
	config := map[string]any{
		"model": model, "openai_base_url": proxy.BaseURL, "check_for_update_on_startup": false,
	}
	if systemPrompt := request.AgentConfiguration.SystemPrompt; systemPrompt != "" {
		config["developer_instructions"] = systemPrompt
	}
	if effort := request.AgentConfiguration.ReasoningEffort; effort != "" {
		config["model_reasoning_effort"] = effort
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return ProviderSessionProjection{}, err
	}
	const maxCodexConfigEnvironmentBytes = 96 << 10
	if len(encoded) > maxCodexConfigEnvironmentBytes {
		return ProviderSessionProjection{}, fmt.Errorf("codex session configuration exceeds the safe environment limit")
	}
	return ProviderSessionProjection{Environment: map[string]string{"CODEX_CONFIG": string(encoded)}}, nil
}

func claudeSessionProjection(
	request harnessv2.CreateRuntimeSessionRequest,
	_ acp.SessionPaths,
	_ ProviderProxyBinding,
	model string,
) (ProviderSessionProjection, error) {
	policy, err := providerSessionPolicy(request, providerKindClaude, model)
	if err != nil {
		return ProviderSessionProjection{}, err
	}
	options := map[string]any{"maxTurns": request.AgentConfiguration.MaxTurns}
	if effort := request.AgentConfiguration.ReasoningEffort; effort != "" {
		options["effort"] = effort
	}
	if !policy.unrestricted {
		allowed, disallowed := providerNativePolicyLists(policy)
		options["tools"] = allowed
		options["disallowedTools"] = disallowed
	}
	meta := acp.Meta{"claudeCode": map[string]any{"options": options}}
	if systemPrompt := request.AgentConfiguration.SystemPrompt; systemPrompt != "" {
		meta["systemPrompt"] = systemPrompt
	}
	return ProviderSessionProjection{NewSessionMeta: meta}, nil
}

var copilotToolIDs = map[string][]string{
	providerToolBash:      {"bash", "list_bash", "read_bash", "stop_bash", "write_bash"},
	providerToolEdit:      {"edit", "str_replace_editor", "apply_patch"},
	providerToolGlob:      {"glob"},
	providerToolGrep:      {"grep", "rg"},
	providerToolRead:      {"view"},
	providerToolWebFetch:  {"web_fetch"},
	providerToolWebSearch: {"web_search"},
	providerToolWrite:     {"create"},
}

var copilotAlwaysExcludedToolIDs = []string{
	"ask_user", "code_review", "custom_tool", "custom_tools", "exit_plan_mode",
	"github", "github-mcp-server", "list_agents", "lsp", "read_agent", "report_intent", "skill", "sql", "task", "write_agent",
}

func copilotSessionProjection(
	request harnessv2.CreateRuntimeSessionRequest,
	_ acp.SessionPaths,
	_ ProviderProxyBinding,
	model string,
) (ProviderSessionProjection, error) {
	policy, err := providerSessionPolicy(request, providerKindCopilot, model)
	if err != nil {
		return ProviderSessionProjection{}, err
	}
	if request.AgentConfiguration.SystemPrompt != "" {
		return ProviderSessionProjection{}, fmt.Errorf("copilot ACP runtime cannot exactly enforce Agent systemPrompt")
	}
	if request.AgentConfiguration.ReasoningEffort != "" {
		return ProviderSessionProjection{}, fmt.Errorf("copilot ACP runtime cannot enforce reasoning effort")
	}
	projection := ProviderSessionProjection{}
	if policy.unrestricted {
		return projection, nil
	}
	if policy.allows(providerToolWebSearch) {
		return ProviderSessionProjection{}, fmt.Errorf("copilot ACP runtime cannot exactly enforce the WebSearch provider-native tool")
	}
	excluded := append([]string(nil), copilotAlwaysExcludedToolIDs...)
	for _, name := range providerNativeToolNames {
		if policy.allows(name) {
			continue
		}
		excluded = append(excluded, copilotToolIDs[name]...)
	}
	projection.AdditionalArgs = []string{"--excluded-tools=" + strings.Join(excluded, ",")}
	return projection, nil
}

func providerProfile(kind, model string, _ harnessv2.WorkspaceIntent) (ProviderProfile, error) {
	switch kind {
	case providerKindCodex:
		return ProviderProfile{
			Kind: kind, Model: model, Command: "/usr/bin/node", Args: []string{"/opt/codex-acp/dist/index.js"},
			AuthMethodID: "api-key", AdapterName: "codex-acp-orka-dist", AdapterDigest: "sha256:" + acp.CodexACPOrkaDistSHA256,
			ProjectSession: func(request harnessv2.CreateRuntimeSessionRequest, paths acp.SessionPaths, proxy ProviderProxyBinding) (ProviderSessionProjection, error) {
				return codexSessionProjection(request, paths, proxy, model)
			},
			EnvironmentForSession: func(_ harnessv2.CreateRuntimeSessionRequest, paths acp.SessionPaths, proxy ProviderProxyBinding) (map[string]string, error) {
				// The Orka-patched adapter uses Codex's externalSandbox policy so the
				// restricted Runtime Pod remains the enforcement boundary without asking
				// the child to create nested Linux namespaces. Network remains restricted
				// and on-request approvals remain active for explicit elevation requests.
				mode := "orka-external"
				config, err := json.Marshal(map[string]any{
					"model": model, "openai_base_url": proxy.BaseURL, "check_for_update_on_startup": false,
				})
				if err != nil {
					return nil, err
				}
				return map[string]string{
					"NO_BROWSER": "1", "CODEX_PATH": "/opt/codex/bin/codex", "CODEX_HOME": filepath.Join(paths.Home, ".codex"),
					"CODEX_CONFIG": string(config), "INITIAL_AGENT_MODE": mode, "CODEX_API_KEY": proxy.Credential,
				}, nil
			},
			PrepareSession: prepareCodexHome,
		}, nil
	case providerKindClaude:
		return ProviderProfile{
			Kind: kind, Model: model, Command: "/usr/bin/node", Args: []string{"/opt/claude-agent-acp/dist/index.js", "--hide-claude-auth"},
			AdapterName: "claude-agent-acp", AdapterDigest: "sha256:" + acp.ClaudeACPTarSHA256,
			ProjectSession: func(request harnessv2.CreateRuntimeSessionRequest, paths acp.SessionPaths, proxy ProviderProxyBinding) (ProviderSessionProjection, error) {
				return claudeSessionProjection(request, paths, proxy, model)
			},
			EnvironmentForSession: func(_ harnessv2.CreateRuntimeSessionRequest, paths acp.SessionPaths, proxy ProviderProxyBinding) (map[string]string, error) {
				return map[string]string{
					"CLAUDE_CONFIG_DIR": filepath.Join(paths.Home, ".claude"), "CLAUDE_CODE_EXECUTABLE": "/opt/claude/bin/claude",
					"NO_BROWSER": "1", "DISABLE_UPDATES": "1", "DISABLE_AUTOUPDATER": "1", "DISABLE_INSTALLATION_CHECKS": "1",
					"ANTHROPIC_BASE_URL": proxy.BaseURL, "ANTHROPIC_API_KEY": proxy.Credential, "ANTHROPIC_MODEL": model,
				}, nil
			},
		}, nil
	case providerKindCopilot:
		adapterName, adapterDigest, err := copilotAdapterIdentity(runtime.GOARCH)
		if err != nil {
			return ProviderProfile{}, err
		}
		return ProviderProfile{
			Kind: kind, Model: model, Command: "/opt/copilot/bin/copilot",
			Args:        []string{"--acp", "--stdio", "--no-auto-update", "--disable-builtin-mcps", "--no-custom-instructions", "--no-experimental", "--no-remote", "--no-remote-export", "--no-ask-user", "--no-bash-env", "--disallow-temp-dir", "--no-color", "--log-level", "none"},
			AdapterName: adapterName, AdapterDigest: adapterDigest,
			ProjectSession: func(request harnessv2.CreateRuntimeSessionRequest, paths acp.SessionPaths, proxy ProviderProxyBinding) (ProviderSessionProjection, error) {
				return copilotSessionProjection(request, paths, proxy, model)
			},
			EnvironmentForSession: func(_ harnessv2.CreateRuntimeSessionRequest, paths acp.SessionPaths, proxy ProviderProxyBinding) (map[string]string, error) {
				return map[string]string{
					"COPILOT_AUTO_UPDATE": "false", "CI": "true", "COPILOT_HOME": filepath.Join(paths.Home, ".copilot"),
					"COPILOT_PROVIDER_BASE_URL": proxy.BaseURL, "COPILOT_PROVIDER_BEARER_TOKEN": proxy.Credential, "COPILOT_PROVIDER_TYPE": "openai",
					"COPILOT_PROVIDER_WIRE_API": "responses", "COPILOT_MODEL": model,
				}, nil
			},
		}, nil
	default:
		return ProviderProfile{}, fmt.Errorf("unsupported ACP provider %q", kind)
	}
}

func prepareCodexHome(paths acp.SessionPaths) error {
	dir := filepath.Join(paths.Home, ".codex")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.toml"), []byte("check_for_update_on_startup = false\n"), 0o600)
}

func openAIProxyURL(base string) string {
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if strings.HasSuffix(base, "/v1") {
		return base
	}
	return base + "/v1"
}

func defaultProxyBaseURL() string {
	return "http://vekil.vekil-system.svc:1337"
}

func providerUpstreamBaseURL(provider, base string) string {
	base = strings.TrimSuffix(strings.TrimSpace(base), "/")
	if provider == providerKindCodex || provider == providerKindCopilot {
		return openAIProxyURL(base)
	}
	return base
}

func copilotAdapterIdentity(goarch string) (string, string, error) {
	switch goarch {
	case "amd64":
		return "copilot-cli-linux-amd64", "sha256:" + acp.CopilotCLILinuxX64SHA256, nil
	case "arm64":
		return "copilot-cli-linux-arm64", "sha256:" + acp.CopilotCLILinuxARM64SHA256, nil
	default:
		return "", "", fmt.Errorf("unsupported Copilot runtime architecture %q", goarch)
	}
}

func defaultProtocolLimits(provider string) harnessv2.ProtocolLimits {
	maxUpdates := harnessv2.DefaultMaxUpdateEventsPerSecond
	if provider == providerKindCodex {
		maxUpdates = runtimeCodexMaxUpdateEventsPerSecond
	}
	return harnessv2.ProtocolLimits{
		MaxResidentSessions: 10, MaxConcurrentPrompts: 4, MaxRequestBytes: 2 << 20,
		MaxEventLineBytes: 1 << 20, MaxTerminalResultBytes: 1 << 20, MaxBufferedEvents: 256,
		MaxUpdateEventsPerSecond: maxUpdates, MinPromptLeaseMillis: 5_000, MaxPromptLeaseMillis: 120_000,
		MaxPendingPermissions: 32, MaxWorkspaceDeltaBytes: defaultWorkspaceDeltaUploadBytes,
	}
}

func workspaceArtifactDownloadLimitFromEnv() (int64, error) {
	raw := strings.TrimSpace(os.Getenv(EnvWorkspaceArtifactMaxBytes))
	if raw == "" {
		return 0, fmt.Errorf("%s is required when the artifact API is configured", EnvWorkspaceArtifactMaxBytes)
	}
	limit, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", EnvWorkspaceArtifactMaxBytes)
	}
	return limit, nil
}

func requiredEnv(name string) string { return strings.TrimSpace(os.Getenv(name)) }
func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func parsePositiveUint(name, value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func parsePositiveInt(name, value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func readRequiredSecretFile(envName string) (string, error) {
	path := requiredEnv(envName)
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must name an absolute file", envName)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", envName, err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s file is empty", envName)
	}
	return value, nil
}
