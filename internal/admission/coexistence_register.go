/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package admission

import (
	"slices"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	ctrladmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/orka-agents/orka/internal/workerenv"
)

// Stable webhook mount paths for the harness v1/v2 coexistence admission
// boundary served by the standalone orka-admission Deployment. The paths are
// part of the installed ValidatingWebhookConfiguration and must not change.
const (
	// CoexistenceAgentWebhookPath validates Agent contract classification.
	CoexistenceAgentWebhookPath = "/validate-coexistence-agent"
	// CoexistenceAgentRuntimeWebhookPath validates AgentRuntime contract classification.
	CoexistenceAgentRuntimeWebhookPath = "/validate-coexistence-agentruntime"
	// CoexistenceTaskProvenanceWebhookPath validates Task execution provenance writes.
	CoexistenceTaskProvenanceWebhookPath = "/validate-coexistence-task-provenance"
	// CoexistenceAdjudicationWebhookPath validates AgentExecutionAdjudication authorship.
	CoexistenceAdjudicationWebhookPath = "/validate-coexistence-adjudication"
	// CoexistenceControlPolicyWebhookPath validates AgentExecutionControl and
	// AgentExecutionPolicy spec authorship.
	CoexistenceControlPolicyWebhookPath = "/validate-coexistence-control-policy"
)

// defaultCoexistenceAdminGroups is the fallback admin group set when no
// --admin-groups value is configured.
var defaultCoexistenceAdminGroups = []string{"system:masters"}

// CoexistenceConfig carries the trusted identities for the coexistence
// admission boundary. ControllerServiceAccounts is intentionally not
// defaulted: an empty list keeps execution-provenance writes fail closed for
// every caller, including the controller.
type CoexistenceConfig struct {
	// ControllerServiceAccounts are fully qualified usernames (for example
	// system:serviceaccount:orka-system:orka-controller-manager) allowed to
	// write Task execution provenance fields.
	ControllerServiceAccounts []string

	// AdminGroups are the groups allowed to author AgentExecutionControl,
	// AgentExecutionPolicy, and AgentExecutionAdjudication specs.
	AdminGroups []string
}

// NewCoexistenceConfig parses comma-separated identity lists into a
// CoexistenceConfig. AdminGroups defaults to system:masters when empty;
// ControllerServiceAccounts stays empty (fail closed) when unset.
func NewCoexistenceConfig(controllerServiceAccounts, adminGroups string) CoexistenceConfig {
	cfg := CoexistenceConfig{
		ControllerServiceAccounts: workerenv.SplitCSV(controllerServiceAccounts),
		AdminGroups:               workerenv.SplitCSV(adminGroups),
	}
	if len(cfg.AdminGroups) == 0 {
		cfg.AdminGroups = append([]string{}, defaultCoexistenceAdminGroups...)
	}
	return cfg
}

// isControllerIdentity reports whether the authenticated user is one of the
// configured controller identities.
func (c CoexistenceConfig) isControllerIdentity(user authenticationv1.UserInfo) bool {
	username := strings.TrimSpace(user.Username)
	return username != "" && slices.Contains(c.ControllerServiceAccounts, username)
}

// isAdminIdentity reports whether any authenticated group is a configured
// admin group.
func (c CoexistenceConfig) isAdminIdentity(user authenticationv1.UserInfo) bool {
	for _, group := range user.Groups {
		if slices.Contains(c.AdminGroups, strings.TrimSpace(group)) {
			return true
		}
	}
	return false
}

// RegisterCoexistenceWebhooks mounts every coexistence admission handler on
// the given webhook server at its stable path.
func RegisterCoexistenceWebhooks(server webhook.Server, scheme *runtime.Scheme, cfg CoexistenceConfig) {
	server.Register(CoexistenceAgentWebhookPath, &ctrladmission.Webhook{
		Handler: NewCoexistenceAgentValidator(scheme),
	})
	server.Register(CoexistenceAgentRuntimeWebhookPath, &ctrladmission.Webhook{
		Handler: NewCoexistenceAgentRuntimeValidator(scheme),
	})
	server.Register(CoexistenceTaskProvenanceWebhookPath, &ctrladmission.Webhook{
		Handler: NewCoexistenceTaskProvenanceValidator(scheme, cfg),
	})
	server.Register(CoexistenceAdjudicationWebhookPath, &ctrladmission.Webhook{
		Handler: NewCoexistenceAdjudicationValidator(scheme, cfg),
	})
	server.Register(CoexistenceControlPolicyWebhookPath, &ctrladmission.Webhook{
		Handler: NewCoexistenceControlPolicyValidator(scheme, cfg),
	})
}
