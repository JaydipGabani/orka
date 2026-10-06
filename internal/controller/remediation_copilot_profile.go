package controller

import (
	"context"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PlanRemediationCopilot uses the same configuration and profile canonicalizer
// as queueing. It does not grant execution authority or create a RuntimePool.
func PlanRemediationCopilot(ctx context.Context, reader client.Reader, task *corev1alpha1.Task,
	agent *corev1alpha1.Agent, image string) (ACPRuntimePlan, error) {
	if err := remediationpolicy.ValidateCopilotAgent(agent); err != nil {
		return ACPRuntimePlan{}, err
	}
	configuration, err := resolveACPAgentSessionConfiguration(ctx, reader, task, agent)
	if err != nil {
		return ACPRuntimePlan{}, err
	}
	return PlanACPRuntimeWithConfiguration(task, agent, ACPRuntimeImages{Copilot: image}, configuration)
}
