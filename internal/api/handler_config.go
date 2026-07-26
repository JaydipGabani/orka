/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package api

import "sigs.k8s.io/controller-runtime/pkg/client"

// handlersConfig adapts server composition dependencies to the narrower
// configuration consumed by the public API handlers.
func (c ServerConfig) handlersConfig(resourceClient client.Client) HandlersConfig {
	return HandlersConfig{
		Client:                    resourceClient,
		APIReader:                 c.APIReader,
		WatchNamespace:            c.WatchNamespace,
		EnforceNamespaceIsolation: c.EnforceNamespaceIsolation,
		ContextTokenAuthorization: c.ContextTokenAuthorization,
		ResultStore:               c.ResultStore,
		SessionStore:              c.SessionStore,
		PlanStore:                 c.PlanStore,
		KubeClient:                c.Clientset,
		HealthChecker:             c.HealthChecker,
		ArtifactStore:             c.ArtifactStore,
		MemoryStore:               c.MemoryStore,
		MemoryProposalStore:       c.MemoryProposalStore,
		SecurityStore:             c.SecurityStore,
		RepositoryMonitorStore:    c.RepositoryMonitorStore,
		ExecutionEventStore:       c.ExecutionEventStore,
		GatewayEventStore:         c.GatewayEventStore,
		GatewayDeliveryStore:      c.GatewayDeliveryStore,
		GatewayService:            c.GatewayService,
	}
}
