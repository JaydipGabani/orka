package environment

import (
	"maps"

	"github.com/orka-agents/orka/internal/remediation/buildjob"
)

// BuildJobsConfig is operator-only, serializable configuration. The existing
// adapter's authenticated, dedicated Kubernetes client is used at execution;
// neither clients nor credentials are embedded in the frozen configuration.
// Exactly one of WorkerArg and WorkerContext must select the approved worker.
type BuildJobsConfig struct {
	Namespace          string
	WorkerImage        string
	BuildKitAddress    string
	OutputRepository   string
	WorkerArg          string
	WorkerContext      string
	TLS                *buildjob.TLS
	Limits             buildjob.Limits
	Args               map[string]string
	RegistrySecretName string `json:",omitempty"`
}

// ValidateBuildJobs is a constructor hook to call after assigning the dedicated
// Kubernetes client. It validates every approved recipe tuple without creating
// workloads or treating configuration as an isolation proof.
func (a *Adapter) ValidateBuildJobs() error {
	if a.config.BuildJobs == nil {
		return nil
	}
	if !a.HasDurableBuildBackend() {
		return failure(NeedsAdapter, "durable-build-kubernetes-client-required")
	}
	for _, entry := range a.catalog {
		recipe := entry.bind.Recipe
		if _, err := a.jobBackend(buildjob.Input{
			RecipePath: recipe.Path, Frontend: recipe.FrontendImage, Worker: recipe.WorkerImage,
			Target: recipe.Target, Platform: recipe.Platform,
			BuildOnlyInputs: maps.Clone(entry.buildOnly),
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

// HasDurableBuildBackend is a configuration/readiness guard for automatic
// callers. It does not attest network isolation or daemon-side settlement.
func (a *Adapter) HasDurableBuildBackend() bool {
	return a.config.BuildJobs != nil && a.kube != nil
}

// HasBuildRegistrySecret is the configuration guard for restricted-report
// automatic execution. The worker still validates scope and basic-auth shape.
func (a *Adapter) HasBuildRegistrySecret() bool {
	return a.HasDurableBuildBackend() && a.config.BuildJobs.RegistrySecretName != ""
}
