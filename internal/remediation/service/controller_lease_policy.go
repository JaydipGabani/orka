package service

import (
	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"k8s.io/apimachinery/pkg/types"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
)

func validControllerClusterUID(uid types.UID) bool {
	return len(uid) <= 128 && len(kubevalidation.IsDNS1123Subdomain(string(uid))) == 0
}

func validControllerLeaseNamespace(config ControllerAdapterConfig) bool {
	return config.BuildEnvironment.BuildJobs != nil &&
		len(kubevalidation.IsDNS1123Label(config.BuildEnvironment.BuildJobs.Namespace)) == 0
}

// Publishing creates cluster-scoped fixtures. All adapters for that cluster,
// including other repositories and legacy capabilities, must share one lock.
// This only describes the frozen policy. Before enabling publishing, stop
// admission and drain/clean every controller run admitted under older policies;
// reloading policy cannot retrofit their frozen selections. Every service
// sharing the dedicated cluster must adopt coordination and the same build
// namespace before admission resumes. Drain again before disabling it. Never
// delete a held Lease or use expiration as a substitute for owned cleanup.
func controllerCoordinatedClusters(policy Policy) (map[types.UID]string, error) {
	clusters := make(map[types.UID]string)
	var controllers []ControllerAdapterConfig
	for _, configured := range policy.Adapters {
		if configured.Kind != controllerAdapterKind {
			continue
		}
		config, err := decodeControllerPolicy(configured)
		if err != nil {
			return nil, err
		}
		controllers = append(controllers, config)
		if selectedControllerCapability(config) == controllerlab.KEDAEventPublishing {
			if !validControllerLeaseNamespace(config) {
				return nil, ErrPolicy
			}
			namespace := config.BuildEnvironment.BuildJobs.Namespace
			if previous, found := clusters[config.ClusterUID]; found && previous != namespace {
				return nil, ErrPolicy
			}
			clusters[config.ClusterUID] = namespace
		}
	}
	for _, config := range controllers {
		if namespace, coordinated := clusters[config.ClusterUID]; coordinated &&
			(!validControllerLeaseNamespace(config) || config.BuildEnvironment.BuildJobs.Namespace != namespace) {
			return nil, ErrPolicy
		}
	}
	return clusters, nil
}

func controllerSelectionExclusive(configured AdapterPolicy, clusters map[types.UID]string) (bool, error) {
	if configured.Kind != controllerAdapterKind {
		return false, nil
	}
	config, err := decodeControllerPolicy(configured)
	if err != nil {
		return false, err
	}
	_, exclusive := clusters[config.ClusterUID]
	return exclusive, nil
}
