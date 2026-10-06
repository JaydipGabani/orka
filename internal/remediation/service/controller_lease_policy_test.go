package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

func TestControllerLeaseCoordinationUsesWholeFrozenPolicy(t *testing.T) {
	t.Parallel()
	fixture, _, _, _ := newControllerLeaseFixture(t, true)
	policy := fixture.service.config.Policies[0]
	// A legacy adapter for another source ref is still part of the cluster's
	// observer interference boundary, even when it is not a selection candidate.
	policy.Adapters[0].Repositories = []string{"https://github.com/example/other-source"}
	clusters, err := controllerCoordinatedClusters(policy)
	require.NoError(t, err)
	require.Equal(t, map[types.UID]string{"dedicated-cluster": "controller-builds"}, clusters)
	for _, configured := range policy.Adapters {
		exclusive, err := controllerSelectionExclusive(configured, clusters)
		require.NoError(t, err)
		require.True(t, exclusive)
	}
	http, err := controllerSelectionExclusive(AdapterPolicy{Kind: httpAdapterKind}, clusters)
	require.NoError(t, err)
	require.False(t, http)
	policy.Adapters = policy.Adapters[:1]
	clusters, err = controllerCoordinatedClusters(policy)
	require.NoError(t, err)
	require.Empty(t, clusters, "legacy-only frozen policies must retain their existing concurrency")
}

func TestControllerLeasePolicyRejectsInvalidPinsAndSplitNamespaces(t *testing.T) {
	for _, invalid := range []string{"namespace-empty", "namespace-case", "namespace-length", "uid-empty", "uid-whitespace", "uid-length", "split-namespaces"} {
		t.Run(invalid, func(t *testing.T) {
			t.Parallel()
			fixture, _, _, _ := newControllerLeaseFixture(t, true)
			policy := fixture.service.config.Policies[0]
			index := 1
			if invalid == "split-namespaces" {
				index = 0
			}
			config, err := decodeControllerPolicy(policy.Adapters[index])
			require.NoError(t, err)
			switch invalid {
			case "namespace-empty":
				config.BuildEnvironment.BuildJobs.Namespace = ""
			case "namespace-case":
				config.BuildEnvironment.BuildJobs.Namespace = "Invalid"
			case "namespace-length":
				config.BuildEnvironment.BuildJobs.Namespace = strings.Repeat("a", 64)
			case "uid-empty":
				config.ClusterUID = ""
			case "uid-whitespace":
				config.ClusterUID = "invalid uid"
			case "uid-length":
				config.ClusterUID = types.UID(strings.Repeat("a", 129))
			case "split-namespaces":
				config.BuildEnvironment.BuildJobs.Namespace = "different-build-namespace"
			}
			config.Controller.ClusterIdentity = controllerlab.ClusterIdentity(string(config.ClusterUID))
			policy.Adapters[index].Configuration, err = json.Marshal(config)
			require.NoError(t, err)
			_, err = controllerCoordinatedClusters(policy)
			require.ErrorIs(t, err, ErrPolicy)
			require.ErrorIs(t, ValidateAdapters(policy), ErrPolicy, "reject statically, before constructing any client or builder")
		})
	}
}

func TestControllerLeaseSelectionCannotDisableFrozenCoordinationOnResume(t *testing.T) {
	t.Parallel()
	fixture, _, _, _ := newControllerLeaseFixture(t, false)
	selection := fixture.adapter.selection
	selection.ClusterExclusive = false
	_, err := (Catalog{}).Resume(t.Context(), fixture.service.config.Policies[0], selection)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestControllerLeaseLegacyFloorDoesNotGainNamespaceValidation(t *testing.T) {
	t.Parallel()
	fixture := newControllerFixture(t)
	config := fixture.adapter.config
	config.BuildEnvironment.BuildJobs = &environment.BuildJobsConfig{}
	config.BuildEnvironment.Kubernetes = &environment.KubernetesConfig{}
	raw, err := json.Marshal(config)
	require.NoError(t, err)
	clusters, err := controllerCoordinatedClusters(Policy{Adapters: []AdapterPolicy{{
		Name: "legacy", Kind: controllerAdapterKind, Configuration: raw,
	}}})
	require.NoError(t, err)
	require.Empty(t, clusters)
}
