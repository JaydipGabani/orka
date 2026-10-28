package patchverification

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func applicationReplicaPolicy(t *testing.T) *ApplicationPolicy {
	t.Helper()
	policy := applicationTestPolicy(t)
	policy.Fixtures = []ApplicationFixtureProfile{{
		ID: "replica-profile", Image: "example/fixture@" + Digest([]byte("fixture-image")), ImageID: Digest([]byte("fixture-config")),
		Args:          []string{"/usr/bin/sleep", "3600"},
		ReplicaTarget: &ApplicationReplicaTargetProfile{Name: "replica-target", InitialReplicas: 0, MaxReplicas: 4},
	}}
	policy.Resources = append(policy.Resources,
		ApplicationResourceRule{APIVersion: "apps/v1", Kind: "Deployment", Resource: "deployments", Namespaced: true,
			Verbs: []string{"get", "list", "watch"}, Status: true, Scale: true},
		ApplicationResourceRule{APIVersion: "autoscaling/v2", Kind: "HorizontalPodAutoscaler", Resource: "horizontalpodautoscalers",
			Namespaced: true, Verbs: []string{"get", "list", "watch", "create", "update"}, Status: true},
	)
	policy.SubjectPermissions = append(policy.SubjectPermissions,
		ApplicationPermission{APIGroup: "apps", Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}},
		ApplicationPermission{APIGroup: "apps", Resources: []string{"deployments/scale"}, Verbs: []string{"get", "patch", "update"}, ResourceNames: []string{"replica-target"}},
		ApplicationPermission{APIGroup: "autoscaling", Resources: []string{"horizontalpodautoscalers"}, Verbs: []string{"get", "list", "watch", "create", "update"}},
	)
	require.NoError(t, ValidateApplicationPolicy(*policy))
	return policy
}

func TestApplicationReplicaPrimitivePinsNameAndOperatorTemplate(t *testing.T) {
	policy := applicationReplicaPolicy(t)
	plan := *applicationTestManifest(t).Application
	plan.Fixtures = []ApplicationFixture{{ID: "replica-target", Kind: "replica", Profile: "replica-profile"}}
	plan.Permissions = []ApplicationPermission{{APIGroup: "apps", Resources: []string{"deployments/scale"},
		Verbs: []string{"patch"}, ResourceNames: []string{"replica-target"}}}
	require.NoError(t, ValidateApplicationPlanWithPolicy(plan, policy))
	plan.Fixtures[0].ID = "another-target"
	require.Error(t, ValidateApplicationPlanWithPolicy(plan, policy))
	plan.Fixtures[0].ID = "replica-target"
	plan.Permissions[0].ResourceNames = nil
	require.Error(t, ValidateApplicationPlanWithPolicy(plan, policy))
	plan.Permissions[0].ResourceNames = []string{"replica-target"}
	plan.Fixtures[0].Config = map[string]string{"script": "untrusted"}
	require.Error(t, ValidateApplicationPlanWithPolicy(plan, policy))
	manifest := applicationTestManifest(t)
	manifest.ApplicationPolicy = policy
	manifest.Application.Fixtures = []ApplicationFixture{{ID: "replica-target", Kind: "replica", Profile: "replica-profile"}}
	require.Error(t, ValidateManifest(manifest), "selecting a replica cannot silently omit actual scaling normal control")
}

func TestApplicationScalingNeverAdmitsRawDeploymentHPAOrActorPrivilege(t *testing.T) {
	policy := applicationReplicaPolicy(t)
	for _, raw := range []json.RawMessage{
		[]byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"replica-target"},"spec":{"replicas":1}}`),
		[]byte(`{"apiVersion":"autoscaling/v2","kind":"HorizontalPodAutoscaler","metadata":{"name":"fake-normal"},"spec":{}}`),
	} {
		_, err := ValidateApplicationResourceWithPolicy(raw, policy)
		require.Error(t, err)
	}
	policy.Actors[0].Permissions = append(policy.Actors[0].Permissions, ApplicationPermission{
		APIGroup: "autoscaling", Resources: []string{"horizontalpodautoscalers"}, Verbs: []string{"create"},
	})
	require.Error(t, ValidateApplicationPolicy(*policy))
	for _, mutate := range []func(*ApplicationPolicy){
		func(p *ApplicationPolicy) { p.Fixtures[0].ReplicaTarget.MaxReplicas = 5 },
		func(p *ApplicationPolicy) { p.Fixtures[0].ReplicaTarget.InitialReplicas = -1 },
		func(p *ApplicationPolicy) { p.Fixtures[0].ConfigKeys = []string{"template"} },
		func(p *ApplicationPolicy) { p.Resources[len(p.Resources)-2].Verbs = []string{"update"} },
		func(p *ApplicationPolicy) { p.Resources[len(p.Resources)-1].Verbs = []string{"delete"} },
		func(p *ApplicationPolicy) { p.Resources[len(p.Resources)-2].Namespaced = false },
	} {
		p := applicationReplicaPolicy(t)
		mutate(p)
		require.Error(t, ValidateApplicationPolicy(*p))
	}
}

func TestApplicationReplicaNormalControlMustShowActualNonInitialReconciliation(t *testing.T) {
	policy := applicationReplicaPolicy(t)
	check := applicationTestManifest(t).Checks[1]
	check.Application.Kubernetes = &ApplicationKubernetesCheck{APIVersion: "apps/v1", Resource: "deployments",
		Name: "replica-target", Pointer: "/status/readyReplicas"}
	check.Healthy, _ = ApplicationAPIExpectation(ApplicationAPIValue{Exists: true, Found: true, Value: []byte("1")})
	check.Failure, _ = ApplicationAPIExpectation(ApplicationAPIValue{Exists: true, Found: false})
	require.Error(t, ValidateApplicationCheckWithPolicy(check, policy))
	check.Application.Actions = []ApplicationAction{{ActorID: "author", Verb: "create", ExpectedStatus: 201,
		Resource: []byte(`{"apiVersion":"testing.example/v1","kind":"Widget","metadata":{"name":"normal-scaling"},"spec":{}}`)}}
	require.NoError(t, ValidateApplicationCheckWithPolicy(check, policy))
	policy.Fixtures[0].ReplicaTarget.InitialReplicas = 1
	require.Error(t, ValidateApplicationCheckWithPolicy(check, policy), "fixture's initial ready status is not controller reconciliation")
}

func TestApplicationReplicaTransportIsNotAcceptedWithoutReadyDescendantEvidence(t *testing.T) {
	manifest := applicationTestManifest(t)
	manifest.ApplicationPolicy = applicationReplicaPolicy(t)
	manifest.Application.Fixtures = []ApplicationFixture{{ID: "replica-target", Kind: "replica", Profile: "replica-profile"}}
	check := &manifest.Checks[1]
	check.Application.Kubernetes = &ApplicationKubernetesCheck{APIVersion: "apps/v1", Resource: "deployments",
		Name: "replica-target", Pointer: "/status/readyReplicas"}
	check.Application.Actions = []ApplicationAction{{ActorID: "author", Verb: "create", ExpectedStatus: 201,
		Resource: []byte(`{"apiVersion":"testing.example/v1","kind":"Widget","metadata":{"name":"normal-scaling"},"spec":{}}`)}}
	check.Healthy, _ = ApplicationAPIExpectation(ApplicationAPIValue{Exists: true, Found: true, Value: []byte("1")})
	check.Failure, _ = ApplicationAPIExpectation(ApplicationAPIValue{Exists: true, Found: false})
	// The separate reproduction still requires its own normal control.
	control := applicationTestManifest(t).Checks[1]
	control.ID = "api-normal"
	manifest.Checks = append(manifest.Checks, control)
	binding, evidence := applicationTestEvidence(t, manifest)
	observation := evidence[1]
	actor := ApplicationActorIdentity{ID: "author", Namespace: "protected-run", NamespaceUID: "protected-uid",
		ServiceAccountName: "author", ServiceAccountUID: "author-uid"}
	target := ApplicationActionTarget{Index: 0, APIVersion: "testing.example/v1", Resource: "widgets",
		Name: "normal-scaling", MustBeAbsent: true, OwnerUID: "ledger-uid"}
	receipt, err := (applicationTestActor{identity: actor, status: 201}).Apply(t.Context(), observation.Application.Target.Namespace,
		manifest.Checks[1].Application.Actions[0], target)
	require.NoError(t, err)
	observation.Application.Actions = []ApplicationActionObservation{receipt}
	require.NoError(t, ValidateApplicationWorkerObservation(manifest, binding, observation))
	require.Error(t, ValidateObservation(manifest, binding, observation), "worker status alone must not become final replica evidence")
	profile := ApplicationReplicaTargetFor(manifest.ApplicationPolicy)
	pod := applicationTestIdentity("replica-pod", profile.ImageID)
	pod.JobUID, pod.Namespace, pod.NamespaceUID = "", observation.Application.Target.Namespace, observation.Application.Target.NamespaceUID
	observation.Application.Replica = &ApplicationReplicaObservation{DeploymentUID: observation.Application.Kubernetes.UID,
		ReplicaSetUIDs: []string{"owned-rs"}, Pods: []ApplicationContainerIdentity{pod},
		DesiredReplicas: 1, ReadyReplicas: 1, InitialReplicas: 0, MaxReplicas: 4}
	require.NoError(t, ValidateObservation(manifest, binding, observation))
	observation.Application.Replica.Pods = nil
	require.Error(t, ValidateObservation(manifest, binding, observation))
}
