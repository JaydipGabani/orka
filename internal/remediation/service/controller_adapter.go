package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/kubeauth"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const controllerAdapterKind = "dalec-keda-events"

// ControllerAdapterConfig is operator-only. Identity pins are established once
// during setup and are frozen in the policy snapshot, never selected by a model.
type ControllerAdapterConfig struct {
	Capability            controllerlab.Capability        `json:"capability,omitempty"`
	BuildEnvironment      environment.Config              `json:"buildEnvironment"`
	Controller            controllerlab.Config            `json:"controller"`
	Kubeconfig            string                          `json:"kubeconfig"`
	Context               string                          `json:"context"`
	AzureWorkloadIdentity *kubeauth.AzureWorkloadIdentity `json:"azureWorkloadIdentity,omitempty"`
	ProbeImage            string                          `json:"probeImage"`
	ClusterUID            types.UID                       `json:"clusterUID"`
	RequiredCapabilities  []string                        `json:"requiredCapabilities,omitempty"`
	RequiredRequirements  []string                        `json:"requiredRequirements,omitempty"`
}

type controllerBuildBackend interface {
	ExecutionAdapter
	FreezeBuildPlan(environment.Bind, string, string) (environment.Plan, error)
}

type controllerExecutionAdapter struct {
	ExecutionAdapter
	builder   controllerBuildBackend
	config    ControllerAdapterConfig
	selection AdapterSelection
	kube      kubernetes.Interface
	newLab    func(controllerlab.Config, controllerlab.Hooks) (*controllerlab.Adapter, error)
}

func decodeControllerPolicy(policy AdapterPolicy) (ControllerAdapterConfig, error) {
	var config ControllerAdapterConfig
	if policy.Kind != controllerAdapterKind ||
		decodeObject(policy.Configuration, MaxPolicyBytes, &config) != nil ||
		len(config.Controller.Bindings) != 0 || !validControllerClusterUID(config.ClusterUID) ||
		config.Controller.ClusterIdentity != controllerlab.ClusterIdentity(string(config.ClusterUID)) ||
		config.Controller.Template.ClusterWatchRole.UID == "" ||
		len(config.RequiredCapabilities) > 8 || len(config.RequiredRequirements) > 8 ||
		config.BuildEnvironment.BuildJobs == nil || config.BuildEnvironment.BuildKit != nil ||
		config.BuildEnvironment.Kubernetes == nil ||
		(config.BuildEnvironment.Limits.MaxNamespaces != 0 && config.BuildEnvironment.Limits.MaxNamespaces != 4) ||
		!pinnedControllerImage(config.ProbeImage) {
		return ControllerAdapterConfig{}, ErrPolicy
	}
	if !validControllerCapability(config) ||
		(config.AzureWorkloadIdentity != nil && config.AzureWorkloadIdentity.Validate() != nil) ||
		(selectedControllerCapability(config) == controllerlab.KEDAEventPublishing && !validControllerLeaseNamespace(config)) {
		return ControllerAdapterConfig{}, ErrPolicy
	}
	return config, nil
}

func controllerPolicyFloor(policy AdapterPolicy) ([]string, []string, error) {
	if policy.Kind != controllerAdapterKind || len(policy.Configuration) == 0 {
		return nil, nil, nil
	}
	var config ControllerAdapterConfig
	if decodeObject(policy.Configuration, MaxPolicyBytes, &config) != nil ||
		len(config.RequiredCapabilities) > 8 || len(config.RequiredRequirements) > 8 || !validControllerCapability(config) {
		return nil, nil, ErrPolicy
	}
	return config.RequiredCapabilities, config.RequiredRequirements, nil
}

func pinnedControllerImage(image string) bool {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return false
	}
	pinned, ok := named.(reference.Canonical)
	return ok && validDigest(pinned.Digest().String())
}

// PinControllerAdapterConfig is an explicit setup operation, not execution-time
// discovery. Persist the returned config in the approved policy before serving
// submissions. Reloads and resumed runs subsequently require these exact UIDs.
func PinControllerAdapterConfig(ctx context.Context, config ControllerAdapterConfig) (ControllerAdapterConfig, error) {
	clientConfig, err := controllerRESTConfig(config)
	if err != nil {
		return ControllerAdapterConfig{}, err
	}
	kube, err := controllerKubeClient(clientConfig)
	if err != nil {
		return ControllerAdapterConfig{}, ErrNeedsAdapter
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cluster, err := kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID == "" || cluster.DeletionTimestamp != nil ||
		(config.ClusterUID != "" && config.ClusterUID != cluster.UID) {
		return ControllerAdapterConfig{}, ErrNeedsAdapter
	}
	role, err := kube.RbacV1().ClusterRoles().Get(ctx, config.Controller.Template.ClusterWatchRole.Name, metav1.GetOptions{})
	if err != nil || role.UID == "" || role.DeletionTimestamp != nil || role.AggregationRule != nil ||
		!reflect.DeepEqual(role.Rules, controllerlab.KEDAClusterWatchRules()) ||
		(config.Controller.Template.ClusterWatchRole.UID != "" && config.Controller.Template.ClusterWatchRole.UID != role.UID) {
		return ControllerAdapterConfig{}, ErrNeedsAdapter
	}
	identity := controllerlab.ClusterIdentity(string(cluster.UID))
	if config.Controller.ClusterIdentity != "" && config.Controller.ClusterIdentity != identity {
		return ControllerAdapterConfig{}, ErrNeedsAdapter
	}
	config.ClusterUID = cluster.UID
	config.Controller.ClusterIdentity = identity
	config.Controller.Template.ClusterWatchRole.UID = role.UID
	return config, nil
}

func controllerRESTConfig(config ControllerAdapterConfig) (*rest.Config, error) {
	path := config.Kubeconfig
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || config.Context == "" {
		return nil, ErrPolicy
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, ErrPolicy
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, ErrPolicy
	}
	raw, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return nil, ErrPolicy
	}
	selected := raw.Contexts[config.Context]
	if selected == nil || raw.AuthInfos[selected.AuthInfo] == nil || raw.Clusters[selected.Cluster] == nil {
		return nil, ErrPolicy
	}
	identity := raw.AuthInfos[selected.AuthInfo]
	if identity.Exec != nil || identity.AuthProvider != nil || raw.Clusters[selected.Cluster].ProxyURL != "" {
		return nil, ErrPolicy
	}
	result, err := clientcmd.NewNonInteractiveClientConfig(*raw, config.Context, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil || result.Insecure || result.Proxy != nil {
		return nil, ErrPolicy
	}
	server, err := url.Parse(result.Host)
	if err != nil || server.Scheme != "https" || server.Hostname() == "" || server.User != nil || server.RawQuery != "" || server.Fragment != "" ||
		(server.Path != "" && server.Path != "/") {
		return nil, ErrPolicy
	}
	if err := kubeauth.ConfigureAzure(result, config.AzureWorkloadIdentity); err != nil {
		return nil, ErrPolicy
	}
	result.Timeout = 5 * time.Second
	return result, nil
}

func controllerKubeClient(config *rest.Config) (kubernetes.Interface, error) {
	bounded := rest.CopyConfig(config)
	bounded.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	httpClient, err := rest.HTTPClientFor(bounded)
	if err != nil {
		return nil, ErrNeedsAdapter
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	kube, err := kubernetes.NewForConfigAndClient(bounded, httpClient)
	if err != nil {
		return nil, ErrNeedsAdapter
	}
	return kube, nil
}

func newControllerExecutionAdapter(config ControllerAdapterConfig, selection AdapterSelection, builder controllerBuildBackend) (*controllerExecutionAdapter, error) {
	clientConfig, err := controllerRESTConfig(config)
	if err != nil {
		return nil, err
	}
	kube, err := controllerKubeClient(clientConfig)
	if err != nil {
		return nil, ErrNeedsAdapter
	}
	adapter := &controllerExecutionAdapter{
		ExecutionAdapter: builder, builder: builder, config: config, selection: selection, kube: kube,
		newLab: func(runtime controllerlab.Config, hooks controllerlab.Hooks) (*controllerlab.Adapter, error) {
			return controllerlab.NewForConfig(runtime, clientConfig, hooks)
		},
	}
	// Construction validates all operator bounds without performing a Step.
	if _, err := adapter.labForSubject(selection.Original, "original", "sha256:"+strings.Repeat("0", 64), controllerlab.Hooks{
		Acceptance:   func(context.Context, controllerlab.Mutation) error { return ErrInvalid },
		PersistState: func(context.Context, uint64, controllerlab.State) error { return ErrInvalid },
	}); err != nil {
		return nil, ErrNeedsAdapter
	}
	return adapter, nil
}

func (a *controllerExecutionAdapter) FreezePlan(environment.Plan) (environment.Plan, error) {
	return environment.Plan{}, ErrNeedsAdapter
}

func (a *controllerExecutionAdapter) Start(context.Context, environment.Request) (environment.Receipt, error) {
	return environment.Receipt{}, ErrNeedsAdapter
}

func (a *controllerExecutionAdapter) Observe(context.Context, environment.Receipt) (environment.Observation, error) {
	return environment.Observation{}, ErrNeedsAdapter
}

func (a *controllerExecutionAdapter) Cancel(context.Context, environment.Receipt) error {
	return ErrNeedsAdapter
}

func (a *controllerExecutionAdapter) freezePlan(plan controllerlab.Plan) (ExecutionPlan, error) {
	if !validControllerPlan(plan) || plan.Capability != selectedControllerCapability(a.config) ||
		plan.BoundSource != a.config.Controller.Template.Source ||
		plan.RecipeID != a.config.Controller.Template.RecipeID ||
		plan.BoundSource.Repository != a.selection.Binding.SourceTarget.Repository ||
		plan.BoundSource.Commit != a.selection.Binding.SourceTarget.Commit ||
		plan.RecipeID != a.selection.Binding.Recipe.ID ||
		!slices.Contains(a.selection.Capabilities, string(plan.Capability)) {
		return ExecutionPlan{}, ErrNeedsAdapter
	}
	built, err := a.builder.FreezeBuildPlan(a.selection.Binding, string(plan.Capability), "sha256:"+controllerlab.PlanDigest(plan))
	if err != nil {
		return ExecutionPlan{}, classifyExecution(err)
	}
	return ExecutionPlan{Binding: built.Bind, Controller: &plan}, nil
}

func controllerRole(role environment.Role) controllerlab.Role {
	switch role {
	case environment.PublishedOriginal:
		return controllerlab.Original
	case environment.RebuiltControl:
		return controllerlab.Control
	case environment.Candidate:
		return controllerlab.Candidate
	default:
		return ""
	}
}

func (a *controllerExecutionAdapter) labForSubject(subject environment.Subject, id, evidence string, hooks controllerlab.Hooks) (*controllerlab.Adapter, error) {
	if !validDigest(evidence) || !pinnedControllerImage(subject.Image) || controllerRole(subject.Role) == "" {
		return nil, ErrInvalid
	}
	config := a.config.Controller
	config.Bindings = []controllerlab.ImageBinding{{
		ID: id, Role: controllerRole(subject.Role), Source: config.Template.Source, RecipeID: config.Template.RecipeID,
		Image: subject.Image, EvidenceDigest: strings.TrimPrefix(evidence, "sha256:"),
	}}
	return a.newLab(config, hooks)
}

func (a *controllerExecutionAdapter) labForOperation(session *Session, state *pipelineState, operation *executionOperation, evidence string) (*controllerlab.Adapter, error) {
	hooks := controllerHooks(session, state, operation, false)
	accept := hooks.Acceptance
	hooks.Acceptance = func(ctx context.Context, mutation controllerlab.Mutation) error {
		if err := a.verifyControllerLease(ctx, session, state, false); err != nil {
			return err
		}
		return accept(ctx, mutation)
	}
	persist := hooks.PersistState
	var lab *controllerlab.Adapter
	hooks.PersistState = func(ctx context.Context, revision uint64, next controllerlab.State) error {
		conclusive := next.Outcome == controllerlab.Reproduced || next.Outcome == controllerlab.Protected
		if next.Phase == controllerlab.Cleaning && operation.Controller.State.Phase != controllerlab.Cleaning && conclusive {
			if lab == nil || lab.ValidateRuntime(ctx, next) != nil {
				return ErrUnknown
			}
		}
		return persist(ctx, revision, next)
	}
	var err error
	lab, err = a.labForSubject(*operation.Subject, operation.ID, evidence, hooks)
	return lab, err
}

func jsonIdentity(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return Digest(raw)
}
