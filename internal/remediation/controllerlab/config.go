package controllerlab

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Adapter struct {
	config   Config
	digest   string
	kube     kubernetes.Interface
	custom   dynamic.Interface
	observer Observer
	hooks    Hooks
	now      func() time.Time
}

// New accepts only dedicated, operator-supplied clients. The observer interface
// is an injection seam for trusted tests/transports, never a model capability.
func New(config Config, clients Clients, hooks Hooks) (*Adapter, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, failure(NeedsAdapter, "invalid-operator-config")
	}
	var frozen Config
	if json.Unmarshal(data, &frozen) != nil {
		return nil, failure(NeedsAdapter, "invalid-operator-config")
	}
	if err := validateConfig(frozen); err != nil {
		return nil, err
	}
	if clients.Kubernetes == nil || clients.CustomResources == nil || clients.Observer == nil ||
		hooks.Acceptance == nil || hooks.PersistState == nil {
		return nil, failure(NeedsAdapter, "dedicated-clients-and-durable-hooks-required")
	}
	policy := frozen
	policy.Bindings = nil
	return &Adapter{
		config: frozen, digest: digest(struct {
			Domain string
			Config Config
		}{"orka.controllerlab.config.v4", policy}),
		kube: clients.Kubernetes, custom: clients.CustomResources, observer: clients.Observer,
		hooks: hooks, now: time.Now,
	}, nil
}

// NewForConfig constructs separate clients from an explicit operator REST config.
// It never falls back to the management client's in-cluster credentials. The
// constructor performs no network calls; Step does all bounded preflight work.
func NewForConfig(config Config, labConfig *rest.Config, hooks Hooks) (*Adapter, error) {
	if labConfig == nil {
		return nil, failure(NeedsAdapter, "dedicated-rest-config-required")
	}
	endpoint, err := url.Parse(labConfig.Host)
	if err != nil || endpoint.Scheme != httpsScheme || endpoint.Hostname() == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		labConfig.Insecure || labConfig.Proxy != nil {
		return nil, failure(NeedsAdapter, "verified-lab-api-tls-required")
	}
	cfg := rest.CopyConfig(labConfig)
	cfg.Timeout = 5 * time.Second
	cfg.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	httpClient, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return nil, failure(NeedsAdapter, "invalid-lab-client")
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return failure(OutsideScope, "lab-api-redirect-refused")
	}
	kube, err := kubernetes.NewForConfigAndClient(cfg, httpClient)
	if err != nil {
		return nil, failure(NeedsAdapter, "invalid-lab-client")
	}
	custom, err := dynamic.NewForConfigAndClient(cfg, httpClient)
	if err != nil {
		return nil, failure(NeedsAdapter, "invalid-lab-client")
	}
	dialer, err := newPodForwardDialer(cfg, kube)
	if err != nil {
		return nil, failure(NeedsAdapter, "invalid-observer-transport")
	}
	observer := &wireObserver{kube: kube, dialer: dialer}
	return New(config, Clients{Kubernetes: kube, CustomResources: custom, Observer: observer}, hooks)
}

func validateConfig(c Config) error {
	if !c.DedicatedClusterApproved || !digestPattern.MatchString(c.ClusterIdentity) ||
		len(c.NamespacePrefix) < 3 || len(c.NamespacePrefix) > 20 ||
		len(validation.IsDNS1123Label(c.NamespacePrefix)) != 0 ||
		strings.HasPrefix(c.NamespacePrefix, "kube-") || c.NamespacePrefix == "default" ||
		c.NamespacePrefix == "production" || c.NamespacePrefix == "prod" {
		return failure(OutsideScope, "isolated-namespace-scope-required")
	}
	if err := validateTemplate(c.Template); err != nil {
		return err
	}
	if c.EnableEventPublishing && c.Template.Source.Commit != kedaPublishingCommit {
		return failure(NeedsAdapter, "unsupported-publishing-source")
	}
	if err := validateRuntimeBounds(c); err != nil {
		return err
	}
	return validateBindings(c)
}

func validateTemplate(t ControllerRuntimeTemplate) error {
	if t.Family != "keda-v2" || !idPattern.MatchString(t.RecipeID) ||
		t.Source.Repository != "https://github.com/kedacore/keda" ||
		!commitPattern.MatchString(t.Source.Commit) ||
		t.ClusterWatchRole.Resource != clusterRoles || t.ClusterWatchRole.Namespace != "" ||
		t.ClusterWatchRole.UID == "" || len(validation.IsDNS1123Subdomain(t.ClusterWatchRole.Name)) != 0 {
		return failure(NeedsAdapter, "unapproved-runtime-template")
	}
	return nil
}

func validateRuntimeBounds(c Config) error {
	if c.DNS != (EgressEndpoint{}) {
		return failure(OutsideScope, "dns-egress-is-not-supported")
	}
	if !imagePattern.MatchString(c.ObserverImage) || !validResources(c.ObserverResources) || !validResources(c.Template.Resources) ||
		!validEndpoint(c.APIServer) {
		return failure(NeedsAdapter, "bounded-observer-and-network-config-required")
	}
	if c.StartupTimeout < 10*time.Second || c.StartupTimeout > 5*time.Minute ||
		c.ObservationWindow < 10*time.Second || c.ObservationWindow > 3*time.Minute ||
		c.TailWindow < 2*time.Second || c.TailWindow > 30*time.Second ||
		c.OperationTimeout < time.Second || c.OperationTimeout > 10*time.Second {
		return failure(NeedsAdapter, "invalid-time-bounds")
	}
	return nil
}

func validateBindings(c Config) error {
	if len(c.Bindings) == 0 || len(c.Bindings) > 64 {
		return failure(NeedsAdapter, "image-bindings-required")
	}
	seen := map[string]bool{}
	for _, b := range c.Bindings {
		if !idPattern.MatchString(b.ID) || seen[b.ID] || b.Source != c.Template.Source || b.RecipeID != c.Template.RecipeID ||
			!imagePattern.MatchString(b.Image) || !digestPattern.MatchString(b.EvidenceDigest) ||
			(b.Role != Original && b.Role != Control && b.Role != Candidate) {
			return failure(NeedsAdapter, "invalid-image-binding")
		}
		seen[b.ID] = true
	}
	return nil
}

func validEndpoint(endpoint EgressEndpoint) bool {
	p, err := netip.ParsePrefix(endpoint.CIDR)
	return err == nil && p.Bits() == p.Addr().BitLen() && !p.Addr().IsUnspecified() &&
		!p.Addr().IsMulticast() && endpoint.Port > 0 && endpoint.Port <= 65535
}

func validResources(r corev1.ResourceRequirements) bool {
	if len(r.Claims) != 0 || len(r.Requests) != 2 || len(r.Limits) != 2 {
		return false
	}
	for name, maximum := range map[corev1.ResourceName]resource.Quantity{
		corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("1Gi"),
	} {
		request, ok := r.Requests[name]
		limit, exists := r.Limits[name]
		if !ok || !exists || request.Sign() <= 0 || limit.Sign() <= 0 || request.Cmp(limit) > 0 || limit.Cmp(maximum) > 0 {
			return false
		}
	}
	return true
}
