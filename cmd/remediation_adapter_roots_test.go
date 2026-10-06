package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	remediationagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/buildjob"
	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	remediationservice "github.com/orka-agents/orka/internal/remediation/service"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type remediationRootsFixture struct {
	root    string
	outside string
	options remediationOptions
	policy  remediationservice.Policy
	config  remediationservice.ControllerAdapterConfig
}

func newRemediationRootsFixture(t *testing.T) remediationRootsFixture {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	cache := filepath.Join(filepath.Dir(cwd), ".cache")
	require.NoError(t, os.MkdirAll(cache, 0700))
	directory, err := os.MkdirTemp(cache, "remediation-roots-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(directory)) })
	root := filepath.Join(directory, "persistent")
	outside := filepath.Join(directory, "outside")
	for _, path := range []string{root, outside, filepath.Join(root, "builds"), filepath.Join(root, "work"),
		filepath.Join(root, "recipes"), filepath.Join(root, "source")} {
		require.NoError(t, os.MkdirAll(path, 0700))
	}
	storePath := filepath.Join(root, "orka.db")
	require.NoError(t, os.WriteFile(storePath, []byte("synthetic datastore"), 0600))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/kube-system" {
			http.Error(w, "unsupported synthetic API request", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
			ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "synthetic-cluster"},
		}); err != nil {
			t.Error("synthetic API response failed")
		}
	}))
	t.Cleanup(server.Close)
	kubeconfigPath := filepath.Join(root, "synthetic-kubeconfig")
	kubeconfig, err := clientcmd.Write(clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{"lab": {
			Server: server.URL,
			CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
			}),
		}},
		Contexts:  map[string]*clientcmdapi.Context{"lab": {Cluster: "lab", AuthInfo: "anonymous"}},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{"anonymous": {}}, CurrentContext: "lab",
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(kubeconfigPath, kubeconfig, 0600))
	sourceURL, commit := "https://github.com/kedacore/keda", strings.Repeat("a", 40)
	frontend := "registry.example.invalid/dalec@sha256:" + strings.Repeat("f", 64)
	recipe := fmt.Sprintf(`# syntax=%s
name: synthetic-keda
version: "2.17.1"
revision: "1"
sources:
  upstream:
    git:
      url: %s
      commit: %s
build:
  steps:
    - command: make build
x-build-extensions:
  build-targets:
    linux/container:
      platforms: [linux/amd64]
`, frontend, sourceURL, commit)
	recipeRoot := filepath.Join(root, "recipes")
	require.NoError(t, os.WriteFile(filepath.Join(recipeRoot, "recipe.yml"), []byte(recipe), 0600))
	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
	}
	config := remediationservice.ControllerAdapterConfig{
		BuildEnvironment: environment.Config{
			OutputRoot: filepath.Join(root, "builds"), TemporaryRoot: filepath.Join(root, "work"),
			SyntheticScope: "loader-fixture",
			Kubernetes: &environment.KubernetesConfig{
				Kubeconfig: kubeconfigPath, Context: "lab", ObserverCIDRs: []string{"192.0.2.1/32"},
			},
			BuildJobs: &environment.BuildJobsConfig{
				Namespace: "private-builds", WorkerImage: "registry.example.invalid/build-client@sha256:" + strings.Repeat("c", 64),
				BuildKitAddress:  "tcp://buildkit.private-builds.svc:1234",
				OutputRepository: "registry.private-builds.svc:5000/remediation",
				WorkerContext:    "dalec-worker", RegistrySecretName: "private-registry",
				TLS: &buildjob.TLS{
					CASecretName: "build-ca", ClientSecretName: "build-client", ServerName: "buildkit.private-builds.svc",
				},
			},
			Repositories: []environment.RepositoryPolicy{{
				ID: "keda", URL: sourceURL, RecipeRepository: "https://github.com/example/recipes",
				RecipeRoot: recipeRoot, SourceRoot: filepath.Join(root, "source"),
				CheckCapabilities: []string{string(controllerlab.KEDANamespaceEvents)},
				Recipes: []environment.RecipePolicy{{
					ID: "keda-build", Commit: strings.Repeat("b", 40), Path: "recipe.yml",
					Files:          map[string]string{"recipe.yml": remediationservice.Digest([]byte(recipe))},
					UpstreamSource: "upstream", Target: "linux/container", Platform: "linux/amd64", FrontendImage: frontend,
					WorkerImage:   "registry.example.invalid/worker@sha256:" + strings.Repeat("e", 64),
					OriginalImage: "registry.example.invalid/original@sha256:" + strings.Repeat("1", 64),
				}},
			}},
		},
		Kubeconfig: kubeconfigPath, Context: "lab", ClusterUID: "synthetic-cluster",
		ProbeImage: "registry.example.invalid/probe@sha256:" + strings.Repeat("d", 64),
		Controller: controllerlab.Config{
			DedicatedClusterApproved: true, ClusterIdentity: controllerlab.ClusterIdentity("synthetic-cluster"),
			NamespacePrefix: "controller-test",
			Template: controllerlab.ControllerRuntimeTemplate{
				RecipeID: "keda-build", Family: "keda-v2", Source: controllerlab.BoundSource{Repository: sourceURL, Commit: commit},
				ClusterWatchRole: controllerlab.ObjectRef{
					Resource: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"},
					Name:     "preinstalled-watch-role", UID: "watch-role-uid",
				}, Resources: resources,
			},
			ObserverImage: "registry.example.invalid/observer@sha256:" + strings.Repeat("c", 64), ObserverResources: resources,
			APIServer:      controllerlab.EgressEndpoint{CIDR: "10.96.0.1/32", Port: 443},
			StartupTimeout: time.Minute, OperationTimeout: 10 * time.Second,
			ObservationWindow: 10 * time.Second, TailWindow: 2 * time.Second,
		},
	}
	copilot := &remediationagent.CopilotConfig{
		Image: "registry.example.invalid/copilot@sha256:" + strings.Repeat("9", 64), RuntimeNamespace: "private-runtime",
		ProxyNamespace: "proxy", ProxyEndpoint: "http://approved-proxy.proxy.svc:8080",
		IdentityReferences: []remediationagent.CopilotIdentityReference{
			{Kind: "ConfigMap", Namespace: "proxy", Name: "model-route"},
			{Kind: "Secret", Namespace: "proxy", Name: "model-identity"},
		},
	}
	return remediationRootsFixture{
		root: root, outside: outside, config: config,
		options: remediationOptions{
			Namespace: "testing", PolicyFile: filepath.Join(root, "policy.json"), StorePath: storePath,
			PrivateNamespaceAcknowledged: true, CopilotRuntimeImage: copilot.Image,
		},
		policy: remediationservice.Policy{
			Version: 1, Name: "approved", Namespace: "testing", AgentName: "copilot",
			ProposalBackend:    remediationpolicy.CopilotBackend,
			Copilot:            copilot,
			Repositories:       []string{sourceURL},
			MaxDurationSeconds: 120,
			MaxCandidates:      2,
			MaxModelCalls:      8,
		},
	}
}

func (f remediationRootsFixture) writePolicy(t *testing.T, kind string, config any) {
	t.Helper()
	raw, err := json.Marshal(config)
	require.NoError(t, err)
	policy := f.policy
	policy.Adapters = []remediationservice.AdapterPolicy{{
		Name: "synthetic", Kind: kind, Repositories: policy.Repositories, Configuration: raw,
	}}
	document, err := json.Marshal(struct {
		Policies []remediationservice.Policy `json:"policies"`
	}{Policies: []remediationservice.Policy{policy}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.options.PolicyFile, document, 0600))
}

func TestRemediationLoaderAcceptsNestedControllerRoots(t *testing.T) {
	t.Parallel()
	f := newRemediationRootsFixture(t)
	f.writePolicy(t, "dalec-keda-events", f.config)
	policies, err := loadRemediationPolicies(f.options)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.Equal(t, remediationpolicy.CopilotBackend, policies[0].ProposalBackend)
	f.writePolicy(t, "dalec-http", f.config.BuildEnvironment)
	_, err = loadRemediationPolicies(f.options)
	require.NoError(t, err, "flat HTTP roots must remain supported")
}

func TestRemediationLoaderRejectsNestedControllerRootEscapes(t *testing.T) {
	for _, field := range []string{"output", "temporary", "recipe", "source", "symlink", "root-itself"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			f := newRemediationRootsFixture(t)
			switch field {
			case "output":
				f.config.BuildEnvironment.OutputRoot = f.outside
			case "temporary":
				f.config.BuildEnvironment.TemporaryRoot = f.outside
			case "recipe":
				f.config.BuildEnvironment.Repositories[0].RecipeRoot = f.outside
			case "source":
				f.config.BuildEnvironment.Repositories[0].SourceRoot = f.outside
			case "symlink":
				link := filepath.Join(f.root, "escape")
				require.NoError(t, os.Symlink(f.outside, link))
				f.config.BuildEnvironment.OutputRoot = link
			case "root-itself":
				f.config.BuildEnvironment.OutputRoot = f.root
			}
			f.writePolicy(t, "dalec-keda-events", f.config)
			_, err := loadRemediationPolicies(f.options)
			require.EqualError(t, err, "remediation adapter directories must exist beneath the private persistent data root")
		})
	}
}
