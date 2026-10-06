package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/distribution/reference"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	remediationagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/environment"
	remediationservice "github.com/orka-agents/orka/internal/remediation/service"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
)

type remediationOptions struct {
	Enabled                      bool
	Namespace                    string
	PolicyFile                   string
	StorePath                    string
	AIWorkerImage                string
	KubeClient                   kubernetes.Interface
	PrivateNamespaceAcknowledged bool
	ACPRuntimeEnabled            bool
	ACPRuntimeNamespace          string
	CopilotRuntimeImage          string
	ProviderProxyBaseURL         string
	ProviderProxyNamespace       string
	IntakeRetention              time.Duration
	IntakeRetentionInterval      time.Duration
}

type remediationManager interface {
	GetClient() client.Client
	GetAPIReader() client.Reader
	Add(manager.Runnable) error
}

type remediationControllerStore interface {
	store.RemediationRunStore
	store.ResultStore
	RemediationStoreInitialized(context.Context) (bool, error)
	CancelActiveRemediationRuns(context.Context, string, time.Time) (int64, error)
}

func setupRemediationService(
	ctx context.Context, mgr remediationManager, storage remediationControllerStore, options remediationOptions,
) (*remediationservice.Service, error) {
	if storage == nil {
		return nil, errors.New("remediation persistence is unavailable")
	}
	var policies []remediationservice.Policy
	if options.Enabled {
		var err error
		policies, err = loadRemediationPolicies(options)
		if err != nil {
			return nil, err
		}
	} else {
		initialized, err := storage.RemediationStoreInitialized(ctx)
		if err != nil {
			return nil, fmt.Errorf("detect retained remediation state: %w", err)
		}
		if !initialized {
			return nil, nil
		}
		// Disabling admission must not strand accepted work, including runs
		// paused for approval. Their frozen policies retain cleanup authority.
		if _, err := storage.CancelActiveRemediationRuns(ctx, options.Namespace, time.Now().UTC()); err != nil {
			return nil, fmt.Errorf("request retained remediation cleanup: %w", err)
		}
	}
	if mgr == nil || mgr.GetClient() == nil || mgr.GetAPIReader() == nil {
		return nil, errors.New("remediation Kubernetes clients are unavailable")
	}
	kubeClient, reader := mgr.GetClient(), mgr.GetAPIReader()
	copilotAgents := map[string]remediationagent.CopilotConfig{}
	for _, policy := range policies {
		if policy.ProposalBackend != remediationpolicy.CopilotBackend {
			continue
		}
		if err := validateRemediationCopilotBoundary(options, policy.Copilot); err != nil {
			return nil, err
		}
		if prior, exists := copilotAgents[policy.AgentName]; exists {
			first, _ := json.Marshal(prior)
			second, _ := json.Marshal(policy.Copilot)
			if string(first) != string(second) {
				return nil, errors.New("one proposal Agent cannot select different model boundaries")
			}
		}
		copilotAgents[policy.AgentName] = *policy.Copilot
	}
	pipeline := &remediationservice.Pipeline{
		Source: source.Client{}, Environments: remediationservice.Catalog{}, PollInterval: time.Second,
		Agents: func(namespace, name string, accepted func(context.Context, remediationagent.Result) error,
		) remediationservice.ProposalClient {
			base := remediationagent.KubernetesClient{Client: kubeClient, Reader: reader, Results: storage,
				Namespace: namespace, AgentName: name, OnAccepted: accepted}
			selected := remediationagent.ControllerClient{Native: base}
			if configured, exists := copilotAgents[name]; exists {
				selected.Copilot = &remediationagent.CopilotClient{Client: kubeClient, Reader: reader, Results: storage,
					Namespace: namespace, AgentName: name, Config: configured, OnAccepted: accepted}
			}
			return selected
		},
	}
	service, err := remediationservice.New(ctx, remediationservice.Config{
		Namespace: options.Namespace, Policies: policies, Store: storage, Processor: pipeline,
		AdmissionDisabled: !options.Enabled, Workers: 2, DispatchReader: reader,
		Authorize:       remediationservice.KubernetesAuthorizer(options.KubeClient),
		IntakeRetention: options.IntakeRetention, IntakeRetentionInterval: options.IntakeRetentionInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize remediation service: %w", err)
	}
	if err := mgr.Add(service); err != nil {
		return nil, fmt.Errorf("register remediation service: %w", err)
	}
	return service, nil
}

func validateRemediationCopilotBoundary(options remediationOptions, configured *remediationagent.CopilotConfig) error {
	if !options.ACPRuntimeEnabled || configured == nil ||
		configured.RuntimeNamespace != options.ACPRuntimeNamespace || configured.Image != options.CopilotRuntimeImage ||
		configured.ProxyEndpoint != options.ProviderProxyBaseURL ||
		configured.ProxyNamespace != options.ProviderProxyNamespace ||
		!remediationpolicy.ValidCopilotProxyEndpoint(options.ProviderProxyBaseURL) {
		return errors.New("copilot remediation requires the configured ACP image, runtime namespace, and proxy boundary")
	}
	return nil
}

func remediationDispatchValidator(service *remediationservice.Service) func(
	context.Context, *corev1alpha1.Task, *corev1alpha1.Agent, *corev1alpha1.Provider,
) error {
	if service != nil {
		return service.DispatchValidator
	}
	return func(context.Context, *corev1alpha1.Task, *corev1alpha1.Agent, *corev1alpha1.Provider) error {
		return remediationservice.ErrDisabled
	}
}

func loadRemediationPolicies(options remediationOptions) ([]remediationservice.Policy, error) {
	if !options.PrivateNamespaceAcknowledged {
		return nil, errors.New("remediation requires private namespace, Task, Secret, audit, and datastore access")
	}
	policies, err := remediationservice.LoadPolicies(options.PolicyFile)
	if err != nil {
		return nil, err
	}
	image := options.AIWorkerImage
	allCopilot := len(policies) > 0
	for _, policy := range policies {
		allCopilot = allCopilot && policy.ProposalBackend == remediationpolicy.CopilotBackend
	}
	if allCopilot {
		image = options.CopilotRuntimeImage
	}
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return nil, errors.New("remediation requires a reviewed, digest-pinned AI worker supporting memory opt-out")
	}
	pinned, ok := named.(reference.Digested)
	if !ok || named.String() != image || !remediationpolicy.ValidDigest(pinned.Digest().String()) {
		return nil, errors.New("remediation requires a reviewed, digest-pinned AI worker supporting memory opt-out")
	}
	root, err := remediationStoreRoot(options.StorePath)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(options.PolicyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("remediation requires a private operator policy file")
	}
	for _, policy := range policies {
		if policy.Namespace != options.Namespace {
			return nil, errors.New("remediation policy must use the controller watch namespace")
		}
		if err := validateRemediationAdapterRoots(root, policy); err != nil {
			return nil, err
		}
		if err := remediationservice.ValidateAdapters(policy); err != nil {
			return nil, fmt.Errorf("validate remediation adapter catalog: %w", err)
		}
	}
	return policies, nil
}

func remediationStoreRoot(storePath string) (string, error) {
	if !filepath.IsAbs(storePath) || filepath.Clean(storePath) != storePath ||
		strings.ContainsAny(storePath, "?\x00") {
		return "", errors.New("remediation requires an absolute persistent SQLite path")
	}
	root := filepath.Dir(storePath)
	if root == "/" || root == "/tmp" || strings.HasPrefix(root, "/tmp/") ||
		root == "/var/tmp" || strings.HasPrefix(root, "/var/tmp/") {
		return "", errors.New("remediation requires a dedicated persistent data directory")
	}
	resolved, err := filepath.EvalSymlinks(storePath)
	if err != nil || resolved != storePath {
		return "", errors.New("remediation SQLite path must exist without symlinks")
	}
	file, err := os.Lstat(storePath)
	if err != nil || !file.Mode().IsRegular() {
		return "", errors.New("remediation requires a persistent SQLite file")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", errors.New("remediation data directory must be private and owner-accessible (0700)")
	}
	return root, nil
}

func validateRemediationAdapterRoots(root string, policy remediationservice.Policy) error {
	for _, adapter := range policy.Adapters {
		var config environment.Config
		switch adapter.Kind {
		case "dalec-http":
			if err := json.Unmarshal(adapter.Configuration, &config); err != nil {
				return remediationservice.ErrPolicy
			}
		case "dalec-keda-events":
			var controller remediationservice.ControllerAdapterConfig
			if err := json.Unmarshal(adapter.Configuration, &controller); err != nil {
				return remediationservice.ErrPolicy
			}
			config = controller.BuildEnvironment
		default:
			return remediationservice.ErrNeedsAdapter
		}
		paths := []string{config.OutputRoot}
		if config.TemporaryRoot != "" {
			paths = append(paths, config.TemporaryRoot)
		}
		for _, repository := range config.Repositories {
			paths = append(paths, repository.RecipeRoot)
			if repository.SourceRoot != "" {
				paths = append(paths, repository.SourceRoot)
			}
		}
		for _, path := range paths {
			if !remediationPersistentChild(root, path) {
				return errors.New("remediation adapter directories must exist beneath the private persistent data root")
			}
		}
	}
	return nil
}

func remediationPersistentChild(root, path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
