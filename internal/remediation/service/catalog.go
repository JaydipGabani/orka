package service

import (
	"context"
	"errors"
	"slices"
	"strings"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/investigate"
)

// Catalog constructs adapters only from the immutable operator policy stored
// with the run. A later policy reload does not remove cleanup authority.
type Catalog struct{}

const (
	httpAdapterKind    = "dalec-http"
	processRequirement = "process"
)

func (Catalog) SourceHints(ctx context.Context, policy Policy) ([]investigate.SourceCatalogEntry, error) {
	var hints []investigate.SourceCatalogEntry
	seen := make(map[investigate.SourceCatalogEntry]bool)
	for _, configured := range policy.Adapters {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		adapter, err := catalogAdapter(configured)
		if err != nil {
			return nil, err
		}
		for _, choice := range adapter.RecipeChoices() {
			if !slices.Contains(configured.Repositories, choice.SourceTarget.Repository) {
				continue
			}
			contract := ""
			if configured.Kind == controllerAdapterKind {
				controller, err := decodeControllerPolicy(configured)
				if err != nil {
					return nil, err
				}
				if choice.ID != controller.Controller.Template.RecipeID ||
					choice.SourceTarget.Repository != controller.Controller.Template.Source.Repository ||
					choice.SourceTarget.Commit != controller.Controller.Template.Source.Commit {
					continue
				}
				if selectedControllerCapability(controller) == controllerlab.KEDAEventPublishing {
					contract = eventPublishingVerificationContract
				}
			}
			hint := investigate.SourceCatalogEntry{
				Repository: choice.SourceTarget.Repository, Commit: choice.SourceTarget.Commit,
				Version: choice.Version, Revision: choice.Revision,
				VerificationContract: contract,
			}
			if !seen[hint] {
				seen[hint] = true
				hints = append(hints, hint)
			}
		}
	}
	return hints, nil
}

func (Catalog) Select(ctx context.Context, policy Policy, source investigate.Plan) (AdapterSelection, ExecutionAdapter, error) {
	if err := ctx.Err(); err != nil {
		return AdapterSelection{}, nil, err
	}
	coordinated, err := controllerCoordinatedClusters(policy)
	if err != nil {
		return AdapterSelection{}, nil, err
	}
	floorCapabilities, floorRequirements, err := catalogSourceFloor(policy, source.Target.Repository.URL, source.Target.Commit)
	if err != nil {
		return AdapterSelection{}, nil, err
	}
	source.Requirements = slices.Clone(source.Requirements)
	for _, requirement := range floorRequirements {
		source.Requirements = append(source.Requirements, pv.EnvironmentRequirement{Kind: requirement, Name: "operator-floor"})
	}
	var selection *AdapterSelection
	var selectedPolicy AdapterPolicy
	var selectedBuilder *environment.Adapter
	for _, configured := range policy.Adapters {
		if !slices.Contains(configured.Repositories, source.Target.Repository.URL) {
			continue
		}
		adapter, err := catalogAdapter(configured)
		if err != nil {
			return AdapterSelection{}, nil, err
		}
		choices := matchingCatalogChoices(adapter, source.Target.Repository.URL, source.Target.Commit)
		if configured.Kind == controllerAdapterKind {
			config, err := decodeControllerPolicy(configured)
			if err != nil {
				return AdapterSelection{}, nil, err
			}
			choices = slices.DeleteFunc(choices, func(choice environment.RecipeChoice) bool {
				return choice.ID != config.Controller.Template.RecipeID ||
					choice.SourceTarget.Repository != config.Controller.Template.Source.Repository ||
					choice.SourceTarget.Commit != config.Controller.Template.Source.Commit
			})
		}
		if len(choices) == 0 {
			continue
		}
		if len(choices) != 1 {
			return AdapterSelection{}, nil, ErrNeedsInput
		}
		choice := choices[0]
		capabilities, requirements, err := catalogRequirements(configured, choice, source)
		if err != nil {
			continue
		}
		if slices.ContainsFunc(floorCapabilities, func(required string) bool { return !slices.Contains(capabilities, required) }) {
			continue
		}
		binding, err := adapter.BindRecipe(choice.SourceTarget, choice.ID)
		if err != nil {
			return AdapterSelection{}, nil, ErrNeedsAdapter
		}
		if selection != nil {
			return AdapterSelection{}, nil, ErrNeedsInput
		}
		selection = &AdapterSelection{
			Name: configured.Name, Kind: configured.Kind, Capabilities: capabilities, Binding: binding,
			Original:     environment.Subject{Role: environment.PublishedOriginal, Image: choice.OriginalImage},
			Requirements: requirements, RequiredCapabilities: slices.Clone(capabilities),
		}
		selectedPolicy, selectedBuilder = configured, adapter
	}
	if selection == nil {
		return AdapterSelection{}, nil, ErrNeedsAdapter
	}
	selection.ClusterExclusive, err = controllerSelectionExclusive(selectedPolicy, coordinated)
	if err != nil {
		return AdapterSelection{}, nil, err
	}
	execution, err := catalogExecution(selectedPolicy, *selection, selectedBuilder)
	return *selection, execution, err
}

// Repository/commit floors apply before adapter filtering. An unavailable
// required primitive must not make an unrelated HTTP adapter eligible.
func catalogSourceFloor(policy Policy, repository, commit string) ([]string, []string, error) {
	var capabilities, requirements []string
	for _, configured := range policy.Adapters {
		if configured.Kind != controllerAdapterKind || !slices.Contains(configured.Repositories, repository) {
			continue
		}
		config, err := decodeControllerPolicy(configured)
		if err != nil {
			return nil, nil, err
		}
		if config.Controller.Template.Source.Repository != repository || config.Controller.Template.Source.Commit != commit {
			continue
		}
		capabilities = append(capabilities, string(selectedControllerCapability(config)))
		capabilities = append(capabilities, config.RequiredCapabilities...)
		requirements = append(requirements, "cluster", "controller", "test-identity")
		requirements = append(requirements, config.RequiredRequirements...)
	}
	slices.Sort(capabilities)
	slices.Sort(requirements)
	return slices.Compact(capabilities), slices.Compact(requirements), nil
}

func (Catalog) Resume(ctx context.Context, policy Policy, selection AdapterSelection) (ExecutionAdapter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	coordinated, err := controllerCoordinatedClusters(policy)
	if err != nil {
		return nil, err
	}
	required, _, err := catalogSourceFloor(policy, selection.Binding.SourceTarget.Repository, selection.Binding.SourceTarget.Commit)
	if err != nil {
		return nil, err
	}
	if slices.ContainsFunc(required, func(capability string) bool { return !slices.Contains(selection.Capabilities, capability) }) {
		return nil, ErrNeedsAdapter
	}

	for _, configured := range policy.Adapters {
		if configured.Name != selection.Name ||
			(selection.Kind != "" && configured.Kind != selection.Kind) ||
			(selection.Kind == "" && configured.Kind != httpAdapterKind) {
			continue
		}
		exclusive, err := controllerSelectionExclusive(configured, coordinated)
		if err != nil {
			return nil, err
		}
		if selection.ClusterExclusive != exclusive {
			return nil, ErrInvalid
		}
		adapter, err := catalogAdapter(configured)
		if err != nil {
			return nil, err
		}
		binding, err := adapter.BindRecipe(selection.Binding.SourceTarget, selection.Binding.Recipe.ID)
		if err != nil || binding != selection.Binding {
			return nil, ErrNeedsAdapter
		}
		for _, choice := range adapter.RecipeChoices() {
			if choice.ID == binding.Recipe.ID && choice.SourceTarget == binding.SourceTarget &&
				selection.Original == (environment.Subject{Role: environment.PublishedOriginal, Image: choice.OriginalImage}) {
				return catalogExecution(configured, selection, adapter)
			}
		}
		return nil, ErrNeedsAdapter
	}
	return nil, ErrNeedsAdapter
}

func catalogAdapter(policy AdapterPolicy) (*environment.Adapter, error) {
	var config environment.Config
	switch policy.Kind {
	case httpAdapterKind:
		if decodeObject(policy.Configuration, MaxPolicyBytes, &config) != nil {
			return nil, ErrPolicy
		}
	case controllerAdapterKind:
		controller, err := decodeControllerPolicy(policy)
		if err != nil {
			return nil, err
		}
		config = controller.BuildEnvironment
	default:
		return nil, ErrNeedsAdapter
	}
	if len(config.Repositories) == 0 {
		return nil, ErrPolicy
	}
	adapter, err := environment.New(config)
	if err != nil {
		if _, ok := errors.AsType[*environment.Error](err); ok {
			return nil, ErrNeedsAdapter
		}
		return nil, err
	}
	return adapter, nil
}

func matchingCatalogChoices(adapter *environment.Adapter, repository, commit string) []environment.RecipeChoice {
	var choices []environment.RecipeChoice
	for _, choice := range adapter.RecipeChoices() {
		if choice.SourceTarget.Repository == repository && choice.SourceTarget.Commit == commit {
			choices = append(choices, choice)
		}
	}
	return choices
}

func catalogRequirements(configured AdapterPolicy, choice environment.RecipeChoice, source investigate.Plan) ([]string, []string, error) {
	capability := environment.HTTPExact
	requirements := []string{processRequirement}
	if configured.Kind == controllerAdapterKind {
		var config ControllerAdapterConfig
		if (len(configured.Configuration) != 0 && decodeObject(configured.Configuration, MaxPolicyBytes, &config) != nil) ||
			!validControllerCapability(config) {
			return nil, nil, ErrPolicy
		}
		capability = string(selectedControllerCapability(config))
		// Compiled controller observations cannot be downgraded to a process
		// check by omitting requirements from a model proposal.
		requirements = []string{processRequirement, "cluster", "controller", "test-identity"}
	}
	declared := append(slices.Clone(choice.SupportedChecks), choice.NeedsAdapterChecks...)
	if !slices.Contains(declared, capability) {
		return nil, nil, ErrNeedsAdapter
	}
	requiredCapabilities, operatorRequirements, err := controllerPolicyFloor(configured)
	if err != nil {
		return nil, nil, err
	}
	for _, required := range requiredCapabilities {
		if required != capability {
			return nil, nil, ErrNeedsAdapter
		}
	}
	for _, required := range operatorRequirements {
		if !slices.Contains(requirements, required) && required != "local-services" {
			return nil, nil, ErrNeedsAdapter
		}
		requirements = append(requirements, required)
	}
	for _, requirement := range source.Requirements {
		switch requirement.Kind {
		case processRequirement, "local-services":
		case "cluster", "controller", "test-identity":
			if configured.Kind != controllerAdapterKind {
				return nil, nil, ErrNeedsAdapter
			}
		default:
			return nil, nil, ErrNeedsAdapter
		}
		if requirement.Name == string(controllerlab.KEDARedisAuth) || requirement.Name == "redis" ||
			(strings.HasSuffix(requirement.Name, "-v1") && requirement.Name != capability) {
			return nil, nil, ErrNeedsAdapter
		}
		requirements = append(requirements, requirement.Kind)
	}
	slices.Sort(requirements)
	return []string{capability}, slices.Compact(requirements), nil
}

func catalogExecution(configured AdapterPolicy, selection AdapterSelection, adapter *environment.Adapter) (ExecutionAdapter, error) {
	if err := validateCatalogSelection(configured, selection, adapter.RecipeChoices()); err != nil {
		return nil, err
	}
	if configured.Kind == httpAdapterKind {
		return adapter, nil
	}
	config, err := decodeControllerPolicy(configured)
	if err != nil {
		return nil, err
	}
	if !adapter.HasDurableBuildBackend() {
		return nil, ErrNeedsAdapter
	}
	if err := adapter.ValidateBuildJobs(); err != nil {
		return nil, ErrNeedsAdapter
	}
	return newControllerExecutionAdapter(config, selection, adapter)
}

func validateCatalogSelection(configured AdapterPolicy, selection AdapterSelection, choices []environment.RecipeChoice) error {
	for _, choice := range choices {
		if choice.ID != selection.Binding.Recipe.ID || choice.SourceTarget != selection.Binding.SourceTarget {
			continue
		}
		capabilities, requirements, err := catalogRequirements(configured, choice, investigate.Plan{})
		if err != nil || !slices.Equal(selection.Capabilities, capabilities) ||
			(len(selection.RequiredCapabilities) != 0 && !slices.Equal(selection.RequiredCapabilities, capabilities)) {
			return ErrNeedsAdapter
		}
		if selection.Kind != "" && slices.ContainsFunc(requirements, func(required string) bool {
			return !slices.Contains(selection.Requirements, required)
		}) {
			return ErrNeedsAdapter
		}
		return nil
	}
	return ErrNeedsAdapter
}

func ValidateAdapters(policy Policy) error {
	if _, err := controllerCoordinatedClusters(policy); err != nil {
		return err
	}
	for _, configured := range policy.Adapters {
		var config = configured.Configuration
		if len(config) == 0 {
			return ErrPolicy
		}
		if _, err := catalogAdapter(configured); err != nil {
			return err
		}
	}
	return nil
}
