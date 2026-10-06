package environment

import (
	"encoding/json"
	"slices"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
)

// FreezeBuildPlan authorizes only a durable build, not subject execution. The
// trusted caller must admit and freeze the external observation contract first.
func (a *Adapter) FreezeBuildPlan(binding Bind, approvedCapability, observationContractDigest string) (Plan, error) {
	plan := Plan{
		Version: Version, Bind: binding,
		ExternalObservation: &ExternalObservation{
			Capability: approvedCapability, ContractDigest: observationContractDigest,
		},
	}
	if err := a.validateExternalBuildPlan(plan); err != nil {
		return Plan{}, err
	}
	expected := ChecksDigest(plan)
	if binding.ChecksDigest != "" && binding.ChecksDigest != expected {
		return Plan{}, failure(NeedsAdapter, "checks-digest-mismatch")
	}
	plan.Bind.ChecksDigest = expected
	return plan, nil
}

func (a *Adapter) validateFrozenBuild(plan Plan) error {
	if plan.ExternalObservation == nil {
		return a.validateFrozen(plan)
	}
	if !digestPattern.MatchString(plan.Bind.ChecksDigest) || ChecksDigest(plan) != plan.Bind.ChecksDigest {
		return failure(NeedsAdapter, "frozen-checks-required")
	}
	return a.validateExternalBuildPlan(plan)
}

func (a *Adapter) validateExternalBuildPlan(plan Plan) error {
	repository, _, err := a.policy(plan.Bind)
	if err != nil {
		return err
	}
	descriptor := plan.ExternalObservation
	raw, err := json.Marshal(plan)
	if err != nil || int64(len(raw)) > a.config.Limits.MaxPlanBytes ||
		plan.Version != Version || descriptor == nil ||
		len(plan.Namespaces) != 0 || len(plan.Resources) != 0 || len(plan.Checks) != 0 ||
		!a.HasDurableBuildBackend() || !commitPattern.MatchString(plan.Bind.SourceTarget.Commit) ||
		(descriptor.Capability != string(controllerlab.KEDANamespaceEvents) &&
			descriptor.Capability != string(controllerlab.KEDAEventPublishing)) ||
		!slices.Contains(repository.CheckCapabilities, descriptor.Capability) ||
		!digestPattern.MatchString(descriptor.ContractDigest) {
		return failure(NeedsAdapter, "unapproved-external-observation-contract")
	}
	return nil
}
