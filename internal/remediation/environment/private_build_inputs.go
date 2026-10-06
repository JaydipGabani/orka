package environment

import (
	"maps"

	"github.com/orka-agents/orka/internal/remediation/buildjob"
)

func (a *Adapter) privateBuildInputsApproved(input buildjob.Input) bool {
	if !a.HasPrivateBuildBoundary() {
		return false
	}
	for _, entry := range a.catalog {
		recipe := entry.bind.Recipe
		if recipe.Path == input.RecipePath && recipe.FrontendImage == input.Frontend &&
			recipe.WorkerImage == input.Worker && recipe.Target == input.Target && recipe.Platform == input.Platform &&
			maps.Equal(entry.buildOnly, input.BuildOnlyInputs) {
			return true
		}
	}
	return false
}
