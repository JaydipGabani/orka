package service

import (
	"context"

	"github.com/orka-agents/orka/internal/remediation/environment"
)

func (Catalog) Cleanup(ctx context.Context, policy Policy, selection AdapterSelection) (ExecutionAdapter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, configured := range policy.Adapters {
		if configured.Name != selection.Name {
			continue
		}
		if configured.Kind == controllerAdapterKind {
			config, err := decodeControllerPolicy(configured)
			if err != nil {
				return nil, err
			}
			builder, err := environment.NewForCleanup(config.BuildEnvironment)
			if err != nil {
				return nil, err
			}
			return newControllerExecutionAdapter(config, selection, builder)
		}
		if configured.Kind != httpAdapterKind {
			return nil, ErrNeedsAdapter
		}
		var config environment.Config
		if decodeObject(configured.Configuration, MaxPolicyBytes, &config) != nil {
			return nil, ErrPolicy
		}
		return environment.NewForCleanup(config)
	}
	return nil, ErrNeedsAdapter
}
