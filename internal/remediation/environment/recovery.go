package environment

import (
	"context"
	"net/http"
	"slices"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (a *Adapter) operationPolicy() OperationPolicy {
	policy := OperationPolicy{
		ClusterIdentity: a.clusterIdentity, Limits: a.config.Limits, SyntheticScope: a.config.SyntheticScope,
	}
	if a.config.Kubernetes != nil {
		policy.ObserverCIDRs = slices.Clone(a.config.Kubernetes.ObserverCIDRs)
	}
	if a.config.Isolation != nil {
		policy.ProbeImage = a.config.Isolation.ProbeImage
	}
	return policy
}

func operationPolicyDigest(policy OperationPolicy) string {
	return jsonDigest(struct {
		Domain string
		Policy OperationPolicy
	}{"orka.remediation.environment.execution-policy.v1", policy})
}

func (a *Adapter) forReceipt(receipt Receipt) (*Adapter, error) {
	policy := receipt.Policy
	if !digestPattern.MatchString(policy.ClusterIdentity) || policy.ClusterIdentity != a.clusterIdentity ||
		!idPattern.MatchString(policy.SyntheticScope) || receipt.ConfigDigest != operationPolicyDigest(policy) {
		return nil, failure(Unknown, "recorded-lab-policy-mismatch")
	}
	if validateLimits(policy.Limits) != nil ||
		validateObserverPolicy(KubernetesConfig{ObserverCIDRs: policy.ObserverCIDRs}) != nil {
		return nil, failure(Unknown, "invalid-recorded-operation-policy")
	}
	bind := receipt.Request.Plan.Bind
	if len(receipt.Request.Plan.Resources) > 8 || len(receipt.Request.Plan.Namespaces) > 4 ||
		len(receipt.Request.Plan.Checks) > 64 {
		return nil, failure(Unknown, "invalid-recorded-plan-bounds")
	}
	ports := make([]int32, 0, len(receipt.Request.Plan.Resources))
	for _, workload := range receipt.Request.Plan.Resources {
		if workload.HTTP == nil || workload.HTTP.Port < 1024 || workload.HTTP.Port > 65535 {
			return nil, failure(Unknown, "invalid-recorded-http-resource")
		}
		ports = append(ports, workload.HTTP.Port)
	}
	frozen := *a
	frozen.config = a.config
	frozen.config.Limits, frozen.config.SyntheticScope = policy.Limits, policy.SyntheticScope
	frozen.config.Kubernetes = &KubernetesConfig{ObserverCIDRs: slices.Clone(policy.ObserverCIDRs)}
	frozen.config.Isolation = nil
	if policy.ProbeImage != "" {
		frozen.config.Isolation = &IsolationConfig{ProbeImage: policy.ProbeImage}
	}
	if err := validateIsolationConfig(frozen.config); err != nil {
		return nil, err
	}
	frozen.config.AllowedGVKs = []schema.GroupVersionKind{{Version: "v1", Kind: podKind}}
	frozen.config.Repositories = []RepositoryPolicy{{
		ID: "recorded", URL: bind.SourceTarget.Repository, RecipeRepository: bind.Recipe.Repository,
		CheckCapabilities: []string{HTTPExact}, HTTPPorts: ports,
		Recipes: []RecipePolicy{{
			ID: bind.Recipe.ID, Commit: bind.Recipe.Commit, Path: bind.Recipe.Path,
			Files:  map[string]string{bind.Recipe.Path: bind.Recipe.ContentDigest},
			Target: bind.Recipe.Target, Platform: bind.Recipe.Platform,
			FrontendImage: bind.Recipe.FrontendImage, WorkerImage: bind.Recipe.WorkerImage,
		}},
	}}
	frozen.catalog = []catalogEntry{{choice: RecipeChoice{ID: bind.Recipe.ID, SourceTarget: bind.SourceTarget}, bind: bind}}
	client := *a.http
	client.Timeout = policy.Limits.ProbeTimeout
	if transport, ok := a.http.Transport.(*http.Transport); ok {
		cloned := transport.Clone()
		cloned.ResponseHeaderTimeout = policy.Limits.ProbeTimeout
		client.Transport = cloned
	}
	frozen.http = &client
	return &frozen, nil
}

func findRequestRecord(state *runJournal, request Request) (*operationRecord, error) {
	request.RequireExisting, request.Expected = false, nil
	var found *operationRecord
	for _, record := range state.Operations {
		if record != nil && sameJSON(record.Receipt.Request, request) {
			if found != nil {
				return nil, failure(Unknown, "ambiguous-recorded-operation")
			}
			found = record
		}
	}
	return found, nil
}

func (a *Adapter) recoverRequest(ctx context.Context, request Request) (Receipt, error) {
	if !idPattern.MatchString(request.RunID) || !idPattern.MatchString(request.OperationID) {
		return Receipt{}, failure(NeedsAdapter, "invalid-operation-request")
	}
	if a.kube == nil {
		return Receipt{}, failure(NeedsAdapter, "dedicated-kubernetes-adapter-required")
	}
	unlock, err := a.lock(ctx, runName(request.RunID))
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	state, err := a.loadRun(request.RunID, request.Plan.Bind)
	if err != nil {
		return Receipt{}, err
	}
	record, err := findRequestRecord(state, request)
	if err != nil {
		return Receipt{}, err
	}
	if record == nil {
		intent, err := a.Intent(request)
		if err != nil {
			return Receipt{}, err
		}
		if intent.Policy.ProbeImage != "" {
			return intent, failure(Unknown, "isolation-recovery-receipt-required")
		}
		if err := a.validateSubject(request, state); err != nil {
			return intent, err
		}
		if err := a.admitOperation(state, intent.OperationDigest); err != nil {
			return intent, err
		}
		record = &operationRecord{Receipt: intent, Observation: Observation{Phase: Starting}}
		state.Operations[intent.OperationDigest] = record
		if err := a.saveRun(request.RunID, state); err != nil {
			return intent, err
		}
	}
	return a.recoverRecord(ctx, request, record, state)
}

func (a *Adapter) recoverRecord(ctx context.Context, request Request, record *operationRecord, state *runJournal) (Receipt, error) {
	if err := a.validateReceipt(record.Receipt); err != nil {
		return record.Receipt, err
	}
	if err := requireExpectedObjects(request.Expected, &record.Receipt); err != nil {
		return record.Receipt, err
	}
	if record.Observation.CleanupComplete {
		return record.Receipt, nil
	}
	if record.Observation.Phase == Cleaning {
		return record.Receipt, failure(Unknown, "operation-cleanup-in-progress")
	}
	frozen, err := a.forReceipt(record.Receipt)
	if err != nil {
		return record.Receipt, err
	}
	if record.Receipt.Policy.ProbeImage != "" {
		return frozen.startIsolated(ctx, record, state)
	}
	bounded, cancel := context.WithDeadline(ctx, record.Receipt.Deadline)
	defer cancel()
	for i := range record.Receipt.Objects {
		if err := frozen.ensureObject(bounded, &record.Receipt, i, true); err != nil {
			if persistErr := a.saveRun(request.RunID, state); persistErr != nil {
				return record.Receipt, failure(Unknown, "resource-acknowledgement-not-persisted")
			}
			if bounded.Err() != nil && ctx.Err() == nil {
				frozen.settleFailedStart(ctx, record, state)
			}
			return record.Receipt, err
		}
		if err := a.saveRun(request.RunID, state); err != nil {
			return record.Receipt, failure(Unknown, "resource-acknowledgement-not-persisted")
		}
	}
	record.Observation.Phase = Running
	return record.Receipt, a.saveRun(request.RunID, state)
}

func requireExpectedObjects(expected []ObjectIdentity, receipt *Receipt) error {
	for _, required := range expected {
		matched := false
		for i, actual := range receipt.Objects {
			if actual.Kind != required.Kind || actual.Name != required.Name || actual.Namespace != required.Namespace {
				continue
			}
			if required.UID == "" || (actual.UID != "" && actual.UID != required.UID) || actual.Image != required.Image {
				return failure(Unknown, "expected-object-uid-mismatch")
			}
			receipt.Objects[i].UID, matched = required.UID, true
		}
		if !matched {
			return failure(Unknown, "invalid-expected-object-identity")
		}
	}
	return nil
}
