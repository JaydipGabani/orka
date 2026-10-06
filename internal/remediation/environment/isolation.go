package environment

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/orka-agents/orka/internal/remediation/isolation"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	isolationPollInterval = 25 * time.Millisecond
	restrictedPolicy      = "restricted"
)

// Call this from the constructor after ordinary config/default validation;
// Intent also enforces it before any namespace or workload is admitted.
func validateIsolationConfig(config Config) error {
	if config.Isolation == nil {
		return nil
	}
	if config.Kubernetes == nil || config.Limits.MaxNamespaces < 2 || !immutableImage(config.Isolation.ProbeImage) {
		return failure(NeedsAdapter, "invalid-runtime-isolation-configuration")
	}
	return nil
}

// Use this for model plan bounds. The reserved control namespace is part of the
// execution namespace budget, not an additional model-selectable allowance.
func modelNamespaceLimit(config Config) int {
	limit := config.Limits.MaxNamespaces
	if config.Isolation != nil {
		limit--
	}
	return limit
}

func isolationControlName(receipt Receipt) string {
	// Slash is forbidden in model namespace aliases, so the private control
	// namespace cannot collide with a model-selected namespace.
	return namespaceName(receipt, "isolation/control")
}

func namespaceIdentity(receipt Receipt, name string) isolation.SubjectNamespace {
	for _, object := range receipt.Objects {
		if object.Kind == namespaceKind && object.Name == name {
			return isolation.SubjectNamespace{Name: object.Name, UID: object.UID}
		}
	}
	return isolation.SubjectNamespace{}
}

func isolationOperationID(receipt Receipt, namespace string) string {
	return "egress-" + shortDigest([]byte(receipt.OperationDigest+":"+namespace))
}

func isolationNodeName(receipt Receipt, namespace string) string {
	for _, recorded := range receipt.Proofs {
		if recorded.Proof.SubjectNamespace.Name != namespace {
			continue
		}
		proof, err := isolation.ExportProof(recorded)
		if err == nil {
			return proof.Endpoint.NodeName
		}
	}
	return ""
}

func allIsolationProofsComplete(receipt Receipt) bool {
	if len(receipt.Proofs) != len(receipt.Request.Plan.Namespaces) {
		return false
	}
	for _, proof := range receipt.Proofs {
		if _, err := isolation.ExportProof(proof); err != nil {
			return false
		}
	}
	return true
}

// startIsolated is called with the parent's run lock already held. Namespace
// allocation is serialized only while allocating; neither the private receipt
// callback nor a probe step recursively acquires an environment lock.
func (a *Adapter) startIsolated(ctx context.Context, record *operationRecord, state *runJournal) (Receipt, error) {
	if ctx.Err() != nil {
		return record.Receipt, ctx.Err()
	}
	if record.Observation.Failure != nil {
		return record.Receipt, failure(NeedsAdapter, "isolation-start-previously-failed")
	}
	receipt := &record.Receipt
	if receipt.IsolationDeadline.IsZero() {
		receipt.IsolationDeadline = minTime(receipt.Deadline, a.now().Add(time.Minute)).UTC()
		if err := a.saveRun(receipt.Request.RunID, state); err != nil {
			return *receipt, err
		}
	}
	deadline := receipt.Deadline
	if !allIsolationProofsComplete(*receipt) {
		deadline = minTime(deadline, receipt.IsolationDeadline)
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	err := a.prepareIsolationNamespaces(bounded, record, state)
	if err == nil {
		err = a.proveIsolation(bounded, record, state)
	}
	if err == nil {
		err = a.createIsolatedSubjects(bounded, record, state)
	}
	if ctx.Err() != nil {
		// Caller cancellation is a pause, not permission to remove the saved
		// namespace/proof generation. Resume via Start(RequireExisting=true).
		return *receipt, ctx.Err()
	}
	if err != nil {
		if bounded.Err() != nil {
			a.settleFailedStart(ctx, record, state)
		} else {
			record.Observation.Phase, record.Observation.Failure = Cleaning, safeError(err)
			if saveErr := a.saveRun(receipt.Request.RunID, state); saveErr != nil {
				return *receipt, saveErr
			}
		}
		return *receipt, err
	}
	record.Observation.Phase = Running
	return *receipt, a.saveRun(receipt.Request.RunID, state)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (a *Adapter) prepareIsolationNamespaces(ctx context.Context, record *operationRecord, state *runJournal) error {
	unlock, err := a.lock(ctx, "namespace-allocation")
	if err != nil {
		return err
	}
	defer unlock()
	if err := a.checkCapacity(ctx, record.Receipt); err != nil {
		return err
	}
	for i, object := range record.Receipt.Objects {
		if object.Kind != podKind {
			if err := a.ensureIsolationObject(ctx, record, state, i); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Adapter) ensureIsolationObject(ctx context.Context, record *operationRecord, state *runJournal, index int) error {
	receipt := &record.Receipt
	if ctx.Err() != nil {
		return ctx.Err()
	}
	existing := receipt.Objects[index].UID != ""
	if !existing {
		if slices.Contains(receipt.CreateIntents, index) {
			return failure(Unknown, "isolation-resource-create-acknowledgement-required")
		}
		receipt.CreateIntents = append(receipt.CreateIntents, index)
		if err := a.saveRun(receipt.Request.RunID, state); err != nil {
			return err
		}
	}
	err := a.ensureObject(ctx, receipt, index, existing)
	// Preserve API acknowledgements even if the caller cancelled after create.
	if saveErr := a.saveRun(receipt.Request.RunID, state); saveErr != nil {
		return failure(Unknown, "resource-acknowledgement-not-persisted")
	}
	return err
}

func (a *Adapter) createIsolatedSubjects(ctx context.Context, record *operationRecord, state *runJournal) error {
	if err := a.verifyIsolationBindings(ctx, record.Receipt); err != nil {
		return err
	}
	for i, object := range record.Receipt.Objects {
		if object.Kind == podKind {
			if err := a.ensureIsolationObject(ctx, record, state, i); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Adapter) proveIsolation(ctx context.Context, record *operationRecord, state *runJournal) error {
	prover, err := isolation.New(a.kube)
	if err != nil {
		return failure(NeedsAdapter, "runtime-isolation-adapter-required")
	}
	for index, namespace := range record.Receipt.Request.Plan.Namespaces {
		name := namespaceName(record.Receipt, namespace.Alias)
		if index >= len(record.Receipt.Proofs) {
			if err := a.beginIsolationProof(ctx, prover, record, state, name); err != nil {
				return err
			}
		}
		if err := a.driveIsolationProof(ctx, prover, record, state, index, false); err != nil {
			return err
		}
		if _, err := isolation.ExportProof(record.Receipt.Proofs[index]); err != nil {
			return failure(NeedsAdapter, "runtime-egress-enforcement-unproven")
		}
	}
	return nil
}

func (a *Adapter) beginIsolationProof(
	ctx context.Context, prover *isolation.Adapter, record *operationRecord, state *runJournal, namespace string,
) error {
	receipt := &record.Receipt
	for _, object := range receipt.Objects {
		if object.Kind == podKind && object.UID != "" {
			return failure(Unknown, "isolation-receipt-missing-after-subject-create")
		}
	}
	var policyIdentity ObjectIdentity
	for _, object := range receipt.Objects {
		if object.Kind == networkPolicyKind && object.Namespace == namespace {
			policyIdentity = object
			break
		}
	}
	policy, err := a.kube.NetworkingV1().NetworkPolicies(namespace).Get(ctx, policyIdentity.Name, metav1.GetOptions{})
	if err != nil || policyIdentity.UID == "" || policy.UID != policyIdentity.UID ||
		policy.DeletionTimestamp != nil || !sameJSON(policy.Spec, a.networkPolicy(*receipt, policyIdentity).Spec) {
		return failure(NeedsAdapter, "isolation-subject-policy-unavailable")
	}
	timeout := minTime(receipt.IsolationDeadline, receipt.Deadline).Sub(a.now())
	if timeout < 2*time.Second {
		return failure(NeedsAdapter, "isolation-start-deadline-exceeded")
	}
	_, err = prover.Start(ctx, isolation.Config{
		ProbeImage: receipt.Policy.ProbeImage, Timeout: min(timeout, time.Minute),
		ControlNamespace: namespaceIdentity(*receipt, isolationControlName(*receipt)),
	}, receipt.Request.RunID, isolationOperationID(*receipt, namespace),
		namespaceIdentity(*receipt, namespace), ownerLabels(*receipt),
		isolation.PolicyIdentity{
			Name: policy.Name, UID: policy.UID, ResourceVersion: policy.ResourceVersion, Digest: isolation.PolicyDigest(policy),
		}, a.isolationCallback(record, state, len(receipt.Proofs)))
	if err != nil {
		return failure(NeedsAdapter, "runtime-isolation-start-failed")
	}
	return nil
}

func (a *Adapter) isolationCallback(record *operationRecord, state *runJournal, index int) isolation.ReceiptCallback {
	return func(_ context.Context, next isolation.Receipt) error {
		if index > len(record.Receipt.Proofs) || isolationReceiptBinding(record.Receipt, next) != nil {
			return failure(Unknown, "isolation-receipt-binding-mismatch")
		}
		var previous uint64
		if index < len(record.Receipt.Proofs) {
			old := record.Receipt.Proofs[index]
			if old.CleanupComplete || old.OperationDigest != next.OperationDigest || old.Nonce != next.Nonce {
				return failure(Unknown, "isolation-generation-mismatch")
			}
			previous = old.Revision
		}
		if next.Revision != previous+1 {
			return failure(Unknown, "isolation-receipt-revision-mismatch")
		}
		if index == len(record.Receipt.Proofs) {
			record.Receipt.Proofs = append(record.Receipt.Proofs, next)
		} else {
			record.Receipt.Proofs[index] = next
		}
		return a.saveRun(record.Receipt.Request.RunID, state)
	}
}

func (a *Adapter) driveIsolationProof(
	ctx context.Context, prover *isolation.Adapter, record *operationRecord, state *runJournal, index int, cancel bool,
) error {
	for !record.Receipt.Proofs[index].CleanupComplete {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		previous := record.Receipt.Proofs[index]
		callback := a.isolationCallback(record, state, index)
		var next isolation.Receipt
		var err error
		if cancel {
			next, err = prover.Cancel(ctx, previous, callback)
		} else {
			next, err = prover.Observe(ctx, previous, callback)
		}
		if err != nil {
			if keepErr := a.retainIsolationAcknowledgement(record, state, index, next); keepErr != nil {
				return keepErr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return failure(NeedsAdapter, "runtime-egress-enforcement-unproven")
		}
		if next.Revision == previous.Revision {
			if err := waitIsolation(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

func waitIsolation(ctx context.Context) error {
	timer := time.NewTimer(isolationPollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (a *Adapter) retainIsolationAcknowledgement(
	record *operationRecord, state *runJournal, index int, next isolation.Receipt,
) error {
	old := record.Receipt.Proofs[index]
	if next.OperationDigest != old.OperationDigest || next.Nonce != old.Nonce ||
		next.Revision < old.Revision || isolationReceiptBinding(record.Receipt, next) != nil {
		return failure(Unknown, "isolation-acknowledgement-mismatch")
	}
	// A context can end after the API returns a UID but before the proof's
	// callback is invoked. The environment's held run lock permits journaling
	// that returned acknowledgement without a Kubernetes operation or re-lock.
	record.Receipt.Proofs[index] = next
	return a.saveRun(record.Receipt.Request.RunID, state)
}

func isolationReceiptBinding(parent Receipt, child isolation.Receipt) error {
	subject := child.Proof.SubjectNamespace
	control := namespaceIdentity(parent, isolationControlName(parent))
	if subject.UID == "" || subject != namespaceIdentity(parent, subject.Name) ||
		control.UID == "" || child.Config.ControlNamespace != control ||
		child.RunID != parent.Request.RunID || child.OperationID != isolationOperationID(parent, subject.Name) ||
		child.Config.ProbeImage != parent.Policy.ProbeImage ||
		!maps.Equal(child.Proof.SubjectSelectorLabels, ownerLabels(parent)) ||
		child.Proof.ControlNamespace != control || child.Proof.Policy.UID == "" ||
		child.Proof.ProbeImage != parent.Policy.ProbeImage ||
		isolationClusterIdentity(string(child.Proof.ClusterUID)) != parent.Policy.ClusterIdentity {
		return failure(Unknown, "isolation-proof-scope-mismatch")
	}
	return nil
}

func isolationClusterIdentity(uid string) string {
	return jsonDigest(struct{ Domain, UID string }{"orka.remediation.environment.cluster.v1", uid})
}

func validateIsolationReceipt(receipt Receipt) error {
	if receipt.Policy.ProbeImage == "" {
		if len(receipt.Proofs) != 0 || len(receipt.CreateIntents) != 0 || !receipt.IsolationDeadline.IsZero() {
			return failure(Unknown, "unexpected-isolation-receipts")
		}
		return nil
	}
	seen := make(map[int]bool, len(receipt.CreateIntents))
	for _, index := range receipt.CreateIntents {
		if index < 0 || index >= len(receipt.Objects) || seen[index] {
			return failure(Unknown, "invalid-isolation-create-intents")
		}
		seen[index] = true
	}
	if len(receipt.Proofs) > len(receipt.Request.Plan.Namespaces) ||
		(!receipt.IsolationDeadline.IsZero() && receipt.IsolationDeadline.After(receipt.Deadline)) {
		return failure(Unknown, "invalid-isolation-receipt-count-or-deadline")
	}
	for index, proof := range receipt.Proofs {
		if receipt.IsolationDeadline.IsZero() ||
			proof.Proof.SubjectNamespace.Name != namespaceName(receipt, receipt.Request.Plan.Namespaces[index].Alias) {
			return failure(Unknown, "isolation-proof-order-mismatch")
		}
		if err := isolationReceiptBinding(receipt, proof); err != nil {
			return err
		}
	}
	return nil
}

func compareIsolationReceipts(supplied, recorded Receipt) error {
	if len(supplied.Proofs) > len(recorded.Proofs) {
		return failure(Unknown, "isolation-receipt-ahead-of-journal")
	}
	for index, proof := range supplied.Proofs {
		canonical := recorded.Proofs[index]
		if proof.OperationDigest != canonical.OperationDigest || proof.Nonce != canonical.Nonce || proof.Revision > canonical.Revision {
			return failure(Unknown, "isolation-generation-mismatch")
		}
		for i, object := range proof.Objects {
			if i >= len(canonical.Objects) || (object.UID != "" && object.UID != canonical.Objects[i].UID) {
				return failure(Unknown, "isolation-receipt-uid-mismatch")
			}
		}
	}
	return nil
}

func (a *Adapter) verifyIsolationBindings(ctx context.Context, receipt Receipt) error {
	if receipt.Policy.ProbeImage == "" {
		return nil
	}
	if !allIsolationProofsComplete(receipt) {
		return failure(NeedsAdapter, "runtime-isolation-proof-required")
	}
	cluster, err := a.kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID == "" || cluster.DeletionTimestamp != nil {
		return failure(NeedsAdapter, "isolation-cluster-identity-unavailable")
	}
	for _, recorded := range receipt.Proofs {
		if err := isolationReceiptBinding(receipt, recorded); err != nil {
			return err
		}
		if cluster.UID != recorded.Proof.ClusterUID {
			return failure(Unknown, "isolation-cluster-identity-changed")
		}
		if err := a.verifyIsolationNamespace(ctx, recorded.Proof.SubjectNamespace, recorded.SubjectLabels); err != nil {
			return err
		}
		if err := a.verifyIsolationNamespace(ctx, recorded.Config.ControlNamespace, recorded.ControlLabels); err != nil {
			return err
		}
		if err := a.verifyIsolationPolicies(ctx, recorded); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) verifyIsolationNamespace(ctx context.Context, identity isolation.SubjectNamespace, labels map[string]string) error {
	ns, err := a.kube.CoreV1().Namespaces().Get(ctx, identity.Name, metav1.GetOptions{})
	if err != nil || ns.UID != identity.UID || ns.DeletionTimestamp != nil ||
		ns.Status.Phase != corev1.NamespaceActive || !maps.Equal(ns.Labels, labels) {
		return failure(Unknown, "isolation-namespace-identity-changed")
	}
	return nil
}

func (a *Adapter) verifyIsolationPolicies(ctx context.Context, recorded isolation.Receipt) error {
	policies, err := a.kube.NetworkingV1().NetworkPolicies(recorded.Proof.SubjectNamespace.Name).List(ctx, metav1.ListOptions{Limit: 65})
	if err != nil || policies.Continue != "" || len(policies.Items) != len(recorded.Proof.SubjectPolicies) {
		return failure(Unknown, "isolation-policy-set-changed")
	}
	for _, policy := range policies.Items {
		identity := isolation.PolicyIdentity{
			Name: policy.Name, UID: policy.UID, ResourceVersion: policy.ResourceVersion, Digest: isolation.PolicyDigest(&policy),
		}
		if policy.DeletionTimestamp != nil || !slices.Contains(recorded.Proof.SubjectPolicies, identity) {
			return failure(Unknown, "isolation-policy-set-changed")
		}
	}
	return nil
}

func (a *Adapter) cleanupIsolation(ctx context.Context, record *operationRecord, state *runJournal) error {
	if record.Receipt.Policy.ProbeImage != "" {
		cluster, err := a.kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
		if err != nil || cluster.UID == "" || isolationClusterIdentity(string(cluster.UID)) != record.Receipt.Policy.ClusterIdentity {
			return failure(Unknown, "isolation-cleanup-cluster-mismatch")
		}
	}
	if len(record.Receipt.Proofs) == 0 {
		return nil
	}
	prover, err := isolation.New(a.kube)
	if err != nil {
		return failure(NeedsAdapter, "runtime-isolation-adapter-required")
	}
	for index := range slices.Backward(record.Receipt.Proofs) {
		if err := a.driveIsolationProof(ctx, prover, record, state, index, true); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				return &Error{Kind: Infrastructure, Code: "isolation-cleanup-pending", Retryable: true}
			}
			return err
		}
	}
	return nil
}

func (a *Adapter) recoverIsolationObjectForCleanup(receipt Receipt, index int, metadata metav1.Object) error {
	if !slices.Contains(receipt.CreateIntents, index) {
		return failure(Unknown, "cleanup-resource-has-no-create-intent")
	}
	identity := receipt.Objects[index]
	switch object := metadata.(type) {
	case *corev1.Namespace:
		if object.Labels["pod-security.kubernetes.io/enforce"] != restrictedPolicy {
			return failure(Unknown, "cleanup-namespace-intent-mismatch")
		}
	case *networkingv1.NetworkPolicy:
		if !sameJSON(object.Spec, a.networkPolicy(receipt, identity).Spec) {
			return failure(Unknown, "cleanup-policy-intent-mismatch")
		}
	case *corev1.Pod:
		desired := a.pod(receipt, identity)
		if !samePodSpec(object.Spec, desired.Spec) || !maps.Equal(object.Labels, desired.Labels) {
			return failure(Unknown, "cleanup-pod-intent-mismatch")
		}
	default:
		return failure(Unknown, "cleanup-object-kind-mismatch")
	}
	return nil
}

func (a *Adapter) recoverCleanupIdentity(ctx context.Context, receipt *Receipt, index int, metadata metav1.Object) error {
	if receipt.Policy.ProbeImage == "" {
		return a.ensureObject(ctx, receipt, index, true)
	}
	if err := a.recoverIsolationObjectForCleanup(*receipt, index, metadata); err != nil {
		return err
	}
	receipt.Objects[index].UID = metadata.GetUID()
	return nil
}
