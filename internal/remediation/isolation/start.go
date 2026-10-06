package isolation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"maps"
	"slices"

	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Start freezes and persists an intent, including fresh synthetic nonce, before
// creating anything. Call Observe repeatedly to advance it. Namespace names,
// selectors, policies and the image must come only from the trusted parent.
func (a *Adapter) Start(
	ctx context.Context, config Config, runID, operationID string,
	subject SubjectNamespace, subjectLabels map[string]string, identity PolicyIdentity, persist ReceiptCallback,
) (Receipt, error) {
	config, err := validateConfig(config, subject)
	if err != nil {
		return Receipt{}, err
	}
	if persist == nil || !idPattern.MatchString(runID) || !idPattern.MatchString(operationID) ||
		!validSubjectLabels(subjectLabels) || !validPolicy(identity) {
		return Receipt{}, &Error{Code: "invalid-start-request"}
	}
	started := a.now().UTC()
	ctx, cancel := context.WithDeadline(ctx, started.Add(config.Timeout))
	defer cancel()
	receipt := Receipt{
		Version: Version, RunID: runID, OperationID: operationID, Config: config,
		StartedAt: started, Deadline: started.Add(config.Timeout), Phase: Preparing, Outcome: Pending,
		Proof: Proof{
			SubjectNamespace: subject, ControlNamespace: config.ControlNamespace,
			SubjectSelectorLabels: maps.Clone(subjectLabels), Policy: identity, ProbeImage: config.ProbeImage,
		},
	}
	if err := a.prepare(ctx, &receipt); err != nil {
		return Receipt{}, err
	}
	nonce := make([]byte, probe.NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return Receipt{}, &Error{Code: "nonce-unavailable"}
	}
	receipt.Nonce = hex.EncodeToString(nonce)
	receipt.OperationDigest = operationDigest(receipt)
	receipt.Objects = inventory(receipt)
	err = save(ctx, &receipt, persist)
	return cloneReceipt(receipt), err
}

func (a *Adapter) prepare(ctx context.Context, receipt *Receipt) error {
	cluster, err := a.kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID == "" || cluster.DeletionTimestamp != nil {
		return &Error{Code: "cluster-identity-unavailable"}
	}
	receipt.Proof.ClusterUID = cluster.UID
	subject, err := a.namespace(ctx, receipt.Proof.SubjectNamespace)
	if err != nil {
		return err
	}
	control, err := a.namespace(ctx, receipt.Config.ControlNamespace)
	if err != nil {
		return err
	}
	receipt.SubjectLabels, receipt.ControlLabels = maps.Clone(subject.Labels), maps.Clone(control.Labels)
	policy, err := a.kube.NetworkingV1().NetworkPolicies(subject.Name).Get(ctx, receipt.Proof.Policy.Name, metav1.GetOptions{})
	if err != nil || policy.DeletionTimestamp != nil || policyIdentity(policy) != receipt.Proof.Policy ||
		!selectsSubject(policy, receipt.Proof.SubjectSelectorLabels) {
		return &Error{Code: "subject-policy-mismatch"}
	}
	receipt.Proof.SubjectPolicies, err = a.subjectPolicies(ctx, subject.Name)
	if err != nil {
		return err
	}
	if !slices.Contains(receipt.Proof.SubjectPolicies, receipt.Proof.Policy) {
		return &Error{Code: "subject-policy-snapshot-mismatch"}
	}
	return a.requireEmpty(ctx, receipt.Proof.SubjectNamespace.Name, receipt.Config.ControlNamespace.Name)
}

func (a *Adapter) namespace(ctx context.Context, identity SubjectNamespace) (*corev1.Namespace, error) {
	ns, err := a.kube.CoreV1().Namespaces().Get(ctx, identity.Name, metav1.GetOptions{})
	if err != nil || ns.UID != identity.UID || ns.DeletionTimestamp != nil ||
		ns.Status.Phase != corev1.NamespaceActive || ns.Labels[namespaceNameKey] != identity.Name {
		return nil, &Error{Code: "namespace-identity-or-readiness-mismatch"}
	}
	return ns, nil
}

func (a *Adapter) requireEmpty(ctx context.Context, subject, control string) error {
	for _, namespace := range []string{subject, control} {
		pods, err := a.kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil || len(pods.Items) != 0 || pods.Continue != "" {
			return &Error{Code: "exclusive-empty-namespaces-required"}
		}
	}
	policies, err := a.kube.NetworkingV1().NetworkPolicies(control).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil || len(policies.Items) != 0 || policies.Continue != "" {
		return &Error{Code: "exclusive-empty-control-namespace-required"}
	}
	return nil
}

func (a *Adapter) subjectPolicies(ctx context.Context, namespace string) ([]PolicyIdentity, error) {
	list, err := a.kube.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{Limit: maxPolicies + 1})
	if err != nil || list.Continue != "" || len(list.Items) > maxPolicies {
		return nil, &Error{Code: "subject-policy-set-unavailable"}
	}
	identities := make([]PolicyIdentity, 0, len(list.Items))
	for i := range list.Items {
		identity := policyIdentity(&list.Items[i])
		if !validPolicy(identity) || list.Items[i].DeletionTimestamp != nil {
			return nil, &Error{Code: "subject-policy-set-unavailable"}
		}
		identities = append(identities, identity)
	}
	slices.SortFunc(identities, func(a, b PolicyIdentity) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return identities, nil
}

func save(ctx context.Context, receipt *Receipt, persist ReceiptCallback) error {
	if persist == nil {
		return &Error{Code: "durable-receipt-callback-required"}
	}
	if ctx.Err() != nil {
		return &Error{Code: contextEnded}
	}
	receipt.Revision++
	if persist(ctx, cloneReceipt(*receipt)) != nil {
		return &Error{Code: "receipt-persistence-failed"}
	}
	return nil
}
