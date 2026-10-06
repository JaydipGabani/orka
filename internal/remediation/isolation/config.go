package isolation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	guardRole        = "guard"
	serverRole       = "canary"
	allowRole        = "allow"
	beforeRole       = "before"
	negativeRole     = "denied"
	afterRole        = "after"
	podKind          = "Pod"
	policyKind       = "NetworkPolicy"
	operationKey     = "isolation.remediation.orka.ai/operation"
	endpointLabel    = "isolation.remediation.orka.ai/endpoint"
	namespaceNameKey = "kubernetes.io/metadata.name"
	defaultAccount   = "default"
	containerName    = "probe"
	invalidPhase     = "invalid-proof-phase"
	contextEnded     = "operation-context-ended"
	maxPolicies      = 64
)

var (
	idPattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// PolicyDigest is a versioned SHA-256 hash over the JSON NetworkPolicy spec.
// Compute it from the API-server-observed object, after Kubernetes defaulting.
// It is an identity fence, not evidence that the CNI enforces that policy.
func PolicyDigest(policy *networkingv1.NetworkPolicy) string {
	if policy == nil {
		return ""
	}
	return jsonDigest(struct {
		Domain string
		Spec   networkingv1.NetworkPolicySpec
	}{"orka.remediation.isolation.policy.v1", policy.Spec})
}

func policyIdentity(policy *networkingv1.NetworkPolicy) PolicyIdentity {
	return PolicyIdentity{
		Name: policy.Name, UID: policy.UID, ResourceVersion: policy.ResourceVersion, Digest: PolicyDigest(policy),
	}
}

func validateConfig(config Config, subject SubjectNamespace) (Config, error) {
	if config.Timeout == 0 {
		config.Timeout = time.Minute
	}
	if config.Timeout < probe.Timeout || config.Timeout > time.Minute ||
		!validNamespace(subject) || !validNamespace(config.ControlNamespace) ||
		subject.Name == config.ControlNamespace.Name || subject.UID == config.ControlNamespace.UID ||
		subject.Name == "kube-system" || config.ControlNamespace.Name == "kube-system" {
		return Config{}, &Error{Code: "invalid-reserved-namespaces-or-timeout"}
	}
	named, err := reference.ParseNormalizedNamed(config.ProbeImage)
	if err != nil {
		return Config{}, &Error{Code: "pinned-probe-image-required"}
	}
	pinned, ok := named.(reference.Canonical)
	if !ok || !digestPattern.MatchString(pinned.Digest().String()) {
		return Config{}, &Error{Code: "pinned-probe-image-required"}
	}
	return config, nil
}

func validNamespace(namespace SubjectNamespace) bool {
	return namespace.UID != "" && len(namespace.UID) <= 256 &&
		len(validation.IsDNS1123Label(namespace.Name)) == 0 &&
		namespace.Name != defaultAccount && !strings.HasPrefix(namespace.Name, "kube-")
}

func validSubjectLabels(subjectLabels map[string]string) bool {
	if len(subjectLabels) > 64 {
		return false
	}
	for key, value := range subjectLabels {
		if key == endpointLabel || len(validation.IsQualifiedName(key)) != 0 || len(validation.IsValidLabelValue(value)) != 0 {
			return false
		}
	}
	return true
}

func validPolicy(identity PolicyIdentity) bool {
	return identity.UID != "" && identity.ResourceVersion != "" &&
		len(validation.IsDNS1123Subdomain(identity.Name)) == 0 && digestPattern.MatchString(identity.Digest)
}

func selectsSubject(policy *networkingv1.NetworkPolicy, subjectLabels map[string]string) bool {
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
	return err == nil && selector.Matches(labels.Set(subjectLabels)) &&
		slices.Contains(policy.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
}

func jsonDigest(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func operationDigest(receipt Receipt) string {
	return jsonDigest(struct {
		Domain                string
		RunID, OperationID    string
		Config                Config
		Nonce                 string
		StartedAt, Deadline   time.Time
		SubjectLabels         map[string]string
		ControlLabels         map[string]string
		ClusterUID            string
		SubjectNamespace      SubjectNamespace
		SubjectSelectorLabels map[string]string
		Policy                PolicyIdentity
		SubjectPolicies       []PolicyIdentity
	}{
		"orka.remediation.isolation.operation.v1", receipt.RunID, receipt.OperationID, receipt.Config, receipt.Nonce,
		receipt.StartedAt, receipt.Deadline, receipt.SubjectLabels, receipt.ControlLabels, string(receipt.Proof.ClusterUID),
		receipt.Proof.SubjectNamespace, receipt.Proof.SubjectSelectorLabels, receipt.Proof.Policy, receipt.Proof.SubjectPolicies,
	})
}

func inventory(receipt Receipt) []ObjectReceipt {
	prefix := "netproof-" + strings.TrimPrefix(receipt.OperationDigest, "sha256:")[:24]
	control, subject := receipt.Config.ControlNamespace.Name, receipt.Proof.SubjectNamespace.Name
	return []ObjectReceipt{
		{Role: guardRole, Kind: policyKind, Namespace: control, Name: prefix + "-guard"},
		{Role: serverRole, Kind: podKind, Namespace: control, Name: prefix + "-canary"},
		{Role: allowRole, Kind: policyKind, Namespace: control, Name: prefix + "-allow"},
		{Role: beforeRole, Kind: podKind, Namespace: control, Name: prefix + "-before"},
		{Role: negativeRole, Kind: podKind, Namespace: subject, Name: prefix + "-denied"},
		{Role: afterRole, Kind: podKind, Namespace: control, Name: prefix + "-after"},
	}
}

func cloneReceipt(receipt Receipt) Receipt {
	receipt.SubjectLabels = maps.Clone(receipt.SubjectLabels)
	receipt.ControlLabels = maps.Clone(receipt.ControlLabels)
	receipt.Objects = slices.Clone(receipt.Objects)
	receipt.Proof = cloneProof(receipt.Proof)
	return receipt
}

func cloneProof(proof Proof) Proof {
	proof.SubjectSelectorLabels = maps.Clone(proof.SubjectSelectorLabels)
	proof.SubjectPolicies = slices.Clone(proof.SubjectPolicies)
	proof.Observations = slices.Clone(proof.Observations)
	return proof
}

func validateReceipt(receipt Receipt) error {
	if err := validateFrozenReceipt(receipt); err != nil {
		return err
	}
	if err := validateInventory(receipt); err != nil {
		return err
	}
	switch receipt.Phase {
	case Preparing, WaitingCanary, PositiveBefore, Negative, PositiveAfter, Cleaning, Complete, Failed:
	default:
		return &Error{Code: invalidPhase}
	}
	if receipt.CleanupComplete && (receipt.Phase != Complete || !allDeleted(receipt)) {
		return &Error{Code: "invalid-cleanup-receipt"}
	}
	return nil
}

func validateFrozenReceipt(receipt Receipt) error {
	config, err := validateConfig(receipt.Config, receipt.Proof.SubjectNamespace)
	if err != nil || config != receipt.Config || receipt.Version != Version || receipt.Revision == 0 ||
		!idPattern.MatchString(receipt.RunID) || !idPattern.MatchString(receipt.OperationID) ||
		!probe.ValidNonce(receipt.Nonce) || receipt.StartedAt.IsZero() ||
		!receipt.Deadline.Equal(receipt.StartedAt.Add(receipt.Config.Timeout)) ||
		receipt.Proof.ClusterUID == "" || receipt.Proof.ControlNamespace != receipt.Config.ControlNamespace ||
		receipt.Proof.ProbeImage != receipt.Config.ProbeImage || !validSubjectLabels(receipt.Proof.SubjectSelectorLabels) ||
		!validPolicy(receipt.Proof.Policy) || receipt.OperationDigest != operationDigest(receipt) {
		return &Error{Code: "invalid-private-receipt"}
	}
	return nil
}

func validateInventory(receipt Receipt) error {
	expected := inventory(receipt)
	if len(receipt.Objects) != len(expected) {
		return &Error{Code: "invalid-resource-inventory"}
	}
	uids := make(map[string]struct{}, len(expected))
	for i, object := range receipt.Objects {
		identity := expected[i]
		if object.Role != identity.Role || object.Kind != identity.Kind || object.Namespace != identity.Namespace || object.Name != identity.Name ||
			(object.UID != "" && !object.CreateAttempted) ||
			(object.Kind == podKind && object.CreateAttempted && (object.ActiveDeadlineSeconds < 1 || object.ActiveDeadlineSeconds > 60)) {
			return &Error{Code: "invalid-resource-inventory"}
		}
		if object.UID != "" {
			if _, duplicate := uids[string(object.UID)]; duplicate {
				return &Error{Code: "duplicate-resource-uid"}
			}
			uids[string(object.UID)] = struct{}{}
		}
	}
	return nil
}

func allDeleted(receipt Receipt) bool {
	for _, object := range receipt.Objects {
		if !object.Deleted {
			return false
		}
	}
	return true
}
