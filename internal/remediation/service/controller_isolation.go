package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	runtimeisolation "github.com/orka-agents/orka/internal/remediation/isolation"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	controllerControlLabel  = "remediation.orka.ai/controller-operation"
	controllerControlIntent = "remediation.orka.ai/controller-control-intent"
)

func controllerControlName(state controllerlab.State) string {
	return state.Namespaces[0] + "-proof"
}

func (a *controllerExecutionAdapter) ensureControllerNamespace(ctx context.Context, session *Session, state *pipelineState, operation *executionOperation) error {
	if _, err := controllerAcceptance(ctx, session, operation, false); err != nil {
		return err
	}
	if operation.Controller.Control == nil {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return ErrUnknown
		}
		expected := cloneControllerOperation(operation.Controller)
		next := cloneControllerOperation(&expected)
		next.Control = &controllerNamespace{
			Name: controllerControlName(next.State), IntentDigest: hex.EncodeToString(nonce),
		}
		if err := checkpointControllerOperation(ctx, session, state, operation, expected, next, false); err != nil {
			return err
		}
	}
	receipt := operation.Controller.Control
	actual, err := a.kube.CoreV1().Namespaces().Get(ctx, receipt.Name, metav1.GetOptions{})
	if err == nil {
		if !controllerControlMatches(actual, *receipt, operation.Controller.State) {
			return ErrUnknown
		}
		if receipt.UID != "" {
			return nil
		}
		if !receipt.CreateAttempted {
			return ErrUnknown
		}
		expected := cloneControllerOperation(operation.Controller)
		next := cloneControllerOperation(&expected)
		next.Control.UID = actual.UID
		return checkpointControllerOperation(ctx, session, state, operation, expected, next, false)
	}
	if !apierrors.IsNotFound(err) {
		return ErrRetryable
	}
	if receipt.UID != "" {
		return ErrUnknown
	}
	if receipt.CreateAttempted {
		// A missing response is not a rejection. Wait for the original
		// write's exact name/intent to become observable; never resubmit it.
		return ErrRetryable
	}
	expected := cloneControllerOperation(operation.Controller)
	next := cloneControllerOperation(&expected)
	next.Control.CreateAttempted = true
	if err := checkpointControllerOperation(ctx, session, state, operation, expected, next, false); err != nil {
		return err
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: receipt.Name, Labels: map[string]string{
			controllerControlLabel:               operation.Controller.State.OperationDigest[:40],
			"pod-security.kubernetes.io/enforce": "restricted",
			"pod-security.kubernetes.io/audit":   "restricted",
		},
		Annotations: map[string]string{controllerControlIntent: receipt.IntentDigest},
	}}
	created, err := a.kube.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	if err != nil {
		if definitiveControllerNamespaceRejection(err) {
			expected := cloneControllerOperation(operation.Controller)
			next := cloneControllerOperation(&expected)
			next.Control.CreateAttempted = false
			ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			if err := checkpointControllerOperation(ack, session, state, operation, expected, next, true); err != nil {
				return err
			}
		}
		return ErrRetryable
	}
	if !controllerControlMatches(created, *receipt, operation.Controller.State) {
		return ErrUnknown
	}
	expected = cloneControllerOperation(operation.Controller)
	next = cloneControllerOperation(&expected)
	next.Control.UID = created.UID
	return checkpointControllerOperation(ctx, session, state, operation, expected, next, false)
}

func definitiveControllerNamespaceRejection(err error) bool {
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return false
	}
	switch status.Status().Code {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusMethodNotAllowed, http.StatusNotAcceptable, http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

func controllerControlMatches(actual *corev1.Namespace, expected controllerNamespace, state controllerlab.State) bool {
	return actual != nil && actual.Name == expected.Name && actual.Name == controllerControlName(state) &&
		actual.UID != "" && (expected.UID == "" || actual.UID == expected.UID) &&
		(actual.DeletionTimestamp == nil || expected.DeleteRequested) &&
		actual.Labels[controllerControlLabel] == state.OperationDigest[:40] &&
		actual.Annotations[controllerControlIntent] == expected.IntentDigest
}

func (p *Pipeline) proveControllerPlacement(ctx context.Context, session *Session, adapter *controllerExecutionAdapter, lab *controllerlab.Adapter, state *pipelineState, operation *executionOperation) (bool, error) {
	if operation.Controller.Proof != nil {
		_, err := adapter.verifyControllerProof(ctx, session, lab, operation)
		return err == nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, adapter.config.Controller.OperationTimeout)
	defer cancel()
	if err := adapter.ensureControllerNamespace(bounded, session, state, operation); err != nil {
		return false, err
	}
	target, err := lab.SubjectIsolationTarget(operation.Controller.State)
	if err != nil {
		return false, ErrInvalid
	}
	policies, err := adapter.controllerPolicySet(bounded, target)
	if err != nil {
		return false, err
	}
	prover, err := runtimeisolation.New(adapter.kube)
	if err != nil {
		return false, ErrNeedsAdapter
	}
	persist := adapter.controllerIsolationCallback(session, state, operation, false)
	if operation.Controller.Isolation == nil {
		remaining := time.Until(operation.Controller.State.Deadline)
		if remaining < 2*time.Second {
			return false, ErrUnknown
		}
		var selected runtimeisolation.PolicyIdentity
		for _, identity := range policies {
			if identity.Name == target.Policy.Name {
				selected = identity
			}
		}
		control := operation.Controller.Control
		_, err := prover.Start(bounded, runtimeisolation.Config{
			ProbeImage: adapter.config.ProbeImage, Timeout: min(time.Minute, remaining),
			ControlNamespace: runtimeisolation.SubjectNamespace{Name: control.Name, UID: control.UID},
		}, operation.Controller.RunID, "controller-"+operation.ID,
			runtimeisolation.SubjectNamespace{Name: target.Namespace.Name, UID: target.Namespace.UID},
			target.Labels, selected, persist)
		if err != nil {
			return false, ErrUnknown
		}
		return false, nil
	}
	saved := operation.Controller.Isolation
	if !saved.CleanupComplete {
		_, err := prover.Observe(bounded, *saved, persist)
		if err != nil {
			return false, ErrUnknown
		}
		return false, nil
	}
	proof, err := runtimeisolation.ExportProof(*saved)
	if err != nil {
		return false, ErrNeedsAdapter
	}
	node, err := adapter.kube.CoreV1().Nodes().Get(bounded, proof.Endpoint.NodeName, metav1.GetOptions{})
	if err != nil || !readyControllerNode(node) || node.UID != operation.Controller.NodeUID {
		return false, ErrNeedsAdapter
	}
	ref, err := p.putJSON(bounded, session, "controller-proof-"+operation.ID, proof)
	if err != nil {
		return false, err
	}
	expected := cloneControllerOperation(operation.Controller)
	next := cloneControllerOperation(&expected)
	next.Proof = ref
	if err := checkpointControllerOperation(bounded, session, state, operation, expected, next, false); err != nil {
		return false, err
	}
	_, err = adapter.verifyControllerProof(bounded, session, lab, operation)
	return err == nil, err
}

func (a *controllerExecutionAdapter) controllerIsolationCallback(session *Session, state *pipelineState, operation *executionOperation, cleanup bool) runtimeisolation.ReceiptCallback {
	return func(ctx context.Context, receipt runtimeisolation.Receipt) error {
		expected := cloneControllerOperation(operation.Controller)
		revision := uint64(0)
		if expected.Isolation != nil {
			revision = expected.Isolation.Revision
		}
		if receipt.Revision != revision+1 || receipt.RunID != expected.RunID ||
			receipt.OperationID != "controller-"+operation.ID {
			return ErrUnknown
		}
		next := cloneControllerOperation(&expected)
		next.Isolation = &receipt
		if nodeName := receipt.Proof.Endpoint.NodeName; !cleanup && nodeName != "" {
			node, err := a.kube.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
			if err != nil || !readyControllerNode(node) || (next.NodeUID != "" && next.NodeUID != node.UID) {
				return ErrNeedsAdapter
			}
			// Pin before the first positive measurement, not after cleanup:
			// a same-name node replacement must invalidate the entire proof.
			next.NodeUID = node.UID
		}
		return checkpointControllerOperation(ctx, session, state, operation, expected, next, cleanup)
	}
}

func (a *controllerExecutionAdapter) controllerPolicySet(ctx context.Context, target controllerlab.SubjectIsolation) ([]runtimeisolation.PolicyIdentity, error) {
	actual, err := a.kube.NetworkingV1().NetworkPolicies(target.Namespace.Name).List(ctx, metav1.ListOptions{Limit: 4})
	if err != nil || actual.Continue != "" || len(actual.Items) != len(target.Policies) {
		return nil, ErrNeedsAdapter
	}
	identities := make([]runtimeisolation.PolicyIdentity, 0, len(actual.Items))
	for i := range actual.Items {
		policy := &actual.Items[i]
		found := false
		for _, expected := range target.Policies {
			if policy.Name == expected.Name {
				found = policy.UID == expected.UID && policy.ResourceVersion != "" && policy.DeletionTimestamp == nil &&
					reflect.DeepEqual(policy.Spec, expected.Spec) &&
					reflect.DeepEqual(policy.OwnerReferences, expected.OwnerReferences) &&
					maps.Equal(policy.Labels, expected.Labels) && maps.Equal(policy.Annotations, expected.Annotations)
			}
		}
		if !found {
			return nil, ErrNeedsAdapter
		}
		identities = append(identities, controllerPolicyIdentity(policy))
	}
	slices.SortFunc(identities, func(a, b runtimeisolation.PolicyIdentity) int {
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

func controllerPolicyIdentity(policy *networkingv1.NetworkPolicy) runtimeisolation.PolicyIdentity {
	return runtimeisolation.PolicyIdentity{
		Name: policy.Name, UID: policy.UID, ResourceVersion: policy.ResourceVersion, Digest: runtimeisolation.PolicyDigest(policy),
	}
}

func (a *controllerExecutionAdapter) verifyRetainedControllerProof(ctx context.Context, session *Session, lab *controllerlab.Adapter, operation *executionOperation) error {
	if operation.Controller.Isolation == nil || operation.Controller.Proof == nil || operation.Controller.Control == nil ||
		operation.Controller.NodeUID == "" {
		return ErrInvalid
	}
	receipt := *operation.Controller.Isolation
	proof, err := runtimeisolation.ExportProof(receipt)
	if err != nil {
		return ErrInvalid
	}
	var retained runtimeisolation.Proof
	if readJSON(ctx, session, operation.Controller.Proof, &retained) != nil ||
		jsonIdentity(proof) != operation.Controller.Proof.Digest || jsonIdentity(retained) != jsonIdentity(proof) {
		return ErrInvalid
	}
	target, err := lab.SubjectIsolationTarget(operation.Controller.State)
	if err != nil || receipt.RunID != operation.Controller.RunID || receipt.OperationID != "controller-"+operation.ID ||
		proof.ClusterUID != a.config.ClusterUID || proof.ProbeImage != a.config.ProbeImage ||
		proof.SubjectNamespace != (runtimeisolation.SubjectNamespace{Name: target.Namespace.Name, UID: target.Namespace.UID}) ||
		proof.ControlNamespace != (runtimeisolation.SubjectNamespace{
			Name: operation.Controller.Control.Name, UID: operation.Controller.Control.UID,
		}) || !maps.Equal(proof.SubjectSelectorLabels, target.Labels) ||
		len(proof.SubjectPolicies) != len(target.Policies) {
		return ErrInvalid
	}
	for _, expected := range target.Policies {
		found := false
		for _, saved := range proof.SubjectPolicies {
			found = found || (saved.Name == expected.Name && saved.UID == expected.UID &&
				saved.Digest == runtimeisolation.PolicyDigest(&expected))
		}
		if !found {
			return ErrInvalid
		}
	}
	if proof.Policy.Name != target.Policy.Name || proof.Policy.UID != target.Policy.UID {
		return ErrInvalid
	}
	if placement := operation.Controller.State.Placement; placement != nil &&
		(placement.OperationDigest != operation.Controller.State.OperationDigest ||
			placement.NodeName != proof.Endpoint.NodeName || placement.ProofDigest != controllerProofDigest(proof)) {
		return ErrInvalid
	}
	return nil
}

func (a *controllerExecutionAdapter) verifyControllerProof(ctx context.Context, session *Session, lab *controllerlab.Adapter, operation *executionOperation) (controllerlab.SubjectPlacement, error) {
	if err := a.verifyRetainedControllerProof(ctx, session, lab, operation); err != nil {
		return controllerlab.SubjectPlacement{}, err
	}
	receipt := operation.Controller.Isolation
	proof := receipt.Proof
	now := time.Now()
	maxAge := 2*a.config.Controller.StartupTimeout + a.config.Controller.ObservationWindow + a.config.Controller.TailWindow
	if !controllerProofFresh(proof.CompletedAt, now, maxAge) {
		return controllerlab.SubjectPlacement{}, ErrNeedsAdapter
	}
	ctx, cancel := context.WithTimeout(ctx, a.config.Controller.OperationTimeout)
	defer cancel()
	cluster, err := a.kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID != proof.ClusterUID || cluster.DeletionTimestamp != nil {
		return controllerlab.SubjectPlacement{}, ErrNeedsAdapter
	}
	for _, identity := range []runtimeisolation.SubjectNamespace{proof.SubjectNamespace, proof.ControlNamespace} {
		namespace, err := a.kube.CoreV1().Namespaces().Get(ctx, identity.Name, metav1.GetOptions{})
		labels := receipt.SubjectLabels
		if identity == proof.ControlNamespace {
			labels = receipt.ControlLabels
		}
		if err != nil || namespace.UID != identity.UID || namespace.DeletionTimestamp != nil ||
			namespace.Status.Phase != corev1.NamespaceActive || !maps.Equal(namespace.Labels, labels) {
			return controllerlab.SubjectPlacement{}, ErrNeedsAdapter
		}
	}
	target, err := lab.SubjectIsolationTarget(operation.Controller.State)
	if err != nil {
		return controllerlab.SubjectPlacement{}, ErrInvalid
	}
	policies, err := a.controllerPolicySet(ctx, target)
	if err != nil || !slices.Equal(policies, proof.SubjectPolicies) {
		return controllerlab.SubjectPlacement{}, ErrNeedsAdapter
	}
	node, err := a.kube.CoreV1().Nodes().Get(ctx, proof.Endpoint.NodeName, metav1.GetOptions{})
	if err != nil || node.UID != operation.Controller.NodeUID || !readyControllerNode(node) {
		return controllerlab.SubjectPlacement{}, ErrNeedsAdapter
	}
	return controllerlab.SubjectPlacement{
		OperationDigest: operation.Controller.State.OperationDigest, NodeName: proof.Endpoint.NodeName,
		ProofDigest: controllerProofDigest(proof),
	}, nil
}

func controllerProofFresh(completedAt, now time.Time, maxAge time.Duration) bool {
	return !completedAt.IsZero() && maxAge > 0 && !now.Before(completedAt) && now.Sub(completedAt) <= maxAge
}

func readyControllerNode(node *corev1.Node) bool {
	if node == nil || node.UID == "" || node.DeletionTimestamp != nil {
		return false
	}
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func (a *controllerExecutionAdapter) verifyControllerCluster(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, a.config.Controller.OperationTimeout)
	defer cancel()
	cluster, err := a.kube.CoreV1().Namespaces().Get(bounded, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID != a.config.ClusterUID || cluster.DeletionTimestamp != nil ||
		controllerlab.ClusterIdentity(string(cluster.UID)) != a.config.Controller.ClusterIdentity {
		return ErrNeedsAdapter
	}
	return nil
}

func (a *controllerExecutionAdapter) cleanupControllerNamespace(ctx context.Context, session *Session, state *pipelineState, operation *executionOperation, cleanup bool) error {
	receipt := operation.Controller.Control
	if receipt == nil || receipt.Deleted {
		return nil
	}
	if _, err := controllerAcceptance(ctx, session, operation, cleanup); err != nil {
		return err
	}
	if receipt.UID == "" && !receipt.CreateAttempted {
		expected := cloneControllerOperation(operation.Controller)
		next := cloneControllerOperation(&expected)
		next.Control = nil
		return checkpointControllerOperation(ctx, session, state, operation, expected, next, cleanup)
	}
	actual, err := a.kube.CoreV1().Namespaces().Get(ctx, receipt.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if receipt.UID == "" || !receipt.DeleteRequested {
			return ErrUnknown
		}
		expected := cloneControllerOperation(operation.Controller)
		next := cloneControllerOperation(&expected)
		next.Control.Deleted = true
		return checkpointControllerOperation(ctx, session, state, operation, expected, next, cleanup)
	}
	if err != nil || !controllerControlMatches(actual, *receipt, operation.Controller.State) {
		return ErrUnknown
	}
	if receipt.UID == "" {
		expected := cloneControllerOperation(operation.Controller)
		next := cloneControllerOperation(&expected)
		next.Control.UID = actual.UID
		return checkpointControllerOperation(ctx, session, state, operation, expected, next, cleanup)
	}
	if !receipt.DeleteRequested {
		expected := cloneControllerOperation(operation.Controller)
		next := cloneControllerOperation(&expected)
		next.Control.DeleteRequested = true
		if err := checkpointControllerOperation(ctx, session, state, operation, expected, next, cleanup); err != nil {
			return err
		}
	}
	uid := receipt.UID
	foreground := metav1.DeletePropagationForeground
	err = a.kube.CoreV1().Namespaces().Delete(ctx, receipt.Name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid}, PropagationPolicy: &foreground,
	})
	if err != nil && !apierrors.IsNotFound(err) {
		return ErrUnknown
	}
	return nil
}
