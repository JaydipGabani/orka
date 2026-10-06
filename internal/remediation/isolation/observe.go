package isolation

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Observe performs a bounded step, never adopting a missing/replaced UID or
// retrying creation after an unacknowledged create. A cancelled context does not
// authorize cleanup: the caller must explicitly invoke Cancel with its receipt.
func (a *Adapter) Observe(ctx context.Context, receipt Receipt, persist ReceiptCallback) (Receipt, error) {
	receipt = cloneReceipt(receipt)
	if ctx.Err() != nil {
		return receipt, &Error{Code: contextEnded}
	}
	if err := validateReceipt(receipt); err != nil {
		return receipt, err
	}
	if receipt.Phase == Complete {
		return receipt, nil
	}
	if receipt.Phase == Failed {
		return receipt, &Error{Code: "proof-previously-failed"}
	}
	if receipt.Phase == Cleaning {
		return a.cleanupStep(ctx, receipt, persist)
	}
	if !a.now().Before(receipt.Deadline) {
		return reject(ctx, receipt, &Error{Code: "proof-deadline-exceeded"}, persist)
	}
	ctx, cancel := context.WithDeadline(ctx, receipt.Deadline)
	defer cancel()
	if err := a.verifyActive(ctx, receipt); err != nil {
		return reject(ctx, receipt, err, persist)
	}
	if err := a.advance(ctx, &receipt, persist); err != nil {
		return reject(ctx, receipt, err, persist)
	}
	return receipt, nil
}

func (a *Adapter) verifyActive(ctx context.Context, receipt Receipt) error {
	if err := a.verifyAnchors(ctx, receipt); err != nil {
		return err
	}
	if err := a.verifyParentPolicies(ctx, receipt); err != nil {
		return err
	}
	for _, object := range receipt.Objects {
		if object.CreateAttempted && object.UID == "" {
			return &Error{Code: "create-acknowledgement-required"}
		}
	}
	return a.verifyInventory(ctx, receipt)
}

func (a *Adapter) advance(ctx context.Context, receipt *Receipt, persist ReceiptCallback) error {
	switch receipt.Phase {
	case Preparing:
		for _, role := range []string{guardRole, serverRole} {
			if receipt.Objects[roleIndex(*receipt, role)].UID == "" {
				return a.create(ctx, receipt, role, persist)
			}
		}
		receipt.Phase = WaitingCanary
		return save(ctx, receipt, persist)
	case WaitingCanary:
		endpoint, ready, err := a.canary(ctx, *receipt)
		if err != nil || !ready {
			return err
		}
		receipt.Proof.Endpoint, receipt.Phase = endpoint, PositiveBefore
		return save(ctx, receipt, persist)
	case PositiveBefore, Negative, PositiveAfter:
		return a.advanceProbe(ctx, receipt, persist)
	default:
		return &Error{Code: invalidPhase}
	}
}

func (a *Adapter) advanceProbe(ctx context.Context, receipt *Receipt, persist ReceiptCallback) error {
	if _, ready, err := a.canary(ctx, *receipt); err != nil || !ready {
		return err
	}
	if receipt.Objects[roleIndex(*receipt, allowRole)].UID == "" {
		return a.create(ctx, receipt, allowRole, persist)
	}
	role := phaseRole(receipt.Phase)
	object := receipt.Objects[roleIndex(*receipt, role)]
	if object.UID == "" {
		return a.create(ctx, receipt, role, persist)
	}
	observation, complete, err := a.observeProbe(ctx, *receipt, object)
	if err != nil || !complete {
		return err
	}
	receipt.Proof.Observations = append(receipt.Proof.Observations, observation)
	switch receipt.Phase {
	case PositiveBefore:
		receipt.Phase = Negative
	case Negative:
		receipt.Phase = PositiveAfter
	case PositiveAfter:
		receipt.Proof.Verified, receipt.Proof.SameNode = true, true
		receipt.Phase, receipt.Outcome = Cleaning, Passed
	default:
		return &Error{Code: invalidPhase}
	}
	return save(ctx, receipt, persist)
}

func phaseRole(phase Phase) string {
	switch phase {
	case PositiveBefore:
		return beforeRole
	case Negative:
		return negativeRole
	case PositiveAfter:
		return afterRole
	default:
		return ""
	}
}

func (a *Adapter) canary(ctx context.Context, receipt Receipt) (Endpoint, bool, error) {
	object := receipt.Objects[roleIndex(receipt, serverRole)]
	actual, err := a.kube.CoreV1().Pods(object.Namespace).Get(ctx, object.Name, metav1.GetOptions{})
	if err != nil || actual.DeletionTimestamp != nil || !matchesPod(receipt, object, actual) {
		return Endpoint{}, false, &Error{Code: "canary-identity-changed"}
	}
	if actual.Status.Phase == corev1.PodFailed || actual.Status.Phase == corev1.PodSucceeded {
		return Endpoint{}, false, &Error{Code: "canary-terminated"}
	}
	if !podReady(actual) {
		return Endpoint{}, false, nil
	}
	address, err := netip.ParseAddr(actual.Status.PodIP)
	status := actual.Status.ContainerStatuses[0]
	if err != nil || !address.IsGlobalUnicast() || actual.Spec.NodeName == "" || imageID(status.ImageID) == "" ||
		status.RestartCount != 0 || status.State.Running == nil || !status.Ready {
		return Endpoint{}, false, &Error{Code: "canary-runtime-identity-invalid"}
	}
	endpoint := Endpoint{
		Pod: object, Address: netip.AddrPortFrom(address.Unmap(), probe.Port).String(),
		NodeName: actual.Spec.NodeName, ImageID: status.ImageID, ObservedAt: a.now().UTC(),
	}
	frozen := receipt.Proof.Endpoint
	if frozen.Pod.UID != "" {
		if frozen.Pod.UID != actual.UID || frozen.Address != endpoint.Address ||
			frozen.NodeName != endpoint.NodeName || imageID(frozen.ImageID) != imageID(endpoint.ImageID) {
			return Endpoint{}, false, &Error{Code: "canary-endpoint-changed"}
		}
		return frozen, true, nil
	}
	return endpoint, true, nil
}

func podReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning || len(pod.Status.ContainerStatuses) != 1 ||
		pod.Status.ContainerStatuses[0].Name != containerName {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (a *Adapter) observeProbe(ctx context.Context, receipt Receipt, object ObjectReceipt) (Observation, bool, error) {
	actual, err := a.kube.CoreV1().Pods(object.Namespace).Get(ctx, object.Name, metav1.GetOptions{})
	if err != nil || actual.DeletionTimestamp != nil || !matchesPod(receipt, object, actual) {
		return Observation{}, false, &Error{Code: "probe-pod-identity-changed"}
	}
	if actual.Status.Phase != corev1.PodSucceeded && actual.Status.Phase != corev1.PodFailed {
		return Observation{}, false, nil
	}
	if actual.Status.Phase != corev1.PodSucceeded || len(actual.Status.ContainerStatuses) != 1 {
		return Observation{}, false, &Error{Code: "probe-did-not-succeed"}
	}
	status := actual.Status.ContainerStatuses[0]
	termination := status.State.Terminated
	if status.Name != containerName || status.RestartCount != 0 || status.LastTerminationState.Terminated != nil ||
		imageID(status.ImageID) == "" || imageID(status.ImageID) != imageID(receipt.Proof.Endpoint.ImageID) ||
		termination == nil || termination.ExitCode != 0 || termination.Signal != 0 || termination.Reason != "Completed" {
		return Observation{}, false, &Error{Code: "probe-termination-invalid"}
	}
	result, err := probe.Decode(termination.Message)
	expect := probe.Reachable
	if receipt.Phase == Negative {
		expect = probe.Blocked
	}
	if err != nil || !probe.Matches(expect, result) {
		return Observation{}, false, &Error{Code: "probe-result-did-not-prove-expectation"}
	}
	observation := Observation{
		Phase: receipt.Phase, Pod: object, ImageID: status.ImageID, NodeName: actual.Spec.NodeName,
		EndpointUID: receipt.Proof.Endpoint.Pod.UID, Target: receipt.Proof.Endpoint.Address,
		StartedAt: termination.StartedAt.Time, FinishedAt: termination.FinishedAt.Time,
		ObservedAt: a.now().UTC(), Result: result,
	}
	if !validObservation(receipt, observation, receipt.Proof.Observations) {
		return Observation{}, false, &Error{Code: "probe-observation-fence-invalid"}
	}
	return observation, true, nil
}

func imageID(value string) string {
	index := strings.LastIndex(value, "sha256:")
	if index < 0 || len(value) > 512 || !digestPattern.MatchString(value[index:]) {
		return ""
	}
	return value[index:]
}

func validObservation(receipt Receipt, observation Observation, previous []Observation) bool {
	if observation.NodeName != receipt.Proof.Endpoint.NodeName || observation.EndpointUID != receipt.Proof.Endpoint.Pod.UID ||
		observation.Target != receipt.Proof.Endpoint.Address || observation.StartedAt.IsZero() || observation.FinishedAt.IsZero() ||
		observation.StartedAt.Before(receipt.StartedAt.Add(-time.Second)) ||
		observation.FinishedAt.Before(observation.StartedAt) || observation.FinishedAt.After(receipt.Deadline) ||
		observation.FinishedAt.After(observation.ObservedAt.Add(time.Second)) || observation.ObservedAt.After(receipt.Deadline) {
		return false
	}
	if len(previous) > 0 {
		last := previous[len(previous)-1]
		if observation.StartedAt.Before(last.FinishedAt) || observation.ObservedAt.Before(last.ObservedAt) {
			return false
		}
	}
	// Kubernetes timestamps have one-second precision. A real two-second dial
	// timeout cannot have an instantaneous termination interval.
	return observation.Phase != Negative || observation.FinishedAt.Sub(observation.StartedAt) >= probe.Timeout-time.Second
}

func reject(ctx context.Context, receipt Receipt, err error, persist ReceiptCallback) (Receipt, error) {
	var classified *Error
	if !errors.As(err, &classified) {
		classified = &Error{Code: "proof-step-failed"}
	}
	if classified.Code == "receipt-persistence-failed" || ctx.Err() != nil {
		return receipt, classified
	}
	receipt.Phase, receipt.Outcome = Failed, Rejected
	receipt.Proof.Verified, receipt.FailureCode = false, classified.Code
	if err := save(ctx, &receipt, persist); err != nil {
		return receipt, err
	}
	return receipt, classified
}
