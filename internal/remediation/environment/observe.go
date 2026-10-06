package environment

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (a *Adapter) Observe(ctx context.Context, receipt Receipt) (Observation, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	if err := a.validateReceipt(receipt); err != nil {
		return Observation{}, err
	}
	if a.kube == nil {
		return Observation{}, failure(NeedsAdapter, "dedicated-kubernetes-adapter-required")
	}
	unlock, err := a.lock(ctx, runName(receipt.Request.RunID))
	if err != nil {
		return Observation{}, err
	}
	defer unlock()
	state, err := a.loadRun(receipt.Request.RunID, receipt.Request.Plan.Bind)
	if err != nil {
		return Observation{}, err
	}
	record, err := a.recordForReceipt(state, receipt)
	if err != nil {
		return Observation{}, err
	}
	if record.Observation.CleanupComplete {
		return record.Observation, nil
	}
	frozen, err := a.forReceipt(record.Receipt)
	if err != nil {
		return Observation{}, err
	}
	if record.Observation.Phase != Cleaning {
		if !a.now().Before(record.Receipt.Deadline) {
			record.Observation.Failure = &Error{Kind: Infrastructure, Code: "operation-timed-out"}
			record.Observation.Phase = Cleaning
		} else {
			wait, observeErr := frozen.observeReady(ctx, record)
			if ctx.Err() != nil {
				return Observation{}, ctx.Err()
			}
			if observeErr != nil {
				var temporary *Error
				if errors.As(observeErr, &temporary) && temporary.Kind == Infrastructure &&
					temporary.Code == "http-observer-unreachable" && a.now().Before(record.Receipt.Deadline) {
					record.Observation.Phase = Running
					record.Observation.Receipt = record.Receipt
					return record.Observation, nil
				}
				record.Observation.Failure = safeError(observeErr)
				record.Observation.Phase = Cleaning
			} else if wait {
				record.Observation.Receipt = record.Receipt
				return record.Observation, a.saveRun(receipt.Request.RunID, state)
			} else {
				record.Observation.Phase = Cleaning
			}
		}
		if err := a.saveRun(receipt.Request.RunID, state); err != nil {
			return Observation{}, failure(Unknown, "observation-not-persisted")
		}
	}
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := frozen.cleanup(cleanupContext, record, state); err != nil {
		record.Observation.Receipt = record.Receipt
		return record.Observation, err
	}
	return record.Observation, nil
}

func (a *Adapter) observeReady(ctx context.Context, record *operationRecord) (bool, error) {
	receipt := &record.Receipt
	for i := range receipt.Objects {
		if err := a.ensureObject(ctx, receipt, i, true); err != nil {
			return false, err
		}
	}
	pods := map[string]*corev1.Pod{}
	for _, identity := range receipt.Objects {
		if identity.Kind != podKind {
			continue
		}
		pod, err := a.kube.CoreV1().Pods(identity.Namespace).Get(ctx, identity.Name, metav1.GetOptions{})
		if err != nil || !owned(pod, *receipt, identity) || !samePodSpec(pod.Spec, a.pod(*receipt, identity).Spec) {
			return false, failure(Unknown, "observed-workload-identity-mismatch")
		}
		if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
			return false, failure(Infrastructure, "http-workload-terminated")
		}
		if !readyPod(pod, identity.Image) {
			record.Observation.Phase = Running
			return true, nil
		}
		pods[identity.Name] = pod
	}
	var results []HTTPResult
	bounded, cancel := context.WithDeadline(ctx, receipt.Deadline)
	defer cancel()
	for _, check := range receipt.Request.Plan.Checks {
		var port int32
		for _, resource := range receipt.Request.Plan.Resources {
			if resource.ID == check.HTTP.Resource {
				port = resource.HTTP.Port
			}
		}
		pod := pods["subject-"+shortDigest([]byte(check.HTTP.Resource))]
		if pod == nil {
			return false, failure(Unknown, "observed-workload-not-found")
		}
		result, err := a.probe(bounded, *receipt, pod, port, check)
		if err != nil {
			return false, err
		}
		after, err := a.kube.CoreV1().Pods(pod.Namespace).Get(bounded, pod.Name, metav1.GetOptions{})
		if err != nil || after.UID != pod.UID || !sameJSON(after.Spec, pod.Spec) || after.Status.PodIP != pod.Status.PodIP ||
			!sameJSON(after.Status.ContainerStatuses, pod.Status.ContainerStatuses) || !readyPod(after, receipt.Request.Subject.Image) {
			return false, failure(Unknown, "workload-changed-during-observation")
		}
		results = append(results, result)
	}
	// Revalidate the namespace and isolation policy after observations too. A
	// policy mutation cannot turn a previously admitted plan into valid evidence.
	for i := range receipt.Objects {
		if err := a.ensureObject(bounded, receipt, i, true); err != nil {
			return false, err
		}
	}
	record.Observation.Checks = results
	return false, nil
}

func (a *Adapter) probe(ctx context.Context, receipt Receipt, pod *corev1.Pod, port int32, check Check) (HTTPResult, error) {
	bounded, cancel := context.WithTimeout(ctx, a.config.Limits.ProbeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, podURL(pod, port, check.HTTP.Path), nil)
	if err != nil {
		return HTTPResult{}, failure(NeedsAdapter, "invalid-http-observation")
	}
	request.Header.Set("User-Agent", "orka-remediation-observer/v1")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := a.http.Do(request)
	if err != nil {
		return HTTPResult{}, failure(Infrastructure, "http-observer-unreachable")
	}
	defer func() { _ = response.Body.Close() }()
	body, err := readBounded(response.Body, a.config.Limits.MaxBodyBytes)
	if err != nil {
		return HTTPResult{}, failure(Infrastructure, "http-observation-body-limit")
	}
	healthy, expectedFailure := ExpectedHTTP(receipt, check)
	result := HTTPResult{
		CheckID: check.ID, Class: check.Class, PodUID: pod.UID, Image: receipt.Request.Subject.Image,
		RuntimeImageID: pod.Status.ContainerStatuses[0].ImageID,
		Status:         response.StatusCode, BodyDigest: digest(body),
		HealthyStatus: healthy.Status, HealthyBodyDigest: digest([]byte(healthy.Body)),
		Outcome: OutcomeOther, ObservedAt: a.now().UTC(),
	}
	if response.StatusCode == healthy.Status && string(body) == healthy.Body {
		result.Outcome = OutcomeHealthy
	}
	if check.HTTP.Failure != nil {
		if *expectedFailure == healthy {
			return HTTPResult{}, failure(NeedsAdapter, "distinct-reproduction-outcomes-required")
		}
		result.FailureStatus, result.FailureBodyDigest = expectedFailure.Status, digest([]byte(expectedFailure.Body))
		if response.StatusCode == expectedFailure.Status && string(body) == expectedFailure.Body {
			result.Outcome = OutcomeFailure
		}
	}
	return result, nil
}

// ExpectedHTTP reconstructs expected bytes from the frozen operation, not from
// subject output. Callers can independently verify response digests.
func ExpectedHTTP(receipt Receipt, check Check) (HTTPExpectation, *HTTPExpectation) {
	expand := func(expected HTTPExpectation) HTTPExpectation {
		synthetic := "synthetic-" + shortDigest([]byte(receipt.Policy.SyntheticScope+":"+receipt.OperationDigest+":"+check.HTTP.Resource))
		expected.Body = strings.ReplaceAll(expected.Body, "${synthetic}", synthetic)
		return expected
	}
	healthy := expand(check.HTTP.Healthy)
	if check.HTTP.Failure == nil {
		return healthy, nil
	}
	failure := expand(*check.HTTP.Failure)
	return healthy, &failure
}
