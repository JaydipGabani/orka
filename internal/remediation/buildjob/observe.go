package buildjob

import (
	"context"
	"reflect"
	"regexp"
	"slices"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var symbolPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.]{0,63}$`)

func (b *Backend) Observe(ctx context.Context, r Receipt) (Result, error) {
	result := Result{Receipt: r, WorkerResult: WorkerResult{Version: Version, InputDigest: r.InputDigest}}
	if err := b.validateReceipt(r, true); err != nil {
		return result, err
	}
	bounded, cancel := context.WithTimeout(ctx, b.config.Limits.APITimeout)
	defer cancel()
	m, input, err := b.observationIdentity(bounded, r)
	if err != nil {
		return result, err
	}
	pods, err := b.listPods(bounded, r)
	if err != nil {
		return result, err
	}
	if len(pods) == 0 {
		anchor, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(bounded, r.AnchorName, metav1.GetOptions{})
		if err != nil {
			return result, apiFailure(bounded, err, "build-anchor-unavailable-after-pod-list")
		}
		if _, _, err := b.verifyAnchor(anchor, r, false); err != nil {
			return result, err
		}
		if anchor.Annotations[podUIDAnnotation] != "" {
			return result, failure(ErrLost, "accepted-build-pod-missing")
		}
		if err := b.checkUnstartedJob(bounded, r); err != nil {
			return result, err
		}
		return result, nil
	}
	if len(pods) != 1 {
		return result, failure(ErrIdentity, "multiple-build-pods-replay-forbidden")
	}
	pod := &pods[0]
	if err := b.verifyPod(pod, r); err != nil {
		return result, err
	}
	if err := b.bindUID(bounded, r, podUIDAnnotation, pod.UID); err != nil {
		return result, err
	}
	result.PodName, result.PodUID = pod.Name, pod.UID
	terminated, imageID, err := b.termination(pod)
	result.ContainerImageID = imageID
	if err != nil || terminated == nil {
		return result, err
	}
	wire, err := readWorkerResult(terminated, r.InputDigest, diagnosticPaths(m, input))
	if err != nil {
		return result, err
	}
	if err := b.recheckTermination(bounded, r, pod); err != nil {
		return result, err
	}
	result.WorkerResult, result.Done = wire, true
	if wire.BuildOutcome == Success {
		result.Image = input.OutputRepository + "@" + wire.ImmutableImageDigest
	}
	result.ResultDigest = result.BindingDigest()
	if wire.DaemonSettled {
		if err := b.recordDaemonSettlement(bounded, r, pod, wire, false); err != nil {
			return Result{Receipt: r}, err
		}
	}
	return result, nil
}

func (b *Backend) checkUnstartedJob(ctx context.Context, r Receipt) error {
	job, err := b.config.APIReader.BatchV1().Jobs(r.Namespace).Get(ctx, r.JobName, metav1.GetOptions{})
	if err != nil {
		return apiFailure(ctx, err, "unstarted-build-job-missing")
	}
	if err := b.verifyJob(job, r, false); err != nil {
		return err
	}
	for _, condition := range job.Status.Conditions {
		if (condition.Type == batchv1.JobComplete || condition.Type == batchv1.JobFailed) &&
			condition.Status == corev1.ConditionTrue {
			return failure(ErrLost, "terminal-build-job-has-no-pod-evidence")
		}
	}
	return nil
}

func (b *Backend) observationIdentity(ctx context.Context, r Receipt) (manifest, Input, error) {
	if _, err := b.namespace(ctx, r.NamespaceUID); err != nil {
		return manifest{}, Input{}, err
	}
	if err := b.verifyClientSecrets(ctx, r); err != nil {
		return manifest{}, Input{}, err
	}
	record, err := b.config.APIReader.CoreV1().ConfigMaps(r.Namespace).Get(ctx, r.LedgerName, metav1.GetOptions{})
	if err != nil {
		return manifest{}, Input{}, apiFailure(ctx, err, "build-ledger-unavailable")
	}
	if err := b.verifyLedger(record, r, false); err != nil {
		return manifest{}, Input{}, err
	}
	anchor, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{})
	if err != nil {
		return manifest{}, Input{}, apiFailure(ctx, err, "build-anchor-unavailable")
	}
	m, input, err := b.verifyAnchor(anchor, r, false)
	if err != nil {
		return m, input, err
	}
	if anchor.Annotations[jobUIDAnnotation] != string(r.JobUID) {
		return m, input, failure(ErrIdentity, "build-job-uid-not-durably-accepted")
	}
	job, err := b.config.APIReader.BatchV1().Jobs(r.Namespace).Get(ctx, r.JobName, metav1.GetOptions{})
	if err != nil {
		return m, input, apiFailure(ctx, err, "accepted-build-job-missing")
	}
	return m, input, b.verifyJob(job, r, false)
}

func (b *Backend) listPods(ctx context.Context, r Receipt) ([]corev1.Pod, error) {
	var result []corev1.Pod
	options := metav1.ListOptions{Limit: 128}
	for range 32 {
		list, err := b.config.APIReader.CoreV1().Pods(r.Namespace).List(ctx, options)
		if err != nil {
			return nil, apiFailure(ctx, err, "build-pod-inventory-unavailable")
		}
		for _, pod := range list.Items {
			if relevantPod(&pod, r) {
				result = append(result, pod)
			}
		}
		if list.Continue == "" {
			return result, nil
		}
		options.Continue = list.Continue
	}
	return nil, failure(ErrLimit, "dedicated-build-namespace-inventory-limit")
}

func relevantPod(pod *corev1.Pod, r Receipt) bool {
	if pod.Labels[operationLabel] == protectedLabels(r)[operationLabel] ||
		pod.Labels[batchv1.JobNameLabel] == r.JobName || pod.Labels["job-name"] == r.JobName {
		return true
	}
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "Job" && (owner.Name == r.JobName || (r.JobUID != "" && owner.UID == r.JobUID)) {
			return true
		}
	}
	return false
}

func ownedPod(pod *corev1.Pod, r Receipt) bool {
	if pod.Namespace != r.Namespace || pod.UID == "" || r.JobUID == "" || len(pod.OwnerReferences) != 1 {
		return false
	}
	owner := pod.OwnerReferences[0]
	return owner.APIVersion == "batch/v1" && owner.Kind == "Job" &&
		owner.Name == r.JobName && owner.UID == r.JobUID && owner.Controller != nil && *owner.Controller
}

func (b *Backend) verifyPod(pod *corev1.Pod, r Receipt) error {
	if !ownedPod(pod, r) || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil ||
		!protectedTemplate(pod.ObjectMeta, r, r.JobUID) {
		return failure(ErrIdentity, "build-pod-identity-or-ownership-mismatch")
	}
	actual, expected := pod.Spec.DeepCopy(), b.desiredPod(r)
	actual.NodeName = ""
	normalizePodDefaults(actual)
	normalizePodDefaults(&expected)
	var remaining []corev1.Toleration
	for _, toleration := range actual.Tolerations {
		if !defaultToleration(toleration) {
			remaining = append(remaining, toleration)
		}
	}
	actual.Tolerations = remaining
	if !equality.Semantic.DeepEqual(*actual, expected) {
		return failure(ErrIdentity, "build-pod-execution-template-mismatch")
	}
	return nil
}

func defaultToleration(toleration corev1.Toleration) bool {
	return (toleration.Key == "node.kubernetes.io/not-ready" || toleration.Key == "node.kubernetes.io/unreachable") &&
		toleration.Operator == corev1.TolerationOpExists && toleration.Effect == corev1.TaintEffectNoExecute &&
		toleration.Value == "" && toleration.TolerationSeconds != nil && *toleration.TolerationSeconds == 300
}

func (b *Backend) termination(pod *corev1.Pod) (*corev1.ContainerStateTerminated, string, error) {
	if len(pod.Status.InitContainerStatuses) != 0 || len(pod.Status.EphemeralContainerStatuses) != 0 ||
		len(pod.Status.ContainerStatuses) > 1 {
		return nil, "", failure(ErrIdentity, "unexpected-build-container-status")
	}
	if len(pod.Status.ContainerStatuses) == 0 {
		if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
			return nil, "", failure(ErrLost, "build-worker-termination-evidence-missing")
		}
		return nil, "", nil
	}
	status := pod.Status.ContainerStatuses[0]
	if status.Name != workerName || status.RestartCount != 0 ||
		status.LastTerminationState != (corev1.ContainerState{}) {
		return nil, "", failure(ErrIdentity, "build-worker-restarted-or-replaced")
	}
	if status.ImageID != "" && !matchesImageID(b.config.WorkerImage, status.ImageID) {
		return nil, "", failure(ErrIdentity, "build-worker-runtime-image-mismatch")
	}
	if status.State.Terminated == nil {
		return nil, status.ImageID, nil
	}
	// CRI may report the image's config digest in Image. The immutable Pod
	// image and the verified runtime ImageID above are the execution identity.
	if status.Image == "" || status.ImageID == "" || status.ContainerID == "" ||
		status.State.Terminated.ContainerID != status.ContainerID ||
		status.State.Running != nil || status.State.Waiting != nil ||
		(pod.Status.Phase != corev1.PodFailed && pod.Status.Phase != corev1.PodSucceeded) ||
		(status.State.Terminated.ExitCode == 0) != (pod.Status.Phase == corev1.PodSucceeded) {
		return nil, "", failure(ErrIdentity, "build-worker-termination-identity-mismatch")
	}
	return status.State.Terminated, status.ImageID, nil
}

func matchesImageID(image, runtimeID string) bool {
	_, wanted, found := strings.Cut(image, "@")
	if !found {
		return false
	}
	for _, prefix := range []string{"docker-pullable://", "docker://", "containerd://", "cri-o://"} {
		runtimeID = strings.TrimPrefix(runtimeID, prefix)
	}
	if _, suffix, ok := strings.Cut(runtimeID, "@"); ok {
		return suffix == wanted
	}
	return runtimeID == wanted
}

func readWorkerResult(terminated *corev1.ContainerStateTerminated, inputDigest string, paths map[string]bool) (WorkerResult, error) {
	var wire WorkerResult
	if terminated.Message == "" && terminated.ExitCode != 0 {
		return WorkerResult{Version: Version, InputDigest: inputDigest, BuildOutcome: Infrastructure}, nil
	}
	if len(terminated.Message) > MaxTerminationBytes || decodeStrict([]byte(terminated.Message), &wire) != nil ||
		wire.Version != Version || wire.InputDigest != inputDigest || len(wire.Diagnostics) > MaxDiagnostics {
		return wire, failure(ErrIdentity, "invalid-build-worker-result")
	}
	if !validSettlementFields(wire) {
		return wire, failure(ErrIdentity, "invalid-build-daemon-settlement")
	}
	if wire.BuildOutcome != TestFailure && wire.BuildExitCode != 0 {
		return wire, failure(ErrIdentity, "unexpected-build-exit-code")
	}
	switch wire.BuildOutcome {
	case Success:
		if terminated.ExitCode != 0 || terminated.Signal != 0 || !digestPattern.MatchString(wire.ImmutableImageDigest) {
			return wire, failure(ErrIdentity, "invalid-successful-build-result")
		}
	case CompileFailure:
		if terminated.ExitCode == 0 || wire.ImmutableImageDigest != "" || len(wire.Diagnostics) == 0 {
			return wire, failure(ErrIdentity, "invalid-compile-failure-result")
		}
	case TestFailure:
		if wire.BuildExitCode < 1 || wire.BuildExitCode > 255 ||
			terminated.ExitCode != int32(wire.BuildExitCode) || terminated.Signal != 0 || wire.ImmutableImageDigest != "" {
			return wire, failure(ErrIdentity, "invalid-test-failure-result")
		}
	case Infrastructure, Cancelled:
		if terminated.ExitCode == 0 || wire.ImmutableImageDigest != "" {
			return wire, failure(ErrIdentity, "invalid-failed-build-result")
		}
	default:
		return wire, failure(ErrIdentity, "unsupported-build-outcome")
	}
	if err := validateWorkerDiagnostics(wire, paths); err != nil {
		return wire, err
	}
	return wire, nil
}

func validateWorkerDiagnostics(wire WorkerResult, paths map[string]bool) error {
	seen := make(map[Diagnostic]bool)
	for _, diagnostic := range wire.Diagnostics {
		if seen[diagnostic] {
			return failure(ErrIdentity, "duplicate-build-diagnostic")
		}
		seen[diagnostic] = true
		if wire.BuildOutcome == TestFailure {
			if diagnostic.Symbol != "" || diagnostic.Column != 0 ||
				(diagnostic.TestName != "" && !SafeTestName(diagnostic.TestName)) {
				return failure(ErrIdentity, "unsafe-test-diagnostic")
			}
			if diagnostic.Path == "" && diagnostic.Line == 0 && SafeTestName(diagnostic.TestName) {
				continue
			}
			if !strings.HasSuffix(diagnostic.Path, ".go") {
				return failure(ErrIdentity, "invalid-test-source-path")
			}
		} else if diagnostic.TestName != "" {
			return failure(ErrIdentity, "unexpected-test-name")
		}
		if !paths[diagnostic.Path] || !safeDiagnosticPath(diagnostic.Path) ||
			diagnostic.Line < 1 || diagnostic.Line > 10000000 || diagnostic.Column < 0 || diagnostic.Column > 1000000 ||
			(diagnostic.Symbol != "" && !symbolPattern.MatchString(diagnostic.Symbol)) {
			return failure(ErrIdentity, "unsafe-build-diagnostic")
		}
	}
	return nil
}

func diagnosticPaths(m manifest, input Input) map[string]bool {
	paths := make(map[string]bool, len(input.Files)+len(m.SourcePaths))
	for name := range input.Files {
		paths[name] = true
	}
	for _, name := range m.SourcePaths {
		paths[name] = true
	}
	return paths
}

func (b *Backend) recheckTermination(ctx context.Context, r Receipt, original *corev1.Pod) error {
	fresh, err := b.config.APIReader.CoreV1().Pods(r.Namespace).Get(ctx, original.Name, metav1.GetOptions{})
	if err != nil {
		return apiFailure(ctx, err, "build-pod-replaced-during-observation")
	}
	if fresh.UID != original.UID || fresh.Status.Phase != original.Status.Phase ||
		!reflect.DeepEqual(fresh.Status.ContainerStatuses, original.Status.ContainerStatuses) {
		return failure(ErrIdentity, "build-termination-changed-during-observation")
	}
	if err := b.verifyPod(fresh, r); err != nil {
		return err
	}
	if _, _, err := b.observationIdentity(ctx, r); err != nil {
		return err
	}
	anchor, err := b.config.APIReader.CoreV1().Secrets(r.Namespace).Get(ctx, r.AnchorName, metav1.GetOptions{})
	if err != nil {
		return apiFailure(ctx, err, "build-anchor-replaced-during-observation")
	}
	if _, _, err := b.verifyAnchor(anchor, r, false); err != nil {
		return err
	}
	if anchor.Annotations[podUIDAnnotation] != string(original.UID) {
		return failure(ErrIdentity, "build-pod-uid-changed-during-observation")
	}
	pods, err := b.listPods(ctx, r)
	if err != nil {
		return err
	}
	if len(pods) != 1 || pods[0].UID != original.UID {
		return failure(ErrIdentity, "build-pod-set-changed-during-observation")
	}
	return nil
}

func sortedUIDs(seen map[types.UID]bool) []types.UID {
	if len(seen) == 0 {
		return nil
	}
	uids := make([]types.UID, 0, len(seen))
	for uid := range seen {
		uids = append(uids, uid)
	}
	slices.Sort(uids)
	return uids
}
