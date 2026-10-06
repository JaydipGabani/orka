package agent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/workerenv"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	nativeProposalOwner       = remediationpolicy.CreatedBy
	nativeTaskKind            = "Task"
	nativeRunLabel            = remediationpolicy.RunLabel
	nativeRunAnnotation       = remediationpolicy.RunAnnotation
	nativeRequestAnnotation   = remediationpolicy.RequestDigestAnnotation
	nativeIdentityAnnotation  = remediationpolicy.IdentityAnnotation
	nativeCancellationMessage = "cancelled by remediation controller"
)

// ErrUnsupported indicates that the observed Task cannot use native cancellation.
var ErrUnsupported = errors.New("proposal Task cancellation is unsupported for this phase")

// ErrNotSubmitted proves this invocation never attempted a Task create.
// It is never returned for an uncertain create or a saved Task identity.
var ErrNotSubmitted = errors.New("proposal Task was not submitted")

var ErrProviderNotReady = errors.New("proposal Provider is not ready")

// ErrCancellationPending means execution has not been observed stopped. The
// service must retain its durable Cancelling intent and reconcile the same Task
// UID rather than treating a status acknowledgement as completion.
var ErrCancellationPending = errors.New("proposal Task cancellation is awaiting execution shutdown")

// ErrCredentialRotated distinguishes a changed Secret from other plan drift.
// It never authorizes an automatic retry or endpoint change.
var ErrCredentialRotated = remediationpolicy.ErrCredentialRotated

// PlanIdentity is the metadata-only identity shared with the dispatch guard.
type PlanIdentity = remediationpolicy.PlanIdentity

type nativePlan struct {
	identity PlanIdentity
	ready    bool
}

// KubernetesClient runs a source-free, no-tools native AI Task using controller
// authority. Reader must be an uncached API reader, not the manager's cache.
// The caller persists intent and TaskName before Generate, then saves the exact
// Task UID in OnAccepted. An uncertain create resumes with RequireExisting.
type KubernetesClient struct {
	Client       client.Client
	Reader       client.Reader
	Results      store.ResultStore
	Namespace    string
	AgentName    string
	PollInterval time.Duration
	OnAccepted   func(context.Context, Result) error
}

// Snapshot validates the native Agent policy and freezes its effective public
// configuration identity without treating readiness as identity. Secret reads
// use Kubernetes metadata negotiation. Creation separately requires readiness.
func (c KubernetesClient) Snapshot(ctx context.Context) (PlanIdentity, error) {
	plan, err := c.readPlan(ctx)
	return plan.identity, err
}

func (c KubernetesClient) readPlan(ctx context.Context) (nativePlan, error) {
	var plan nativePlan
	if err := c.validateReader(ctx); err != nil {
		return plan, err
	}
	registered := &corev1alpha1.Agent{}
	key := client.ObjectKey{Namespace: c.Namespace, Name: c.AgentName}
	if err := c.Reader.Get(ctx, key, registered); err != nil {
		return plan, nativePublicError(ctx, err, "proposal Agent is unavailable")
	}
	if registered.Name != c.AgentName || registered.Namespace != c.Namespace {
		return plan, errors.New("proposal Agent has a different identity")
	}
	if err := remediationpolicy.ValidateAgent(registered); err != nil {
		return plan, err
	}
	provider := &corev1alpha1.Provider{}
	key.Name = registered.Spec.ProviderRef.Name
	if err := c.Reader.Get(ctx, key, provider); err != nil {
		return plan, nativePublicError(ctx, err, "proposal Provider is unavailable")
	}
	identity, err := remediationpolicy.MetadataIdentity(ctx, c.Reader, registered, provider)
	if err != nil {
		return plan, err
	}
	return nativePlan{identity: identity, ready: provider.Status.Ready}, nil
}

func (c KubernetesClient) validateReader(ctx context.Context) error {
	if ctx == nil {
		return errors.New("proposal context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Reader == nil {
		return errors.New("proposal uncached Kubernetes reader is required")
	}
	if len(validation.IsDNS1123Label(c.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(c.AgentName)) != 0 {
		return errors.New("proposal namespace and Agent must be explicit Kubernetes names")
	}
	return nil
}

// Generate creates at most once, or resumes the exact native Task. Cancellation
// of ctx only stops observation; it never deletes or replaces accepted work.
func (c KubernetesClient) Generate(ctx context.Context, request Request) (result Result, resultErr error) {
	result = Result{TaskName: request.TaskName, TaskUID: request.ExpectedTaskUID}
	attempted := false
	defer func() {
		if resultErr != nil && !attempted && !request.RequireExisting && request.ExpectedTaskUID == "" && result.TaskUID == "" {
			resultErr = errors.Join(ErrNotSubmitted, resultErr)
		}
	}()
	if err := c.validateRequest(ctx, request); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, generateTimeout)
	defer cancel()
	if c.PollInterval == 0 {
		c.PollInterval = defaultPollInterval
	}
	identity, err := c.Snapshot(ctx)
	if err != nil {
		return result, err
	}
	if request.ExpectedIdentity != "" && request.ExpectedIdentity != identity.Digest {
		return result, remediationpolicy.ErrIdentityChanged
	}
	request.ExpectedIdentity = identity.Digest
	expected, err := c.nativeTask(request)
	if err != nil {
		return result, err
	}
	task, err := c.getOrCreate(ctx, expected, request, identity, &attempted)
	if err != nil {
		return result, err
	}
	if err := matchNativeTask(task, expected, &result); err != nil {
		return result, err
	}
	expected.Generation = task.Generation
	if c.OnAccepted != nil {
		if err := c.OnAccepted(ctx, result); err != nil {
			return result, nativePublicError(ctx, err, "proposal Task acceptance checkpoint failed")
		}
	}
	return c.observe(ctx, expected, task, result, identity)
}

func (c KubernetesClient) validateRequest(ctx context.Context, request Request) error {
	if err := c.validateReader(ctx); err != nil {
		return err
	}
	if c.Client == nil || c.Results == nil {
		return errors.New("proposal Kubernetes client and result store are required")
	}
	if len(validation.IsDNS1123Subdomain(request.TaskName)) != 0 {
		return errors.New("proposal Task name must be a deterministic Kubernetes name")
	}
	if len(request.Prompt) > maxPromptBytes || !utf8.ValidString(request.Prompt) || strings.TrimSpace(request.Prompt) == "" {
		return errors.New("proposal prompt must be nonempty UTF-8 and at most 256 KiB")
	}
	if request.Repository != "" || request.Commit != "" || request.MaxTurns != 0 {
		return errors.New("native proposals require source in the prompt and do not accept repository or runtime overrides")
	}
	if request.ExpectedIdentity != "" && !validNativeDigest(request.ExpectedIdentity) {
		return errors.New("proposal expected identity must be an exact SHA-256 digest")
	}
	if request.RunID != "" && (len(request.RunID) > 253 || len(validation.IsDNS1123Subdomain(request.RunID)) != 0) {
		return errors.New("proposal run identity must be a stable Kubernetes-compatible identifier")
	}
	if c.PollInterval < 0 || c.PollInterval > maxPollInterval {
		return errors.New("proposal polling interval must be positive and at most 30 seconds")
	}
	return nil
}

func (c KubernetesClient) nativeTask(request Request) (*corev1alpha1.Task, error) {
	runID := request.RunID
	if runID == "" {
		runID = request.TaskName
	}
	task := &corev1alpha1.Task{
		TypeMeta: metav1.TypeMeta{APIVersion: corev1alpha1.GroupVersion.String(), Kind: nativeTaskKind},
		ObjectMeta: metav1.ObjectMeta{
			Name: request.TaskName, Namespace: c.Namespace,
			Labels: map[string]string{
				labels.LabelCreatedBy: nativeProposalOwner,
				nativeRunLabel:        labels.SelectorValue(runID),
			},
			Annotations: map[string]string{
				nativeRunAnnotation: runID, nativeIdentityAnnotation: request.ExpectedIdentity,
			},
		},
		Spec: remediationpolicy.TaskSpec(request.Prompt, c.AgentName),
	}
	digest, err := remediationpolicy.RequestDigest(c.Namespace, request.TaskName, runID, request.ExpectedIdentity, task.Spec)
	if err != nil {
		return nil, err
	}
	task.Annotations[nativeRequestAnnotation] = digest
	return task, nil
}

func validNativeDigest(value string) bool {
	return remediationpolicy.ValidDigest(value)
}

func (c KubernetesClient) checkIdentity(ctx context.Context, expected PlanIdentity) error {
	current, err := c.Snapshot(ctx)
	if err != nil {
		return err
	}
	return remediationpolicy.CompareIdentity(expected, current)
}

func (c KubernetesClient) getOrCreate(
	ctx context.Context, expected *corev1alpha1.Task, request Request, identity PlanIdentity, attempted *bool,
) (*corev1alpha1.Task, error) {
	task := &corev1alpha1.Task{}
	key := client.ObjectKeyFromObject(expected)
	err := c.Reader.Get(ctx, key, task)
	if err == nil {
		return task, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, nativePublicError(ctx, err, "proposal Task could not be read")
	}
	if request.ExpectedTaskUID != "" || request.RequireExisting {
		return nil, errors.New("saved proposal Task is missing; refusing to recreate")
	}
	plan, err := c.readPlan(ctx)
	if err != nil {
		return nil, err
	}
	if err := remediationpolicy.CompareIdentity(identity, plan.identity); err != nil {
		return nil, err
	}
	if !plan.ready {
		return nil, ErrProviderNotReady
	}
	// Even a failed Create can have committed. There is never a second Create;
	// a caller recovering an unresolved outcome must use RequireExisting.
	*attempted = true
	createErr := c.Client.Create(ctx, expected.DeepCopy())
	if apierrors.IsBadRequest(createErr) || apierrors.IsForbidden(createErr) || apierrors.IsUnauthorized(createErr) || apierrors.IsInvalid(createErr) {
		*attempted = false
	}
	for attempt := range maxReadAttempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := c.Reader.Get(ctx, key, task); err == nil {
			return task, nil
		}
		if attempt+1 < maxReadAttempts {
			if err := wait(ctx, c.PollInterval); err != nil {
				return nil, err
			}
		}
	}
	return nil, nativePublicError(ctx, createErr, "proposal Task create outcome is unresolved; resume the same name with RequireExisting")
}

func matchNativeTask(task, expected *corev1alpha1.Task, result *Result) error {
	if task.Name != expected.Name || task.Namespace != expected.Namespace || task.UID == "" || task.Generation < 1 ||
		(task.Kind != "" && task.Kind != expected.Kind) ||
		(task.APIVersion != "" && task.APIVersion != expected.APIVersion) {
		return errors.New("proposal Task has a different or missing identity")
	}
	if result.TaskUID != "" && result.TaskUID != string(task.UID) {
		return errors.New("proposal Task UID changed")
	}
	if expected.Generation != 0 && task.Generation != expected.Generation {
		return errors.New("proposal Task generation changed")
	}
	if task.DeletionTimestamp != nil || len(task.OwnerReferences) != 0 {
		return errors.New("proposal Task is deleting or owned by another resource")
	}
	if !reflect.DeepEqual(task.Labels, expected.Labels) || !reflect.DeepEqual(task.Annotations, expected.Annotations) ||
		!reflect.DeepEqual(remediationpolicy.NormalizeTaskSpec(task.Spec), remediationpolicy.NormalizeTaskSpec(expected.Spec)) {
		return errors.New("proposal Task name is occupied by a different request or native policy")
	}
	result.TaskUID = string(task.UID)
	return nil
}

func (c KubernetesClient) observe(
	ctx context.Context, expected, task *corev1alpha1.Task, result Result, identity PlanIdentity,
) (Result, error) {
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := matchNativeTask(task, expected, &result); err != nil {
			return result, err
		}
		switch task.Status.Phase {
		case corev1alpha1.TaskPhaseSucceeded:
			output, err := c.readCompletedResult(ctx, expected, &result, identity)
			if err != nil {
				return result, err
			}
			result.Output = output
			return result, nil
		case corev1alpha1.TaskPhaseFailed:
			return result, errors.New("proposal Task failed")
		case corev1alpha1.TaskPhaseCancelled:
			return result, errors.New("proposal Task was cancelled")
		case "", corev1alpha1.TaskPhasePending, corev1alpha1.TaskPhaseRunning, corev1alpha1.TaskPhaseFinalizing:
		default:
			return result, errors.New("proposal Task has an unexpected phase")
		}
		if err := c.checkIdentity(ctx, identity); err != nil {
			return result, err
		}
		if err := wait(ctx, c.PollInterval); err != nil {
			return result, err
		}
		if err := c.Reader.Get(ctx, client.ObjectKeyFromObject(expected), task); err != nil {
			return result, nativePublicError(ctx, err, "accepted proposal Task could not be read; refusing to recreate")
		}
	}
}

func (c KubernetesClient) readCompletedResult(
	ctx context.Context, expected *corev1alpha1.Task, result *Result, identity PlanIdentity,
) (string, error) {
	if err := c.checkIdentity(ctx, identity); err != nil {
		return "", err
	}
	before, err := c.completedTask(ctx, expected, result)
	if err != nil {
		return "", err
	}
	// ResultStore is indexed by name, not UID. Both uncached reads must attest
	// the same successful Task before any bytes are released to the caller.
	data, readErr := c.Results.GetResult(ctx, expected.Namespace, expected.Name)
	after, err := c.completedTask(ctx, expected, result)
	if err != nil {
		return "", err
	}
	if before.Generation != after.Generation {
		return "", errors.New("proposal Task generation changed while reading its result")
	}
	if err := c.checkIdentity(ctx, identity); err != nil {
		return "", err
	}
	if readErr != nil {
		return "", nativePublicError(ctx, readErr, "proposal result is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(data) > maxResponseBytes || !utf8.Valid(data) {
		return "", errors.New("proposal result must be UTF-8 and at most 2 MiB")
	}
	output := string(data)
	if text := strings.TrimSpace(output); text == "" || text == emptyProposalOutput {
		return "", errors.New("proposal result contains no textual output")
	}
	return output, nil
}

func (c KubernetesClient) completedTask(
	ctx context.Context, expected *corev1alpha1.Task, result *Result,
) (*corev1alpha1.Task, error) {
	task := &corev1alpha1.Task{}
	if err := c.Reader.Get(ctx, client.ObjectKeyFromObject(expected), task); err != nil {
		return nil, nativePublicError(ctx, err, "completed proposal Task could not be read")
	}
	if err := matchNativeTask(task, expected, result); err != nil {
		return nil, err
	}
	if task.Status.Phase != corev1alpha1.TaskPhaseSucceeded {
		return nil, errors.New("proposal Task completion changed while reading its result")
	}
	return task, nil
}

// Cancel follows the native controller's Cancelled status transition and reports
// ErrCancellationPending until uncached Job/Pod observations prove quiescence.
// Native handleCompleted deletes Jobs with background propagation, so neither a
// status acknowledgement nor an absent Job proves that its Pods have stopped.
// A pre-dispatch Task without a Job receipt stays pending: the native controller
// does not expose a fenced acknowledgement that execution never started.
func (c KubernetesClient) Cancel(ctx context.Context, name, uid string) error {
	if err := c.validateReader(ctx); err != nil {
		return err
	}
	if c.Client == nil || len(validation.IsDNS1123Subdomain(name)) != 0 || strings.TrimSpace(uid) == "" {
		return errors.New("proposal cancellation requires a client, Task name, and exact UID")
	}
	task := &corev1alpha1.Task{}
	if err := c.Reader.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: name}, task); err != nil {
		return nativePublicError(ctx, err, "proposal Task cancellation target is unavailable")
	}
	if task.ResourceVersion == "" || task.UID != types.UID(uid) {
		return errors.New("proposal Task cancellation identity changed")
	}
	request := Request{
		TaskName: name, ExpectedTaskUID: uid, Prompt: task.Spec.Prompt,
		ExpectedIdentity: task.Annotations[nativeIdentityAnnotation], RunID: task.Annotations[nativeRunAnnotation],
	}
	if !validNativeDigest(request.ExpectedIdentity) || request.RunID == "" {
		return errors.New("proposal cancellation target is not an owned native Task")
	}
	expected, err := c.nativeTask(request)
	if err != nil {
		return err
	}
	if err := matchNativeTask(task, expected, &Result{TaskName: name, TaskUID: uid}); err != nil {
		return err
	}
	expected.Generation = task.Generation
	switch task.Status.Phase {
	case corev1alpha1.TaskPhaseSucceeded, corev1alpha1.TaskPhaseFailed, corev1alpha1.TaskPhaseCancelled:
		return c.observeNativeShutdown(ctx, task, expected)
	case "":
		// Initial status reconciliation can still write Pending. Do not race
		// that initialization or claim that an unacknowledged dispatch stopped.
		return ErrCancellationPending
	case corev1alpha1.TaskPhasePending, corev1alpha1.TaskPhaseRunning:
	default:
		return ErrUnsupported
	}
	if err := c.validateCancellationJob(ctx, task); err != nil {
		return err
	}
	now := metav1.Now()
	task.Status.Phase = corev1alpha1.TaskPhaseCancelled
	task.Status.CompletionTime = &now
	task.Status.Message = nativeCancellationMessage
	if err := c.Client.Status().Update(ctx, task); err != nil {
		if apierrors.IsConflict(err) {
			return ErrCancellationPending
		}
		return nativePublicError(ctx, err, "proposal Task cancellation was not acknowledged; recheck the same UID")
	}
	return ErrCancellationPending
}

func (c KubernetesClient) validateCancellationJob(ctx context.Context, task *corev1alpha1.Task) error {
	if task.Status.JobName == "" {
		return nil
	}
	job := &batchv1.Job{}
	err := c.Reader.Get(ctx, client.ObjectKey{Namespace: task.Namespace, Name: task.Status.JobName}, job)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return nativePublicError(ctx, err, "proposal cancellation Job identity is unavailable")
	}
	if !nativeJobOwnedByTask(job, task) {
		return errors.New("proposal cancellation Job has a different owner")
	}
	return nil
}

func nativeJobOwnedByTask(job *batchv1.Job, task *corev1alpha1.Task) bool {
	owner := metav1.GetControllerOf(job)
	return job.Namespace == task.Namespace && owner != nil &&
		owner.APIVersion == corev1alpha1.GroupVersion.String() && owner.Kind == nativeTaskKind &&
		owner.Name == task.Name && owner.UID == task.UID && job.UID != "" && job.ResourceVersion != ""
}

func (c KubernetesClient) observeNativeShutdown(ctx context.Context, task, expected *corev1alpha1.Task) error {
	jobs := &batchv1.JobList{}
	if err := c.Reader.List(ctx, jobs, client.InNamespace(task.Namespace)); err != nil {
		return nativePublicError(ctx, err, "proposal cancellation Jobs could not be observed")
	}
	jobUIDs := make(map[types.UID]bool)
	pending := false
	for i := range jobs.Items {
		job := &jobs.Items[i]
		if !nativeJobOwnedByTask(job, task) {
			if job.Name == task.Status.JobName {
				return errors.New("proposal cancellation Job has a different owner")
			}
			continue
		}
		jobUIDs[job.UID] = true
		if task.Status.JobName == "" {
			// Preserve the exact observed Job name before cleanup, including
			// the create/cancel race where the controller never saved it.
			task.Status.JobName = job.Name
			if err := c.Client.Status().Update(ctx, task); err != nil {
				if apierrors.IsConflict(err) {
					return ErrCancellationPending
				}
				return nativePublicError(ctx, err, "proposal cancellation Job observation could not be saved")
			}
		}
		if nativeJobStopped(job) {
			continue
		}
		pending = true
		if job.DeletionTimestamp != nil {
			continue
		}
		// A cancellation can race Job creation before JobName is persisted.
		// handleCompleted cannot find that Job. Reap only this Task UID's exact
		// owned Job, with foreground GC and both optimistic preconditions.
		options := []client.DeleteOption{
			client.Preconditions{UID: &job.UID, ResourceVersion: &job.ResourceVersion},
			client.PropagationPolicy(metav1.DeletePropagationForeground),
		}
		if err := c.Client.Delete(ctx, job, options...); err != nil && !apierrors.IsNotFound(err) {
			if apierrors.IsConflict(err) {
				return ErrCancellationPending
			}
			return nativePublicError(ctx, err, "proposal cancellation Job shutdown was not acknowledged")
		}
	}
	pods := &corev1.PodList{}
	if err := c.Reader.List(ctx, pods, client.InNamespace(task.Namespace)); err != nil {
		return nativePublicError(ctx, err, "proposal cancellation Pods could not be observed")
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed &&
			nativePodMayBelongToTask(pod, task, jobUIDs) {
			pending = true
		}
	}
	current := &corev1alpha1.Task{}
	if err := c.Reader.Get(ctx, client.ObjectKeyFromObject(task), current); err != nil {
		return nativePublicError(ctx, err, "proposal cancellation Task could not be revalidated")
	}
	if err := matchNativeTask(current, expected, &Result{TaskName: task.Name, TaskUID: string(task.UID)}); err != nil {
		return err
	}
	if pending || current.Status.Phase != task.Status.Phase || current.Status.JobName != task.Status.JobName {
		return ErrCancellationPending
	}
	// The native controller has no never-started receipt. A cancelled Task
	// without an acknowledged Job cannot rule out an in-flight create.
	if current.Status.Phase == corev1alpha1.TaskPhaseCancelled && current.Status.JobName == "" {
		return ErrCancellationPending
	}
	return ctx.Err()
}

func nativeJobStopped(job *batchv1.Job) bool {
	if job.Status.Active != 0 {
		return false
	}
	for _, condition := range job.Status.Conditions {
		if condition.Status == corev1.ConditionTrue &&
			(condition.Type == batchv1.JobComplete || condition.Type == batchv1.JobFailed) {
			return true
		}
	}
	return false
}

func nativePodMayBelongToTask(pod *corev1.Pod, task *corev1alpha1.Task, jobUIDs map[types.UID]bool) bool {
	if pod.Labels[labels.LabelTask] == labels.SelectorValue(task.Name) {
		return true
	}
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "Job" && (jobUIDs[owner.UID] || (task.Status.JobName != "" && owner.Name == task.Status.JobName)) {
			return true
		}
	}
	// Labels can disappear after background Job deletion. The real JobBuilder
	// stamps TaskUID in the immutable worker container environment. This is only
	// a conservative stop-observation check, never authority to delete a Pod.
	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			if env.Name == workerenv.TaskUID && env.Value == string(task.UID) {
				return true
			}
		}
	}
	return false
}

// API errors and callback errors can contain request bodies or provider output.
// Only context sentinels cross this boundary; all other messages are static.
func nativePublicError(ctx context.Context, err error, message string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New(message)
}
