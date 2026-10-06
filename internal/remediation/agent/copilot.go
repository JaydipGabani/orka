package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/controller"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	"github.com/orka-agents/orka/internal/store"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CopilotConfig freezes the operator-owned model path. IdentityReferences must
// include the proxy routing ConfigMap and credential Secret; only their metadata
// is read. No upstream credential is supplied to the agent.
type CopilotConfig struct {
	Image              string                     `json:"image"`
	RuntimeNamespace   string                     `json:"runtimeNamespace"`
	ProxyEndpoint      string                     `json:"proxyEndpoint"`
	ProxyNamespace     string                     `json:"proxyNamespace"`
	IdentityReferences []CopilotIdentityReference `json:"identityReferences"`
}

var ErrDependencyUnavailable = errors.New("proposal dependency is temporarily unavailable")

type CopilotIdentityReference struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type CopilotClient struct {
	Client       client.Client
	Reader       client.Reader
	Results      store.ResultStore
	Namespace    string
	AgentName    string
	Config       CopilotConfig
	PollInterval time.Duration
	OnAccepted   func(context.Context, Result) error
}

func (c CopilotClient) Snapshot(ctx context.Context) (PlanIdentity, error) {
	if c.Reader == nil || c.Client == nil || c.Results == nil ||
		len(validation.IsDNS1123Subdomain(c.AgentName)) != 0 {
		return PlanIdentity{}, errors.New("governed Copilot remediation configuration is incomplete")
	}
	if err := c.Config.Validate(c.Namespace); err != nil {
		return PlanIdentity{}, err
	}
	var agent corev1alpha1.Agent
	if err := c.Reader.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: c.AgentName}, &agent); err != nil {
		return PlanIdentity{}, copilotIdentityReadError(ctx, err)
	}
	if err := remediationpolicy.ValidateCopilotAgent(&agent); err != nil {
		return PlanIdentity{}, err
	}
	type referenceIdentity struct {
		Reference    CopilotIdentityReference
		UID, Version string
	}
	references := make([]referenceIdentity, 0, len(c.Config.IdentityReferences))
	namespaceUIDs := make(map[string]string, 2)
	for _, namespace := range []string{c.Config.RuntimeNamespace, c.Config.ProxyNamespace} {
		metadata := &metav1.PartialObjectMetadata{}
		metadata.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Namespace"})
		if err := c.Reader.Get(ctx, client.ObjectKey{Name: namespace}, metadata); err != nil {
			return PlanIdentity{}, copilotIdentityReadError(ctx, err)
		}
		if metadata.UID == "" || metadata.DeletionTimestamp != nil {
			return PlanIdentity{}, remediationpolicy.ErrIdentityChanged
		}
		namespaceUIDs[namespace] = string(metadata.UID)
	}
	for _, ref := range c.Config.IdentityReferences {
		metadata := &metav1.PartialObjectMetadata{}
		metadata.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: ref.Kind})
		if err := c.Reader.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, metadata); err != nil {
			return PlanIdentity{}, copilotIdentityReadError(ctx, err)
		}
		if metadata.UID == "" || metadata.ResourceVersion == "" || metadata.DeletionTimestamp != nil {
			return PlanIdentity{}, remediationpolicy.ErrIdentityChanged
		}
		references = append(references, referenceIdentity{ref, string(metadata.UID), metadata.ResourceVersion})
	}
	raw, err := json.Marshal(struct {
		Endpoint   string
		References []referenceIdentity
	}{c.Config.ProxyEndpoint, references})
	if err != nil {
		return PlanIdentity{}, err
	}
	sum := sha256.Sum256(raw)
	placeholder := "sha256:" + strings.Repeat("0", 64)
	probe, err := c.task(Request{TaskName: "rm-" + strings.Repeat("0", 32) + "-checks", RunID: "rm-" + strings.Repeat("0", 32), Prompt: "profile preflight", ExpectedIdentity: placeholder})
	if err != nil {
		return PlanIdentity{}, err
	}
	probe.UID, probe.Generation = types.UID("profile-preflight"), 1
	plan, err := controller.PlanRemediationCopilot(ctx, c.Reader, probe, &agent, c.Config.Image)
	if err != nil {
		return PlanIdentity{}, err
	}
	identity := PlanIdentity{
		Backend: remediationpolicy.CopilotBackend, Namespace: c.Namespace, AgentName: c.AgentName,
		AgentUID: string(agent.UID), AgentGeneration: agent.Generation, RuntimeImage: c.Config.Image,
		RuntimeNamespace: c.Config.RuntimeNamespace, RuntimeProfileDigest: string(plan.Digest),
		RuntimeNamespaceUID: namespaceUIDs[c.Config.RuntimeNamespace],
		ProxyEndpoint:       c.Config.ProxyEndpoint, ProxyNamespace: c.Config.ProxyNamespace,
		ProxyNamespaceUID:   namespaceUIDs[c.Config.ProxyNamespace],
		ProxyIdentityDigest: "sha256:" + hex.EncodeToString(sum[:]),
	}
	identity.CopilotConfigDigest, err = c.Config.Digest()
	if err != nil {
		return PlanIdentity{}, err
	}
	identity.Digest, err = remediationpolicy.MetadataDigest(identity)
	return identity, err
}

func copilotIdentityReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) ||
		apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) {
		return remediationpolicy.ErrIdentityChanged
	}
	return ErrDependencyUnavailable
}

func (c CopilotClient) task(request Request) (*corev1alpha1.Task, error) {
	task := &corev1alpha1.Task{TypeMeta: metav1.TypeMeta{APIVersion: corev1alpha1.GroupVersion.String(), Kind: "Task"},
		ObjectMeta: metav1.ObjectMeta{Name: request.TaskName, Namespace: c.Namespace,
			Labels:      map[string]string{labels.LabelCreatedBy: remediationpolicy.CreatedBy, remediationpolicy.RunLabel: labels.SelectorValue(request.RunID)},
			Annotations: map[string]string{remediationpolicy.RunAnnotation: request.RunID, remediationpolicy.IdentityAnnotation: request.ExpectedIdentity, labels.AnnotationAgentReadOnly: "true"}},
		Spec: remediationpolicy.CopilotTaskSpec(request.Prompt, c.AgentName)}
	digest, err := remediationpolicy.RequestDigest(task.Namespace, task.Name, request.RunID, request.ExpectedIdentity, task.Spec)
	if err != nil {
		return nil, err
	}
	task.Annotations[remediationpolicy.RequestDigestAnnotation] = digest
	return task, nil
}

func (c CopilotClient) Generate(ctx context.Context, request Request) (result Result, resultErr error) {
	result = Result{TaskName: request.TaskName, TaskUID: request.ExpectedTaskUID}
	attempted := false
	defer func() {
		if resultErr != nil && !attempted && !request.RequireExisting && request.ExpectedTaskUID == "" && result.TaskUID == "" {
			resultErr = errors.Join(ErrNotSubmitted, resultErr)
		}
	}()
	if request.Repository != "" || request.Commit != "" || request.MaxTurns != 0 || request.RunID == "" ||
		len(validation.IsDNS1123Subdomain(request.TaskName)) != 0 || len(request.Prompt) > maxPromptBytes ||
		!utf8.ValidString(request.Prompt) || strings.TrimSpace(request.Prompt) == "" {
		return result, errors.New("copilot proposals require a bounded source-free prompt and exact run identity")
	}
	operation, cancel := context.WithTimeout(ctx, generateTimeout)
	defer cancel()
	var identity PlanIdentity
	var err error
	if request.RequireExisting || request.ExpectedTaskUID != "" {
		identity, err = c.snapshotWhenAvailable(operation)
	} else {
		// Before any create, let the durable caller retry a dependency
		// outage without retaining an ambiguous submission intent.
		identity, err = c.Snapshot(operation)
	}
	if err != nil {
		return result, err
	}
	if request.ExpectedIdentity != "" && request.ExpectedIdentity != identity.Digest {
		return result, remediationpolicy.ErrIdentityChanged
	}
	request.ExpectedIdentity = identity.Digest
	expected, err := c.task(request)
	if err != nil {
		return result, err
	}
	if err := c.acceptTask(operation, request, expected, &result, &attempted); err != nil {
		return result, err
	}
	result.Output, resultErr = c.observeCopilotResult(operation, expected, identity, &result)
	return result, resultErr
}

func matchCopilotTask(actual, expected *corev1alpha1.Task, result *Result) error {
	if actual.Name != expected.Name || actual.Namespace != expected.Namespace ||
		(result.TaskUID != "" && result.TaskUID != string(actual.UID)) ||
		remediationpolicy.ValidateCopilotTask(actual) != nil ||
		!reflect.DeepEqual(remediationpolicy.NormalizeTaskSpec(actual.Spec), remediationpolicy.NormalizeTaskSpec(expected.Spec)) ||
		actual.Annotations[remediationpolicy.IdentityAnnotation] != expected.Annotations[remediationpolicy.IdentityAnnotation] ||
		actual.Annotations[remediationpolicy.RunAnnotation] != expected.Annotations[remediationpolicy.RunAnnotation] {
		return errors.New("copilot Task does not match its immutable proposal")
	}
	result.TaskUID = string(actual.UID)
	return nil
}

func (c CopilotClient) Cancel(ctx context.Context, name, uid string) error {
	if c.Reader == nil || c.Client == nil || name == "" || uid == "" {
		return ErrUnsupported
	}
	task := &corev1alpha1.Task{}
	if err := c.Reader.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: name}, task); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return cleanupDependencyError(ctx, err, "Copilot cancellation identity is unavailable")
	}
	if string(task.UID) != uid || !remediationpolicy.IsNativeProposal(task) {
		return remediationpolicy.ErrIdentityChanged
	}
	if task.DeletionTimestamp != nil {
		return ErrCancellationPending
	}
	if remediationpolicy.ValidateCopilotTask(task) != nil {
		return remediationpolicy.ErrIdentityChanged
	}
	if execution := task.Status.Execution; execution != nil {
		switch execution.State {
		case corev1alpha1.TaskExecutionStateSucceeded, corev1alpha1.TaskExecutionStateFailed,
			corev1alpha1.TaskExecutionStateCancelled, corev1alpha1.TaskExecutionStateOutcomeUnknown:
			// Retirement still waits for the controller's finalizer to prove
			// runtime-session cleanup, including an unknown prompt outcome.
			return nil
		}
	}
	switch task.Status.Phase {
	case corev1alpha1.TaskPhaseSucceeded, corev1alpha1.TaskPhaseFailed, corev1alpha1.TaskPhaseCancelled:
		if task.Status.Execution == nil {
			return nil
		}
	}
	if task.Status.Phase == corev1alpha1.TaskPhaseCancelled {
		return ErrCancellationPending
	}
	task.Status.Phase = corev1alpha1.TaskPhaseCancelled
	task.Status.Message = "cancelled by remediation controller"
	if err := c.Client.Status().Update(ctx, task); err != nil {
		if apierrors.IsConflict(err) && ctx.Err() == nil {
			return ErrCancellationPending
		}
		return cleanupDependencyError(ctx, err, "Copilot cancellation could not be recorded")
	}
	return ErrCancellationPending
}

func (c CopilotClient) Retire(ctx context.Context, name, uid string) error {
	return (KubernetesClient{Client: c.Client, Reader: c.Reader, Results: c.Results, Namespace: c.Namespace, AgentName: c.AgentName}).Retire(ctx, name, uid)
}
