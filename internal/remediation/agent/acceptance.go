package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/remediationpolicy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AcceptanceRequest binds a read-only cleanup lookup to the durable model
// intent. It deliberately carries a prompt digest, not another prompt to send.
type AcceptanceRequest struct {
	TaskName        string
	ExpectedTaskUID string
	RunID           string
	PromptDigest    string
	Expected        PlanIdentity
}

// AcceptanceResolver is optional: transports without an uncached, canonical
// Task reader cannot recover an uncertain create from a deterministic name.
type AcceptanceResolver interface {
	ResolveAccepted(context.Context, AcceptanceRequest) (Result, error)
}

// ErrAcceptanceUnresolved does not prove either creation or retirement.
var ErrAcceptanceUnresolved = errors.New("proposal Task acceptance remains unresolved")

// ResolveAccepted never creates, dispatches, or reads model output. Current
// Agent/Provider configuration is irrelevant to retiring a frozen operation.
func (c KubernetesClient) ResolveAccepted(ctx context.Context, request AcceptanceRequest) (Result, error) {
	result := Result{TaskName: request.TaskName, TaskUID: request.ExpectedTaskUID}
	if err := c.validateReader(ctx); err != nil {
		return result, err
	}
	identity, err := remediationpolicy.MetadataDigest(request.Expected)
	if err != nil || identity != request.Expected.Digest ||
		request.Expected.Namespace != c.Namespace || request.Expected.AgentName != c.AgentName ||
		len(validation.IsDNS1123Subdomain(request.TaskName)) != 0 ||
		len(validation.IsDNS1123Subdomain(request.RunID)) != 0 ||
		!validNativeDigest(request.PromptDigest) {
		return result, remediationpolicy.ErrIdentityChanged
	}
	task := &corev1alpha1.Task{}
	if err := c.Reader.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: request.TaskName}, task); err != nil {
		if apierrors.IsNotFound(err) {
			if request.ExpectedTaskUID != "" {
				return result, nil
			}
			// Without a saved UID, absence cannot prove whether creation
			// committed. It must never become successful cleanup.
			return result, ErrAcceptanceUnresolved
		}
		return result, cleanupDependencyError(ctx, err, "proposal acceptance observation is unavailable")
	}
	if task.Name != request.TaskName || task.Namespace != c.Namespace ||
		(request.ExpectedTaskUID != "" && string(task.UID) != request.ExpectedTaskUID) ||
		task.Annotations[nativeRunAnnotation] != request.RunID ||
		task.Annotations[nativeIdentityAnnotation] != request.Expected.Digest ||
		task.Spec.AgentRef == nil || task.Spec.AgentRef.Name != request.Expected.AgentName {
		return result, remediationpolicy.ErrIdentityChanged
	}
	switch task.Spec.Type {
	case corev1alpha1.TaskTypeAI:
		if request.Expected.Backend != "" {
			return result, remediationpolicy.ErrIdentityChanged
		}
	case corev1alpha1.TaskTypeAgent:
		if request.Expected.Backend != remediationpolicy.CopilotBackend {
			return result, remediationpolicy.ErrIdentityChanged
		}
	default:
		return result, remediationpolicy.ErrIdentityChanged
	}
	digest := sha256.Sum256([]byte(task.Spec.Prompt))
	if request.PromptDigest != "sha256:"+hex.EncodeToString(digest[:]) || validateCleanupTask(task) != nil {
		return result, remediationpolicy.ErrIdentityChanged
	}
	result.TaskUID = string(task.UID)
	return result, nil
}

func (c CopilotClient) ResolveAccepted(ctx context.Context, request AcceptanceRequest) (Result, error) {
	return (KubernetesClient{Reader: c.Reader, Namespace: c.Namespace, AgentName: c.AgentName}).ResolveAccepted(ctx, request)
}

func validateCleanupTask(task *corev1alpha1.Task) error {
	if task == nil || task.UID == "" || task.ResourceVersion == "" || task.Generation < 1 ||
		len(validation.IsDNS1123Subdomain(task.Name)) != 0 ||
		len(validation.IsDNS1123Label(task.Namespace)) != 0 || len(task.OwnerReferences) != 0 ||
		(task.Kind != "" && task.Kind != nativeTaskKind) ||
		(task.APIVersion != "" && task.APIVersion != corev1alpha1.GroupVersion.String()) ||
		!utf8.ValidString(task.Spec.Prompt) || strings.TrimSpace(task.Spec.Prompt) == "" {
		return remediationpolicy.ErrIdentityChanged
	}
	// Only cleanup accepts deletion in progress. The original dispatch
	// validators remain unchanged and still reject deleting Tasks.
	observed := task.DeepCopy()
	observed.DeletionTimestamp = nil
	switch observed.Spec.Type {
	case corev1alpha1.TaskTypeAI:
		return remediationpolicy.ValidateTask(observed)
	case corev1alpha1.TaskTypeAgent:
		return remediationpolicy.ValidateCopilotTask(observed)
	default:
		return remediationpolicy.ErrIdentityChanged
	}
}

func cleanupDependencyError(ctx context.Context, err error, message string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	public := errors.New(message)
	// Identity/precondition and other permanent API rejections are not
	// dependency outages. Never retain the API response in the returned error.
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		code := status.Status().Code
		if code >= http.StatusBadRequest && code < http.StatusInternalServerError &&
			code != http.StatusRequestTimeout && code != http.StatusTooManyRequests {
			return public
		}
	}
	return errors.Join(ErrDependencyUnavailable, public)
}
