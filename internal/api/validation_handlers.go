package api

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/gofiber/fiber/v3"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	pv "github.com/orka-agents/orka/internal/patchverification"
)

type ValidationService interface {
	SubmitRequest(context.Context, string, string, pv.Request) (*pv.KubernetesSubmission, error)
	GetSubmission(context.Context, string, string) (*pv.KubernetesSubmission, error)
	LinkedValidation(context.Context, string, string) (*pv.KubernetesSubmission, error)
	Cancel(context.Context, string, string) error
	Evidence(context.Context, string, string) (*pv.Record, error)
	EvidenceBlob(context.Context, string, string, string) ([]byte, error)
}

func (h *Handlers) validationRequest(c fiber.Ctx, verb, resource string) (string, string, error) {
	if h.validationService == nil ||
		(reflect.ValueOf(h.validationService).Kind() == reflect.Pointer && reflect.ValueOf(h.validationService).IsNil()) {
		return "", "", fiber.NewError(fiber.StatusNotFound, "validation API is disabled")
	}
	user := GetUserInfo(c)
	if user == nil {
		return "", "", fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	if user.AuthType != AuthTypeTokenReview {
		return "", "", fiber.NewError(fiber.StatusForbidden, "validation access requires Kubernetes TokenReview authentication")
	}
	if strings.TrimSpace(user.Username) == "" {
		return "", "", fiber.NewError(fiber.StatusForbidden, "authenticated identity is unavailable")
	}
	explicit := c.Query("namespace")
	if explicit != "" && len(kubevalidation.IsDNS1123Label(explicit)) != 0 {
		return "", "", fiber.NewError(fiber.StatusForbidden, "namespace not allowed")
	}
	namespace, err := h.resolveNamespace(c, explicit)
	if err != nil {
		return "", "", err
	}
	if len(kubevalidation.IsDNS1123Label(namespace)) != 0 {
		return "", "", fiber.NewError(fiber.StatusForbidden, "namespace not allowed")
	}
	if err := authorizeKubernetesResourceAction(c.Context(), h.clientset, user,
		namespace, verb, corev1alpha1.GroupVersion.Group, resource, c.Params("id")); err != nil {
		return "", "", err
	}
	return namespace, user.Username, nil
}

func (h *Handlers) CreateValidation(c fiber.Ctx) (resultErr error) {
	var request pv.Request
	stage := "authorization"
	namespace, identity, err := h.validationRequest(c, "create", "validations")
	defer func() {
		if resultErr == nil {
			return
		}
		action := pv.ActionOrDefault(request.Action)
		if action != pv.ValidateReport && action != pv.VerifyPatch {
			action = "invalid"
		}
		// Decoder and preparation errors can contain private content or paths.
		logf.FromContext(c.Context()).Info("validation creation rejected",
			"namespace", namespace, "action", action, "stage", stage)
	}()
	if err != nil {
		return err
	}
	stage = "decoding"
	if len(c.Body()) > 1<<20 {
		return fiber.NewError(fiber.StatusRequestEntityTooLarge, "validation request exceeds 1 MiB")
	}
	request, err = pv.DecodeRequestJSON(c.Body())
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid validation request")
	}
	if request.EarlierValidation != "" {
		stage = "linked-validation"
		earlier, err := h.validationService.LinkedValidation(c.Context(), namespace, request.EarlierValidation)
		if err != nil {
			return validationHTTPError(err)
		}
		if earlier == nil || earlier.Namespace != namespace || earlier.RunID != request.EarlierValidation ||
			earlier.RequestID == "" || earlier.RequestID != strings.TrimSpace(earlier.RequestID) {
			return fiber.NewError(fiber.StatusNotFound, "validation not found")
		}
		stage = "linked-evidence-authorization"
		if err := authorizeKubernetesResourceAction(c.Context(), h.clientset, GetUserInfo(c),
			namespace, "get", corev1alpha1.GroupVersion.Group, "validations/evidence", earlier.RequestID); err != nil {
			return err
		}
	}
	stage = "preparation"
	submission, err := h.validationService.SubmitRequest(c.Context(), namespace, identity, request)
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, string(pv.UnavailableAction(request.Action)))
	}
	stage = "response"
	return c.Status(fiber.StatusAccepted).JSON(submission)
}

func (h *Handlers) GetValidation(c fiber.Ctx) error {
	namespace, _, err := h.validationRequest(c, "get", "validations")
	if err != nil {
		return err
	}
	submission, err := h.validationService.GetSubmission(c.Context(), namespace, c.Params("id"))
	if err != nil {
		return validationHTTPError(err)
	}
	return c.JSON(submission)
}

func (h *Handlers) GetValidationEvidence(c fiber.Ctx) error {
	namespace, _, err := h.validationRequest(c, "get", "validations/evidence")
	if err != nil {
		return err
	}
	record, err := h.validationService.Evidence(c.Context(), namespace, c.Params("id"))
	if err != nil {
		return validationHTTPError(err)
	}
	return c.JSON(record)
}

func (h *Handlers) GetValidationEvidenceBlob(c fiber.Ctx) error {
	namespace, _, err := h.validationRequest(c, "get", "validations/evidence")
	if err != nil {
		return err
	}
	content, err := h.validationService.EvidenceBlob(c.Context(), namespace, c.Params("id"), c.Params("digest"))
	if err != nil {
		return validationHTTPError(err)
	}
	c.Set(fiber.HeaderContentType, fiber.MIMEOctetStream)
	return c.Send(content)
}

func (h *Handlers) CancelValidation(c fiber.Ctx) error {
	namespace, _, err := h.validationRequest(c, "update", "validations/cancel")
	if err != nil {
		return err
	}
	if err := h.validationService.Cancel(c.Context(), namespace, c.Params("id")); err != nil {
		return validationHTTPError(err)
	}
	submission, err := h.validationService.GetSubmission(c.Context(), namespace, c.Params("id"))
	if err != nil {
		return validationHTTPError(err)
	}
	return c.Status(fiber.StatusAccepted).JSON(submission)
}

func validationHTTPError(err error) error {
	if errors.Is(err, pv.ErrRunNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "validation not found")
	}
	if errors.Is(err, pv.ErrClosed) {
		return fiber.NewError(fiber.StatusConflict, "validation is already closed")
	}
	return fiber.NewError(fiber.StatusInternalServerError, "validation operation failed")
}
