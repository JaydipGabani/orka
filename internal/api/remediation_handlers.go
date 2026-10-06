package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	remediationservice "github.com/orka-agents/orka/internal/remediation/service"
	"github.com/orka-agents/orka/internal/store"
)

type RemediationService interface {
	PolicyName(namespace, name string) (string, error)
	Submit(context.Context, string, string, remediationservice.Request) (remediationservice.Status, bool, error)
	Get(context.Context, string, string) (remediationservice.Status, error)
	Cancel(context.Context, string, string) (remediationservice.Status, error)
	Approve(context.Context, string, string, string, string) (remediationservice.Status, error)
	Artifact(context.Context, string, string, string) (*store.RemediationArtifact, []byte, error)
	List(context.Context, string, int, string) (remediationservice.RunList, error)
	DrainNamespace(context.Context, string) (remediationservice.DrainStatus, error)
	ReconcileCleanup(context.Context, string, string, string, uint64) (remediationservice.Status, error)
}

func (h *Handlers) remediationAvailable() bool {
	if h.remediationService == nil {
		return false
	}
	value := reflect.ValueOf(h.remediationService)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return !value.IsNil()
	default:
		return true
	}
}

func (h *Handlers) requireRemediationEnabled(c fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	if !h.remediationAvailable() {
		return fiber.NewError(fiber.StatusNotFound, "remediation API is disabled")
	}
	return c.Next()
}

func (h *Handlers) remediationRequest(c fiber.Ctx, verb, resource string) (string, string, error) {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	if !h.remediationAvailable() {
		return "", "", fiber.NewError(fiber.StatusNotFound, "remediation API is disabled")
	}
	user := GetUserInfo(c)
	if user == nil {
		return "", "", fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	// The experiment has no OIDC or context-token authorization contract.
	if user.AuthType != AuthTypeTokenReview {
		return "", "", fiber.NewError(fiber.StatusForbidden, "remediation access requires Kubernetes TokenReview authentication")
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
	id := c.Params("id")
	if id != "" && (len(id) > 96 || len(kubevalidation.IsDNS1123Subdomain(id)) != 0) {
		return "", "", fiber.NewError(fiber.StatusBadRequest, "invalid remediation ID")
	}
	if err := authorizeKubernetesResourceAction(c.Context(), h.clientset, user,
		namespace, verb, corev1alpha1.GroupVersion.Group, resource, id); err != nil {
		return "", "", err
	}
	return namespace, user.Username, nil
}

func (h *Handlers) CreateRemediation(c fiber.Ctx) error {
	namespace, actor, err := h.remediationRequest(c, "create", "remediations")
	if err != nil {
		return err
	}
	raw, err := remediationBody(c, remediationservice.MaxRequestBytes)
	if err != nil {
		return err
	}
	request, err := remediationservice.DecodeRequest(raw)
	if err != nil {
		return remediationHTTPError(remediationservice.ErrInvalid)
	}
	policy, err := h.remediationService.PolicyName(namespace, request.Policy)
	if err != nil {
		return remediationHTTPError(err)
	}
	if len(kubevalidation.IsDNS1123Label(policy)) != 0 {
		return remediationHTTPError(remediationservice.ErrPolicy)
	}
	if err := authorizeKubernetesResourceAction(c.Context(), h.clientset, GetUserInfo(c),
		namespace, "use", corev1alpha1.GroupVersion.Group, "remediationpolicies", policy); err != nil {
		return err
	}
	request.Policy = policy
	user := GetUserInfo(c)
	ctx := remediationservice.WithActor(c.Context(), remediationservice.ActorIdentity{Username: user.Username, UID: user.UID, Groups: user.Groups})
	status, _, err := h.remediationService.Submit(ctx, namespace, actor, request)
	if err != nil {
		return remediationHTTPError(err)
	}
	if status.RequestID != request.RequestID {
		return remediationHTTPError(store.ErrRemediationIntegrity)
	}
	return remediationStatusResponse(c, namespace, "", status, fiber.StatusAccepted)
}

func (h *Handlers) GetRemediation(c fiber.Ctx) error {
	namespace, _, err := h.remediationRequest(c, "get", "remediations")
	if err != nil {
		return err
	}
	status, err := h.remediationService.Get(c.Context(), namespace, c.Params("id"))
	if err != nil {
		return remediationHTTPError(err)
	}
	return remediationStatusResponse(c, namespace, c.Params("id"), status, fiber.StatusOK)
}

func (h *Handlers) ListRemediations(c fiber.Ctx) error {
	namespace, _, err := h.remediationRequest(c, "list", "remediations")
	if err != nil {
		return err
	}
	limit := store.RemediationMaxListLimit
	if requested := c.Query("limit"); requested != "" {
		limit, err = strconv.Atoi(requested)
		if err != nil || limit < 1 || limit > store.RemediationMaxListLimit {
			return remediationHTTPError(remediationservice.ErrInvalid)
		}
	}
	before := c.Query("continue")
	if len(before) > 96 || (before != "" && len(kubevalidation.IsDNS1123Subdomain(before)) != 0) {
		return remediationHTTPError(remediationservice.ErrInvalid)
	}
	page, err := h.remediationService.List(c.Context(), namespace, limit, before)
	if err != nil {
		return remediationHTTPError(err)
	}
	if len(page.Items) > limit || (page.Continue != "" && (len(page.Items) == 0 || page.Continue != page.Items[len(page.Items)-1].ID)) {
		return remediationHTTPError(store.ErrRemediationIntegrity)
	}
	for _, run := range page.Items {
		if run.Namespace != namespace || run.ID == "" {
			return remediationHTTPError(store.ErrRemediationIntegrity)
		}
	}
	return c.JSON(page)
}

func (h *Handlers) GetRemediationDrain(c fiber.Ctx) error {
	namespace, _, err := h.remediationRequest(c, "get", "remediations/drain")
	if err != nil {
		return err
	}
	status, err := h.remediationService.DrainNamespace(c.Context(), namespace)
	if err != nil {
		return remediationHTTPError(err)
	}
	if status.Namespace != namespace || status.Active < 0 || status.Quarantined < 0 || status.RetainedIntakes < 0 ||
		status.Complete != (status.Active == 0 && status.Quarantined == 0) || status.IntakeDrained != (status.RetainedIntakes == 0) {
		return remediationHTTPError(store.ErrRemediationIntegrity)
	}
	return c.JSON(status)
}

func (h *Handlers) ReconcileRemediationCleanup(c fiber.Ctx) error {
	namespace, actor, err := h.remediationRequest(c, "update", "remediations/reconcile")
	if err != nil {
		return err
	}
	raw, err := remediationBody(c, 4<<10)
	if err != nil {
		return err
	}
	revision, err := decodeRemediationReconcile(raw)
	if err != nil {
		return remediationHTTPError(err)
	}
	status, err := h.remediationService.ReconcileCleanup(c.Context(), namespace, c.Params("id"), actor, revision)
	if err != nil {
		return remediationHTTPError(err)
	}
	return remediationStatusResponse(c, namespace, c.Params("id"), status, fiber.StatusAccepted)
}

func (h *Handlers) ApproveRemediation(c fiber.Ctx) error {
	namespace, actor, err := h.remediationRequest(c, "update", "remediations/approve")
	if err != nil {
		return err
	}
	raw, err := remediationBody(c, 4<<10)
	if err != nil {
		return err
	}
	digest, err := decodeRemediationApproval(raw)
	if err != nil {
		return remediationHTTPError(err)
	}
	status, err := h.remediationService.Approve(c.Context(), namespace, c.Params("id"), digest, actor)
	if err != nil {
		return remediationHTTPError(err)
	}
	return remediationStatusResponse(c, namespace, c.Params("id"), status, fiber.StatusAccepted)
}

func (h *Handlers) CancelRemediation(c fiber.Ctx) error {
	namespace, _, err := h.remediationRequest(c, "update", "remediations/cancel")
	if err != nil {
		return err
	}
	status, err := h.remediationService.Cancel(c.Context(), namespace, c.Params("id"))
	if err != nil {
		return remediationHTTPError(err)
	}
	return remediationStatusResponse(c, namespace, c.Params("id"), status, fiber.StatusAccepted)
}

func (h *Handlers) DownloadRemediationArtifact(c fiber.Ctx) error {
	namespace, _, err := h.remediationRequest(c, "get", "remediations/artifacts")
	if err != nil {
		return err
	}
	name := c.Params("name")
	if !safeRemediationArtifactName(name) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid remediation artifact name")
	}
	artifact, content, err := h.remediationService.Artifact(c.Context(), namespace, c.Params("id"), name)
	if err != nil {
		return remediationHTTPError(err)
	}
	if artifact == nil || artifact.Name != name || artifact.Size != int64(len(content)) ||
		len(content) > store.RemediationMaxArtifactBytes || artifact.Digest != remediationservice.Digest(content) {
		return remediationHTTPError(store.ErrRemediationIntegrity)
	}
	digest := sha256.Sum256(content)
	c.Set(fiber.HeaderContentType, safeRemediationContentType(artifact.MediaType))
	c.Set(fiber.HeaderContentDisposition, mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	c.Set(fiber.HeaderContentLength, strconv.Itoa(len(content)))
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(digest[:]))
	c.Set(fiber.HeaderETag, `"`+artifact.Digest+`"`)
	return c.Send(content)
}

func remediationStatusResponse(c fiber.Ctx, namespace, id string, status remediationservice.Status, code int) error {
	if status.Namespace != namespace || status.ID == "" || (id != "" && status.ID != id) {
		return remediationHTTPError(store.ErrRemediationIntegrity)
	}
	return c.Status(code).JSON(status)
}

func remediationBody(c fiber.Ctx, limit int) ([]byte, error) {
	if encoding := c.Get(fiber.HeaderContentEncoding); encoding != "" && encoding != "identity" {
		c.Response().Header.SetConnectionClose()
		return nil, fiber.NewError(fiber.StatusBadRequest, "encoded remediation requests are not supported")
	}
	if c.Request().Header.ContentLength() > limit {
		c.Response().Header.SetConnectionClose()
		return nil, fiber.NewError(fiber.StatusRequestEntityTooLarge, "remediation request exceeds its size limit")
	}
	raw := c.Body()
	if len(raw) > limit {
		return nil, fiber.NewError(fiber.StatusRequestEntityTooLarge, "remediation request exceeds its size limit")
	}
	return raw, nil
}

func decodeRemediationApproval(raw []byte) (string, error) {
	if len(raw) > 4<<10 || !utf8.Valid(raw) {
		return "", remediationservice.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return "", remediationservice.ErrInvalid
	}
	if token, err := decoder.Token(); err != nil || token != "planDigest" {
		return "", remediationservice.ErrInvalid
	}
	var digest string
	if err := decoder.Decode(&digest); err != nil || !validRemediationDigest(digest) {
		return "", remediationservice.ErrInvalid
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return "", remediationservice.ErrInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return "", remediationservice.ErrInvalid
	}
	return digest, nil
}

func decodeRemediationReconcile(raw []byte) (uint64, error) {
	if len(raw) > 4<<10 || !utf8.Valid(raw) {
		return 0, remediationservice.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return 0, remediationservice.ErrInvalid
	}
	if token, err := decoder.Token(); err != nil || token != "expectedRevision" {
		return 0, remediationservice.ErrInvalid
	}
	var revision uint64
	if err := decoder.Decode(&revision); err != nil || revision == 0 || revision >= math.MaxInt64 {
		return 0, remediationservice.ErrInvalid
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return 0, remediationservice.ErrInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return 0, remediationservice.ErrInvalid
	}
	return revision, nil
}

func validRemediationDigest(digest string) bool {
	if len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") || strings.ToLower(digest) != digest {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	return err == nil
}

func safeRemediationArtifactName(name string) bool {
	if len(name) == 0 || len(name) > 256 {
		return false
	}
	for i, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if i == 0 || (r != '.' && r != '_' && r != '-') {
			return false
		}
	}
	return true
}

func safeRemediationContentType(value string) string {
	mediaType, _, err := mime.ParseMediaType(value)
	if err == nil {
		switch mediaType {
		case fiber.MIMEApplicationJSON:
			return fiber.MIMEApplicationJSON
		case fiber.MIMETextPlain, "text/x-diff", "text/x-patch":
			return mediaType + "; charset=utf-8"
		}
	}
	return fiber.MIMEOctetStream
}

func remediationHTTPError(err error) error {
	switch {
	case errors.Is(err, remediationservice.ErrDisabled):
		return fiber.NewError(fiber.StatusNotFound, "remediation API is disabled")
	case errors.Is(err, remediationservice.ErrIntakeConnectorUnavailable):
		return fiber.NewError(fiber.StatusNotImplemented, "server-side IcM acquisition is not configured; submit a complete snapshot using the CLI")
	case errors.Is(err, remediationservice.ErrRetryable):
		return fiber.NewError(fiber.StatusServiceUnavailable, "remediation dependency is temporarily unavailable")
	case errors.Is(err, store.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "remediation or artifact not found")
	case errors.Is(err, remediationservice.ErrPolicy):
		return fiber.NewError(fiber.StatusForbidden, "remediation policy is unavailable or not permitted")
	case errors.Is(err, remediationservice.ErrInvalid), errors.Is(err, store.ErrValidation):
		return fiber.NewError(fiber.StatusBadRequest, "invalid remediation request")
	case errors.Is(err, store.ErrDuplicateMismatch):
		return fiber.NewError(fiber.StatusConflict, "request ID was already used for different input")
	case errors.Is(err, store.ErrConflict), errors.Is(err, remediationservice.ErrApproval):
		return fiber.NewError(fiber.StatusConflict, "remediation state or approval digest does not match")
	case errors.Is(err, store.ErrCapacity):
		return fiber.NewError(fiber.StatusTooManyRequests, "remediation capacity is unavailable")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, "remediation operation failed")
	}
}
