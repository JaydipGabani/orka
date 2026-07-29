/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"

	"github.com/gofiber/fiber/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

const (
	toolListCursorVersion    = 1
	maxToolListCursorLength  = 16 * 1024
	maxToolCursorHistorySize = 64
)

// toolListCursor is traversal state, not an authorization credential. Every
// request resolves its namespace and re-applies item authorization before data
// is returned. The cursor only combines the built-in offset with Kubernetes'
// opaque continuation token and detects non-progress/cycles.
type toolListCursor struct {
	Version         int      `json:"v"`
	Namespace       string   `json:"n"`
	BuiltinOffset   int      `json:"b"`
	Continue        string   `json:"c,omitempty"`
	History         []string `json:"h,omitempty"`
	ResourceVersion string   `json:"r,omitempty"`
	CustomAvailable bool     `json:"a,omitempty"`
}

func (h *Handlers) allowedBuiltinTools(c fiber.Ctx) ([]fiber.Map, error) {
	allowedTools := make([]fiber.Map, 0, len(builtinToolsList))
	for _, tool := range builtinToolsList {
		name, _ := tool["name"].(string)
		allowed, err := contextTokenAllowsToolMetadata(c, h.contextTokenAuthorization, "listTools", name)
		if err != nil {
			return nil, err
		}
		if allowed {
			allowedTools = append(allowedTools, tool)
		}
	}
	return allowedTools, nil
}

func (h *Handlers) filteredCustomToolNames(c fiber.Ctx) ([]string, bool) {
	if !h.contextTokenAuthorization.enforcing() || !isContextTokenRequest(c) {
		return nil, false
	}
	ui := GetUserInfo(c)
	if ui == nil || ui.ContextToken == nil {
		return nil, false
	}
	allowedTools, ok := contextStringList(ui.ContextToken.TransactionContext, "allowedTools")
	if !ok {
		return nil, false
	}

	unique := make(map[string]struct{}, len(allowedTools))
	for _, name := range allowedTools {
		if name != "" {
			unique[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(unique))
	for name := range unique {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, true
}

// filteredToolListAll resolves only names already authorized by the token. It
// intentionally returns one complete logical page: exposing a raw Kubernetes
// continuation after filtering would reveal hidden inventory structure, while
// the signed token already bounds the candidate name set.
func (h *Handlers) filteredToolListAll(
	c fiber.Ctx,
	namespace string,
	builtins []fiber.Map,
	allowedNames []string,
) (ListResponse, error) {
	items := append([]fiber.Map(nil), builtins...)
	builtinNames := make(map[string]struct{}, len(builtins))
	for _, builtin := range builtins {
		if name, _ := builtin["name"].(string); name != "" {
			builtinNames[name] = struct{}{}
		}
	}
	for _, name := range allowedNames {
		if _, builtin := builtinNames[name]; builtin {
			continue
		}
		tool := &corev1alpha1.Tool{}
		if err := h.apiReader.Get(c.Context(), client.ObjectKey{Namespace: namespace, Name: name}, tool); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return ListResponse{}, fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("failed to get tool %q: %v", name, err))
		}
		allowed, err := contextTokenAllowsToolMetadata(c, h.contextTokenAuthorization, "listTools", tool.Name)
		if err != nil {
			return ListResponse{}, err
		}
		if allowed {
			items = append(items, customToolListItem(tool))
		}
	}
	return ListResponse{Items: items, Metadata: ListMeta{}}, nil
}

func (h *Handlers) unpaginatedToolListAll(
	c fiber.Ctx,
	namespace string,
	builtins []fiber.Map,
) (ListResponse, error) {
	toolList := &corev1alpha1.ToolList{}
	if err := h.apiReader.List(c.Context(), toolList, &client.ListOptions{Namespace: namespace}); err != nil {
		return ListResponse{}, paginationListError("tools", err)
	}
	customItems, _, err := customToolListItems(c, h.contextTokenAuthorization, toolList.Items)
	if err != nil {
		return ListResponse{}, err
	}
	items := append(append([]fiber.Map(nil), builtins...), customItems...)
	return ListResponse{Items: items, Metadata: ListMeta{}}, nil
}

func decodeToolListCursor(raw, namespace string, builtinCount int) (toolListCursor, error) {
	cursor := toolListCursor{Version: toolListCursorVersion, Namespace: namespace}
	if raw == "" {
		return cursor, nil
	}
	if len(raw) > maxToolListCursorLength {
		return toolListCursor{}, fmt.Errorf("invalid tools continue cursor: cursor is too large")
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return toolListCursor{}, fmt.Errorf("invalid tools continue cursor: malformed encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil {
		return toolListCursor{}, fmt.Errorf("invalid tools continue cursor: malformed payload")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return toolListCursor{}, fmt.Errorf("invalid tools continue cursor: trailing payload")
	}
	if cursor.Version != toolListCursorVersion || cursor.Namespace != namespace ||
		cursor.BuiltinOffset < 0 || cursor.BuiltinOffset > builtinCount ||
		len(cursor.History) > maxToolCursorHistorySize ||
		(cursor.Continue != "" && (cursor.BuiltinOffset != builtinCount || cursor.ResourceVersion == "" || !cursor.CustomAvailable)) {
		return toolListCursor{}, fmt.Errorf("invalid tools continue cursor: cursor does not match this request")
	}
	return cursor, nil
}

func encodeToolListCursor(cursor toolListCursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encode tools continue cursor: %w", err)
	}
	if len(data) > maxToolListCursorLength {
		return "", fmt.Errorf("encode tools continue cursor: cursor is too large")
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func advanceToolListCursor(cursor toolListCursor, nextContinue string) (toolListCursor, error) {
	if nextContinue == "" {
		cursor.Continue = ""
		return cursor, nil
	}
	if nextContinue == cursor.Continue {
		return toolListCursor{}, fmt.Errorf("tools continue cursor did not advance")
	}
	digest := hashToolContinuation(nextContinue)
	if slices.Contains(cursor.History, digest) {
		return toolListCursor{}, fmt.Errorf("tools continue cursor cycle detected")
	}
	if len(cursor.History) >= maxToolCursorHistorySize {
		cursor.History = append(cursor.History[1:], digest)
	} else {
		cursor.History = append(cursor.History, digest)
	}
	cursor.Continue = nextContinue
	return cursor, nil
}

func hashToolContinuation(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func (h *Handlers) kubernetesToolListPage(
	c fiber.Ctx,
	namespace string,
	pageSize int64,
	builtins []fiber.Map,
	cursor toolListCursor,
	items []fiber.Map,
) (ListResponse, error) {
	for cursor.BuiltinOffset < len(builtins) && int64(len(items)) < pageSize {
		items = append(items, builtins[cursor.BuiltinOffset])
		cursor.BuiltinOffset++
	}

	if int64(len(items)) == pageSize {
		if cursor.ResourceVersion == "" {
			resourceVersion, available, err := h.probeCustomToolSnapshot(c.Context(), namespace)
			if err != nil {
				return ListResponse{}, err
			}
			cursor.ResourceVersion = resourceVersion
			cursor.CustomAvailable = available
		}
		if cursor.BuiltinOffset >= len(builtins) && !cursor.CustomAvailable {
			return ListResponse{Items: items, Metadata: ListMeta{}}, nil
		}
		continuation, err := encodeToolListCursor(cursor)
		if err != nil {
			return ListResponse{}, fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		return ListResponse{Items: items, Metadata: ListMeta{Continue: continuation}}, nil
	}
	if cursor.ResourceVersion != "" && !cursor.CustomAvailable {
		return ListResponse{Items: items, Metadata: ListMeta{}}, nil
	}

	toolList := &corev1alpha1.ToolList{}
	opts := &client.ListOptions{
		Namespace: namespace,
		Limit:     pageSize - int64(len(items)),
		Continue:  cursor.Continue,
	}
	if cursor.Continue == "" && cursor.ResourceVersion != "" {
		opts.Raw = &metav1.ListOptions{
			ResourceVersion:      cursor.ResourceVersion,
			ResourceVersionMatch: metav1.ResourceVersionMatchExact,
		}
	}
	if err := h.apiReader.List(c.Context(), toolList, opts); err != nil {
		return ListResponse{}, paginationListError("tools", err)
	}
	customItems, filtered, err := customToolListItems(c, h.contextTokenAuthorization, toolList.Items)
	if err != nil {
		return ListResponse{}, err
	}
	items = append(items, customItems...)
	metadata := ListMeta{}
	if !filtered {
		remaining := int64(len(builtins) - cursor.BuiltinOffset)
		if toolList.RemainingItemCount != nil {
			remaining += *toolList.RemainingItemCount
			metadata.RemainingItemCount = &remaining
		}
	}
	if toolList.Continue == "" {
		return ListResponse{Items: items, Metadata: metadata}, nil
	}
	if toolList.ResourceVersion == "" {
		return ListResponse{}, fiber.NewError(fiber.StatusInternalServerError, "tool list response omitted resourceVersion")
	}

	cursor.BuiltinOffset = len(builtins)
	cursor.ResourceVersion = toolList.ResourceVersion
	cursor.CustomAvailable = true
	cursor, err = advanceToolListCursor(cursor, toolList.Continue)
	if err != nil {
		return ListResponse{}, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	metadata.Continue, err = encodeToolListCursor(cursor)
	if err != nil {
		return ListResponse{}, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return ListResponse{Items: items, Metadata: metadata}, nil
}

func (h *Handlers) probeCustomToolSnapshot(ctx context.Context, namespace string) (string, bool, error) {
	probe := &corev1alpha1.ToolList{}
	if err := h.apiReader.List(ctx, probe, &client.ListOptions{Namespace: namespace, Limit: 1}); err != nil {
		return "", false, paginationListError("tools", err)
	}
	if probe.ResourceVersion == "" {
		return "", false, fiber.NewError(fiber.StatusInternalServerError, "tool list response omitted resourceVersion")
	}
	return probe.ResourceVersion, len(probe.Items) > 0 || probe.Continue != "", nil
}

func customToolListItems(
	c fiber.Ctx,
	authz ContextTokenAuthorizationConfig,
	tools []corev1alpha1.Tool,
) ([]fiber.Map, bool, error) {
	items := make([]fiber.Map, 0, len(tools))
	filtered := false
	for i := range tools {
		tool := &tools[i]
		allowed, err := contextTokenAllowsToolMetadata(c, authz, "listTools", tool.Name)
		if err != nil {
			return nil, false, err
		}
		if !allowed {
			filtered = true
			continue
		}
		items = append(items, customToolListItem(tool))
	}
	return items, filtered, nil
}

func customToolListItem(tool *corev1alpha1.Tool) fiber.Map {
	return fiber.Map{
		"name":        tool.Name,
		"namespace":   tool.Namespace,
		"builtin":     false,
		"description": tool.Spec.Description,
		"available":   tool.Status.Available,
		"url":         toolSpecHTTPURL(tool),
	}
}
