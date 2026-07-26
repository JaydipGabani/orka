/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"

	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
)

type memoryHandlerSurface struct {
	app                 *fiber.App
	listMemories        string
	createMemory        string
	memory              func(string) string
	disableMemory       func(string) string
	enableMemory        func(string) string
	listProposals       string
	createProposal      string
	proposal            func(string) string
	reviewProposal      func(string) string
	applyProposal       func(string) string
	archiveProposal     func(string) string
	expectsListEnvelope bool
}

func TestMemoryHandlerSharedOperations(t *testing.T) {
	for _, setup := range []struct {
		name string
		new  func(*testing.T, *sqlite.Store) memoryHandlerSurface
	}{
		{name: "public", new: newPublicMemoryHandlerSurface},
		{name: "internal", new: newInternalMemoryHandlerSurface},
	} {
		t.Run(setup.name, func(t *testing.T) {
			memoryStore := newMemoryHandlerTestStore(t)
			surface := setup.new(t, memoryStore)

			created := requestMemoryHandlerJSON[store.Memory](t, surface.app, http.MethodPost, surface.createMemory, http.StatusCreated, map[string]any{
				"namespace": "default",
				"source":    "manual",
				"content":   "remember this",
			})
			require.NotEmpty(t, created.ID)
			require.Equal(t, "default", created.Namespace)

			fetched := requestMemoryHandlerJSON[store.Memory](t, surface.app, http.MethodGet, surface.memory(created.ID), http.StatusOK, nil)
			require.Equal(t, created.ID, fetched.ID)

			updated := requestMemoryHandlerJSON[store.Memory](t, surface.app, http.MethodPut, surface.memory(created.ID), http.StatusOK, map[string]any{
				"namespace": "default",
				"content":   "updated memory",
				"tags":      []string{"shared", "operation"},
			})
			require.Equal(t, "updated memory", updated.Content)
			require.Equal(t, []string{"shared", "operation"}, updated.Tags)

			requestMemoryHandlerStatus(t, surface.app, http.MethodPost, surface.disableMemory(created.ID), nil, http.StatusNoContent)
			disabled, err := memoryStore.GetMemory(context.Background(), "default", created.ID)
			require.NoError(t, err)
			require.True(t, disabled.Disabled)

			requestMemoryHandlerStatus(t, surface.app, http.MethodPost, surface.enableMemory(created.ID), nil, http.StatusNoContent)
			enabled, err := memoryStore.GetMemory(context.Background(), "default", created.ID)
			require.NoError(t, err)
			require.False(t, enabled.Disabled)

			requestMemoryHandlerStatus(t, surface.app, http.MethodDelete, surface.memory(created.ID), nil, http.StatusNoContent)
			deleted, err := memoryStore.GetMemory(context.Background(), "default", created.ID)
			require.NoError(t, err)
			require.True(t, deleted.Deleted)
			require.True(t, deleted.Disabled)

			proposal := requestMemoryHandlerJSON[store.MemoryProposal](t, surface.app, http.MethodPost, surface.createProposal, http.StatusCreated, map[string]any{
				"namespace": "default",
				"type":      "memory",
				"title":     "Remember shared operations",
				"content":   "Proposal content",
			})
			require.NotEmpty(t, proposal.ID)

			fetchedProposal := requestMemoryHandlerJSON[store.MemoryProposal](t, surface.app, http.MethodGet, surface.proposal(proposal.ID), http.StatusOK, nil)
			require.Equal(t, proposal.ID, fetchedProposal.ID)

			requestMemoryHandlerStatus(t, surface.app, http.MethodPost, surface.reviewProposal(proposal.ID), map[string]any{
				"namespace": "default",
				"status":    "accepted",
				"reviewer":  "reviewer",
			}, http.StatusNoContent)

			applied := requestMemoryHandlerJSON[store.Memory](t, surface.app, http.MethodPost, surface.applyProposal(proposal.ID), http.StatusOK, map[string]any{
				"namespace": "default",
				"appliedBy": "operator",
			})
			require.Equal(t, proposal.ID, applied.SourceProposalID)

			archivedProposal := requestMemoryHandlerJSON[store.MemoryProposal](t, surface.app, http.MethodPost, surface.createProposal, http.StatusCreated, map[string]any{
				"namespace": "default",
				"type":      "skill",
				"title":     "Archive this proposal",
			})
			requestMemoryHandlerStatus(t, surface.app, http.MethodPost, surface.archiveProposal(archivedProposal.ID), nil, http.StatusNoContent)
			archived, err := memoryStore.GetMemoryProposal(context.Background(), "default", archivedProposal.ID)
			require.NoError(t, err)
			require.Equal(t, "archived", archived.Status)
		})
	}
}

func TestMemoryHandlerListResponseShapes(t *testing.T) {
	for _, setup := range []struct {
		name string
		new  func(*testing.T, *sqlite.Store) memoryHandlerSurface
	}{
		{name: "public", new: newPublicMemoryHandlerSurface},
		{name: "internal", new: newInternalMemoryHandlerSurface},
	} {
		t.Run(setup.name, func(t *testing.T) {
			memoryStore := newMemoryHandlerTestStore(t)
			surface := setup.new(t, memoryStore)
			require.NoError(t, memoryStore.CreateMemory(context.Background(), &store.Memory{
				Namespace: "default",
				Content:   "listed memory",
			}))
			require.NoError(t, memoryStore.CreateMemoryProposal(context.Background(), &store.MemoryProposal{
				Namespace: "default",
				Title:     "Listed proposal",
			}))

			assertMemoryHandlerListShape(t, surface.app, surface.listMemories, surface.expectsListEnvelope)
			assertMemoryHandlerListShape(t, surface.app, surface.listProposals, surface.expectsListEnvelope)
		})
	}
}

func TestInternalMemoryHandlersRejectNamespaceMismatch(t *testing.T) {
	memoryStore := newMemoryHandlerTestStore(t)
	surface := newInternalMemoryHandlerSurface(t, memoryStore)
	memory := &store.Memory{Namespace: "default", Content: "unchanged"}
	require.NoError(t, memoryStore.CreateMemory(context.Background(), memory))
	proposal := &store.MemoryProposal{Namespace: "default", Title: "Pending proposal"}
	require.NoError(t, memoryStore.CreateMemoryProposal(context.Background(), proposal))

	tests := []struct {
		name   string
		method string
		path   string
		body   map[string]any
	}{
		{
			name:   "create memory",
			method: http.MethodPost,
			path:   surface.createMemory,
			body:   map[string]any{"namespace": "other", "content": "wrong namespace"},
		},
		{
			name:   "update memory",
			method: http.MethodPut,
			path:   surface.memory(memory.ID),
			body:   map[string]any{"namespace": "other", "content": "wrong namespace"},
		},
		{
			name:   "create proposal",
			method: http.MethodPost,
			path:   surface.createProposal,
			body:   map[string]any{"namespace": "other", "title": "Wrong namespace"},
		},
		{
			name:   "review proposal",
			method: http.MethodPost,
			path:   surface.reviewProposal(proposal.ID),
			body:   map[string]any{"namespace": "other", "status": "accepted"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestMemoryHandlerStatus(t, surface.app, tt.method, tt.path, tt.body, http.StatusBadRequest)
		})
	}

	unchanged, err := memoryStore.GetMemory(context.Background(), "default", memory.ID)
	require.NoError(t, err)
	require.Equal(t, "unchanged", unchanged.Content)
	unchangedProposal, err := memoryStore.GetMemoryProposal(context.Background(), "default", proposal.ID)
	require.NoError(t, err)
	require.Equal(t, "pending", unchangedProposal.Status)
}

func newMemoryHandlerTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	db, err := sqlite.NewDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return sqlite.NewStore(db, ":memory:")
}

func newPublicMemoryHandlerSurface(t *testing.T, memoryStore *sqlite.Store) memoryHandlerSurface {
	t.Helper()
	h := NewHandlers(HandlersConfig{MemoryStore: memoryStore, MemoryProposalStore: memoryStore})
	app := fiber.New()
	app.Get("/memories", h.ListMemories)
	app.Post("/memories", h.CreateMemory)
	app.Get("/memories/:id", h.GetMemory)
	app.Put("/memories/:id", h.UpdateMemory)
	app.Delete("/memories/:id", h.DeleteMemory)
	app.Post("/memories/:id/disable", h.DisableMemory)
	app.Post("/memories/:id/enable", h.EnableMemory)
	app.Get("/memory-proposals", h.ListMemoryProposals)
	app.Post("/memory-proposals", h.CreateMemoryProposal)
	app.Get("/memory-proposals/:id", h.GetMemoryProposal)
	app.Post("/memory-proposals/:id/review", h.ReviewMemoryProposal)
	app.Post("/memory-proposals/:id/apply", h.ApplyMemoryProposal)
	app.Post("/memory-proposals/:id/archive", h.ArchiveMemoryProposal)

	withNamespace := func(path string) string { return path + "?namespace=default" }
	return memoryHandlerSurface{
		app:                 app,
		listMemories:        withNamespace("/memories"),
		createMemory:        "/memories",
		memory:              func(id string) string { return withNamespace("/memories/" + id) },
		disableMemory:       func(id string) string { return withNamespace("/memories/" + id + "/disable") },
		enableMemory:        func(id string) string { return withNamespace("/memories/" + id + "/enable") },
		listProposals:       withNamespace("/memory-proposals"),
		createProposal:      "/memory-proposals",
		proposal:            func(id string) string { return withNamespace("/memory-proposals/" + id) },
		reviewProposal:      func(id string) string { return withNamespace("/memory-proposals/" + id + "/review") },
		applyProposal:       func(id string) string { return withNamespace("/memory-proposals/" + id + "/apply") },
		archiveProposal:     func(id string) string { return withNamespace("/memory-proposals/" + id + "/archive") },
		expectsListEnvelope: true,
	}
}

func newInternalMemoryHandlerSurface(t *testing.T, memoryStore *sqlite.Store) memoryHandlerSurface {
	t.Helper()
	h := NewInternalHandlers(nil, nil, nil, nil, nil, InternalHandlersConfig{
		MemoryStore:         memoryStore,
		MemoryProposalStore: memoryStore,
	})
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.Locals(UserInfoContextKey, &UserInfo{Username: "system:serviceaccount:default:worker"})
		return c.Next()
	})
	app.Get("/internal/v1/memories/:namespace", h.ListMemories)
	app.Post("/internal/v1/memories/:namespace", h.CreateMemory)
	app.Get("/internal/v1/memories/:namespace/:id", h.GetMemory)
	app.Put("/internal/v1/memories/:namespace/:id", h.UpdateMemory)
	app.Delete("/internal/v1/memories/:namespace/:id", h.DeleteMemory)
	app.Post("/internal/v1/memories/:namespace/:id/disable", h.DisableMemory)
	app.Post("/internal/v1/memories/:namespace/:id/enable", h.EnableMemory)
	app.Get("/internal/v1/memory-proposals/:namespace", h.ListMemoryProposals)
	app.Post("/internal/v1/memory-proposals/:namespace", h.CreateMemoryProposal)
	app.Get("/internal/v1/memory-proposals/:namespace/:id", h.GetMemoryProposal)
	app.Post("/internal/v1/memory-proposals/:namespace/:id/review", h.ReviewMemoryProposal)
	app.Post("/internal/v1/memory-proposals/:namespace/:id/apply", h.ApplyMemoryProposal)
	app.Post("/internal/v1/memory-proposals/:namespace/:id/archive", h.ArchiveMemoryProposal)

	return memoryHandlerSurface{
		app:             app,
		listMemories:    "/internal/v1/memories/default",
		createMemory:    "/internal/v1/memories/default",
		memory:          func(id string) string { return "/internal/v1/memories/default/" + id },
		disableMemory:   func(id string) string { return "/internal/v1/memories/default/" + id + "/disable" },
		enableMemory:    func(id string) string { return "/internal/v1/memories/default/" + id + "/enable" },
		listProposals:   "/internal/v1/memory-proposals/default",
		createProposal:  "/internal/v1/memory-proposals/default",
		proposal:        func(id string) string { return "/internal/v1/memory-proposals/default/" + id },
		reviewProposal:  func(id string) string { return "/internal/v1/memory-proposals/default/" + id + "/review" },
		applyProposal:   func(id string) string { return "/internal/v1/memory-proposals/default/" + id + "/apply" },
		archiveProposal: func(id string) string { return "/internal/v1/memory-proposals/default/" + id + "/archive" },
	}
}

func requestMemoryHandlerJSON[T any](
	t *testing.T,
	app *fiber.App,
	method, path string,
	want int,
	body any,
) T {
	t.Helper()
	resp := requestMemoryHandler(t, app, method, path, body)
	require.Equal(t, want, resp.StatusCode)
	var result T
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

func requestMemoryHandlerStatus(
	t *testing.T,
	app *fiber.App,
	method, path string,
	body any,
	want int,
) {
	t.Helper()
	resp := requestMemoryHandler(t, app, method, path, body)
	require.Equal(t, want, resp.StatusCode)
}

func requestMemoryHandler(t *testing.T, app *fiber.App, method, path string, body any) *http.Response {
	t.Helper()
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		require.NoError(t, err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, resp.Body.Close()) })
	return resp
}

func assertMemoryHandlerListShape(t *testing.T, app *fiber.App, path string, envelope bool) {
	t.Helper()
	resp := requestMemoryHandler(t, app, http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	if envelope {
		var response map[string]json.RawMessage
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
		require.Contains(t, response, "items")
		require.Contains(t, response, "metadata")
		return
	}
	var response []json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
	require.Len(t, response, 1, "unexpected response from %s", path)
}
