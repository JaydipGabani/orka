package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	memoryruntime "github.com/orka-agents/orka/internal/memory"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
)

func TestMemoryOperationCursorRoundTripBindsNamespaceAndFilters(t *testing.T) {
	createdAt := time.Date(2026, 8, 1, 8, 30, 0, 123, time.UTC)
	filter := store.MemoryOperationFilter{
		MemoryID: "mem-a", ProposalID: "proposal-a",
		Kinds:  []store.MemoryOperationKind{store.MemoryOperationDelete, store.MemoryOperationCreate},
		States: []store.MemoryOperationState{store.MemoryOperationQueued, store.MemoryOperationSucceeded},
		Limit:  2,
	}
	operations := []store.MemoryOperation{
		{Sequence: 9, CreatedAt: createdAt.Add(time.Second)},
		{Sequence: 8, CreatedAt: createdAt},
	}

	encoded, err := encodeMemoryOperationCursor("team-a", filter, operations)
	if err != nil || encoded == "" {
		t.Fatalf("encodeMemoryOperationCursor() = %q, %v", encoded, err)
	}
	cursor, err := decodeMemoryOperationCursor(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !cursor.CreatedAt.Equal(createdAt) || cursor.Sequence != 8 ||
		!memoryOperationCursorMatches(cursor, "team-a", filter) {
		t.Fatalf("decoded cursor = %#v", cursor)
	}
	if memoryOperationCursorMatches(cursor, "team-b", filter) {
		t.Fatal("cursor matched a different namespace")
	}
	changed := filter
	changed.MemoryID = "mem-b"
	if memoryOperationCursorMatches(cursor, "team-a", changed) {
		t.Fatal("cursor matched different filters")
	}
}

func TestAuthorizeMemoryReadVisibilityRequiresOperateForDisabledContent(t *testing.T) {
	h := &Handlers{contextTokenAuthorization: ContextTokenAuthorizationConfig{
		Mode:                ContextTokenAuthorizationModeEnforce,
		MemoryReadScopes:    []string{ContextTokenScopeMemoryRead},
		MemoryOperateScopes: []string{ContextTokenScopeMemoryOperate},
	}}
	user := &UserInfo{AuthType: AuthTypeContextToken, ContextToken: &ContextToken{
		Scopes: []string{ContextTokenScopeMemoryRead},
	}}
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.Locals(UserInfoContextKey, user)
		return c.Next()
	})
	app.Get("/authorize", func(c fiber.Ctx) error {
		if err := h.authorizeMemoryReadVisibility(c, "listMemories", c.Query("includeDisabled") == "true"); err != nil {
			return err
		}
		return c.SendStatus(fiber.StatusNoContent)
	})

	for _, path := range []string{"/authorize", "/authorize?includeDisabled=false"} {
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s status = %d, want %d", path, resp.StatusCode, http.StatusNoContent)
		}
	}
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/authorize?includeDisabled=true", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("includeDisabled status = %d, want %d without operate scope", resp.StatusCode, http.StatusForbidden)
	}
	user.ContextToken.Scopes = append(user.ContextToken.Scopes, ContextTokenScopeMemoryOperate)
	resp, err = app.Test(httptest.NewRequest(http.MethodGet, "/authorize?includeDisabled=true", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("includeDisabled status = %d, want %d with operate scope", resp.StatusCode, http.StatusNoContent)
	}
}

func TestMemoryOperationLocationPreservesSelectedNamespace(t *testing.T) {
	got := memoryOperationLocation("team blue", "operation/1")
	want := "/api/v1/memory-operations/operation%2F1?namespace=team+blue"
	if got != want {
		t.Fatalf("memoryOperationLocation() = %q, want %q", got, want)
	}
}

func TestMemorySearchContextUsesRemoteSearchScopeCallback(t *testing.T) {
	h := &Handlers{contextTokenAuthorization: ContextTokenAuthorizationConfig{
		Mode:                     ContextTokenAuthorizationModeEnforce,
		MemorySearchRemoteScopes: []string{ContextTokenScopeMemorySearchRemote},
	}}
	user := &UserInfo{AuthType: AuthTypeContextToken, ContextToken: &ContextToken{
		Scopes: []string{ContextTokenScopeMemoryRead},
	}}
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.Locals(UserInfoContextKey, user)
		return c.Next()
	})
	app.Get("/authorize", func(c fiber.Ctx) error {
		if err := h.memorySearchContext(c).AuthorizeRemote(); err != nil {
			return err
		}
		return c.SendStatus(fiber.StatusNoContent)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/authorize", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d without remote-search scope", resp.StatusCode, http.StatusForbidden)
	}
	user.ContextToken.Scopes = append(user.ContextToken.Scopes, ContextTokenScopeMemorySearchRemote)
	resp, err = app.Test(httptest.NewRequest(http.MethodGet, "/authorize", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d with remote-search scope", resp.StatusCode, http.StatusNoContent)
	}
}

func TestGetMemoryDisabledInspectionRequiresOperateScope(t *testing.T) {
	db, err := sqlite.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	memoryStore := sqlite.NewStore(db, ":memory:")
	if err := memoryStore.CreateMemory(context.Background(), &store.Memory{
		ID: "mem-disabled", Namespace: "default", Content: "disabled content", Disabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	h := NewHandlers(HandlersConfig{
		MemoryStore:   memoryStore,
		MemoryService: &memoryruntime.Service{Legacy: memoryStore},
		ContextTokenAuthorization: ContextTokenAuthorizationConfig{
			Mode:                ContextTokenAuthorizationModeEnforce,
			MemoryReadScopes:    []string{ContextTokenScopeMemoryRead},
			MemoryOperateScopes: []string{ContextTokenScopeMemoryOperate},
		},
	})
	user := &UserInfo{
		AuthType: AuthTypeContextToken, Namespace: "default",
		ContextToken: &ContextToken{
			Scopes:             []string{ContextTokenScopeMemoryRead},
			TransactionContext: map[string]any{"namespace": "default"},
		},
	}
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.Locals(UserInfoContextKey, user)
		return c.Next()
	})
	app.Get("/api/v1/memories/:id", h.GetMemory)

	request := func(target string) (*http.Response, store.Memory) {
		t.Helper()
		response, err := app.Test(httptest.NewRequest(http.MethodGet, target, nil))
		if err != nil {
			t.Fatal(err)
		}
		var memory store.Memory
		if response.StatusCode == http.StatusOK {
			if err := json.NewDecoder(response.Body).Decode(&memory); err != nil {
				_ = response.Body.Close()
				t.Fatal(err)
			}
		}
		_ = response.Body.Close()
		return response, memory
	}

	response, memory := request("/api/v1/memories/mem-disabled?namespace=default")
	if response.StatusCode != http.StatusOK || !memory.Disabled || memory.Content != "" {
		t.Fatalf("default disabled GET status=%d memory=%#v, want suppression metadata", response.StatusCode, memory)
	}
	response, _ = request("/api/v1/memories/mem-disabled?namespace=default&includeDisabled=true")
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only includeDisabled status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	user.ContextToken.Scopes = append(user.ContextToken.Scopes, ContextTokenScopeMemoryOperate)
	response, memory = request("/api/v1/memories/mem-disabled?namespace=default&includeDisabled=true")
	if response.StatusCode != http.StatusOK || memory.Content != "disabled content" {
		t.Fatalf("operator includeDisabled status=%d memory=%#v, want content", response.StatusCode, memory)
	}
}
