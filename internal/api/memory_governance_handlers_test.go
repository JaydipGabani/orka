package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/orka-agents/orka/internal/store"
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
