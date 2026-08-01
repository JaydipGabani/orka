package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

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
