/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package specv01

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientCreateMemoryUsesPinnedDefaultsAndIdentityHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/stores/store one/memories" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer caller-token" ||
			r.Header.Get(HeaderTenantID) != "tenant-a" || r.Header.Get(HeaderAgentID) != "agent-a" {
			t.Fatalf("identity headers = %#v", r.Header)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var request CreateMemoryRequest
		if err := json.Unmarshal(body, &request); err != nil {
			t.Fatal(err)
		}
		if request.Layer != LayerWorking || request.AccessControl.Policy != AccessPrivate {
			t.Fatalf("request defaults = %#v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{
			"id":"11111111-1111-4111-8111-111111111111",
			"store_id":"22222222-2222-4222-8222-222222222222",
			"layer":"working",
			"content":"hello",
			"owner_agent_id":"agent-a",
			"scope":{"tenant_id":"tenant-a"},
			"tags":[],"categories":[],
			"access_control":{"policy":"private"},
			"created_at":"2026-08-04T00:00:00Z",
			"updated_at":"2026-08-04T00:00:00Z",
			"immutable":false,"version":1
		}`)
	}))
	defer server.Close()
	client, err := NewClient(Target{
		BaseURL: server.URL, AuthorizationValue: "Bearer caller-token",
		TenantID: "tenant-a", AgentID: "agent-a", InsecureLoopbackOnly: true, DisableProxy: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := client.CreateMemory(context.Background(), "store one", CreateMemoryRequest{
		Content: "hello", OwnerAgentID: "agent-a", Scope: MemoryScope{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry.Content != "hello" || entry.Scope.TenantID != "tenant-a" || entry.Version != 1 {
		t.Fatalf("entry = %#v", entry)
	}
}

func TestNewClientRejectsUnsafeEndpointAuthorizationAndIdentity(t *testing.T) {
	tests := []Target{
		{BaseURL: "http://example.com", AuthorizationValue: "Bearer token", TenantID: "tenant", AgentID: "agent"},
		{BaseURL: "https://user@example.com", AuthorizationValue: "Bearer token", TenantID: "tenant", AgentID: "agent"},
		{BaseURL: "https://example.com", AuthorizationValue: "token", TenantID: "tenant", AgentID: "agent"},
		{BaseURL: "https://example.com", AuthorizationValue: "Bearer token extra", TenantID: "tenant", AgentID: "agent"},
		{BaseURL: "https://example.com", AuthorizationValue: "Bearer token", TenantID: "tenant value", AgentID: "agent"},
		{BaseURL: "https://example.com", AuthorizationValue: "Bearer token", TenantID: " tenant", AgentID: "agent"},
		{BaseURL: "https://example.com", AuthorizationValue: "Bearer token", TenantID: "tenant", AgentID: "agent/value"},
	}
	for index, target := range tests {
		if _, err := NewClient(target); err == nil {
			t.Fatalf("case %d unexpectedly succeeded: %#v", index, target)
		}
	}
}

func TestPathHelpersEscapeNames(t *testing.T) {
	if got := StorePath("store one"); got != "/v1/stores/store%20one" {
		t.Fatalf("StorePath = %q", got)
	}
	got := MemoryPath("store one", "id/value")
	if !strings.Contains(got, "store%20one") || !strings.Contains(got, "id%2Fvalue") {
		t.Fatalf("MemoryPath = %q", got)
	}
}

func TestClientRejectsSuccessfulWrongStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"11111111-1111-4111-8111-111111111111",
			"name":"store","tenant_id":"tenant-a","config":{},
			"sovereignty":{"mode":"","region":"","replication":{"enabled":false,"target_regions":null,"consistency":""}},
			"metadata":{},"created_at":"2026-08-04T00:00:00Z","updated_at":"2026-08-04T00:00:00Z"
		}`)
	}))
	defer server.Close()
	client, err := NewClient(Target{
		BaseURL: server.URL, AuthorizationValue: "Bearer caller-token",
		TenantID: "tenant-a", AgentID: "agent-a", InsecureLoopbackOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateStore(context.Background(), CreateStoreRequest{Name: "store"}); err == nil {
		t.Fatal("CreateStore accepted HTTP 200 instead of 201")
	}
}
