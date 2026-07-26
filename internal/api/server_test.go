/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gofiber/fiber/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	gatewayruntime "github.com/orka-agents/orka/internal/gateway"
	"github.com/orka-agents/orka/internal/store/sqlite"
)

// mockHealthChecker implements store.HealthChecker for tests.
type mockHealthChecker struct{}

func (m *mockHealthChecker) HealthCheck(_ context.Context) error { return nil }

func TestNewServer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	config := ServerConfig{
		Port:           8080,
		MetricsPort:    9090,
		WatchNamespace: "default",
	}

	server := NewServer(fakeClient, nil, config)
	if server == nil {
		t.Fatal("NewServer returned nil")
	}

	if server.app == nil {
		t.Error("app is nil")
	}
	if server.handlers == nil {
		t.Error("handlers is nil")
	}
	if server.config.Port != 8080 {
		t.Errorf("Port = %d, want 8080", server.config.Port)
	}
}

func TestServerConfigHandlersConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	resourceClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	apiReader := fake.NewClientBuilder().WithScheme(scheme).Build()
	clientset := kubernetesfake.NewSimpleClientset()

	db, err := sqlite.NewDB(":memory:")
	if err != nil {
		t.Fatalf("create sqlite database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	stores := sqlite.NewStore(db, ":memory:")
	healthChecker := &mockHealthChecker{}
	gatewayService := &gatewayruntime.Service{}
	authorization := ContextTokenAuthorizationConfig{
		Mode:           ContextTokenAuthorizationModeEnforce,
		TaskReadScopes: []string{ContextTokenScopeTaskGet},
	}

	config := ServerConfig{
		APIReader:                 apiReader,
		WatchNamespace:            "test-namespace",
		EnforceNamespaceIsolation: true,
		ContextTokenAuthorization: authorization,
		ResultStore:               stores,
		SessionStore:              stores,
		PlanStore:                 stores,
		ArtifactStore:             stores,
		MemoryStore:               stores,
		MemoryProposalStore:       stores,
		SecurityStore:             stores,
		RepositoryMonitorStore:    stores,
		ExecutionEventStore:       stores,
		GatewayEventStore:         stores,
		GatewayDeliveryStore:      stores,
		GatewayService:            gatewayService,
		HealthChecker:             healthChecker,
		Clientset:                 clientset,
	}

	got := config.handlersConfig(resourceClient)
	checks := []struct {
		name string
		got  any
		want any
	}{
		{name: "client", got: got.Client, want: resourceClient},
		{name: "API reader", got: got.APIReader, want: apiReader},
		{name: "watch namespace", got: got.WatchNamespace, want: "test-namespace"},
		{name: "namespace isolation", got: got.EnforceNamespaceIsolation, want: true},
		{name: "context token authorization", got: got.ContextTokenAuthorization, want: authorization},
		{name: "result store", got: got.ResultStore, want: stores},
		{name: "session store", got: got.SessionStore, want: stores},
		{name: "plan store", got: got.PlanStore, want: stores},
		{name: "Kubernetes client", got: got.KubeClient, want: clientset},
		{name: "health checker", got: got.HealthChecker, want: healthChecker},
		{name: "artifact store", got: got.ArtifactStore, want: stores},
		{name: "memory store", got: got.MemoryStore, want: stores},
		{name: "memory proposal store", got: got.MemoryProposalStore, want: stores},
		{name: "security store", got: got.SecurityStore, want: stores},
		{name: "repository monitor store", got: got.RepositoryMonitorStore, want: stores},
		{name: "execution event store", got: got.ExecutionEventStore, want: stores},
		{name: "gateway event store", got: got.GatewayEventStore, want: stores},
		{name: "gateway delivery store", got: got.GatewayDeliveryStore, want: stores},
		{name: "gateway service", got: got.GatewayService, want: gatewayService},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if !reflect.DeepEqual(check.got, check.want) {
				t.Fatalf("got %#v, want %#v", check.got, check.want)
			}
		})
	}
}

func TestServer_HealthEndpoints(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	config := ServerConfig{
		Port:          8080,
		HealthChecker: &mockHealthChecker{},
	}

	server := NewServer(fakeClient, nil, config)

	tests := []struct {
		name   string
		path   string
		status int
	}{
		{"healthz", "/healthz", http.StatusOK},
		{"readyz", "/readyz", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			resp, err := server.app.Test(req)
			if err != nil {
				t.Fatalf("Test request failed: %v", err)
			}
			if resp.StatusCode != tt.status {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.status)
			}
		})
	}
}

func TestServer_APIRoutes_RequireAuth(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	config := ServerConfig{
		Port: 8080,
	}

	server := NewServer(fakeClient, nil, config)

	// These endpoints should require authentication
	apiEndpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/tasks"},
		{http.MethodPost, "/api/v1/tasks"},
		{http.MethodGet, "/api/v1/sessions"},
		{http.MethodGet, "/api/v1/tools"},
		{http.MethodGet, "/api/v1/agents"},
	}

	for _, ep := range apiEndpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			// No auth header
			resp, err := server.app.Test(req)
			if err != nil {
				t.Fatalf("Test request failed: %v", err)
			}
			// Should return 401 Unauthorized
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func TestCustomErrorHandler(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{
			name:     "fiber error",
			err:      fiber.NewError(fiber.StatusBadRequest, "bad request"),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "fiber not found",
			err:      fiber.NewError(fiber.StatusNotFound, "not found"),
			wantCode: http.StatusNotFound,
		},
		{
			name:     "generic error",
			err:      fiber.NewError(fiber.StatusInternalServerError, "something went wrong"),
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New(fiber.Config{
				ErrorHandler: customErrorHandler,
			})
			app.Get("/api/test", func(c fiber.Ctx) error {
				return tt.err
			})

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("Test request failed: %v", err)
			}

			if resp.StatusCode != tt.wantCode {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.wantCode)
			}
		})
	}
}

func TestServerConfig(t *testing.T) {
	config := ServerConfig{
		Port:           8080,
		MetricsPort:    9090,
		WatchNamespace: "custom-ns",
	}

	if config.Port != 8080 {
		t.Errorf("Port = %d, want 8080", config.Port)
	}
	if config.MetricsPort != 9090 {
		t.Errorf("MetricsPort = %d, want 9090", config.MetricsPort)
	}
	if config.WatchNamespace != "custom-ns" {
		t.Errorf("WatchNamespace = %s, want custom-ns", config.WatchNamespace)
	}
}

func TestServer_CORS(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	config := ServerConfig{
		Port: 8080,
	}

	server := NewServer(fakeClient, nil, config)

	// Test OPTIONS preflight request
	req := httptest.NewRequest(http.MethodOptions, "/healthz", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}

	// Should allow CORS
	corsHeader := resp.Header.Get("Access-Control-Allow-Origin")
	if corsHeader == "" {
		t.Error("Missing Access-Control-Allow-Origin header")
	}
}

func TestServer_RequestID(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	config := ServerConfig{
		Port: 8080,
	}

	server := NewServer(fakeClient, nil, config)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}

	// Should have request ID header
	requestID := resp.Header.Get("X-Request-Id")
	if requestID == "" {
		t.Error("Missing X-Request-Id header")
	}
}

func TestServer_Start_ContextCancellation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	config := ServerConfig{
		Port: 0, // Use port 0 to avoid conflicts
	}

	server := NewServer(fakeClient, nil, config)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start(ctx)
	}()

	// Cancel context to trigger shutdown
	cancel()

	err := <-errCh
	if err != nil {
		t.Errorf("Start() returned error on clean shutdown: %v", err)
	}
}

func TestCustomErrorHandler_NonFiberError(t *testing.T) {
	app := fiber.New(fiber.Config{
		ErrorHandler: customErrorHandler,
	})
	app.Get("/api/fail", func(c fiber.Ctx) error {
		return fmt.Errorf("plain go error")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/fail", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

func TestCustomErrorHandler_NonAPI404_ServesSPA(t *testing.T) {
	app := fiber.New(fiber.Config{
		ErrorHandler: customErrorHandler,
	})
	app.Get("/api/test", func(c fiber.Ctx) error {
		return c.SendString("api")
	})

	// Request to a non-API, non-health path that doesn't exist
	req := httptest.NewRequest(http.MethodGet, "/some-ui-route", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}

	// Should serve SPA (200 with index.html) or fall through to JSON error
	// depending on whether embedded UI assets are available
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want 200 or 404", resp.StatusCode)
	}
}

func TestCustomErrorHandler_API404_ReturnsJSON(t *testing.T) {
	app := fiber.New(fiber.Config{
		ErrorHandler: customErrorHandler,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nonexistent", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}

	// API 404s should return JSON error, not SPA fallback
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])
	if len(bodyStr) == 0 {
		t.Error("expected non-empty body for API 404")
	}
}

func TestCustomErrorHandler_Health404_ReturnsJSON(t *testing.T) {
	app := fiber.New(fiber.Config{
		ErrorHandler: customErrorHandler,
	})

	// /healthz is excluded from SPA fallback
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestServer_SetupRoutes_WithChat(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	config := ServerConfig{
		Port: 8080,
		Chat: ChatConfig{Enabled: true},
	}

	server := NewServer(fakeClient, nil, config)
	if server.chatHandler == nil {
		t.Error("chatHandler should be non-nil when chat is enabled")
	}

	// Chat endpoint should require auth (return 401 without token)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", nil)
	resp, err := server.app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestServer_SetupRoutes_OpenAI(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	config := ServerConfig{
		Port: 8080,
	}

	server := NewServer(fakeClient, nil, config)

	// OpenAI-compatible endpoints should require auth
	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/openai/v1/chat/completions"},
		{http.MethodGet, "/openai/v1/models"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			resp, err := server.app.Test(req)
			if err != nil {
				t.Fatalf("Test request failed: %v", err)
			}
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func TestServer_SetupRoutes_InternalAPIStoreRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	db, err := sqlite.NewDB(":memory:")
	if err != nil {
		t.Fatalf("create sqlite database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqliteStore := sqlite.NewStore(db, ":memory:")

	tests := []struct {
		name         string
		config       ServerConfig
		wantInternal bool
	}{
		{name: "no stores", config: ServerConfig{}, wantInternal: false},
		{name: "result store", config: ServerConfig{ResultStore: sqliteStore}, wantInternal: true},
		{name: "session store", config: ServerConfig{SessionStore: sqliteStore}, wantInternal: true},
		{name: "plan store", config: ServerConfig{PlanStore: sqliteStore}, wantInternal: true},
		{name: "message store", config: ServerConfig{MessageStore: sqliteStore}, wantInternal: true},
		{name: "artifact store", config: ServerConfig{ArtifactStore: sqliteStore}, wantInternal: true},
		{name: "memory store", config: ServerConfig{MemoryStore: sqliteStore}, wantInternal: true},
		{name: "memory proposal store", config: ServerConfig{MemoryProposalStore: sqliteStore}, wantInternal: true},
		{name: "execution event store", config: ServerConfig{ExecutionEventStore: sqliteStore}, wantInternal: true},
		{name: "security store only", config: ServerConfig{SecurityStore: sqliteStore}, wantInternal: false},
		{name: "repository monitor store only", config: ServerConfig{RepositoryMonitorStore: sqliteStore}, wantInternal: false},
		{name: "gateway event store only", config: ServerConfig{GatewayEventStore: sqliteStore}, wantInternal: false},
		{name: "gateway delivery store only", config: ServerConfig{GatewayDeliveryStore: sqliteStore}, wantInternal: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(fakeClient, nil, tt.config)
			if got := server.internalHandlers != nil; got != tt.wantInternal {
				t.Fatalf("internalHandlers configured = %t, want %t", got, tt.wantInternal)
			}
			if !tt.wantInternal {
				return
			}

			req := httptest.NewRequest(http.MethodPost, "/internal/v1/results/default/task1", nil)
			resp, err := server.app.Test(req)
			if err != nil {
				t.Fatalf("Test request failed: %v", err)
			}
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func TestServer_SetupRoutes_InternalAPI(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	db, _ := sqlite.NewDB(":memory:")
	ss := sqlite.NewStore(db, ":memory:")

	config := ServerConfig{
		Port:         8080,
		ResultStore:  ss,
		SessionStore: ss,
		PlanStore:    ss,
		MessageStore: ss,
	}

	server := NewServer(fakeClient, nil, config)
	if server.internalHandlers == nil {
		t.Error("internalHandlers should be non-nil when stores are provided")
	}

	// Internal endpoints should require auth
	internalEndpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/internal/v1/results/default/task1"},
		{http.MethodGet, "/internal/v1/sessions/default/session1/transcript"},
		{http.MethodPost, "/internal/v1/plans/default/task1"},
		{http.MethodGet, "/internal/v1/plans/default/task1"},
		{http.MethodPost, "/internal/v1/messages/default"},
		{http.MethodGet, "/internal/v1/messages/default/task1"},
	}

	for _, ep := range internalEndpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			resp, err := server.app.Test(req)
			if err != nil {
				t.Fatalf("Test request failed: %v", err)
			}
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}
