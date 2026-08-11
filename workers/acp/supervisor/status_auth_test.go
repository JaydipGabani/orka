package supervisor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
)

func TestSupervisorV2ProbeAuthenticationBoundary(t *testing.T) {
	server, cfg, _ := newTestServer(t, "immediate")
	tests := []struct {
		name          string
		path          string
		authorization string
		wantStatus    int
	}{
		{name: "health is public", path: harnessv2.HealthPath, wantStatus: http.StatusOK},
		{name: "capabilities are public", path: harnessv2.CapabilitiesPath, wantStatus: http.StatusOK},
		{name: "status rejects missing authorization", path: harnessv2.StatusPath, wantStatus: http.StatusUnauthorized},
		{name: "status rejects wrong bearer", path: harnessv2.StatusPath, authorization: "Bearer " + strings.Repeat("w", 32), wantStatus: http.StatusUnauthorized},
		{name: "status rejects bare token", path: harnessv2.StatusPath, authorization: cfg.ControllerBearerToken, wantStatus: http.StatusUnauthorized},
		{name: "status rejects wrong scheme", path: harnessv2.StatusPath, authorization: "Basic " + cfg.ControllerBearerToken, wantStatus: http.StatusUnauthorized},
		{name: "status accepts controller bearer", path: harnessv2.StatusPath, authorization: "Bearer " + cfg.ControllerBearerToken, wantStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("GET %s status = %d, want %d", test.path, response.Code, test.wantStatus)
			}
			if test.wantStatus != http.StatusUnauthorized {
				return
			}
			var apiError harnessv2.ErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &apiError); err != nil {
				t.Fatalf("decode auth rejection: %v", err)
			}
			if apiError.Code != harnessv2.ErrorCodeUnauthenticated {
				t.Fatalf("auth rejection code = %q, want %q", apiError.Code, harnessv2.ErrorCodeUnauthenticated)
			}
		})
	}
}
