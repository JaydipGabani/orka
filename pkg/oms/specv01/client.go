/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package specv01

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Target struct {
	BaseURL              string
	AuthorizationValue   string
	TenantID             string
	AgentID              string
	Timeout              time.Duration
	DisableProxy         bool
	InsecureLoopbackOnly bool
	HTTPClient           *http.Client
}

type Client struct {
	baseURL            string
	authorizationValue string
	tenantID           string
	agentID            string
	http               *http.Client
}

type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("OMS request failed with HTTP %d: %s", e.StatusCode, e.Message)
}

func NewClient(target Target) (*Client, error) {
	baseURL, err := validateBaseURL(target.BaseURL, target.InsecureLoopbackOnly)
	if err != nil {
		return nil, err
	}
	authorization := strings.TrimSpace(target.AuthorizationValue)
	if authorization == "" {
		return nil, errors.New("authorization value is required")
	}
	if !strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
		return nil, errors.New("authorization value must be a safe Bearer value")
	}
	rawToken := strings.TrimSpace(authorization[len("Bearer "):])
	if rawToken == "" || strings.ContainsAny(rawToken, " \t\r\n\x00") {
		return nil, errors.New("authorization value must be a safe Bearer value")
	}
	authorization = "Bearer " + rawToken
	if err := validateIdentity("tenant ID", target.TenantID); err != nil {
		return nil, err
	}
	if err := validateIdentity("agent ID", target.AgentID); err != nil {
		return nil, err
	}
	timeout := target.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	if target.HTTPClient != nil {
		copy := *target.HTTPClient
		client = &copy
		if client.Timeout <= 0 {
			client.Timeout = timeout
		}
	}
	if target.DisableProxy {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if client.Transport != nil {
			configured, ok := client.Transport.(*http.Transport)
			if !ok {
				return nil, errors.New("DisableProxy requires an *http.Transport")
			}
			transport = configured.Clone()
		}
		transport.Proxy = nil
		client.Transport = transport
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		baseURL: strings.TrimRight(baseURL.String(), "/"), authorizationValue: authorization,
		tenantID: target.TenantID, agentID: target.AgentID, http: client,
	}, nil
}

func validateBaseURL(raw string, insecureLoopbackOnly bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("OMS endpoint must be an absolute URL without credentials, query, or fragment")
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if parsed.Scheme != "http" || !insecureLoopbackOnly {
		return nil, errors.New("OMS endpoint must use HTTPS")
	}
	host := net.ParseIP(parsed.Hostname())
	if host == nil || !host.IsLoopback() {
		return nil, errors.New("plaintext OMS endpoint is allowed only on a literal loopback address")
	}
	return parsed, nil
}

func validateIdentity(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 {
		return fmt.Errorf("%s is required and must be a safe value", name)
	}
	for _, r := range value {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.IsSpace(r) || r == '/' || r == '\\' {
			return fmt.Errorf("%s is required and must be a safe value", name)
		}
	}
	return nil
}

func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var response HealthResponse
	if err := c.doJSON(ctx, http.MethodGet, PathHealth, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) Capabilities(ctx context.Context) (*ProviderCapabilities, error) {
	var response ProviderCapabilities
	if err := c.doJSON(ctx, http.MethodGet, PathCapabilities, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) CreateStore(ctx context.Context, request CreateStoreRequest) (*MemoryStore, error) {
	var response MemoryStore
	if err := c.doJSON(ctx, http.MethodPost, PathStores, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) GetStore(ctx context.Context, name string) (*MemoryStore, error) {
	var response MemoryStore
	if err := c.doJSON(ctx, http.MethodGet, StorePath(name), nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) ListStores(ctx context.Context) ([]MemoryStore, error) {
	var response []MemoryStore
	if err := c.doJSON(ctx, http.MethodGet, PathStores, nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) UpdateStore(ctx context.Context, name string, request UpdateStoreRequest) (*MemoryStore, error) {
	var response MemoryStore
	if err := c.doJSON(ctx, http.MethodPatch, StorePath(name), request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) DeleteStore(ctx context.Context, name string) error {
	return c.doJSON(ctx, http.MethodDelete, StorePath(name), nil, nil)
}

func (c *Client) CreateMemory(
	ctx context.Context, storeName string, request CreateMemoryRequest,
) (*MemoryEntry, error) {
	if request.Layer == "" {
		request.Layer = LayerWorking
	}
	if request.AccessControl.Policy == "" {
		request.AccessControl.Policy = AccessPrivate
	}
	var response MemoryEntry
	if err := c.doJSON(ctx, http.MethodPost, MemoriesPath(storeName), request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) GetMemory(ctx context.Context, storeName, memoryID string) (*MemoryEntry, error) {
	var response MemoryEntry
	if err := c.doJSON(ctx, http.MethodGet, MemoryPath(storeName, memoryID), nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) ListMemories(ctx context.Context, storeName string, filter ListMemoriesFilter) (*MemoryPage, error) {
	query := url.Values{}
	if filter.Layer != "" {
		query.Set("layer", string(filter.Layer))
	}
	for _, tag := range filter.Tags {
		query.Add("tags", tag)
	}
	for _, category := range filter.Categories {
		query.Add("categories", category)
	}
	if filter.OwnerAgentID != "" {
		query.Set("owner_agent_id", filter.OwnerAgentID)
	}
	if filter.Scope != nil {
		encoded, err := json.Marshal(filter.Scope)
		if err != nil {
			return nil, err
		}
		query.Set("scope", string(encoded))
	}
	if filter.Limit > 0 {
		query.Set("limit", strconv.FormatUint(uint64(filter.Limit), 10))
	}
	if filter.Offset > 0 {
		query.Set("offset", strconv.FormatUint(uint64(filter.Offset), 10))
	}
	path := MemoriesPath(storeName)
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var response MemoryPage
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) UpdateMemory(
	ctx context.Context,
	storeName, memoryID string,
	request UpdateMemoryRequest,
) (*MemoryEntry, error) {
	var response MemoryEntry
	if err := c.doJSON(ctx, http.MethodPatch, MemoryPath(storeName, memoryID), request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *Client) DeleteMemory(ctx context.Context, storeName, memoryID string) error {
	return c.doJSON(ctx, http.MethodDelete, MemoryPath(storeName, memoryID), nil, nil)
}

func (c *Client) Search(ctx context.Context, storeName string, request SearchQuery) ([]SearchResult, error) {
	var response []SearchResult
	if err := c.doJSON(ctx, http.MethodPost, SearchPath(storeName), request, &response); err != nil {
		return nil, err
	}
	return response, nil
}

// DoRaw supports conformance negative tests. It never returns the configured
// authorization value or response body in an error.
func (c *Client) DoRaw(
	ctx context.Context,
	method, path string,
	body []byte,
	authorizationValue, tenantID, agentID string,
) (int, []byte, error) {
	return c.do(ctx, method, path, body, authorizationValue, tenantID, agentID)
}

func (c *Client) doJSON(ctx context.Context, method, path string, request, response any) error {
	var body []byte
	var err error
	if request != nil {
		body, err = json.Marshal(request)
		if err != nil {
			return err
		}
		if len(body) > MaxBodyBytes {
			return errors.New("OMS request exceeds the compatibility body limit")
		}
	}
	status, responseBody, err := c.do(
		ctx, method, path, body, c.authorizationValue, c.tenantID, c.agentID,
	)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return &HTTPError{StatusCode: status, Message: http.StatusText(status)}
	}
	if response == nil {
		if status != http.StatusNoContent && len(bytes.TrimSpace(responseBody)) != 0 {
			return errors.New("OMS response unexpectedly included a body")
		}
		return nil
	}
	if len(responseBody) == 0 {
		return errors.New("OMS response body is required")
	}
	if err := json.Unmarshal(responseBody, response); err != nil {
		return fmt.Errorf("decode OMS response: %w", err)
	}
	return nil
}

func (c *Client) do(
	ctx context.Context,
	method, path string,
	body []byte,
	authorizationValue, tenantID, agentID string,
) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorizationValue != "" {
		request.Header.Set("Authorization", authorizationValue)
	}
	if tenantID != "" {
		request.Header.Set(HeaderTenantID, tenantID)
	}
	if agentID != "" {
		request.Header.Set(HeaderAgentID, agentID)
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close() //nolint:errcheck
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, MaxBodyBytes+1))
	if err != nil {
		return response.StatusCode, nil, err
	}
	if len(responseBody) > MaxBodyBytes {
		return response.StatusCode, nil, errors.New("OMS response exceeds the compatibility body limit")
	}
	if response.StatusCode != http.StatusNoContent && len(responseBody) > 0 {
		mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if parseErr != nil || mediaType != "application/json" {
			return response.StatusCode, nil, errors.New("OMS response must use application/json")
		}
	}
	return response.StatusCode, responseBody, nil
}
