/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package specv01

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}

type CheckResult struct {
	SpecVersion    string  `json:"specVersion"`
	SourceRevision string  `json:"sourceRevision"`
	Passed         bool    `json:"passed"`
	Message        string  `json:"message"`
	Checks         []Check `json:"checks"`
}

type level1Checker struct {
	ctx          context.Context
	target       Target
	client       *Client
	otherClient  *Client
	result       CheckResult
	storeName    string
	createdStore bool
	memoryIDs    []string
	store        *MemoryStore
	first        *MemoryEntry
	upserted     *MemoryEntry
	second       *MemoryEntry
}

// CheckLevel1 runs a destructive, self-cleaning black-box Level 1 proof against
// one isolated target. The target tenant must be reserved for conformance use.
func CheckLevel1(ctx context.Context, target Target) CheckResult {
	checker, err := newLevel1Checker(ctx, target)
	if err != nil {
		return CheckResult{
			SpecVersion: Version, SourceRevision: SourceRevision,
			Message: err.Error(),
		}
	}
	defer checker.cleanup()
	if !checker.runPrelude() || !checker.runStores() || !checker.runMemories() || !checker.runDeletion() {
		return checker.result
	}
	checker.result.Passed = true
	checker.result.Message = "KD6 OMS draft v0.1.0 Level 1 API compatibility passed"
	return checker.result
}

func newLevel1Checker(ctx context.Context, target Target) (*level1Checker, error) {
	client, err := NewClient(target)
	if err != nil {
		return nil, err
	}
	suffix, err := randomSuffix()
	if err != nil {
		return nil, errors.New("could not create conformance fixture identity")
	}
	otherTarget := target
	otherTarget.TenantID = "orka-level1-isolated-" + suffix
	otherClient, err := NewClient(otherTarget)
	if err != nil {
		return nil, err
	}
	return &level1Checker{
		ctx: ctx, target: target, client: client, otherClient: otherClient,
		result: CheckResult{
			SpecVersion: Version, SourceRevision: SourceRevision,
			Message: "KD6 OMS Level 1 API compatibility failed",
		},
		storeName: "orka-level1-" + suffix,
		memoryIDs: make([]string, 0, 2),
	}, nil
}

func (c *level1Checker) cleanup() {
	for _, memoryID := range c.memoryIDs {
		_ = c.client.DeleteMemory(context.Background(), c.storeName, memoryID)
	}
	if c.createdStore {
		_ = c.client.DeleteStore(context.Background(), c.storeName)
	}
}

func (c *level1Checker) run(name string, check func() error) bool {
	err := check()
	passed := err == nil
	c.result.Checks = append(c.result.Checks, Check{Name: name, Passed: passed})
	if err != nil {
		c.result.Message = name + ": " + err.Error()
	}
	return passed
}

func (c *level1Checker) runPrelude() bool {
	return c.run("authentication", func() error { return checkAuthentication(c.ctx, c.client) }) &&
		c.run("identity headers", func() error { return checkIdentityHeaders(c.ctx, c.client) }) &&
		c.run("credential identity binding", func() error { return checkBoundIdentity(c.ctx, c.client) }) &&
		c.run("health", c.checkHealth) &&
		c.run("capabilities", c.checkCapabilities)
}

func (c *level1Checker) checkHealth() error {
	health, err := c.client.Health(c.ctx)
	if err != nil {
		return err
	}
	if health.Status != "ok" || health.Version != Version {
		return fmt.Errorf("health response must report version %s", Version)
	}
	return nil
}

func (c *level1Checker) checkCapabilities() error {
	capabilities, err := c.client.Capabilities(c.ctx)
	if err != nil {
		return err
	}
	if !capabilities.VectorSearch {
		return errors.New("vector_search must be advertised")
	}
	if !slices.Contains(capabilities.SupportedLayers, LayerWorking) {
		return errors.New("supported_layers must include working")
	}
	if capabilities.MaxEmbeddingDimensions != nil && *capabilities.MaxEmbeddingDimensions < 4 {
		return errors.New("max_embedding_dimensions is below the conformance vector size")
	}
	return nil
}

func (c *level1Checker) runStores() bool {
	return c.run("store create", c.checkStoreCreate) &&
		c.run("store get", c.checkStoreGet) &&
		c.run("store list", c.checkStoreList) &&
		c.run("store update", c.checkStoreUpdate) &&
		c.run("store tenant isolation", c.checkStoreTenantIsolation)
}

func (c *level1Checker) checkStoreCreate() error {
	store, err := c.client.CreateStore(c.ctx, CreateStoreRequest{
		Name: c.storeName, Region: "local", Metadata: map[string]string{"conformance": "level1"},
	})
	if err != nil {
		return err
	}
	c.createdStore = true
	c.store = store
	if store.Name != c.storeName || store.TenantID != c.target.TenantID || store.ID == "" {
		return errors.New("created store identity is invalid")
	}
	return nil
}

func (c *level1Checker) checkStoreGet() error {
	store, err := c.client.GetStore(c.ctx, c.storeName)
	if err != nil {
		return err
	}
	if c.store == nil || store.ID != c.store.ID || store.Name != c.storeName {
		return errors.New("store get changed identity")
	}
	return nil
}

func (c *level1Checker) checkStoreList() error {
	stores, err := c.client.ListStores(c.ctx)
	if err != nil {
		return err
	}
	if c.store == nil || !slices.ContainsFunc(stores, func(item MemoryStore) bool { return item.ID == c.store.ID }) {
		return errors.New("created store is missing from list")
	}
	return nil
}

func (c *level1Checker) checkStoreUpdate() error {
	ttl := int64(3600)
	store, err := c.client.UpdateStore(c.ctx, c.storeName, UpdateStoreRequest{
		Config:   &StoreConfig{DefaultTTLSeconds: &ttl},
		Metadata: map[string]string{"conformance": "updated"},
	})
	if err != nil {
		return err
	}
	if store.Name != c.storeName || store.Config.DefaultTTLSeconds == nil ||
		*store.Config.DefaultTTLSeconds != ttl {
		return errors.New("store update did not preserve name and apply config")
	}
	return nil
}

func (c *level1Checker) checkStoreTenantIsolation() error {
	_, err := c.otherClient.GetStore(c.ctx, c.storeName)
	if isHTTPStatus(err, http.StatusNotFound) || isHTTPStatus(err, http.StatusUnauthorized) ||
		isHTTPStatus(err, http.StatusForbidden) {
		return nil
	}
	if err == nil {
		return errors.New("other tenant could read the store")
	}
	return err
}

func (c *level1Checker) runMemories() bool {
	return c.run("memory create", c.checkMemoryCreate) &&
		c.run("atomic upsert_key", c.checkMemoryUpsert) &&
		c.run("second memory create", c.checkSecondMemoryCreate) &&
		c.run("memory get", c.checkMemoryGet) &&
		c.run("memory list", c.checkMemoryList) &&
		c.run("filtered vector search", c.checkFilteredVectorSearch) &&
		c.run("memory update", c.checkMemoryUpdate)
}

func (c *level1Checker) baseMemoryRequest(content, upsertKey string, tags []string) CreateMemoryRequest {
	return CreateMemoryRequest{
		Layer: LayerWorking, Content: content, Embedding: []float32{1, 0, 0, 0},
		OwnerAgentID: c.target.AgentID, Scope: MemoryScope{}, Tags: tags,
		Categories:    []string{"procedure"},
		AccessControl: AccessControl{Policy: AccessPrivate}, UpsertKey: upsertKey,
	}
}

func (c *level1Checker) checkMemoryCreate() error {
	entry, err := c.client.CreateMemory(c.ctx, c.storeName, c.baseMemoryRequest(
		"Run verification before release.", "release-checklist-"+c.storeName, []string{"level1-match", "release"},
	))
	if err != nil {
		return err
	}
	c.first = entry
	c.memoryIDs = append(c.memoryIDs, entry.ID)
	if entry.ID == "" || entry.Version < 1 || entry.Scope.TenantID != c.target.TenantID ||
		entry.UpsertKey == "" || entry.Content != "Run verification before release." {
		return errors.New("created memory is incomplete")
	}
	return nil
}

func (c *level1Checker) checkMemoryUpsert() error {
	if c.first == nil {
		return errors.New("initial memory is missing")
	}
	request := c.baseMemoryRequest(
		"Run lint, tests, and verification before release.",
		c.first.UpsertKey,
		[]string{"level1-match", "release"},
	)
	entry, err := c.client.CreateMemory(c.ctx, c.storeName, request)
	if err != nil {
		return err
	}
	c.upserted = entry
	if entry.ID != c.first.ID || entry.Version <= c.first.Version || entry.Content != request.Content {
		return errors.New("atomic upsert did not preserve ID and advance version")
	}
	return nil
}

func (c *level1Checker) checkSecondMemoryCreate() error {
	request := c.baseMemoryRequest("Unrelated lunch note.", "", []string{"level1-excluded"})
	request.Embedding = []float32{1, 0, 0, 0}
	entry, err := c.client.CreateMemory(c.ctx, c.storeName, request)
	if err != nil {
		return err
	}
	c.second = entry
	c.memoryIDs = append(c.memoryIDs, entry.ID)
	return nil
}

func (c *level1Checker) checkMemoryGet() error {
	if c.first == nil || c.upserted == nil {
		return errors.New("upserted memory is missing")
	}
	entry, err := c.client.GetMemory(c.ctx, c.storeName, c.first.ID)
	if err != nil {
		return err
	}
	if entry.ID != c.first.ID || entry.Content != c.upserted.Content {
		return errors.New("memory get returned stale content")
	}
	return nil
}

func (c *level1Checker) checkMemoryList() error {
	if c.first == nil || c.second == nil {
		return errors.New("memory fixtures are missing")
	}
	page, err := c.client.ListMemories(c.ctx, c.storeName, ListMemoriesFilter{Limit: 100})
	if err != nil {
		return err
	}
	firstFound := slices.ContainsFunc(page.Items, func(item MemoryEntry) bool { return item.ID == c.first.ID })
	secondFound := slices.ContainsFunc(page.Items, func(item MemoryEntry) bool { return item.ID == c.second.ID })
	if !firstFound || !secondFound {
		return errors.New("memory list omitted conformance fixtures")
	}
	return nil
}

func (c *level1Checker) checkFilteredVectorSearch() error {
	results, err := c.client.Search(c.ctx, c.storeName, SearchQuery{
		Query: "release verification checklist", Embedding: []float32{1, 0, 0, 0}, TopK: 10,
		Filters: MetadataFilters{Tags: []string{"level1-match"}, OwnerAgentID: c.target.AgentID},
	})
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return errors.New("vector search returned no matching result")
	}
	for _, item := range results {
		if item.Score < 0 || item.Score > 1 || item.Entry.OwnerAgentID != c.target.AgentID ||
			!slices.Contains(item.Entry.Tags, "level1-match") {
			return errors.New("search returned a result outside metadata filters")
		}
	}
	return nil
}

func (c *level1Checker) checkMemoryUpdate() error {
	if c.first == nil || c.upserted == nil {
		return errors.New("upserted memory is missing")
	}
	content := "Run the complete release verification checklist."
	entry, err := c.client.UpdateMemory(c.ctx, c.storeName, c.first.ID, UpdateMemoryRequest{
		Content: content, Embedding: json.RawMessage(`[1,0,0,0]`),
		Tags: []string{"level1-match", "verified"},
	})
	if err != nil {
		return err
	}
	if entry.ID != c.first.ID || entry.Version <= c.upserted.Version || entry.Content != content {
		return errors.New("memory update did not advance the existing entry")
	}
	return nil
}

func (c *level1Checker) runDeletion() bool {
	return c.run("memory delete", c.checkMemoryDelete) &&
		c.run("memory delete visibility", c.checkMemoryDeleteVisibility) &&
		c.run("upserted memory cleanup", c.checkFirstMemoryDelete) &&
		c.run("store delete", c.checkStoreDelete) &&
		c.run("store delete visibility", c.checkStoreDeleteVisibility)
}

func (c *level1Checker) checkMemoryDelete() error {
	if c.second == nil {
		return errors.New("second memory is missing")
	}
	if err := c.client.DeleteMemory(c.ctx, c.storeName, c.second.ID); err != nil {
		return err
	}
	c.memoryIDs = c.memoryIDs[:1]
	return nil
}

func (c *level1Checker) checkMemoryDeleteVisibility() error {
	if c.second == nil {
		return errors.New("second memory is missing")
	}
	_, err := c.client.GetMemory(c.ctx, c.storeName, c.second.ID)
	if isHTTPStatus(err, http.StatusNotFound) {
		return nil
	}
	if err == nil {
		return errors.New("deleted memory remained readable")
	}
	return err
}

func (c *level1Checker) checkFirstMemoryDelete() error {
	if c.first == nil {
		return errors.New("first memory is missing")
	}
	if err := c.client.DeleteMemory(c.ctx, c.storeName, c.first.ID); err != nil {
		return err
	}
	c.memoryIDs = nil
	return nil
}

func (c *level1Checker) checkStoreDelete() error {
	if err := c.client.DeleteStore(c.ctx, c.storeName); err != nil {
		return err
	}
	c.createdStore = false
	return nil
}

func (c *level1Checker) checkStoreDeleteVisibility() error {
	_, err := c.client.GetStore(c.ctx, c.storeName)
	if isHTTPStatus(err, http.StatusNotFound) {
		return nil
	}
	if err == nil {
		return errors.New("deleted store remained readable")
	}
	return err
}

func checkAuthentication(ctx context.Context, client *Client) error {
	status, body, err := client.DoRaw(
		ctx, http.MethodGet, PathStores, nil, "", client.tenantID, client.agentID,
	)
	if err != nil {
		return err
	}
	if err := requireErrorResponse(status, body, http.StatusUnauthorized, "unauthenticated request"); err != nil {
		return err
	}
	status, body, err = client.DoRaw(
		ctx, http.MethodGet, PathStores, nil, "Bearer invalid-level1-token", client.tenantID, client.agentID,
	)
	if err != nil {
		return err
	}
	return requireErrorResponse(status, body, http.StatusUnauthorized, "invalid-token request")
}

func checkIdentityHeaders(ctx context.Context, client *Client) error {
	status, body, err := client.DoRaw(
		ctx, http.MethodGet, PathStores, nil, client.authorizationValue, "", client.agentID,
	)
	if err != nil {
		return err
	}
	if status != http.StatusUnauthorized && status != http.StatusBadRequest && status != http.StatusForbidden {
		return fmt.Errorf("missing tenant request returned HTTP %d", status)
	}
	if err := requireJSONErrorBody(body, "missing tenant request"); err != nil {
		return err
	}
	status, body, err = client.DoRaw(
		ctx, http.MethodGet, PathStores, nil, client.authorizationValue, client.tenantID, "",
	)
	if err != nil {
		return err
	}
	if status != http.StatusUnauthorized && status != http.StatusBadRequest && status != http.StatusForbidden {
		return fmt.Errorf("missing agent request returned HTTP %d", status)
	}
	return requireJSONErrorBody(body, "missing agent request")
}

func checkBoundIdentity(ctx context.Context, client *Client) error {
	tests := []struct {
		name     string
		tenantID string
		agentID  string
	}{
		{name: "tenant switch", tenantID: client.tenantID + "-other", agentID: client.agentID},
		{name: "agent switch", tenantID: client.tenantID, agentID: client.agentID + "-other"},
	}
	for _, test := range tests {
		status, body, err := client.DoRaw(
			ctx, http.MethodGet, PathStores, nil, client.authorizationValue, test.tenantID, test.agentID,
		)
		if err != nil {
			return err
		}
		if status != http.StatusUnauthorized && status != http.StatusForbidden {
			return fmt.Errorf("%s returned HTTP %d", test.name, status)
		}
		if err := requireJSONErrorBody(body, test.name); err != nil {
			return err
		}
	}
	return nil
}

func requireErrorResponse(status int, body []byte, expected int, name string) error {
	if status != expected {
		return fmt.Errorf("%s returned HTTP %d, want %d", name, status, expected)
	}
	return requireJSONErrorBody(body, name)
}

func requireJSONErrorBody(body []byte, name string) error {
	var response ErrorResponse
	if len(body) == 0 || json.Unmarshal(body, &response) != nil || strings.TrimSpace(response.Error) == "" {
		return fmt.Errorf("%s did not return a JSON error object", name)
	}
	return nil
}

func isHTTPStatus(err error, status int) bool {
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == status
}

func randomSuffix() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
