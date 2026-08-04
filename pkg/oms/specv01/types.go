/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

// Package specv01 defines the KD6 Open Memory Service draft v0.1.0
// Level 1 compatibility contract pinned by Orka.
package specv01

import (
	"encoding/json"
	"time"
)

const (
	// Version is the pinned prose specification version.
	Version = "0.1.0"
	// SourceRevision is the immutable KD6 source revision used for wire behavior.
	SourceRevision = "042cff94bf82e92dea3a47f181121fd9cdcbc434"

	HeaderTenantID = "X-Tenant-ID"
	HeaderAgentID  = "X-Agent-ID"

	MaxBodyBytes = 10 << 20
)

type MemoryLayer string

const (
	LayerWorking    MemoryLayer = "working"
	LayerEpisodic   MemoryLayer = "episodic"
	LayerSemantic   MemoryLayer = "semantic"
	LayerProcedural MemoryLayer = "procedural"
	LayerArchival   MemoryLayer = "archival"
)

type AccessPolicy string

const (
	AccessPrivate    AccessPolicy = "private"
	AccessInherit    AccessPolicy = "inherit"
	AccessShared     AccessPolicy = "shared"
	AccessPublicRead AccessPolicy = "public_read"
)

type MemoryScope struct {
	TenantID  string `json:"tenant_id"`
	OrgID     string `json:"org_id,omitempty"`
	TeamID    string `json:"team_id,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	RunID     string `json:"run_id,omitempty"`
}

type AccessControl struct {
	Policy        AccessPolicy `json:"policy"`
	AllowedAgents []string     `json:"allowed_agents,omitempty"`
	AllowedScopes []string     `json:"allowed_scopes,omitempty"`
}

type SourceReference struct {
	ConversationID string `json:"conversation_id,omitempty"`
	DocumentID     string `json:"document_id,omitempty"`
	URI            string `json:"uri,omitempty"`
}

type StoreConfig struct {
	DefaultTTLSeconds    *int64 `json:"default_ttl_seconds,omitempty"`
	DefaultSharingPolicy string `json:"default_sharing_policy,omitempty"`
	EmbeddingModel       string `json:"embedding_model,omitempty"`
}

type SovereigntyReplication struct {
	Enabled       bool     `json:"enabled"`
	TargetRegions []string `json:"target_regions"`
	Consistency   string   `json:"consistency"`
}

type SovereigntyConfig struct {
	Mode        string                 `json:"mode"`
	Region      string                 `json:"region"`
	Replication SovereigntyReplication `json:"replication"`
}

type MemoryStore struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	TenantID    string            `json:"tenant_id"`
	Region      string            `json:"region,omitempty"`
	Config      StoreConfig       `json:"config"`
	Sovereignty SovereigntyConfig `json:"sovereignty"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type CreateStoreRequest struct {
	Name     string            `json:"name"`
	Region   string            `json:"region,omitempty"`
	Config   StoreConfig       `json:"config,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type UpdateStoreRequest struct {
	Config   *StoreConfig      `json:"config,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type ProviderCapabilities struct {
	SupportedLayers          []MemoryLayer `json:"supported_layers"`
	VectorSearch             bool          `json:"vector_search"`
	GraphSupport             bool          `json:"graph_support"`
	TemporalQueries          bool          `json:"temporal_queries"`
	KeywordSearch            bool          `json:"keyword_search"`
	MaxEmbeddingDimensions   *int          `json:"max_embedding_dimensions,omitempty"`
	SupportedDistanceMetrics []string      `json:"supported_distance_metrics"`
	CompactionSupport        bool          `json:"compaction_support"`
	ArchivalSupport          bool          `json:"archival_support"`
	MaxEntrySizeBytes        *int          `json:"max_entry_size_bytes,omitempty"`
	BatchOperations          bool          `json:"batch_operations"`
	MaxBatchSize             *int          `json:"max_batch_size,omitempty"`
	PubSubNotifications      bool          `json:"pub_sub_notifications"`
	EncryptionAtRest         bool          `json:"encryption_at_rest"`
	AuditLog                 bool          `json:"audit_log"`
}

type CreateMemoryRequest struct {
	Layer         MemoryLayer      `json:"layer,omitempty"`
	Content       any              `json:"content"`
	Embedding     []float32        `json:"embedding,omitempty"`
	OwnerAgentID  string           `json:"owner_agent_id"`
	Scope         MemoryScope      `json:"scope"`
	Tags          []string         `json:"tags,omitempty"`
	Categories    []string         `json:"categories,omitempty"`
	Source        *SourceReference `json:"source,omitempty"`
	AccessControl AccessControl    `json:"access_control,omitempty"`
	ExpiresAt     *time.Time       `json:"expires_at,omitempty"`
	Immutable     bool             `json:"immutable,omitempty"`
	ValidFrom     *time.Time       `json:"valid_from,omitempty"`
	ValidUntil    *time.Time       `json:"valid_until,omitempty"`
	Confidence    *float64         `json:"confidence,omitempty"`
	EntityType    string           `json:"entity_type,omitempty"`
	UpsertKey     string           `json:"upsert_key,omitempty"`
}

type UpdateMemoryRequest struct {
	Content       any             `json:"content,omitempty"`
	Embedding     json.RawMessage `json:"embedding,omitempty"`
	Tags          []string        `json:"tags,omitempty"`
	Categories    []string        `json:"categories,omitempty"`
	AccessControl *AccessControl  `json:"access_control,omitempty"`
	ExpiresAt     json.RawMessage `json:"expires_at,omitempty"`
}

type MemoryEntry struct {
	ID            string           `json:"id"`
	StoreID       string           `json:"store_id"`
	Layer         MemoryLayer      `json:"layer"`
	Content       any              `json:"content"`
	Embedding     []float32        `json:"embedding,omitempty"`
	OwnerAgentID  string           `json:"owner_agent_id"`
	Scope         MemoryScope      `json:"scope"`
	Tags          []string         `json:"tags"`
	Categories    []string         `json:"categories"`
	Source        *SourceReference `json:"source,omitempty"`
	AccessControl AccessControl    `json:"access_control"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	ExpiresAt     *time.Time       `json:"expires_at,omitempty"`
	Immutable     bool             `json:"immutable"`
	Version       int64            `json:"version"`
	ValidFrom     *time.Time       `json:"valid_from,omitempty"`
	ValidUntil    *time.Time       `json:"valid_until,omitempty"`
	Confidence    *float64         `json:"confidence,omitempty"`
	EntityType    string           `json:"entity_type,omitempty"`
	UpsertKey     string           `json:"upsert_key,omitempty"`
}

type MemoryPage struct {
	Items  []MemoryEntry `json:"items"`
	Total  uint64        `json:"total"`
	Limit  uint32        `json:"limit"`
	Offset uint32        `json:"offset"`
}

type ListMemoriesFilter struct {
	Layer        MemoryLayer
	Tags         []string
	Categories   []string
	OwnerAgentID string
	Scope        *MemoryScope
	Limit        uint32
	Offset       uint32
}

type MetadataFilters struct {
	Tags         []string `json:"tags,omitempty"`
	Categories   []string `json:"categories,omitempty"`
	OwnerAgentID string   `json:"owner_agent_id,omitempty"`
}

type SearchQuery struct {
	Query     string          `json:"query"`
	Embedding []float32       `json:"embedding,omitempty"`
	Layers    []MemoryLayer   `json:"layers,omitempty"`
	Scope     *MemoryScope    `json:"scope,omitempty"`
	TopK      int             `json:"top_k,omitempty"`
	Threshold float32         `json:"threshold,omitempty"`
	Filters   MetadataFilters `json:"filters,omitempty"`
	Keyword   bool            `json:"keyword,omitempty"`
}

type SearchResult struct {
	Entry MemoryEntry `json:"entry"`
	Score float32     `json:"score"`
}

type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
