package memory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/orka-agents/orka/internal/oms/protocol"
	"github.com/orka-agents/orka/internal/store"
)

const (
	remoteSearchCursorTTL      = 5 * time.Minute
	maxRemoteSearchCursorBytes = 16 << 10
)

type remoteSearchCursorRecord struct {
	MemoryID        string  `json:"m"`
	Generation      uint64  `json:"g"`
	BackendVersion  string  `json:"v"`
	BackendMemoryID string  `json:"i"`
	ContentDigest   string  `json:"d"`
	Score           float64 `json:"s,omitempty"`
}

type remoteSearchCursor struct {
	ProviderToken     string                     `json:"p"`
	ProviderExhausted bool                       `json:"x,omitempty"`
	PageSize          int                        `json:"z"`
	ActualMode        string                     `json:"m,omitempty"`
	Pending           []remoteSearchCursorRecord `json:"n,omitempty"`
}

func saveRemoteSearchCursor(
	ctx context.Context,
	governed store.GovernedMemoryStore,
	binding *store.MemoryBackendBinding,
	queryDigest string,
	state remoteSearchCursor,
	now time.Time,
) (string, error) {
	if governed == nil || binding == nil || (state.ProviderToken == "" && len(state.Pending) == 0) {
		return "", errors.New("memory search cursor state is unavailable")
	}
	identity, err := protocolBinding(binding)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(state)
	if err != nil || len(payload) == 0 || len(payload) > maxRemoteSearchCursorBytes {
		return "", errors.New("memory search cursor state is invalid")
	}
	id := "msc-" + uuid.NewString()
	err = governed.SaveMemorySearchCursor(ctx, store.MemorySearchCursorState{
		ID: id, NamespaceUID: binding.NamespaceUID,
		BindingDigest: protocol.BindingDigest(identity), QueryDigest: queryDigest,
		State: payload, CreatedAt: now, ExpiresAt: now.Add(remoteSearchCursorTTL),
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func loadRemoteSearchCursor(
	ctx context.Context,
	governed store.GovernedMemoryStore,
	binding *store.MemoryBackendBinding,
	queryDigest, encoded string,
	now time.Time,
) (remoteSearchCursor, error) {
	if strings.TrimSpace(encoded) == "" {
		return remoteSearchCursor{}, nil
	}
	if governed == nil || binding == nil || !strings.HasPrefix(encoded, "msc-") || len(encoded) > 128 {
		return remoteSearchCursor{}, errors.New("invalid memory search cursor")
	}
	identity, err := protocolBinding(binding)
	if err != nil {
		return remoteSearchCursor{}, err
	}
	stored, err := governed.GetMemorySearchCursor(ctx, binding.NamespaceUID, encoded, now)
	if err != nil {
		return remoteSearchCursor{}, err
	}
	if stored.BindingDigest != protocol.BindingDigest(identity) || stored.QueryDigest != queryDigest ||
		len(stored.State) == 0 || len(stored.State) > maxRemoteSearchCursorBytes {
		return remoteSearchCursor{}, errors.New("mismatched memory search cursor")
	}
	var cursor remoteSearchCursor
	if err := json.Unmarshal(stored.State, &cursor); err != nil || cursor.PageSize <= 0 ||
		cursor.PageSize > protocol.MaxPageSize ||
		(cursor.ActualMode != protocol.SearchModeKeyword && cursor.ActualMode != protocol.SearchModeSemantic &&
			cursor.ActualMode != protocol.SearchModeHybrid) ||
		(cursor.ProviderToken == "" && len(cursor.Pending) == 0) || len(cursor.Pending) > protocol.MaxPageSize {
		return remoteSearchCursor{}, errors.New("invalid memory search cursor state")
	}
	return cursor, nil
}
