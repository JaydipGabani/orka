package memory

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/pkg/oms/protocol"
)

const (
	remoteSearchCursorTTL      = 5 * time.Minute
	maxRemoteSearchCursorBytes = 16 << 10
	legacySearchCursorPrefix   = "lsc-"
)

var errLegacySearchCursorInvalid = errors.New("invalid legacy memory search cursor")

type memorySearchCursorStore interface {
	SaveMemorySearchCursor(context.Context, store.MemorySearchCursorState) error
	GetMemorySearchCursor(context.Context, string, string, time.Time) (*store.MemorySearchCursorState, error)
}

type serviceLegacyCursorStore struct{ service *Service }

func (s *Service) legacySearchCursorStore() memorySearchCursorStore {
	if s != nil && s.Governed != nil {
		return s.Governed
	}
	return serviceLegacyCursorStore{service: s}
}

func (s serviceLegacyCursorStore) SaveMemorySearchCursor(_ context.Context, cursor store.MemorySearchCursorState) error {
	if s.service == nil || strings.TrimSpace(cursor.ID) == "" || strings.TrimSpace(cursor.NamespaceUID) == "" ||
		len(cursor.State) == 0 || len(cursor.State) > maxRemoteSearchCursorBytes || !cursor.ExpiresAt.After(cursor.CreatedAt) {
		return store.ErrValidation
	}
	s.service.legacyCursorMu.Lock()
	defer s.service.legacyCursorMu.Unlock()
	if s.service.legacyCursors == nil {
		s.service.legacyCursors = make(map[string]store.MemorySearchCursorState)
	}
	bytes := 0
	for id, existing := range s.service.legacyCursors {
		if !existing.ExpiresAt.After(cursor.CreatedAt) {
			delete(s.service.legacyCursors, id)
			continue
		}
		bytes += len(existing.State)
	}
	if len(s.service.legacyCursors) >= 128 || bytes+len(cursor.State) > 2<<20 {
		return store.ErrCapacity
	}
	copy := cursor
	copy.State = append([]byte(nil), cursor.State...)
	s.service.legacyCursors[cursor.ID] = copy
	return nil
}

func (s serviceLegacyCursorStore) GetMemorySearchCursor(
	_ context.Context,
	namespaceUID, id string,
	now time.Time,
) (*store.MemorySearchCursorState, error) {
	if s.service == nil {
		return nil, store.ErrNotFound
	}
	s.service.legacyCursorMu.Lock()
	defer s.service.legacyCursorMu.Unlock()
	cursor, ok := s.service.legacyCursors[strings.TrimSpace(id)]
	if !ok || cursor.NamespaceUID != strings.TrimSpace(namespaceUID) || !cursor.ExpiresAt.After(now) {
		return nil, store.ErrNotFound
	}
	copy := cursor
	copy.State = append([]byte(nil), cursor.State...)
	return &copy, nil
}

type legacySearchCursor struct {
	PageSize        int       `json:"z"`
	MACKey          []byte    `json:"k"`
	CursorID        string    `json:"-"`
	BeforeUpdatedAt time.Time `json:"-"`
	BeforeID        string    `json:"-"`
	PendingIDs      []string  `json:"-"`
}

type legacySearchCursorBoundary struct {
	BeforeUpdatedAt time.Time `json:"t"`
	BeforeID        string    `json:"i"`
	PendingIDs      []string  `json:"p,omitempty"`
}

func saveLegacySearchCursor(
	ctx context.Context,
	governed memorySearchCursorStore,
	authority *ResolvedAuthority,
	queryDigest string,
	state legacySearchCursor,
	now time.Time,
) (string, error) {
	state.BeforeID = strings.TrimSpace(state.BeforeID)
	namespaceUID := legacySearchCursorNamespace(authority)
	if governed == nil || authority == nil || namespaceUID == "" ||
		strings.TrimSpace(queryDigest) == "" || state.PageSize <= 0 || state.PageSize > maxRemoteCatalogLimit ||
		state.BeforeUpdatedAt.IsZero() || state.BeforeID == "" || len(state.PendingIDs) > state.PageSize {
		return "", errLegacySearchCursorInvalid
	}
	if err := validateLegacySearchPendingIDs(state.PendingIDs); err != nil {
		return "", err
	}
	if state.CursorID == "" {
		state.CursorID = legacySearchCursorPrefix + uuid.NewString()
		state.MACKey = make([]byte, sha256.Size)
		if _, err := rand.Read(state.MACKey); err != nil {
			return "", errLegacySearchCursorInvalid
		}
		payload, err := json.Marshal(state)
		if err != nil || len(payload) == 0 || len(payload) > maxRemoteSearchCursorBytes {
			return "", errLegacySearchCursorInvalid
		}
		err = governed.SaveMemorySearchCursor(ctx, store.MemorySearchCursorState{
			ID: state.CursorID, NamespaceUID: namespaceUID,
			BindingDigest: legacySearchBindingDigest(authority), QueryDigest: queryDigest,
			State: payload, CreatedAt: now, ExpiresAt: now.Add(remoteSearchCursorTTL),
		})
		if err != nil {
			return "", err
		}
	}
	if len(state.MACKey) != sha256.Size {
		return "", errLegacySearchCursorInvalid
	}
	return formatLegacySearchCursor(state)
}

func loadLegacySearchCursor(
	ctx context.Context,
	governed memorySearchCursorStore,
	authority *ResolvedAuthority,
	queryDigest, encoded string,
	now time.Time,
) (legacySearchCursor, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return legacySearchCursor{}, nil
	}
	if len(encoded) > 2*maxRemoteSearchCursorBytes || !strings.HasPrefix(encoded, legacySearchCursorPrefix) {
		return legacySearchCursor{}, errLegacySearchCursorInvalid
	}
	parts := strings.SplitN(encoded, ".", 4)
	namespaceUID := legacySearchCursorNamespace(authority)
	if governed == nil || authority == nil || namespaceUID == "" || len(parts) != 3 {
		return legacySearchCursor{}, errLegacySearchCursorInvalid
	}
	boundaryPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(boundaryPayload) == 0 || len(boundaryPayload) > maxRemoteSearchCursorBytes {
		return legacySearchCursor{}, errLegacySearchCursorInvalid
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(providedMAC) != sha256.Size {
		return legacySearchCursor{}, errLegacySearchCursorInvalid
	}
	stored, err := governed.GetMemorySearchCursor(ctx, namespaceUID, parts[0], now)
	if err != nil {
		return legacySearchCursor{}, err
	}
	if stored.BindingDigest != legacySearchBindingDigest(authority) || stored.QueryDigest != strings.TrimSpace(queryDigest) ||
		len(stored.State) == 0 || len(stored.State) > maxRemoteSearchCursorBytes {
		return legacySearchCursor{}, errLegacySearchCursorInvalid
	}
	var cursor legacySearchCursor
	if err := json.Unmarshal(stored.State, &cursor); err != nil || cursor.PageSize <= 0 ||
		cursor.PageSize > maxRemoteCatalogLimit || len(cursor.MACKey) != sha256.Size {
		return legacySearchCursor{}, errLegacySearchCursorInvalid
	}
	expectedMAC := legacySearchCursorMAC(parts[0], cursor.MACKey, boundaryPayload)
	if !hmac.Equal(providedMAC, expectedMAC) {
		return legacySearchCursor{}, errLegacySearchCursorInvalid
	}
	var boundary legacySearchCursorBoundary
	if err := json.Unmarshal(boundaryPayload, &boundary); err != nil || boundary.BeforeUpdatedAt.IsZero() ||
		strings.TrimSpace(boundary.BeforeID) == "" || len(boundary.PendingIDs) > cursor.PageSize {
		return legacySearchCursor{}, errLegacySearchCursorInvalid
	}
	if err := validateLegacySearchPendingIDs(boundary.PendingIDs); err != nil {
		return legacySearchCursor{}, err
	}
	cursor.CursorID = parts[0]
	cursor.BeforeUpdatedAt = boundary.BeforeUpdatedAt.UTC()
	cursor.BeforeID = strings.TrimSpace(boundary.BeforeID)
	cursor.PendingIDs = append([]string(nil), boundary.PendingIDs...)
	return cursor, nil
}

func validateLegacySearchPendingIDs(ids []string) error {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			return errLegacySearchCursorInvalid
		}
		if _, duplicate := seen[id]; duplicate {
			return errLegacySearchCursorInvalid
		}
		seen[id] = struct{}{}
	}
	return nil
}

func formatLegacySearchCursor(state legacySearchCursor) (string, error) {
	boundary, err := json.Marshal(legacySearchCursorBoundary{
		BeforeUpdatedAt: state.BeforeUpdatedAt.UTC(), BeforeID: strings.TrimSpace(state.BeforeID),
		PendingIDs: append([]string(nil), state.PendingIDs...),
	})
	if err != nil || len(boundary) == 0 || len(boundary) > maxRemoteSearchCursorBytes {
		return "", errLegacySearchCursorInvalid
	}
	encoded := state.CursorID + "." + base64.RawURLEncoding.EncodeToString(boundary) + "." +
		base64.RawURLEncoding.EncodeToString(legacySearchCursorMAC(state.CursorID, state.MACKey, boundary))
	if len(encoded) > 2*maxRemoteSearchCursorBytes {
		return "", errLegacySearchCursorInvalid
	}
	return encoded, nil
}

func legacySearchCursorMAC(id string, key, boundary []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(id))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(boundary)
	return mac.Sum(nil)
}

func legacySearchBindingDigest(authority *ResolvedAuthority) string {
	if authority == nil {
		return ""
	}
	return digestJSON(struct {
		Mode         string `json:"mode"`
		Namespace    string `json:"namespace"`
		NamespaceUID string `json:"namespaceUid"`
	}{Mode: "legacy", Namespace: authority.Namespace, NamespaceUID: authority.NamespaceUID})
}

func legacySearchCursorNamespace(authority *ResolvedAuthority) string {
	if authority == nil {
		return ""
	}
	if namespaceUID := strings.TrimSpace(authority.NamespaceUID); namespaceUID != "" {
		return namespaceUID
	}
	if namespace := strings.TrimSpace(authority.Namespace); namespace != "" {
		return "legacy:" + namespace
	}
	return ""
}

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
