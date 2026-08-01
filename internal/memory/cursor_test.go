package memory

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/oms/protocol"
	"github.com/orka-agents/orka/internal/store"
)

func TestRemoteSearchCursorIsOpaqueAndBoundToQueryAndAuthority(t *testing.T) {
	governed := newMemoryTestStore(t)
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	binding := &store.MemoryBackendBinding{
		ClusterID: "cluster-a", NamespaceUID: "namespace-a",
		BackendUID:     "22222222-2222-4222-8222-222222222222",
		AuthorityEpoch: 1, RoutingEpoch: 2,
		TenantID:  protocol.DeriveTenantID("cluster-a", "namespace-a"),
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	state := remoteSearchCursor{
		ProviderToken: "provider-token", PageSize: 4, ActualMode: protocol.SearchModeKeyword,
		Pending: []remoteSearchCursorRecord{{
			MemoryID: "mem-2", Generation: 2, BackendMemoryID: "provider-secret-id",
			ContentDigest: protocol.ContentDigest("two"),
		}},
	}
	cursor, err := saveRemoteSearchCursor(context.Background(), governed, binding, "query-a", state, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cursor, "provider") || strings.Contains(cursor, "mem-2") || !strings.HasPrefix(cursor, "msc-") {
		t.Fatalf("cursor exposed provider state: %q", cursor)
	}
	decoded, err := loadRemoteSearchCursor(context.Background(), governed, binding, "query-a", cursor, now.Add(time.Minute))
	if err != nil || decoded.ProviderToken != "provider-token" || decoded.PageSize != 4 || len(decoded.Pending) != 1 {
		t.Fatalf("decode = %#v, %v", decoded, err)
	}
	if _, err := loadRemoteSearchCursor(context.Background(), governed, binding, "query-b", cursor, now.Add(time.Minute)); err == nil {
		t.Fatal("cursor accepted a different query")
	}
	changed := *binding
	changed.RoutingEpoch++
	if _, err := loadRemoteSearchCursor(context.Background(), governed, &changed, "query-a", cursor, now.Add(time.Minute)); err == nil {
		t.Fatal("cursor accepted a different routing epoch")
	}
	if _, err := loadRemoteSearchCursor(
		context.Background(), governed, binding, "query-a", cursor, now.Add(remoteSearchCursorTTL+time.Second),
	); err == nil {
		t.Fatal("cursor accepted after expiry")
	}
}
