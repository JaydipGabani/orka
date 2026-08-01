package kd6adapter

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/oms/protocol"
)

func TestLiveControlsForEntriesInTxLoadsOnlyManifestReferences(t *testing.T) {
	ctx := context.Background()
	database, err := openControlDatabase(ctx, filepath.Join(t.TempDir(), "controls.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.close() })
	tx, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck

	const authority = "sha256:manifest-authority"
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	for index := range 450 {
		key := fmt.Sprintf("key-%03d", index)
		if err := upsertControlInTx(ctx, tx, controlRecord{
			AuthorityDigest: authority, UpsertKey: key, MemoryID: fmt.Sprintf("mem-%03d", index),
			State: protocol.RecordStateLive, Generation: 1, BackendVersion: fmt.Sprintf("version-%03d", index),
			BackendMemoryID: fmt.Sprintf("provider-%03d", index), ContentDigest: protocol.ContentDigest(key), UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	entries := []ContentDescriptor{
		{UpsertKey: "key-000"}, {UpsertKey: "key-199"}, {UpsertKey: "key-200"},
		{UpsertKey: "key-449"}, {UpsertKey: "key-449"}, {UpsertKey: "missing"},
	}
	controls, err := liveControlsForEntriesInTx(ctx, tx, authority, entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(controls) != 4 {
		t.Fatalf("loaded controls = %d, want exactly 4 manifest references", len(controls))
	}
	for _, key := range []string{"key-000", "key-199", "key-200", "key-449"} {
		if _, found := controls[key]; !found {
			t.Fatalf("manifest control %q was not loaded", key)
		}
	}
}
