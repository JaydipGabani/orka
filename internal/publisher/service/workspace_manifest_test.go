package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
)

func TestWorkspaceManifestDigestPreservesCanonicalBytes(t *testing.T) {
	for _, entries := range [][]workspaceEntry{
		nil,
		{},
		{{Path: "plain/file.go", Mode: "100644", OID: strings.Repeat("a", 40), Size: 123}},
		{{Path: "quotes-\"-and-<>&-\u2028-\u00e9", Mode: "120000", OID: strings.Repeat("b", 40), Size: 6, Target: "../foo"},
			{Path: "other", Mode: "100755", OID: strings.Repeat("c", 64), Size: 1 << 30}},
	} {
		manifest := workspaceManifest{Schema: workspaceManifestSchema, RepositoryID: "repository",
			SourceRef: "refs/tags/v1", BaselineOID: strings.Repeat("a", 40), TreeOID: strings.Repeat("b", 40), Entries: entries}
		canonical, err := harnessv2.CanonicalValue(manifest)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(canonical)
		want := "sha256:" + hex.EncodeToString(sum[:])
		got, err := workspaceManifestDigest(manifest)
		if err != nil || got != want {
			t.Fatalf("canonical identity changed: got %q, want %q, error %v", got, want, err)
		}
	}
}

func TestWorkspaceManifestDigestBeyondRPCBodyLimit(t *testing.T) {
	manifest := workspaceManifest{Schema: workspaceManifestSchema, RepositoryID: "repository",
		SourceRef: strings.Repeat("a", 40), BaselineOID: strings.Repeat("a", 40), TreeOID: strings.Repeat("b", 40)}
	entries := make([]map[string]any, 18000)
	for index := range entries {
		entry := workspaceEntry{Path: fmt.Sprintf("vendor/example.org/module/long-component-name/subdirectory/file-%05d.go", index),
			Mode: "100644", OID: strings.Repeat("c", 40), Size: 1024}
		manifest.Entries = append(manifest.Entries, entry)
		entries[index] = map[string]any{"path": entry.Path, "mode": entry.Mode, "oid": entry.OID, "size": entry.Size}
	}
	independent := map[string]any{"schema": manifest.Schema, "repositoryId": manifest.RepositoryID,
		"sourceRef": manifest.SourceRef, "baselineOid": manifest.BaselineOID, "treeOid": manifest.TreeOID, "entries": entries}
	raw, err := json.Marshal(independent)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= harnessv2.MaxCanonicalJSONBytes {
		t.Fatal("fixture does not exceed the RPC body bound")
	}
	sum := sha256.Sum256(raw)
	got, err := workspaceManifestDigest(manifest)
	if err != nil || got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("bounded large workspace inventory failed: %v", err)
	}
}

func TestWorkspaceManifestDigestRejectsInvalidEntryEncoding(t *testing.T) {
	manifest := workspaceManifest{Entries: []workspaceEntry{{Path: string([]byte{0xff}), Mode: "100644"}}}
	if _, err := workspaceManifestDigest(manifest); err == nil {
		t.Fatal("invalid UTF-8 changed canonical identity silently")
	}
}
