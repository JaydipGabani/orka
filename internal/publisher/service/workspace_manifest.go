package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"unicode/utf8"

	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
)

// Hash each bounded entry using the existing canonical encoding. Workspace
// inventories are governed by WorkspaceLimits, not the JSON-RPC body limit.
func workspaceManifestDigest(manifest workspaceManifest) (string, error) {
	for _, value := range []string{manifest.Schema, manifest.RepositoryID, manifest.SourceRef, manifest.BaselineOID, manifest.TreeOID} {
		if !utf8.ValidString(value) {
			return "", fmt.Errorf("workspace manifest contains invalid UTF-8")
		}
	}
	fields := map[string]any{
		"baselineOid": manifest.BaselineOID, "entries": nil,
		"repositoryId": manifest.RepositoryID, "schema": manifest.Schema,
		"sourceRef": manifest.SourceRef, "treeOid": manifest.TreeOID,
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("{"))
	for index, key := range keys {
		if index != 0 {
			_, _ = hasher.Write([]byte(","))
		}
		encodedKey, err := harnessv2.CanonicalValue(key)
		if err != nil {
			return "", err
		}
		_, _ = hasher.Write(encodedKey)
		_, _ = hasher.Write([]byte(":"))
		if key != "entries" || manifest.Entries == nil {
			content, err := harnessv2.CanonicalValue(fields[key])
			if err != nil {
				return "", err
			}
			_, _ = hasher.Write(content)
			continue
		}
		_, _ = hasher.Write([]byte("["))
		for entryIndex, entry := range manifest.Entries {
			if entryIndex != 0 {
				_, _ = hasher.Write([]byte(","))
			}
			for _, value := range []string{entry.Path, entry.Mode, entry.OID, entry.Target} {
				if !utf8.ValidString(value) {
					return "", fmt.Errorf("workspace manifest entry contains invalid UTF-8")
				}
			}
			content, err := harnessv2.CanonicalValue(entry)
			if err != nil {
				return "", err
			}
			_, _ = hasher.Write(content)
		}
		_, _ = hasher.Write([]byte("]"))
	}
	_, _ = hasher.Write([]byte("}"))
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}
