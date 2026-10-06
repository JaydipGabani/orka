package provenance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrivateBuildInputsClassifyWithoutChangingVendorBytes(t *testing.T) {
	input := fixture(t)
	name := "patches/0001-vendor.patch"
	raw := []byte("--- a/tests/config.txt\n+++ b/tests/config.txt\n@@ -1 +1 @@\n-password=old-example\n+password=new-example\n")
	input.files[name] = bytes.Clone(raw)
	input.metadata.ExpectedDigests = make(map[string]string)
	for path, content := range input.files {
		input.metadata.ExpectedDigests[path] = expectedDigest(content)
	}
	if _, err := ParseDalec(input.spec, input.files, input.metadata); err == nil {
		t.Fatal("strict compatibility parser silently authorized disclosure")
	}
	classified, err := InspectPrivateBuildInputs(input.spec, input.files, input.metadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(classified.BuildOnly) != 1 || classified.BuildOnly[0].Path != name ||
		classified.BuildOnly[0].Digest != expectedDigest(raw) || !bytes.Equal(input.files[name], raw) {
		t.Fatal("private opaque input lost its exact identity or disclosure restriction")
	}
	encoded, err := json.Marshal(classified)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"old-example", "new-example"} {
		if strings.Contains(string(encoded), value) {
			t.Fatal("classification metadata disclosed matched bytes")
		}
	}
	input.files[name] = append(raw, '\n')
	if _, err := InspectPrivateBuildInputs(input.spec, input.files, input.metadata); err == nil {
		t.Fatal("changed opaque bytes bypassed the independent digest")
	}
}

func TestPrivateInputParsingDoesNotAuthorizeExecutableCredentialFields(t *testing.T) {
	input := fixture(t)
	input.replace(t, `CGO_ENABLED: "0"`, `PASSWORD: "credential-value"`)
	input.metadata.ExpectedDigests = make(map[string]string)
	for path, content := range input.files {
		input.metadata.ExpectedDigests[path] = expectedDigest(content)
	}
	if _, err := InspectPrivateBuildInputs(input.spec, input.files, input.metadata); err == nil {
		t.Fatal("private input parser accepted a credential-bearing execution environment")
	}
}
