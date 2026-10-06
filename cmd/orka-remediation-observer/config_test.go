package main

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func configJSON(t *testing.T, cfg config) []byte {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal("encode synthetic configuration")
	}
	return data
}

func TestConfigurationDefaultsAndStrictJSON(t *testing.T) {
	cfg := testConfig(syntheticValue())
	encoded := configJSON(t, cfg)
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal("decode synthetic configuration")
	}
	delete(document, "limits")
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal("encode configuration without limits")
	}
	parsed, err := parseConfig(data)
	if err != nil {
		t.Fatalf("default limits rejected: %v", err)
	}
	want := limits{
		HTTPBodyBytes: 65536, HTTPObservations: 256, HTTPConnections: 16, HTTPReadTimeoutMillis: 5000,
		RESPBytes: 65536, RESPCommands: 16, RESPConnections: 16, RESPObservations: 256,
		RESPReadTimeoutMillis: 5000, ShutdownTimeoutMillis: 2000,
	}
	if parsed.Limits != want {
		t.Fatal("documented hard default limits changed")
	}
	cases := map[string][]byte{
		"empty":       nil,
		"too-large":   []byte(strings.Repeat(" ", 65537)),
		"null":        []byte("null"),
		"trailing":    append(append([]byte{}, encoded...), []byte("{}")...),
		"duplicate":   []byte(strings.Replace(string(encoded), `"runID":`, `"runID":"other","runID":`, 1)),
		"case-alias":  []byte(strings.Replace(string(encoded), `"runID":`, `"RunID":`, 1)),
		"unknown":     []byte(strings.Replace(string(encoded), `"runID":`, `"unexpected":true,"runID":`, 1)),
		"null-limits": []byte(strings.Replace(string(data), `"runID":`, `"limits":null,"runID":`, 1)),
		"wrong-type":  []byte(strings.Replace(string(encoded), `"runID":"synthetic-run"`, `"runID":1`, 1)),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig(input); err == nil {
				t.Fatal("ambiguous or malformed configuration was accepted")
			}
		})
	}
}

func TestConfigurationRejectsUnsafeValues(t *testing.T) {
	cases := []struct {
		name   string
		change func(*config)
	}{
		{"version", func(c *config) { c.SchemaVersion = "v2" }},
		{"empty-run", func(c *config) { c.RunID = "" }},
		{"run-path", func(c *config) { c.RunID = "../other" }},
		{"long-run", func(c *config) { c.RunID = strings.Repeat("a", 65) }},
		{"host-name", func(c *config) { c.HTTPAddress = "localhost:18080" }},
		{"privileged-port", func(c *config) { c.HTTPAddress = "127.0.0.1:1024" }},
		{"multicast", func(c *config) { c.HTTPAddress = "224.0.0.1:18080" }},
		{"shared-listener", func(c *config) { c.RESPAddress = c.HTTPAddress }},
		{"admin-file", func(c *config) { c.AdminTokenFile = "" }},
		{"partial-tls", func(c *config) { c.TLS.CertFile = "synthetic-cert.pem" }},
		{"missing-canary-digest", func(c *config) { c.SyntheticCanarySHA256 = "" }},
		{"uppercase-digest", func(c *config) { c.SyntheticCanarySHA256 = strings.Repeat("AB", 32) }},
		{"no-markers", func(c *config) { c.Markers = []markerConfig{} }},
		{"short-marker", func(c *config) { c.Markers[0].Value = "short" }},
		{"long-marker", func(c *config) { c.Markers[0].Value = strings.Repeat("m", 257) }},
		{"marker-newline", func(c *config) { c.Markers[0].Value = "marker-\n-value" }},
		{"duplicate-marker-id", func(c *config) { c.Markers[1].ID = c.Markers[0].ID }},
		{"duplicate-marker-value", func(c *config) { c.Markers[1].Value = c.Markers[0].Value }},
		{"duplicate-channel", func(c *config) { c.Channels = []string{"alpha", "alpha"} }},
		{"channel-path", func(c *config) { c.Channels = []string{"../state"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(syntheticValue())
			tc.change(&cfg)
			if _, err := parseConfig(configJSON(t, cfg)); err == nil {
				t.Fatal("unsafe observer configuration accepted")
			}
		})
	}
}

func TestConfigurationLimitBoundaries(t *testing.T) {
	for _, bound := range []struct {
		field string
		max   int
	}{
		{"HTTPBodyBytes", 65536}, {"HTTPObservations", 256}, {"HTTPConnections", 16},
		{"HTTPReadTimeoutMillis", 5000}, {"RESPBytes", 65536}, {"RESPCommands", 16},
		{"RESPConnections", 16}, {"RESPObservations", 256},
		{"RESPReadTimeoutMillis", 5000}, {"ShutdownTimeoutMillis", 2000},
	} {
		for _, value := range []int{-1, 0, 1, bound.max, bound.max + 1} {
			t.Run(bound.field+"/"+strconv.Itoa(value), func(t *testing.T) {
				cfg := testConfig(syntheticValue())
				reflect.ValueOf(&cfg.Limits).Elem().FieldByName(bound.field).SetInt(int64(value))
				_, err := parseConfig(configJSON(t, cfg))
				wantValid := value > 0 && value <= bound.max
				if (err == nil) != wantValid {
					t.Fatal("configuration limit boundary was not enforced")
				}
			})
		}
	}
}

func TestAdminTokenFilePolicy(t *testing.T) {
	dir := testFiles(t)
	admin, canary := syntheticValue(), syntheticValue()
	canaryDigest := sha256.Sum256([]byte(canary))
	cases := []struct {
		name  string
		value string
		mode  os.FileMode
		valid bool
	}{
		{"private", admin, 0600, true},
		{"group-readable", admin, 0640, true},
		{"world-readable", admin, 0644, false},
		{"group-writable", admin, 0620, false},
		{"owner-executable", admin, 0700, false},
		{"group-executable", admin, 0610, false},
		{"short", admin[:31], 0600, false},
		{"minimum", admin[:32], 0600, true},
		{"maximum", strings.Repeat(admin, 79)[:4096], 0600, true},
		{"oversized", strings.Repeat(admin, 79)[:4097], 0600, false},
		{"newline", admin + "\n", 0600, false},
		{"space", admin + " ", 0600, false},
		{"non-ascii", admin + "é", 0600, false},
		{"shared-canary", canary, 0600, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".key")
			writeTestFile(t, path, []byte(tc.value), tc.mode)
			got, err := loadAdminDigest(path, canaryDigest)
			if (err == nil) != tc.valid {
				t.Fatal("admin token file violated the bounded, private, separate-key policy")
			}
			if tc.valid && got != sha256.Sum256([]byte(tc.value)) {
				t.Fatal("admin authentication digest did not cover the exact file bytes")
			}
			if err != nil {
				assertNoDisclosure(t, []byte(err.Error()), admin, canary, tc.value)
			}
		})
	}
	for _, path := range []string{dir, filepath.Join(dir, "missing.key")} {
		if _, err := loadAdminDigest(path, canaryDigest); err == nil {
			t.Fatal("non-regular or missing admin token file was accepted")
		}
	}
}
