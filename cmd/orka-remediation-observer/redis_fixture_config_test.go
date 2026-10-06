package main

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"
)

func TestRedisFixtureConfiguration(t *testing.T) {
	keyDigest := wireDigest("synthetic-list-" + syntheticValue())
	cases := []struct {
		name       string
		fields     map[string]any
		disableTCP bool
		valid      bool
	}{
		{"disabled", nil, false, true},
		{"zero", map[string]any{"redisFixtureQueueLength": 0, "redisFixtureListKeySHA256": keyDigest}, false, true},
		{"maximum", map[string]any{"redisFixtureQueueLength": 10, "redisFixtureListKeySHA256": keyDigest}, false, true},
		{"negative", map[string]any{"redisFixtureQueueLength": -1, "redisFixtureListKeySHA256": keyDigest}, false, false},
		{"over-limit", map[string]any{"redisFixtureQueueLength": 11, "redisFixtureListKeySHA256": keyDigest}, false, false},
		{"fraction", map[string]any{"redisFixtureQueueLength": 0.5, "redisFixtureListKeySHA256": keyDigest}, false, false},
		{"string", map[string]any{"redisFixtureQueueLength": "0", "redisFixtureListKeySHA256": keyDigest}, false, false},
		{"null", map[string]any{"redisFixtureQueueLength": nil, "redisFixtureListKeySHA256": keyDigest}, false, false},
		{"missing-key", map[string]any{"redisFixtureQueueLength": 0}, false, false},
		{"missing-opt-in", map[string]any{"redisFixtureListKeySHA256": keyDigest}, false, false},
		{"empty-key", map[string]any{
			"redisFixtureQueueLength": 0, "redisFixtureListKeySHA256": wireDigest("")}, false, false},
		{"no-resp", map[string]any{"redisFixtureQueueLength": 0, "redisFixtureListKeySHA256": keyDigest}, true, false},
		{"case-alias", map[string]any{"RedisFixtureQueueLength": 0, "redisFixtureListKeySHA256": keyDigest}, false, false},
		{"untrusted-match-flag", map[string]any{"metricQueryMatched": true}, false, false},
		{"untrusted-script", map[string]any{"redisFixtureScriptSHA256": keyDigest}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(syntheticValue())
			if tc.disableTCP {
				cfg.RESPAddress = ""
			}
			var document map[string]any
			if err := json.Unmarshal(configJSON(t, cfg), &document); err != nil {
				t.Fatal("decode synthetic Redis fixture configuration")
			}
			maps.Copy(document, tc.fields)
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal("encode synthetic Redis fixture configuration")
			}
			parsed, err := parseConfig(data)
			if (err == nil) != tc.valid {
				t.Fatal("Redis fixture opt-in, key pin, or numeric bound was not enforced")
			}
			if tc.valid {
				var roundTrip map[string]any
				if err := json.Unmarshal(configJSON(t, parsed), &roundTrip); err != nil {
					t.Fatal("decode fixture configuration round-trip")
				}
				_, enabled := roundTrip["redisFixtureQueueLength"]
				if enabled != (tc.fields != nil) {
					t.Fatal("omitting the fixture must not enable default queue responses")
				}
				if enabled && (parsed.RedisFixtureQueueLength == nil ||
					*parsed.RedisFixtureQueueLength != tc.fields["redisFixtureQueueLength"].(int) ||
					parsed.RedisFixtureListKeySHA256 != keyDigest) {
					t.Fatal("configuration decoding changed the operator's exact integer or key pin")
				}
			}
		})
	}
}

func TestRedisFixtureKeyDigestValidation(t *testing.T) {
	for _, value := range []string{"", "not-a-digest", strings.Repeat("AB", 32), strings.Repeat("g", 64)} {
		cfg := testConfig(syntheticValue())
		data := strings.TrimSuffix(string(configJSON(t, cfg)), "}") +
			`,"redisFixtureQueueLength":0,"redisFixtureListKeySHA256":"` + value + `"}`
		if _, err := parseConfig([]byte(data)); err == nil {
			t.Fatal("invalid list-key digest admitted a synthetic metric fixture")
		}
	}
}
