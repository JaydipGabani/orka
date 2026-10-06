package main

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func TestHashedMarkerConfiguration(t *testing.T) {
	value := syntheticValue()
	for _, tc := range []struct {
		name    string
		markers []markerConfig
		valid   bool
	}{
		{"legacy", []markerConfig{{ID: "legacy", Value: value}}, true},
		{"digest-only", []markerConfig{{ID: "private-challenge", SHA256: wireDigest(value)}}, true},
		{"both", []markerConfig{{ID: "both", Value: value, SHA256: wireDigest(value)}}, false},
		{"neither", []markerConfig{{ID: "neither"}}, false},
		{"empty-digest", []markerConfig{{ID: "empty", SHA256: wireDigest("")}}, false},
		{"invalid-digest", []markerConfig{{ID: "invalid", SHA256: "wrong"}}, false},
		{"duplicate-value", []markerConfig{{ID: "raw", Value: value}, {ID: "hashed", SHA256: wireDigest(value)}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(syntheticValue())
			cfg.Markers = tc.markers
			parsed, err := parseConfig(configJSON(t, cfg))
			if (err == nil) != tc.valid {
				t.Fatal("marker representation was not validated")
			}
			if tc.valid && !reflect.DeepEqual(parsed.Markers, tc.markers) {
				t.Fatal("marker representation changed on decode")
			}
		})
	}
}

func TestTLSDataIngressMatchesHashedSubjectsWithoutRevealingChallenges(t *testing.T) {
	value := syntheticValue()
	f := startTLSIngressObserver(t, func(c *config) {
		c.Markers = []markerConfig{{ID: "final-challenge", SHA256: wireDigest(value)}}
	})
	for _, subject := range []string{value, "prefix-" + value} {
		body, err := json.Marshal([]map[string]string{{"subject": subject, "source": "synthetic-source"}})
		if err != nil {
			t.Fatal("encode synthetic hashed-marker event")
		}
		requireStatus(t, f.dataRequest(t, "/events/alpha", http.Header{"Aeg-Sas-Key": {f.canary}}, body), http.StatusOK)
		state := f.state(t)
		record := state.HTTP[len(state.HTTP)-1]
		if len(record.MarkerIDs) != 0 || len(record.CloudEvents) != 1 ||
			!record.TLSDataIngress || !record.SyntheticCredentialObserved {
			t.Fatal("hashed marker was treated as a body substring or lost its TLS evidence")
		}
		got := record.CloudEvents[0].Subject
		if got == nil || (len(got.MarkerIDs) == 1) != (subject == value) {
			t.Fatal("hashed subject marker did not require an exact value")
		}
		response := f.request(t, http.MethodGet, "/state", f.admin, nil, nil)
		assertNoDisclosure(t, response.body, value, f.admin, f.canary, f.control)
	}
}
