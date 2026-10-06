package main

import (
	"encoding/json"
	"testing"
)

func TestIngressConfiguration(t *testing.T) {
	cases := []struct {
		name    string
		field   string
		address any
		tls     tlsFiles
		valid   bool
	}{
		{"enabled", "ingressHTTPAddress", "0.0.0.0:8080", tlsFiles{"cert.pem", "key.pem"}, true},
		{"ipv6", "ingressHTTPAddress", "[::1]:8080", tlsFiles{"cert.pem", "key.pem"}, true},
		{"minimum-port", "ingressHTTPAddress", "127.0.0.1:1025", tlsFiles{"cert.pem", "key.pem"}, true},
		{"maximum-port", "ingressHTTPAddress", "127.0.0.1:65535", tlsFiles{"cert.pem", "key.pem"}, true},
		{"disabled", "ingressHTTPAddress", "", tlsFiles{}, true},
		{"missing-tls", "ingressHTTPAddress", "0.0.0.0:8080", tlsFiles{}, false},
		{"missing-tls-key", "ingressHTTPAddress", "0.0.0.0:8080", tlsFiles{CertFile: "cert.pem"}, false},
		{"missing-tls-cert", "ingressHTTPAddress", "0.0.0.0:8080", tlsFiles{KeyFile: "key.pem"}, false},
		{"admin-port", "ingressHTTPAddress", "127.0.0.1:8443", tlsFiles{"cert.pem", "key.pem"}, false},
		{"wildcard-overlap", "ingressHTTPAddress", "0.0.0.0:8443", tlsFiles{"cert.pem", "key.pem"}, false},
		{"resp-port", "ingressHTTPAddress", "127.0.0.2:6379", tlsFiles{"cert.pem", "key.pem"}, false},
		{"privileged-port", "ingressHTTPAddress", "0.0.0.0:1024", tlsFiles{"cert.pem", "key.pem"}, false},
		{"ephemeral-port", "ingressHTTPAddress", "0.0.0.0:0", tlsFiles{"cert.pem", "key.pem"}, false},
		{"hostname", "ingressHTTPAddress", "observer.invalid:8080", tlsFiles{"cert.pem", "key.pem"}, false},
		{"multicast", "ingressHTTPAddress", "224.0.0.1:8080", tlsFiles{"cert.pem", "key.pem"}, false},
		{"ipv6-zone", "ingressHTTPAddress", "[fe80::1%lo]:8080", tlsFiles{"cert.pem", "key.pem"}, false},
		{"worker-alias", "workerHTTPAddress", "0.0.0.0:8080", tlsFiles{"cert.pem", "key.pem"}, false},
		{"case-alias", "IngressHTTPAddress", "0.0.0.0:8080", tlsFiles{"cert.pem", "key.pem"}, false},
		{"null", "ingressHTTPAddress", nil, tlsFiles{"cert.pem", "key.pem"}, false},
		{"wrong-type", "ingressHTTPAddress", 8080, tlsFiles{"cert.pem", "key.pem"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(syntheticValue())
			cfg.HTTPAddress, cfg.RESPAddress, cfg.TLS = "127.0.0.1:8443", "127.0.0.1:6379", tc.tls
			var document map[string]any
			if err := json.Unmarshal(configJSON(t, cfg), &document); err != nil {
				t.Fatal("decode synthetic split-listener configuration")
			}
			document[tc.field] = tc.address
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal("encode synthetic split-listener configuration")
			}
			parsed, err := parseConfig(data)
			if (err == nil) != tc.valid {
				t.Fatal("split-listener configuration violated the exact field, TLS, or port contract")
			}
			if tc.valid {
				var roundTrip map[string]any
				if err := json.Unmarshal(configJSON(t, parsed), &roundTrip); err != nil ||
					roundTrip["ingressHTTPAddress"] != tc.address {
					t.Fatal("ingressHTTPAddress was not preserved exactly")
				}
			}
		})
	}
}

func TestIngressPreservesDistinctAdminAndRESPAddressesSharingAPort(t *testing.T) {
	cfg := testConfig(syntheticValue())
	cfg.HTTPAddress, cfg.RESPAddress = "127.0.0.1:18443", "127.0.0.2:18443"
	cfg.IngressHTTPAddress = "127.0.0.1:18080"
	cfg.TLS = tlsFiles{CertFile: "synthetic.crt", KeyFile: "synthetic.key"}
	for _, address := range []string{"", "127.0.0.1:19443"} {
		cfg.IngressHTTPSAddress = address
		if _, err := parseConfig(configJSON(t, cfg)); err != nil {
			t.Fatal("adding data TLS tightened the existing distinct-address admin/RESP contract")
		}
	}
}
