package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

type tlsIngressFixture struct {
	*ingressFixture
	dataURL string
}

func startTLSIngressObserver(t *testing.T, change func(*config)) *tlsIngressFixture {
	t.Helper()
	base, release := newIngressConfig(t)
	listener := testListener(t)
	base.config.IngressHTTPSAddress = listener.Addr().String()
	base.config.ChannelCanaries = []channelCanaryConfig{
		{Channel: "alpha", SHA256: wireDigest(base.canary)},
		{Channel: "beta", SHA256: wireDigest(base.control)},
	}
	if change != nil {
		change(&base.config)
	}
	release()
	_ = listener.Close()
	server, err := startServer(base.config)
	if err != nil {
		t.Fatal("start synthetic TLS ingress")
	}
	base.server = server
	t.Cleanup(func() {
		base.client.CloseIdleConnections()
		if err := base.stop(); err != nil {
			t.Error("TLS ingress cleanup failed")
		}
	})
	return &tlsIngressFixture{ingressFixture: base, dataURL: "https://" + base.config.IngressHTTPSAddress}
}

func (f *tlsIngressFixture) dataRequest(t *testing.T, path string, headers http.Header, body []byte) wireResponse {
	t.Helper()
	response, err := requestHTTP(f.client, http.MethodPost, f.dataURL+path, "", body, headers)
	if err != nil {
		t.Fatal("synthetic HTTPS data request failed")
	}
	assertNoDisclosure(t, response.body, f.admin, f.canary, f.control)
	return response
}

func TestTLSDataIngressConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*config)
		valid  bool
	}{
		{"enabled", func(*config) {}, true},
		{"no-plaintext", func(c *config) { c.IngressHTTPAddress = "" }, true},
		{"no-tls", func(c *config) { c.TLS = tlsFiles{} }, false},
		{"admin-port", func(c *config) { c.IngressHTTPSAddress = c.HTTPAddress }, false},
		{"plain-port", func(c *config) { c.IngressHTTPSAddress = c.IngressHTTPAddress }, false},
		{"resp-port", func(c *config) { c.IngressHTTPSAddress = c.RESPAddress }, false},
		{"hostname", func(c *config) { c.IngressHTTPSAddress = "synthetic.invalid:9443" }, false},
		{"low-port", func(c *config) { c.IngressHTTPSAddress = "127.0.0.1:1024" }, false},
		{"invalid-canary", func(c *config) { c.ChannelCanaries[0].SHA256 = "not-a-digest" }, false},
		{"empty-canary", func(c *config) { c.ChannelCanaries[0].SHA256 = wireDigest("") }, false},
		{"unknown-channel", func(c *config) { c.ChannelCanaries[0].Channel = "unconfigured" }, false},
		{"duplicate-channel", func(c *config) { c.ChannelCanaries = append(c.ChannelCanaries, c.ChannelCanaries[0]) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(syntheticValue())
			cfg.TLS = tlsFiles{CertFile: "synthetic.crt", KeyFile: "synthetic.key"}
			cfg.IngressHTTPAddress, cfg.IngressHTTPSAddress = "127.0.0.1:8080", "127.0.0.1:9443"
			cfg.ChannelCanaries = []channelCanaryConfig{{Channel: "alpha", SHA256: wireDigest(syntheticValue())}}
			tc.change(&cfg)
			parsed, err := parseConfig(configJSON(t, cfg))
			if (err == nil) != tc.valid {
				t.Fatal("TLS ingress or channel canary validation disagreed with the contract")
			}
			if tc.valid && !reflect.DeepEqual(parsed, cfg) {
				t.Fatal("TLS ingress configuration did not round-trip")
			}
		})
	}
	cfg := testConfig(syntheticValue())
	for _, extra := range []string{
		`"ingressHTTPSAddress":null`,
		`"IngressHTTPSAddress":"127.0.0.1:9443"`,
		`"channelCanaries":[{"channel":"alpha","sha256":"x","header":"Authorization"}]`,
	} {
		data := configJSON(t, cfg)
		data = append(data[:len(data)-1], []byte(","+extra+"}")...)
		if _, err := parseConfig(data); err == nil {
			t.Fatal("an untyped ingress or credential selector was accepted")
		}
	}
}

func TestTLSDataIngressCannotReachAdmin(t *testing.T) {
	f := startTLSIngressObserver(t, nil)
	before := f.state(t)
	for _, base := range []string{f.dataURL, f.ingressURL} {
		for _, path := range []string{"/state", "/reset", "/%73tate", "/%72eset", "/events/../state", "//reset"} {
			for _, token := range []string{"", f.control, f.admin} {
				for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
					response, err := requestHTTP(f.client, method, base+path, token, resetBody(f.config.RunID, 1), nil)
					if err != nil {
						t.Fatal("data-only boundary request failed")
					}
					requireStatus(t, response, http.StatusNotFound)
					assertNoDisclosure(t, response.body, f.admin, f.canary, f.control)
				}
			}
		}
	}
	if !reflect.DeepEqual(before, f.state(t)) {
		t.Fatal("ingress requests read or reset administrative state")
	}
	for _, token := range []string{"", f.control} {
		requireStatus(t, f.request(t, http.MethodGet, "/state", token, nil, nil), http.StatusUnauthorized)
	}
	requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil), http.StatusOK)
	if f.state(t).Generation != 2 {
		t.Fatal("authenticated admin TLS reset did not work")
	}
}

func TestTLSDataIngressRecordsOnlyExactChannelHeaderAndTLS(t *testing.T) {
	f := startTLSIngressObserver(t, nil)
	body, err := json.Marshal([]map[string]string{{
		"specversion": "1.0", "type": "keda.scaledobject.failed.v1",
		"subject": f.config.Markers[0].Value, "source": f.config.Markers[1].Value,
	}})
	if err != nil {
		t.Fatal("encode synthetic CloudEvent")
	}
	for _, tc := range []struct {
		path    string
		values  []string
		matched bool
	}{
		{"/events/alpha", []string{f.canary}, true},
		{"/events/beta", []string{f.control}, true},
		{"/events/beta", []string{f.canary}, false},
		{"/events/alpha", nil, false},
		{"/events/alpha", []string{f.canary + "-not-exact"}, false},
		{"/events/alpha", []string{f.canary, f.canary}, false},
	} {
		headers := http.Header{
			"Content-Type": {"application/cloudevents-batch+json; charset=utf-8"},
			"Aeg-Sas-Key":  tc.values,
		}
		requireStatus(t, f.dataRequest(t, tc.path+"?api-version=2018-01-01", headers, body), http.StatusOK)
		state := f.state(t)
		record := state.HTTP[len(state.HTTP)-1]
		if record.Route != tc.path || !record.TLSDataIngress || record.SyntheticCredentialObserved != tc.matched ||
			len(record.CloudEvents) != 1 || record.CloudEvents[0].Subject == nil ||
			record.CloudEvents[0].Subject.SHA256 != wireDigest(f.config.Markers[0].Value) {
			t.Fatal("TLS/channel/header evidence was not derived from the actual request")
		}
	}
	for _, base := range []string{f.ingressURL, f.url} {
		response, err := requestHTTP(f.client, http.MethodPost, base+"/events/alpha", "", body, http.Header{
			"Aeg-Sas-Key": {f.canary}, "X-Forwarded-Proto": {"https"}, "Tls-Data-Ingress": {"true"},
		})
		if err != nil {
			t.Fatal("non-data-TLS control failed")
		}
		requireStatus(t, response, http.StatusOK)
		state := f.state(t)
		if state.HTTP[len(state.HTTP)-1].TLSDataIngress {
			t.Fatal("a header or admin listener forged TLS data-ingress evidence")
		}
	}
}

func TestTLSDataIngressRequiresCertificateTrustAndExactName(t *testing.T) {
	f := startTLSIngressObserver(t, nil)
	for _, variant := range []string{"untrusted-root", "wrong-name"} {
		cfg := f.clientTLS.Clone()
		if variant == "untrusted-root" {
			cfg.RootCAs = x509.NewCertPool()
		} else {
			cfg.ServerName = "other-synthetic-observer.test"
		}
		client := ingressClient(t, cfg)
		if _, err := requestHTTP(client, http.MethodPost, f.dataURL+"/events/alpha", "", nil,
			http.Header{"Aeg-Sas-Key": {f.canary}}); err == nil {
			t.Fatal("untrusted or wrong-identity TLS accepted a publishing request")
		}
	}
	if len(f.state(t).HTTP) != 0 {
		t.Fatal("failed TLS handshakes emitted request evidence")
	}
	o := f.server.observer
	r := httptest.NewRequest(http.MethodPost, "/events/alpha", bytes.NewReader(nil))
	r.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	o.serveIngressHTTPS(response, r)
	if response.Code != http.StatusBadRequest || len(f.state(t).HTTP) != 0 {
		t.Fatal("TLS handler trusted a request without actual TLS")
	}
	requireStatus(t, f.dataRequest(t, "/events/alpha", http.Header{"Aeg-Sas-Key": {f.canary}}, nil), http.StatusOK)
}

func TestTLSDataIngressResetAndLimitsAreShared(t *testing.T) {
	f := startTLSIngressObserver(t, func(c *config) {
		c.Limits.HTTPBodyBytes = 64
		c.Limits.HTTPObservations = 2
	})
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: testDeadline}, "tcp", f.config.IngressHTTPSAddress, f.clientTLS)
	if err != nil {
		t.Fatal("connect synthetic TLS body")
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(testDeadline))
	_, reader := beginHTTPBodyOnConn(t, conn, 8)
	requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil), http.StatusOK)
	sendWire(t, conn, "old-body")
	requireHTTPReply(t, reader, http.StatusOK)
	if len(f.state(t).HTTP) != 0 {
		t.Fatal("TLS request admitted before reset contaminated a new generation")
	}
	for index, base := range []string{f.dataURL, f.ingressURL, f.url} {
		body := bytes.Repeat([]byte("x"), 63+index%2)
		response, err := requestHTTP(f.client, http.MethodPost, base+"/events/alpha", "", body, nil)
		if err != nil {
			t.Fatal("bounded shared-ingress control failed")
		}
		requireStatus(t, response, http.StatusOK)
	}
	requireStatus(t, f.dataRequest(t, "/events/alpha", nil, bytes.Repeat([]byte("x"), 65)),
		http.StatusRequestEntityTooLarge)
	state := f.state(t)
	if state.Generation != 2 || len(state.HTTP) != 2 || state.DroppedHTTP != 1 || !state.HTTP[0].TLSDataIngress {
		t.Fatal("TLS listener bypassed the generation, body, or shared evidence budget")
	}
}

func TestTLSDataIngressConnectionBudgetAndShutdown(t *testing.T) {
	f := startTLSIngressObserver(t, func(c *config) { c.Limits.HTTPConnections = 1 })
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: testDeadline}, "tcp", f.config.IngressHTTPSAddress, f.clientTLS)
	if err != nil {
		t.Fatal("reserve synthetic TLS connection")
	}
	defer func() { _ = conn.Close() }()
	for _, base := range []string{f.ingressURL, f.url} {
		if _, err := requestHTTP(f.client, http.MethodGet, base+"/healthz", "", nil, nil); err == nil {
			t.Fatal("another listener bypassed the TLS connection quota")
		}
	}
	if err := f.stop(); err != nil {
		t.Fatal("shutdown did not join TLS ingress")
	}
	for _, address := range []string{
		f.config.HTTPAddress, f.config.IngressHTTPAddress, f.config.IngressHTTPSAddress, f.config.RESPAddress,
	} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("shutdown left an observer listener bound")
		}
		_ = listener.Close()
	}
}

func TestTLSDataIngressStartupRecoveryAndAdminCanarySeparation(t *testing.T) {
	f, release := newIngressConfig(t)
	occupied := testListener(t)
	f.config.IngressHTTPSAddress = occupied.Addr().String()
	release()
	if _, err := startServer(f.config); err == nil {
		t.Fatal("occupied TLS ingress listener was silently skipped")
	}
	for _, address := range []string{f.config.HTTPAddress, f.config.IngressHTTPAddress, f.config.RESPAddress} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("failed TLS startup leaked another listener")
		}
		_ = listener.Close()
	}
	_ = occupied.Close()
	f.config.ChannelCanaries = []channelCanaryConfig{{Channel: "alpha", SHA256: wireDigest(f.admin)}}
	if _, err := startServer(f.config); err == nil {
		t.Fatal("an admin credential was accepted as a channel canary")
	}
	f.config.ChannelCanaries[0].SHA256 = wireDigest(f.canary)
	server, err := startServer(f.config)
	if err != nil {
		t.Fatal("TLS ingress startup did not recover after the port was released")
	}
	if err := server.shutdown(); err != nil {
		t.Fatal("recovered TLS listener did not shut down")
	}
}
