package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

type ingressFixture struct {
	*testObserver
	ingressURL string
	clientTLS  *tls.Config
}

func syntheticTLS(t *testing.T) (tlsFiles, *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic TLS key")
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"synthetic-observer.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal("generate synthetic TLS certificate")
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("encode synthetic TLS key")
	}
	defer clear(key)
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("parse synthetic TLS certificate")
	}
	dir := testFiles(t)
	files := tlsFiles{CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem")}
	writeTestFile(t, files.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0444)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	defer clear(keyPEM)
	writeTestFile(t, files.KeyFile, keyPEM, 0400)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return files, &tls.Config{
		RootCAs: roots, ServerName: "synthetic-observer.test", MinVersion: tls.VersionTLS12,
	}
}

func ingressClient(t *testing.T, config *tls.Config) *http.Client {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: config, DisableKeepAlives: true},
		Timeout:   testDeadline,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func newIngressConfig(t *testing.T) (*ingressFixture, func()) {
	t.Helper()
	f := &ingressFixture{testObserver: &testObserver{
		admin: syntheticValue(), canary: syntheticValue(), control: syntheticValue(),
	}}
	f.config = testConfig(f.canary)
	f.config.TLS, f.clientTLS = syntheticTLS(t)
	f.config.AdminTokenFile = filepath.Join(testFiles(t), "admin.key")
	writeTestFile(t, f.config.AdminTokenFile, []byte(f.admin), 0440)
	admin, ingress, resp := testListener(t), testListener(t), testListener(t)
	f.config.HTTPAddress = admin.Addr().String()
	f.config.IngressHTTPAddress = ingress.Addr().String()
	f.config.RESPAddress = resp.Addr().String()
	f.url, f.ingressURL = "https://"+f.config.HTTPAddress, "http://"+f.config.IngressHTTPAddress
	f.client = ingressClient(t, f.clientTLS)
	return f, func() {
		_ = admin.Close()
		_ = ingress.Close()
		_ = resp.Close()
	}
}

func startIngressObserver(t *testing.T, change func(*config)) *ingressFixture {
	t.Helper()
	f, release := newIngressConfig(t)
	if change != nil {
		change(&f.config)
	}
	release()
	server, err := startServer(f.config)
	if err != nil {
		t.Fatalf("start split-listener observer: %v", err)
	}
	f.server = server
	t.Cleanup(func() {
		f.client.CloseIdleConnections()
		if err := f.stop(); err != nil {
			t.Errorf("split-listener cleanup: %v", err)
		}
	})
	return f
}

func (f *ingressFixture) ingressRequest(t *testing.T, method, path, token string, body []byte,
	headers http.Header,
) wireResponse {
	t.Helper()
	response, err := requestHTTP(f.client, method, f.ingressURL+path, token, body, headers)
	if err != nil {
		t.Fatal(err)
	}
	if response.header.Get("Location") != "" || response.header.Get("Cache-Control") != "no-store" ||
		response.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("ingress redirected or omitted safe response headers")
	}
	assertNoDisclosure(t, response.body, f.admin, f.canary, f.control)
	return response
}

func TestIngressHTTPAndTLSHandlerBoundary(t *testing.T) {
	f := &ingressFixture{testObserver: &testObserver{
		admin: syntheticValue(), canary: syntheticValue(), control: syntheticValue(),
	}}
	f.config = testConfig(f.canary)
	f.config.TLS, f.clientTLS = syntheticTLS(t)
	o := newObserver(f.config, sha256.Sum256([]byte(f.admin)), sha256.Sum256([]byte(f.canary)))
	admin := httptest.NewUnstartedServer(o)
	serverTLS, err := loadTLS(f.config.TLS)
	if err != nil {
		t.Fatal("load generated TLS material")
	}
	admin.TLS = serverTLS
	admin.StartTLS()
	t.Cleanup(admin.Close)
	ingress := httptest.NewServer(http.HandlerFunc(o.serveIngressHTTP))
	t.Cleanup(ingress.Close)
	f.url, f.ingressURL, f.client = admin.URL, ingress.URL, ingressClient(t, f.clientTLS)

	requireStatus(t, f.ingressRequest(t, http.MethodPost, "/events/alpha", "", []byte(f.control), nil),
		http.StatusOK)
	before := f.state(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/state"}, {http.MethodPost, "/reset"},
		{http.MethodPost, "/state"}, {http.MethodGet, "/reset"},
		{http.MethodHead, "/state"}, {http.MethodOptions, "/reset"},
		{http.MethodGet, "/%73tate"}, {http.MethodPost, "/%72eset"},
		{http.MethodGet, "//state"}, {http.MethodGet, "/events/../state"},
		{http.MethodPost, "/events/unconfigured"}, {http.MethodGet, "/"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			for _, token := range []string{"", f.control, f.admin} {
				response := f.ingressRequest(t, tc.method, tc.path, token,
					resetBody(f.config.RunID, 1), http.Header{"X-Forwarded-Host": {"synthetic-admin.test"}})
				requireStatus(t, response, http.StatusNotFound)
			}
		})
	}
	if !reflect.DeepEqual(f.state(t), before) {
		t.Fatal("denied plaintext routes reached administrative operations or mutated evidence")
	}
	requireStatus(t, f.request(t, http.MethodGet, "/state", "", nil, nil), http.StatusUnauthorized)
	requireStatus(t, f.request(t, http.MethodPost, "/reset", f.admin, resetBody(f.config.RunID, 1), nil),
		http.StatusOK)
	if f.state(t).Generation != 2 {
		t.Fatal("authenticated HTTPS reset stopped working when ingress was enabled")
	}
}

func TestIngressEventsReachVerifiedHTTPSState(t *testing.T) {
	f := startIngressObserver(t, nil)
	subject, source := f.config.Markers[0].Value, f.config.Markers[1].Value
	body, err := json.Marshal(map[string]string{"subject": subject, "source": source, "data": f.canary})
	if err != nil {
		t.Fatal("marshal synthetic ingress event")
	}
	requireStatus(t, f.ingressRequest(t, http.MethodPost, "/events/alpha", f.admin, body,
		http.Header{"Aeg-Sas-Key": {f.canary}}), http.StatusOK)
	state := f.state(t)
	if state.Generation != 1 || len(state.HTTP) != 1 || len(state.RESP) != 0 {
		t.Fatal("plaintext ingress did not share the authenticated HTTPS evidence store")
	}
	event := state.HTTP[0]
	if event.Route != "/events/alpha" || event.BodySHA256 != wireDigest(string(body)) ||
		!event.SyntheticCredentialObserved ||
		!slices.Equal(event.MarkerIDs, []string{"first-marker", "second-marker"}) ||
		len(event.CloudEvents) != 1 || event.CloudEvents[0].Subject == nil ||
		event.CloudEvents[0].Subject.SHA256 != wireDigest(subject) ||
		event.CloudEvents[0].Source == nil || event.CloudEvents[0].Source.SHA256 != wireDigest(source) {
		t.Fatal("ingress lost exact body/field digests, marker IDs, or canary-positive evidence")
	}
	requireStatus(t, f.ingressRequest(t, http.MethodPost, "/reset", f.admin,
		resetBody(f.config.RunID, 1), nil), http.StatusNotFound)
	if !reflect.DeepEqual(f.state(t), state) {
		t.Fatal("plaintext reset changed authenticated HTTPS state")
	}
}

func TestIngressWhitelistOverTCP(t *testing.T) {
	f := startIngressObserver(t, nil)
	for _, tc := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodHead, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/metric", http.StatusOK},
		{http.MethodPost, "/metric", http.StatusOK},
		{http.MethodOptions, "/metric", http.StatusMethodNotAllowed},
		{http.MethodPost, "/events/alpha", http.StatusOK},
		{http.MethodGet, "/events/alpha", http.StatusMethodNotAllowed},
		{http.MethodPut, "/events/alpha", http.StatusMethodNotAllowed},
		{http.MethodGet, "/state", http.StatusNotFound},
		{http.MethodPost, "/reset", http.StatusNotFound},
		{http.MethodGet, "/state/", http.StatusNotFound},
		{http.MethodPost, "/events/ALPHA", http.StatusNotFound},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			response := f.ingressRequest(t, tc.method, tc.path, f.admin, nil, nil)
			requireStatus(t, response, tc.status)
		})
	}
	if len(f.state(t).HTTP) != 3 {
		t.Fatal("non-whitelisted ingress routes or methods became observations")
	}
}

func TestIngressPreservesAdminCertificateVerification(t *testing.T) {
	f := startIngressObserver(t, nil)
	if f.clientTLS.InsecureSkipVerify || f.clientTLS.RootCAs == nil || f.clientTLS.ServerName == "" {
		t.Fatal("admin fixture must verify its pinned certificate and DNS identity")
	}
	for _, mode := range []string{"untrusted-root", "wrong-server-name", "tls-below-minimum"} {
		t.Run(mode, func(t *testing.T) {
			config := f.clientTLS.Clone()
			switch mode {
			case "untrusted-root":
				config.RootCAs = x509.NewCertPool()
			case "wrong-server-name":
				config.ServerName = "different-observer.test"
			case "tls-below-minimum":
				config.MinVersion, config.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
			}
			client := ingressClient(t, config)
			if _, err := requestHTTP(client, http.MethodGet, f.url+"/state", f.admin, nil, nil); err == nil {
				t.Fatal("admin client bypassed its certificate or TLS-version verification")
			}
		})
	}
	requireStatus(t, f.request(t, http.MethodGet, "/state", "", nil, nil), http.StatusUnauthorized)
	if f.state(t).Generation != 1 {
		t.Fatal("valid pinned HTTPS admin access failed after rejected TLS handshakes")
	}
}
