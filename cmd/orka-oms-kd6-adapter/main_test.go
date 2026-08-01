package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	testKD6EndpointFlag  = "--kd6-endpoint"
	testStoreMappingFlag = "--store-mapping"
	testKD6Endpoint      = "https://kd6.example"
	testTLSServerName    = "adapter.test"
)

func TestParseOptionsRequiresStoreMappingAndTLS(t *testing.T) {
	if _, err := parseOptions([]string{testKD6EndpointFlag, testKD6Endpoint}); err == nil {
		t.Fatal("missing store mapping was accepted")
	}
	if _, err := parseOptions([]string{
		testKD6EndpointFlag, testKD6Endpoint, testStoreMappingFlag, "memory=store-1", "--tls-cert-file", "cert.pem",
	}); err == nil {
		t.Fatal("partial TLS configuration was accepted")
	}
	if _, err := parseOptions([]string{
		testKD6EndpointFlag, testKD6Endpoint, testStoreMappingFlag, "memory=store-1",
	}); err == nil {
		t.Fatal("missing TLS configuration was accepted")
	}
	if _, err := parseOptions([]string{
		testKD6EndpointFlag, testKD6Endpoint, testStoreMappingFlag, "memory=store-1",
		"--tls-cert-file", "cert.pem", "--tls-key-file", "key.pem", "--tls-reload-interval", "10ms",
	}); err == nil {
		t.Fatal("unsafe TLS reload interval was accepted")
	}
	options, err := parseOptions([]string{
		testKD6EndpointFlag, testKD6Endpoint, testStoreMappingFlag, "memory=store-1",
		testStoreMappingFlag, "archive=store-2", "--control-db", "/tmp/control.db",
		"--tls-cert-file", "cert.pem", "--tls-key-file", "key.pem",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(options.storeMappings) != 2 || options.storeMappings["memory"] != "store-1" {
		t.Fatalf("store mappings = %#v", options.storeMappings)
	}
	if options.enableConformanceFailpoints {
		t.Fatal("conformance failpoints were enabled by default")
	}
	enabled, err := parseOptions([]string{
		testKD6EndpointFlag, testKD6Endpoint, testStoreMappingFlag, "memory=store-1",
		"--tls-cert-file", "cert.pem", "--tls-key-file", "key.pem", "--enable-conformance-failpoints",
	})
	if err != nil || !enabled.enableConformanceFailpoints {
		t.Fatalf("explicit conformance failpoint option = %#v, err = %v", enabled, err)
	}
}

func TestBearerTokenProviderReloadsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ORKA_TEST_TOKEN", "env-secret")
	provider, err := newBearerTokenProvider(path, "test-token-file", "ORKA_TEST_TOKEN", "test bearer token")
	if err != nil {
		t.Fatal(err)
	}
	value, err := provider.BearerToken()
	if err != nil || value != "file-secret" {
		t.Fatalf("BearerToken() = %q, %v", value, err)
	}
	if err := os.WriteFile(path, []byte("rotated-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err = provider.BearerToken()
	if err != nil || value != "rotated-secret" {
		t.Fatalf("BearerToken() after rotation = %q, %v", value, err)
	}
}

func TestNewHTTPServerUsesHardenedTimeouts(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t, 1)
	options := options{
		listenAddr: ":0", controlDB: "/tmp/control.db", kd6Endpoint: testKD6Endpoint,
		storeMappings: stringMapFlag{"memory": "store-1"}, tlsCertFile: certFile, tlsKeyFile: keyFile,
		tlsReloadInterval: time.Second,
	}
	server, err := newHTTPServer(options, http.NewServeMux())
	if err != nil {
		t.Fatal(err)
	}
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 ||
		server.IdleTimeout <= 0 || server.TLSConfig == nil || server.TLSConfig.GetCertificate == nil ||
		!server.TLSConfig.SessionTicketsDisabled {
		t.Fatalf("server = %#v", server)
	}
}

func TestTLSCertificateReloadCannotBeBypassedBySessionResumption(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t, 1)
	server, err := newHTTPServer(options{
		listenAddr: "127.0.0.1:0", controlDB: "/tmp/control.db", kd6Endpoint: testKD6Endpoint,
		storeMappings: stringMapFlag{"memory": "store-1"}, tlsCertFile: certFile, tlsKeyFile: keyFile,
		tlsReloadInterval: minTLSReloadInterval,
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.ServeTLS(listener, "", "") }()

	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, // Test-only self-signed certificate.
		ServerName:         testTLSServerName, ClientSessionCache: tls.NewLRUClientSessionCache(1),
	}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	endpoint := "https://" + listener.Addr().String()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatalf("initial TLS request: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.TLS == nil || response.TLS.DidResume {
		t.Fatalf("initial TLS state = %#v", response.TLS)
	}

	if err := os.WriteFile(certFile, []byte("invalid certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("invalid key"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * minTLSReloadInterval)
	transport.CloseIdleConnections()
	if resumed, requestErr := client.Get(endpoint); requestErr == nil {
		_ = resumed.Body.Close()
		t.Fatalf(
			"request unexpectedly succeeded after certificate reload failed; TLS resumed=%v",
			resumed.TLS != nil && resumed.TLS.DidResume,
		)
	}
}

func TestCertificateReloaderUsesRotatedCertificateAfterBoundedCache(t *testing.T) {
	directory := t.TempDir()
	certFile := filepath.Join(directory, "tls.crt")
	keyFile := filepath.Join(directory, "tls.key")
	writeTestCertificateFiles(t, certFile, keyFile, 1)
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	reloader, err := newCertificateReloader(certFile, keyFile, time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	initial, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	writeTestCertificateFiles(t, certFile, keyFile, 2)
	cached, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if certificateSerial(t, cached).Cmp(certificateSerial(t, initial)) != 0 {
		t.Fatal("certificate cache was not bounded by the configured reload interval")
	}
	now = now.Add(time.Second)
	rotated, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if certificateSerial(t, rotated).Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("rotated certificate serial = %s, want 2", certificateSerial(t, rotated))
	}
}

func writeTestCertificate(t *testing.T, serial int64) (string, string) {
	t.Helper()
	directory := t.TempDir()
	certFile := filepath.Join(directory, "tls.crt")
	keyFile := filepath.Join(directory, "tls.key")
	writeTestCertificateFiles(t, certFile, keyFile, serial)
	return certFile, keyFile
}

func writeTestCertificateFiles(t *testing.T, certFile, keyFile string, serial int64) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: testTLSServerName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{testTLSServerName},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	if err := os.WriteFile(certFile, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	if err := os.WriteFile(keyFile, privateKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func certificateSerial(t *testing.T, certificate *tls.Certificate) *big.Int {
	t.Helper()
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return parsed.SerialNumber
}
