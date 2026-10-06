package controllerlab

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestPublishingGeneratedPublicTrustVerifiesExactTLSDataIdentity(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingInitial)
	private, err := l.kube.CoreV1().Secrets(s.ObserverNamespace).Get(context.Background(), adminSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(private.Data["tls.crt"], private.Data["tls.key"])
	require.NoError(t, err)
	trust, err := l.kube.CoreV1().ConfigMaps(s.Namespaces[0]).Get(context.Background(), observerTrustName, metav1.GetOptions{})
	require.NoError(t, err)
	key, err := l.kube.CoreV1().Secrets(s.Namespaces[0]).Get(context.Background(), canaryName, metav1.GetOptions{})
	require.NoError(t, err)
	source, err := l.custom.Resource(cloudEventSources).Namespace(s.Namespaces[0]).Get(context.Background(), "scope-grid-source", metav1.GetOptions{})
	require.NoError(t, err)
	endpoint, found, err := unstructured.NestedString(source.Object, "spec", "destination", "azureEventGridTopic", "endpoint")
	require.NoError(t, err)
	require.True(t, found)
	destination, err := url.Parse(endpoint)
	require.NoError(t, err)
	var requests atomic.Int32
	var matched atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		matched.Store(request.TLS != nil && request.Method == http.MethodPost && request.URL.Path == "/events/grid-a" &&
			request.URL.Query().Get("api-version") == "2018-01-01" &&
			request.Header.Get("X-Orka-Observer-Token") == "" &&
			bytesDigest([]byte(request.Header.Get("Aeg-Sas-Key"))) == bytesDigest(key.Data["key"]))
		_, _ = io.Copy(io.Discard, request.Body)
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM([]byte(trust.Data["ca.crt"])))
	for _, mode := range []string{"trusted", "wrong-root", "wrong-name"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &tls.Config{RootCAs: roots, ServerName: observerDNS(s), MinVersion: tls.VersionTLS12}
			switch mode {
			case "wrong-root":
				cfg.RootCAs = x509.NewCertPool()
			case "wrong-name":
				cfg.ServerName = "not-the-owned-observer.invalid"
			}
			transport := &http.Transport{
				Proxy: nil, DisableKeepAlives: true, TLSClientConfig: cfg,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					if network != "tcp" || address != destination.Host {
						return nil, errors.New("non-fixture destination refused")
					}
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				},
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
			request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint+"?api-version=2018-01-01", strings.NewReader("[]"))
			require.NoError(t, err)
			request.Header.Set("Aeg-Sas-Key", string(key.Data["key"]))
			request.Header.Set("Content-Type", "application/cloudevents-batch+json; charset=utf-8")
			before := requests.Load()
			response, err := client.Do(request)
			if mode != "trusted" {
				require.Error(t, err)
				require.Equal(t, before, requests.Load(), "untrusted TLS must fail before the header is emitted")
				return
			}
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, http.StatusOK, response.StatusCode)
			require.True(t, matched.Load())
		})
	}
	r.Cancel = true
	_ = l.until(t, s, r, State.Terminal)
}

func TestPublishingTLSReceiptMirrorRequiresTypedTransportAndHeaderEvidence(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	s := l.phase(t, l.request(Candidate), ObservingInitial)
	// This is the digest-only shape emitted by the observer command's real
	// TLS data listener; protocol tests in that package exercise its creation.
	wire := Observation{SchemaVersion: "v1", RunID: s.OperationDigest, Generation: 1,
		HTTP: []HTTPObservation{observedEvent(s, 0, false, 0)}, RESP: []RESPObservation{}}
	wire.HTTP[0].Route = "/events/grid-a"
	wire.HTTP[0].TLSDataIngress = true
	wire.HTTP[0].SyntheticCredentialObserved = true
	raw, err := json.Marshal(wire)
	require.NoError(t, err)
	decoded, err := decodeObservation(raw)
	require.NoError(t, err)
	require.NoError(t, validateObservation(decoded, s.OperationDigest))
	require.NoError(t, incorporate(&s, decoded))
	require.True(t, s.Evidence.Publishing.InitialHTTPS[0])
	for _, mutation := range []string{`"tlsDataIngress":"true"`, `"rawHeader":"forbidden"`, `"tlsDataIngress":true,"tlsDataIngress":true`} {
		h := `{"route":"/events/grid-a","bodySHA256":"` + bytesDigest(nil) + `",` + mutation + `}`
		_, err := decodeObservation([]byte(`{"schemaVersion":"v1","runID":"` + s.OperationDigest +
			`","generation":1,"http":[` + h + `],"resp":[],"droppedHTTP":0,"droppedRESP":0,"rejectedHTTPConnections":0,"rejectedRESPConnections":0}`))
		require.Error(t, err)
	}
}
