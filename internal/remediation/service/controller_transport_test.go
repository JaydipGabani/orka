package service

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestControllerProbeClientRefusesRedirectsAndAmbientProxy(t *testing.T) {
	t.Parallel()
	var redirected, proxied atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	t.Cleanup(destination.Close)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	config := &rest.Config{
		Host: server.URL, Timeout: time.Second,
		TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})},
		Proxy: func(*http.Request) (*url.URL, error) {
			proxied.Add(1)
			return url.Parse(destination.URL)
		},
	}
	client, err := controllerKubeClient(config)
	require.NoError(t, err)
	_, err = client.CoreV1().Namespaces().Get(t.Context(), "kube-system", metav1.GetOptions{})
	require.Error(t, err)
	require.Zero(t, redirected.Load())
	require.Zero(t, proxied.Load())
}
