package environment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func freshAPIServer(t *testing.T, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic TLS key generation failed")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal("synthetic TLS serial generation failed")
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "synthetic-lab"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("synthetic TLS certificate generation failed")
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: key}},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
}

func writeSyntheticKubeconfig(t *testing.T, path, endpoint string, ca []byte, credential string) {
	t.Helper()
	config := clientcmdapi.Config{
		Clusters:       map[string]*clientcmdapi.Cluster{"lab": {Server: endpoint, CertificateAuthorityData: ca}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"observer": {Token: credential}},
		Contexts:       map[string]*clientcmdapi.Context{"approved": {Cluster: "lab", AuthInfo: "observer"}},
		CurrentContext: "deliberately-not-used",
	}
	data, err := clientcmd.Write(config)
	if err != nil || os.WriteFile(path, data, 0600) != nil {
		t.Fatal("private synthetic kubeconfig creation failed")
	}
}

func TestPublicNewAuthenticatesStableLabIdentityAcrossCredentialRotation(t *testing.T) {
	var authorized atomic.Bool
	var clusterUID atomic.Value
	clusterUID.Store("synthetic-first-cluster")
	server, ca := freshAPIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorized.Load() || r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/kube-system" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: namespaceKind},
			ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(clusterUID.Load().(string))},
		}); err != nil {
			t.Error("synthetic API response failed")
		}
	}))
	f := testFixture(t)
	kubeconfig := filepath.Join(f.root, "approved-kubeconfig")
	writeSyntheticKubeconfig(t, kubeconfig, server.URL, ca, "synthetic-fixture-credential-one")
	f.config.Kubernetes = &KubernetesConfig{
		Kubeconfig: kubeconfig, Context: "approved", ObserverCIDRs: []string{"192.0.2.1/32"},
	}
	_, err := New(f.config)
	assertKind(t, err, NeedsAdapter)
	authorized.Store(true)
	first, err := New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	writeSyntheticKubeconfig(t, kubeconfig, server.URL, ca, "synthetic-fixture-credential-two")
	second, err := New(f.config)
	if err != nil || first.clusterIdentity != second.clusterIdentity {
		t.Fatal("credential rotation changed the stable authenticated lab identity")
	}
	clusterUID.Store("synthetic-replacement-cluster")
	replacement, err := New(f.config)
	if err != nil || replacement.clusterIdentity == first.clusterIdentity {
		t.Fatal("replacement lab inherited the old cluster identity")
	}
}
