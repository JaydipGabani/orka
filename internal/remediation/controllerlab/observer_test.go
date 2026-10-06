package controllerlab

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type loopbackDialer struct {
	address string
	target  ObjectRef
	calls   atomic.Int32
}

func (d *loopbackDialer) DialPod(ctx context.Context, pod ObjectRef, port int32) (net.Conn, error) {
	host, _, err := net.SplitHostPort(d.address)
	if err != nil || !net.ParseIP(host).IsLoopback() || pod != d.target || port != observerPort {
		return nil, errors.New("unapproved loopback target")
	}
	d.calls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.address)
}

func wireTarget(t *testing.T, l *testLab, s State) ObserverTarget {
	t.Helper()
	pod := receiptFor(s, ref(pods, s.ObserverNamespace, serviceName))
	secret := receiptFor(s, ref(secrets, s.ObserverNamespace, adminSecretName))
	namespace := receiptFor(s, ref(namespaces, "", s.ObserverNamespace))
	require.NotNil(t, pod)
	require.NotNil(t, secret)
	require.NotNil(t, namespace)
	return ObserverTarget{
		Pod: pod.Object, Credentials: secret.Object, NamespaceUID: namespace.Object.UID,
		PodIntentDigest: pod.IntentDigest, CredentialsIntentDigest: secret.IntentDigest,
		OperationDigest: s.OperationDigest, TLSServerName: observerDNS(s),
		PodIP: s.ObserverPodIP, Image: l.config.ObserverImage,
	}
}

func TestTrustedObserverUsesActualDigestOnlyWireAndPinnedTLS(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	s := l.phase(t, l.request(Candidate), WaitingRuntime)
	target := wireTarget(t, l, s)
	secret, err := l.kube.CoreV1().Secrets(target.Credentials.Namespace).Get(context.Background(), target.Credentials.Name, metav1.GetOptions{})
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
	require.NoError(t, err)
	adminDigest := bytesDigest(secret.Data["admin-token"])
	var authenticated atomic.Bool
	state := Observation{
		SchemaVersion: "v1", RunID: s.OperationDigest, Generation: 1,
		HTTP: []HTTPObservation{observedEvent(s, 0, false, 0)},
		RESP: []RESPObservation{{Command: "AUTH", SyntheticCredentialObserved: true}, {Command: "HELLO", SyntheticCredentialObserved: false}},
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/state" || r.Header.Get("Authorization") != "" ||
			bytesDigest([]byte(r.Header.Get("X-Orka-Observer-Token"))) != adminDigest {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		authenticated.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	dialer := &loopbackDialer{address: server.Listener.Addr().String(), target: target.Pod}
	observer, err := NewTrustedObserver(l.kube, dialer)
	require.NoError(t, err)
	actual, err := observer.Snapshot(context.Background(), target)
	require.NoError(t, err)
	require.True(t, authenticated.Load())
	require.Equal(t, 1, int(dialer.calls.Load()))
	require.Equal(t, state, actual)
	require.True(t, actual.RESP[0].SyntheticCredentialObserved)
	require.Equal(t, "AUTH", actual.RESP[0].Command)
	for _, action := range l.kube.Actions() {
		require.NotEqual(t, "proxy", action.GetSubresource())
	}
}

func TestObserverRejectsUntrustedRootsBeforeSendingAdminToken(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	s := l.phase(t, l.request(Candidate), WaitingRuntime)
	target := wireTarget(t, l, s)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	observer, err := NewTrustedObserver(l.kube, &loopbackDialer{address: server.Listener.Addr().String(), target: target.Pod})
	require.NoError(t, err)
	_, err = observer.Snapshot(context.Background(), target)
	require.Error(t, err)
	require.Zero(t, requests.Load())
	require.NotContains(t, err.Error(), server.URL)
}

func TestObserverWireRejectsRedirectsOversizeRawAndDuplicateFields(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"redirect", "oversize", "raw-field", "duplicate-field", "missing-counter", "null-counter", "unauthorized"} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			s := l.phase(t, l.request(Candidate), WaitingRuntime)
			target := wireTarget(t, l, s)
			secret, err := l.kube.CoreV1().Secrets(target.Credentials.Namespace).Get(context.Background(), target.Credentials.Name, metav1.GetOptions{})
			require.NoError(t, err)
			certificate, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
			require.NoError(t, err)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch variant {
				case "redirect":
					http.Redirect(w, r, "https://other.invalid/state", http.StatusTemporaryRedirect)
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat("x", (1<<20)+1))
				case "raw-field":
					_, _ = io.WriteString(w, `{"schemaVersion":"v1","rawCredential":"forbidden"}`)
				case "duplicate-field":
					_, _ = io.WriteString(w, `{"schemaVersion":"v1","SchemaVersion":"v1"}`)
				case "missing-counter", "null-counter":
					value, _ := json.Marshal(Observation{
						SchemaVersion: "v1", RunID: s.OperationDigest, Generation: 1,
						HTTP: []HTTPObservation{}, RESP: []RESPObservation{},
					})
					var fields map[string]any
					_ = json.Unmarshal(value, &fields)
					if variant == "missing-counter" {
						delete(fields, "droppedHTTP")
					} else {
						fields["droppedHTTP"] = nil
					}
					_ = json.NewEncoder(w).Encode(fields)
				case "unauthorized":
					http.Error(w, "no", http.StatusUnauthorized)
				}
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			dialer := &loopbackDialer{address: server.Listener.Addr().String(), target: target.Pod}
			observer, err := NewTrustedObserver(l.kube, dialer)
			require.NoError(t, err)
			_, err = observer.Snapshot(context.Background(), target)
			require.Error(t, err)
			require.LessOrEqual(t, dialer.calls.Load(), int32(1))
			require.False(t, strings.Contains(err.Error(), string(secret.Data["admin-token"])))
			require.NotContains(t, err.Error(), "other.invalid")
		})
	}
}

func TestObserverUIDAndSecretUIDAreMandatoryTransportPreconditions(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	s := l.phase(t, l.request(Candidate), WaitingRuntime)
	target := wireTarget(t, l, s)
	dialer := &loopbackDialer{address: "127.0.0.1:1", target: target.Pod}
	observer, err := NewTrustedObserver(l.kube, dialer)
	require.NoError(t, err)
	for _, variant := range []string{"pod", "secret", "server-name", "namespace", "restart"} {
		changed := target
		switch variant {
		case "pod":
			changed.Pod.UID = "replacement"
		case "secret":
			changed.Credentials.UID = "replacement"
		case "server-name":
			changed.TLSServerName = "external.invalid"
		case "namespace":
			changed.NamespaceUID = "replacement"
		case "restart":
			pod, err := l.kube.CoreV1().Pods(target.Pod.Namespace).Get(context.Background(), target.Pod.Name, metav1.GetOptions{})
			require.NoError(t, err)
			pod.Status.ContainerStatuses[0].RestartCount = 1
			require.NoError(t, l.kube.Tracker().Update(pods, pod, pod.Namespace))
		}
		_, err := observer.Snapshot(context.Background(), changed)
		require.Error(t, err)
	}
	require.Zero(t, dialer.calls.Load())
}

func TestPortForwardUpgradeHonorsContextAndNeverUsesPodProxy(t *testing.T) {
	t.Parallel()
	started, finished := make(chan struct{}), make(chan struct{})
	var wrongPath atomic.Bool
	var adminForwarded atomic.Bool
	pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: "owned-lab", UID: "pinned-pod"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: serviceName, Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "/api/v1/namespaces/owned-lab/pods/observer"
		if r.Header.Get("X-Orka-Observer-Token") != "" {
			adminForwarded.Store(true)
		}
		if r.Method == http.MethodGet && r.URL.Path == base {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pod)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != base+"/portforward" {
			wrongPath.Store(true)
			http.Error(w, "refused", http.StatusNotFound)
			return
		}
		close(started)
		<-r.Context().Done()
		close(finished)
	}))
	defer func() {
		server.CloseClientConnections()
		server.Close()
	}()
	config := &rest.Config{
		Host: server.URL, TLSClientConfig: rest.TLSClientConfig{
			CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		},
	}
	kube, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)
	dialer, err := newPodForwardDialer(config, kube)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := dialer.DialPod(ctx, ObjectRef{Resource: pods, Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}, observerPort)
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		require.FailNow(t, "port-forward upgrade was not attempted")
	}
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		require.FailNow(t, "port-forward did not cancel")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		require.FailNow(t, "API upgrade request outlived its context")
	}
	require.False(t, wrongPath.Load())
	require.False(t, adminForwarded.Load())
}

func TestProductionConstructorIsOfflineAndLabClientRefusesRedirects(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	var requests, redirected atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/unexpected" {
			redirected.Add(1)
			http.Error(w, "unexpected", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/unexpected", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	adapter, err := NewForConfig(l.config, &rest.Config{
		Host: server.URL, TLSClientConfig: rest.TLSClientConfig{
			CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		},
	}, l.journal.hooks())
	require.NoError(t, err)
	require.Zero(t, requests.Load())
	state, err := adapter.Step(context.Background(), State{}, l.request(Candidate))
	require.NoError(t, err)
	require.Zero(t, requests.Load())
	state, err = adapter.Step(context.Background(), state, l.request(Candidate))
	require.Error(t, err)
	require.Equal(t, Inconclusive, state.Outcome)
	require.Equal(t, int32(1), requests.Load())
	require.Zero(t, redirected.Load())
}
