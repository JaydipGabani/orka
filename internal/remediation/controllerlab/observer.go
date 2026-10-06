package controllerlab

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// These types mirror cmd/orka-remediation-observer/{config,http,resp,evidence}.
// No response type can contain captured bodies, headers, passwords or commands
// with arguments. Strict decoding rejects additions rather than retaining them.
type FieldEvidence struct {
	SHA256    string   `json:"sha256"`
	MarkerIDs []string `json:"markerIDs"`
}

type CloudEventEvidence struct {
	Subject *FieldEvidence `json:"subject,omitempty"`
	Source  *FieldEvidence `json:"source,omitempty"`
}

type HTTPObservation struct {
	Route                       string               `json:"route"`
	BodySHA256                  string               `json:"bodySHA256"`
	MarkerIDs                   []string             `json:"markerIDs"`
	CloudEvents                 []CloudEventEvidence `json:"cloudEvents"`
	CloudEventsTruncated        bool                 `json:"cloudEventsTruncated"`
	SyntheticCredentialObserved bool                 `json:"syntheticCredentialObserved"`
	TLSDataIngress              bool                 `json:"tlsDataIngress,omitempty"`
}

type RESPObservation struct {
	Command                     string `json:"command"`
	SyntheticCredentialObserved bool   `json:"syntheticCredentialObserved"`
}

type Observation struct {
	SchemaVersion            string            `json:"schemaVersion"`
	RunID                    string            `json:"runID"`
	Generation               uint64            `json:"generation"`
	HTTP                     []HTTPObservation `json:"http"`
	RESP                     []RESPObservation `json:"resp"`
	DroppedHTTP              uint64            `json:"droppedHTTP"`
	DroppedRESP              uint64            `json:"droppedRESP"`
	RejectedHTTPConnections  uint64            `json:"rejectedHTTPConnections"`
	RejectedRESPConnections  uint64            `json:"rejectedRESPConnections"`
	DuplicateHTTP            uint64            `json:"duplicateHTTP,omitempty"`
	RejectedAdminConnections uint64            `json:"rejectedAdminConnections,omitempty"`
}

type ObserverTarget struct {
	Pod                     ObjectRef
	Credentials             ObjectRef
	NamespaceUID            types.UID
	PodIntentDigest         string
	CredentialsIntentDigest string
	OperationDigest         string
	TLSServerName           string
	PodIP                   string
	Image                   string
}

type Observer interface {
	Snapshot(context.Context, ObserverTarget) (Observation, error)
}

// PodDialer is a trusted transport boundary. Implementations must connect only
// the exact owned Pod UID/port, using pod-portforward or a fixed loopback test
// socket. It is NOT a subject-configurable URL/TCP proxy.
type PodDialer interface {
	DialPod(context.Context, ObjectRef, int32) (net.Conn, error)
}

func NewTrustedObserver(kube kubernetes.Interface, dialer PodDialer) (Observer, error) {
	if kube == nil || dialer == nil {
		return nil, failure(NeedsAdapter, "trusted-observer-transport-required")
	}
	return &wireObserver{kube: kube, dialer: dialer}, nil
}

type wireObserver struct {
	kube   kubernetes.Interface
	dialer PodDialer
}

func targetOwns(target ObserverTarget, object metav1.Object, uid types.UID, intent string) bool {
	owners := object.GetOwnerReferences()
	return object.GetUID() == uid && uid != "" && object.GetNamespace() == target.Pod.Namespace &&
		object.GetLabels()[runLabel] == target.OperationDigest[:40] &&
		object.GetAnnotations()[intentAnnotation] == intent && object.GetDeletionTimestamp() == nil &&
		len(owners) == 1 && owners[0].APIVersion == "v1" && owners[0].Kind == "Namespace" &&
		owners[0].Name == target.Pod.Namespace && owners[0].UID == target.NamespaceUID
}

func (w *wireObserver) Snapshot(ctx context.Context, target ObserverTarget) (Observation, error) {
	if !validObserverTarget(target) {
		return Observation{}, failure(InvalidState, "invalid-observer-target")
	}
	pod, err := w.kube.CoreV1().Pods(target.Pod.Namespace).Get(ctx, target.Pod.Name, metav1.GetOptions{})
	if err != nil || !targetOwns(target, pod, target.Pod.UID, target.PodIntentDigest) || !observerExecutionMatches(pod, target.Image, target.PodIP) {
		return Observation{}, failure(Infrastructure, "exact-observer-pod-unavailable")
	}
	secret, err := w.kube.CoreV1().Secrets(target.Credentials.Namespace).Get(ctx, target.Credentials.Name, metav1.GetOptions{})
	if err != nil || !targetOwns(target, secret, target.Credentials.UID, target.CredentialsIntentDigest) ||
		secret.Immutable == nil || !*secret.Immutable || !digestPattern.Match(secret.Data["admin-token"]) ||
		len(secret.Data["tls.crt"]) > 8192 {
		return Observation{}, failure(Infrastructure, "observer-admin-material-unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(secret.Data["tls.crt"]) {
		return Observation{}, failure(Infrastructure, "invalid-observer-root")
	}
	address := net.JoinHostPort(target.TLSServerName, strconv.Itoa(int(observerPort)))
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 8192,
		TLSClientConfig:     &tls.Config{RootCAs: roots, ServerName: target.TLSServerName, MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
		DialContext: func(ctx context.Context, network, destination string) (net.Conn, error) {
			if network != "tcp" || destination != address {
				return nil, failure(OutsideScope, "observer-destination-refused")
			}
			connection, err := w.dialer.DialPod(ctx, target.Pod, observerPort)
			if err != nil {
				return nil, failure(Infrastructure, "observer-dial-unavailable")
			}
			current, err := w.kube.CoreV1().Pods(target.Pod.Namespace).Get(ctx, target.Pod.Name, metav1.GetOptions{})
			if err != nil || !targetOwns(target, current, target.Pod.UID, target.PodIntentDigest) ||
				!observerExecutionMatches(current, target.Image, target.PodIP) {
				_ = connection.Close()
				return nil, failure(OwnershipLost, "observer-dial-identity-changed")
			}
			return connection, nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return failure(OutsideScope, "observer-redirect-refused")
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/state", nil)
	if err != nil {
		return Observation{}, failure(Infrastructure, "observer-request-failed")
	}
	// The actual observer wire uses this one bearer-token header. It is sent
	// inside pinned TLS to the observer, NEVER to a KAS pod/proxy request.
	request.Header.Set("X-Orka-Observer-Token", string(secret.Data["admin-token"]))
	response, err := client.Do(request)
	if err != nil {
		return Observation{}, failure(Infrastructure, "observer-state-unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return Observation{}, failure(Infrastructure, "observer-state-rejected")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	defer clear(data)
	if err != nil || len(data) > 1<<20 {
		return Observation{}, failure(Infrastructure, "invalid-observer-state")
	}
	observation, err := decodeObservation(data)
	if err != nil {
		return Observation{}, err
	}
	if err := validateObservation(observation, target.OperationDigest); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func validObserverTarget(target ObserverTarget) bool {
	return digestPattern.MatchString(target.OperationDigest) && target.Pod.Resource == pods &&
		target.Credentials.Resource == secrets && target.Credentials.Namespace == target.Pod.Namespace &&
		target.TLSServerName == serviceName+"."+target.Pod.Namespace+".svc" && target.NamespaceUID != "" &&
		privateObserverIP(target.PodIP) && imagePattern.MatchString(target.Image)
}

func decodeObservation(data []byte) (Observation, error) {
	var observation Observation
	if strictJSON(data, &observation) != nil {
		return Observation{}, failure(Infrastructure, "invalid-observer-state")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return Observation{}, failure(Infrastructure, "invalid-observer-state")
	}
	for _, name := range []string{"schemaVersion", "runID", "generation", httpScheme, "resp",
		"droppedHTTP", "droppedRESP", "rejectedHTTPConnections", "rejectedRESPConnections"} {
		if raw, ok := fields[name]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return Observation{}, failure(Infrastructure, "observer-state-field-missing")
		}
	}
	return observation, nil
}

func observerReady(pod *corev1.Pod) bool {
	if pod == nil || pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil ||
		len(pod.Status.ContainerStatuses) != 1 {
		return false
	}
	status := pod.Status.ContainerStatuses[0]
	return status.Name == serviceName && status.Ready && status.RestartCount == 0 && status.State.Running != nil
}

func validateObservation(o Observation, operation string) error {
	if !validObservationEnvelope(o, operation) {
		return failure(Infrastructure, "observer-evidence-incomplete")
	}
	markers := func(ids []string) bool {
		if len(ids) > 4 {
			return false
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if seen[id] || !slices.Contains([]string{"initial-0", "initial-1", "final-0", "final-1", credentialFinalMarkerID}, id) {
				return false
			}
			seen[id] = true
		}
		return true
	}
	field := func(e *FieldEvidence) bool {
		return e == nil || digestPattern.MatchString(e.SHA256) && markers(e.MarkerIDs)
	}
	for _, h := range o.HTTP {
		if !slices.Contains([]string{httpARoute, httpBRoute, metricRoute,
			gridARoute, gridBRoute, gridCredentialAttackRoute, clusterHTTPRoute}, h.Route) ||
			!digestPattern.MatchString(h.BodySHA256) || !markers(h.MarkerIDs) ||
			len(h.CloudEvents) > 16 || h.CloudEventsTruncated {
			return failure(Infrastructure, "invalid-http-evidence")
		}
		for _, e := range h.CloudEvents {
			if !field(e.Subject) || !field(e.Source) {
				return failure(Infrastructure, "invalid-cloudevent-evidence")
			}
		}
	}
	for _, r := range o.RESP {
		if !slices.Contains([]string{"AUTH", "HELLO", "PING", "CLIENT", "SELECT", "UNKNOWN"}, r.Command) {
			return failure(Infrastructure, "invalid-resp-evidence")
		}
	}
	return nil
}

func validObservationEnvelope(o Observation, operation string) bool {
	return o.SchemaVersion == "v1" && o.RunID == operation && o.Generation == 1 &&
		o.HTTP != nil && o.RESP != nil && len(o.HTTP) <= 256 && len(o.RESP) <= 256 &&
		o.DroppedHTTP == 0 && o.DroppedRESP == 0 && o.RejectedHTTPConnections == 0 &&
		o.RejectedRESPConnections == 0 && o.RejectedAdminConnections == 0 && o.DuplicateHTTP != ^uint64(0)
}
