package controllerlab

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	httpstreamspdy "k8s.io/streaming/pkg/httpstream/spdy"
)

type podForwardDialer struct {
	config *rest.Config
	kube   kubernetes.Interface
}

func newPodForwardDialer(config *rest.Config, kube kubernetes.Interface) (PodDialer, error) {
	if config == nil || kube == nil {
		return nil, failure(NeedsAdapter, "pod-forward-config-required")
	}
	return &podForwardDialer{config: rest.CopyConfig(config), kube: kube}, nil
}

func (p *podForwardDialer) DialPod(ctx context.Context, pod ObjectRef, port int32) (net.Conn, error) {
	if pod.Resource != pods || pod.UID == "" || port != observerPort {
		return nil, failure(OutsideScope, "pod-forward-target-refused")
	}
	check := func() bool {
		actual, err := p.kube.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		return err == nil && actual.UID == pod.UID && observerReady(actual)
	}
	if !check() {
		return nil, failure(OwnershipLost, "pod-forward-uid-changed")
	}
	config := rest.CopyConfig(p.config)
	dial := config.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	tlsConfig, err := rest.TLSConfigFor(config)
	if err != nil {
		return nil, failure(Infrastructure, "pod-forward-tls-unavailable")
	}
	if tlsConfig == nil {
		// A nil TLS config in the SDK's UpgradeTransport path disables peer
		// verification. Supply a real config even when using system roots.
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	upgradeTransport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
		connection, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return bindConnection(ctx, connection), nil
	}}
	upgrader, err := httpstreamspdy.NewRoundTripperWithConfig(httpstreamspdy.RoundTripperConfig{UpgradeTransport: upgradeTransport})
	if err != nil {
		return nil, failure(Infrastructure, "pod-forward-transport-unavailable")
	}
	transport, err := rest.HTTPWrappersForConfig(config, upgrader)
	if err != nil {
		return nil, failure(Infrastructure, "pod-forward-transport-unavailable")
	}
	url := p.kube.CoreV1().RESTClient().Post().Resource("pods").Namespace(pod.Namespace).Name(pod.Name).SubResource("portforward").URL()
	client := &http.Client{
		Transport: forwardTransport{context: ctx, base: transport},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return failure(OutsideScope, "pod-forward-redirect-refused")
		},
	}
	dialer := spdy.NewDialer(spdy.NewUpgraderForStreaming(upgrader), client, http.MethodPost, url)
	stop, ready, ended := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	forward, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{"0:" + strconv.Itoa(int(port))},
		stop, ready, io.Discard, io.Discard)
	if err != nil {
		return nil, failure(Infrastructure, "pod-forward-unavailable")
	}
	var once sync.Once
	closeForward := func() { once.Do(func() { close(stop) }) }
	go func() { ended <- forward.ForwardPorts() }()
	go func() {
		select {
		case <-ctx.Done():
			closeForward()
		case <-stop:
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		closeForward()
		return nil, failure(Infrastructure, "pod-forward-cancelled")
	case <-ended:
		closeForward()
		return nil, failure(Infrastructure, "pod-forward-unavailable")
	}
	ports, err := forward.GetPorts()
	if err != nil || len(ports) != 1 || !check() {
		closeForward()
		return nil, failure(OwnershipLost, "pod-forward-identity-unavailable")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(ports[0].Local))))
	if err != nil || !check() {
		if connection != nil {
			_ = connection.Close()
		}
		closeForward()
		return nil, failure(Infrastructure, "pod-forward-connection-unavailable")
	}
	return &forwardedConn{Conn: connection, closeForward: closeForward}, nil
}

type forwardedConn struct {
	net.Conn
	closeForward func()
}

// The SPDY dialer constructs its own HTTP request. Bind the upgrade itself to
// the Step deadline, not only the local listener, so cancellation cannot leave
// a blocked API-server upgrade goroutine behind.
type forwardTransport struct {
	context context.Context
	base    http.RoundTripper
}

// SPDY performs raw reads during HTTP upgrade, outside net/http's usual request
// cancellation. Closing the actual API-server connection fences those reads as
// well as the established tunnel to the Step lifetime.
type contextConnection struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func bindConnection(ctx context.Context, connection net.Conn) net.Conn {
	bound := &contextConnection{Conn: connection, done: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = bound.Close()
		case <-bound.done:
		}
	}()
	return bound
}

func (c *contextConnection) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

func (t forwardTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(r.WithContext(t.context))
}

func (c *forwardedConn) Close() error {
	err := c.Conn.Close()
	c.closeForward()
	return err
}
