package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type trackedListener struct {
	net.Listener
	mu       sync.Mutex
	stopping bool
	active   map[*trackedConn]struct{}
	slots    chan struct{}
	reject   func()
}

type trackedConn struct {
	net.Conn
	owner *trackedListener
	once  sync.Once
}

func trackListener(listener net.Listener, slots chan struct{}, reject func()) *trackedListener {
	return &trackedListener{
		Listener: listener, slots: slots, reject: reject, active: make(map[*trackedConn]struct{}),
	}
}

func (l *trackedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		if l.stopping {
			l.mu.Unlock()
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		select {
		case l.slots <- struct{}{}:
			tracked := &trackedConn{Conn: conn, owner: l}
			l.active[tracked] = struct{}{}
			l.mu.Unlock()
			return tracked, nil
		default:
			l.mu.Unlock()
			_ = conn.Close()
			l.reject()
		}
	}
}

func (l *trackedListener) Close() error {
	l.mu.Lock()
	l.stopping = true
	l.mu.Unlock()
	return l.Listener.Close()
}

func (l *trackedListener) closeConnections() {
	l.mu.Lock()
	connections := make([]*trackedConn, 0, len(l.active))
	for conn := range l.active {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (c *trackedConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.active, c)
		<-c.owner.slots
		c.owner.mu.Unlock()
	})
	return err
}

type runningServer struct {
	observer     *observer
	http         *http.Server
	httpLn       *trackedListener
	ingress      *http.Server
	ingressLn    *trackedListener
	ingressTLS   *http.Server
	ingressTLSLn *trackedListener
	respLn       *trackedListener
	cancel       context.CancelFunc
	servers      sync.WaitGroup
	clients      sync.WaitGroup
	failures     chan struct{}
}

func startServer(cfg config) (*runningServer, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	canary, err := parseDigest(cfg.SyntheticCanarySHA256)
	if err != nil {
		return nil, err
	}
	admin, err := loadAdminDigest(cfg.AdminTokenFile, canary)
	if err != nil {
		return nil, err
	}
	for _, pin := range cfg.ChannelCanaries {
		if pin.SHA256 == hex.EncodeToString(admin[:]) {
			return nil, errors.New("admin token must be separate from every synthetic channel canary")
		}
	}
	tlsConfig, err := loadTLS(cfg.TLS)
	if err != nil {
		return nil, err
	}
	httpLn, err := net.Listen("tcp", cfg.HTTPAddress)
	if err != nil {
		return nil, errors.New("HTTP listener could not start")
	}
	var respLn net.Listener
	if cfg.RESPAddress != "" {
		respLn, err = net.Listen("tcp", cfg.RESPAddress)
		if err != nil {
			_ = httpLn.Close()
			return nil, errors.New("RESP listener could not start")
		}
	}
	var ingressLn net.Listener
	if cfg.IngressHTTPAddress != "" {
		ingressLn, err = net.Listen("tcp", cfg.IngressHTTPAddress)
		if err != nil {
			_ = httpLn.Close()
			if respLn != nil {
				_ = respLn.Close()
			}
			return nil, errors.New("ingress HTTP listener could not start")
		}
	}
	var ingressTLSLn net.Listener
	if cfg.IngressHTTPSAddress != "" {
		ingressTLSLn, err = net.Listen("tcp", cfg.IngressHTTPSAddress)
		if err != nil {
			_ = httpLn.Close()
			if respLn != nil {
				_ = respLn.Close()
			}
			if ingressLn != nil {
				_ = ingressLn.Close()
			}
			return nil, errors.New("ingress HTTPS listener could not start")
		}
	}
	return serveListeners(newObserver(cfg, admin, canary), httpLn, respLn, ingressLn, ingressTLSLn, tlsConfig), nil
}

func loadTLS(files tlsFiles) (*tls.Config, error) {
	if files.CertFile == "" {
		return nil, nil
	}
	cert, err := readBoundedFile(files.CertFile, maxConfigBytes, false)
	if err != nil {
		return nil, errors.New("TLS certificate could not be read")
	}
	defer clear(cert)
	key, err := readBoundedFile(files.KeyFile, maxConfigBytes, true)
	if err != nil {
		return nil, errors.New("TLS private key could not be read")
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, errors.New("TLS certificate and key are invalid")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
}

func serveListeners(
	o *observer, httpLn, respLn, ingressLn, ingressTLSLn net.Listener, tlsConfig *tls.Config,
) *runningServer {
	ctx, cancel := context.WithCancel(context.Background())
	// Publishing data cannot occupy the administrative pool used to collect
	// evidence. Legacy listener accounting remains unchanged.
	httpSlots := make(chan struct{}, o.config.Limits.HTTPConnections)
	rejectHTTP := func() { o.store.rejectedConnection(false) }
	adminSlots, rejectAdmin := httpSlots, rejectHTTP
	if o.config.HTTPSetEvidence {
		adminSlots = make(chan struct{}, adminConnections)
		rejectAdmin = o.store.rejectedAdminConnection
	}
	server := &runningServer{
		observer: o, cancel: cancel, failures: make(chan struct{}, 4),
		httpLn: trackListener(httpLn, adminSlots, rejectAdmin),
	}
	server.http = o.newHTTPServer(ctx, o)
	var servingHTTP net.Listener = server.httpLn
	if tlsConfig != nil {
		servingHTTP = tls.NewListener(servingHTTP, tlsConfig)
	}
	server.servers.Go(func() { server.serveHTTP(server.http, servingHTTP) })
	if ingressLn != nil {
		server.ingressLn = trackListener(ingressLn, httpSlots, rejectHTTP)
		server.ingress = o.newHTTPServer(ctx, http.HandlerFunc(o.serveIngressHTTP))
		// Keep net/http's implicit OPTIONS * response outside the data-only whitelist.
		server.ingress.DisableGeneralOptionsHandler = true
		server.servers.Go(func() { server.serveHTTP(server.ingress, server.ingressLn) })
	}
	if ingressTLSLn != nil {
		server.ingressTLSLn = trackListener(ingressTLSLn, httpSlots, rejectHTTP)
		server.ingressTLS = o.newHTTPServer(ctx, http.HandlerFunc(o.serveIngressHTTPS))
		server.ingressTLS.DisableGeneralOptionsHandler = true
		server.servers.Go(func() {
			server.serveHTTP(server.ingressTLS, tls.NewListener(server.ingressTLSLn, tlsConfig))
		})
	}
	if respLn != nil {
		server.respLn = trackListener(respLn, make(chan struct{}, o.config.Limits.RESPConnections),
			func() { o.store.rejectedConnection(true) })
		server.servers.Go(server.serveRESP)
	}
	return server
}

func (o *observer) newHTTPServer(ctx context.Context, handler http.Handler) *http.Server {
	timeout := time.Duration(o.config.Limits.HTTPReadTimeoutMillis) * time.Millisecond
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: timeout, ReadTimeout: timeout,
		WriteTimeout: timeout, IdleTimeout: timeout, MaxHeaderBytes: 8 * 1024,
		ErrorLog:    log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
}

func (s *runningServer) serveHTTP(server *http.Server, listener net.Listener) {
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.failures <- struct{}{}
	}
}

func (s *runningServer) serveRESP() {
	for {
		conn, err := s.respLn.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.failures <- struct{}{}
			}
			return
		}
		generation := s.observer.store.generation()
		s.clients.Go(func() { s.observer.handleRESP(conn, generation) })
	}
}

func (s *runningServer) shutdown() error {
	s.cancel()
	s.observer.activity.stop()
	budget := time.Duration(s.observer.config.Limits.ShutdownTimeoutMillis) * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if s.respLn != nil {
		_ = s.respLn.Close()
		s.respLn.closeConnections()
	}
	// Closing incomplete requests unblocks bounded body/frame reads immediately;
	// this observer has no work queue or external side effects to drain.
	for _, server := range []*http.Server{s.http, s.ingress, s.ingressTLS} {
		if server != nil {
			_ = server.Close()
		}
	}
	for _, listener := range []*trackedListener{s.httpLn, s.ingressLn, s.ingressTLSLn} {
		if listener != nil {
			_ = listener.Close()
			listener.closeConnections()
		}
	}
	done := make(chan struct{})
	go func() {
		s.servers.Wait()
		s.clients.Wait()
		s.observer.activity.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errors.New("observer shutdown deadline exceeded")
	}
}
