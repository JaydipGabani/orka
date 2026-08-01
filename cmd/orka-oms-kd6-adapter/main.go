/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/orka-agents/orka/internal/oms/kd6adapter"
)

const (
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteTimeout      = 60 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultShutdownTimeout   = 15 * time.Second
	defaultTLSReloadInterval = time.Second
	minTLSReloadInterval     = 100 * time.Millisecond
	maxTLSReloadInterval     = time.Minute
)

type options struct {
	listenAddr                  string
	tlsCertFile                 string
	tlsKeyFile                  string
	tlsReloadInterval           time.Duration
	inboundTokenFile            string
	controlDB                   string
	kd6Endpoint                 string
	kd6TokenFile                string
	enableConformanceFailpoints bool
	storeMappings               stringMapFlag
}

func (o options) validate() error {
	if strings.TrimSpace(o.tlsCertFile) == "" || strings.TrimSpace(o.tlsKeyFile) == "" {
		return errors.New("--tls-cert-file and --tls-key-file are required")
	}
	if o.tlsReloadInterval < minTLSReloadInterval || o.tlsReloadInterval > maxTLSReloadInterval {
		return fmt.Errorf("--tls-reload-interval must be between %s and %s", minTLSReloadInterval, maxTLSReloadInterval)
	}
	if strings.TrimSpace(o.controlDB) == "" {
		return errors.New("--control-db is required")
	}
	if strings.TrimSpace(o.kd6Endpoint) == "" {
		return errors.New("--kd6-endpoint is required")
	}
	if len(o.storeMappings) == 0 {
		return errors.New("at least one --store-mapping name=provider-store-id is required")
	}
	return nil
}

func (o options) tlsEnabled() bool { return o.tlsCertFile != "" && o.tlsKeyFile != "" }

type stringMapFlag map[string]string

func (m *stringMapFlag) String() string {
	if m == nil || len(*m) == 0 {
		return ""
	}
	return fmt.Sprintf("%d configured mappings", len(*m))
}

func (m *stringMapFlag) Set(value string) error {
	name, providerID, ok := strings.Cut(value, "=")
	name, providerID = strings.TrimSpace(name), strings.TrimSpace(providerID)
	if !ok || name == "" || providerID == "" {
		return errors.New("store mapping must be name=provider-store-id")
	}
	if *m == nil {
		*m = stringMapFlag{}
	}
	if previous, exists := (*m)[name]; exists && previous != providerID {
		return fmt.Errorf("store mapping %q was configured more than once", name)
	}
	(*m)[name] = providerID
	return nil
}

func parseOptions(args []string) (options, error) {
	result := options{storeMappings: stringMapFlag{}}
	flags := flag.NewFlagSet("orka-oms-kd6-adapter", flag.ContinueOnError)
	flags.StringVar(&result.listenAddr, "listen", ":8091", "listen address")
	flags.StringVar(&result.tlsCertFile, "tls-cert-file", "", "TLS certificate file (requires --tls-key-file)")
	flags.StringVar(&result.tlsKeyFile, "tls-key-file", "", "TLS private key file (requires --tls-cert-file)")
	flags.DurationVar(&result.tlsReloadInterval, "tls-reload-interval", defaultTLSReloadInterval,
		"maximum cache interval before reloading the TLS certificate pair")
	flags.StringVar(&result.inboundTokenFile, "inbound-token-file", "",
		"file containing the inbound OMS bearer token (or set ORKA_OMS_INBOUND_BEARER_TOKEN)")
	flags.StringVar(&result.controlDB, "control-db", "/data/oms-control.db", "durable SQLite OMS control-state database")
	flags.StringVar(&result.kd6Endpoint, "kd6-endpoint", "", "HTTPS KD6/proxy base URL")
	flags.StringVar(&result.kd6TokenFile, "kd6-token-file", "",
		"file containing the KD6/proxy bearer token (or set ORKA_KD6_BEARER_TOKEN)")
	flags.BoolVar(&result.enableConformanceFailpoints, "enable-conformance-failpoints", false,
		"enable authenticated conformance-only crash-gap failpoints (test environments only)")
	flags.Var(&result.storeMappings, "store-mapping", "repeatable OMS-name=provider-store-id mapping")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("positional arguments are not supported")
	}
	if err := result.validate(); err != nil {
		return options{}, err
	}
	return result, nil
}

func newBearerTokenProvider(
	filePath, flagName, environmentName, tokenName string,
) (kd6adapter.BearerTokenProvider, error) {
	if strings.TrimSpace(filePath) != "" {
		return kd6adapter.NewFileBearerTokenProvider(filePath, tokenName)
	}
	value := strings.TrimSpace(os.Getenv(environmentName))
	if value == "" {
		return nil, fmt.Errorf("--%s or %s is required", flagName, environmentName)
	}
	return kd6adapter.NewStaticBearerTokenProvider(value, tokenName)
}

func newHTTPServer(options options, handler http.Handler) (*http.Server, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	server := &http.Server{
		Addr: options.listenAddr, Handler: handler,
		ReadHeaderTimeout: defaultReadHeaderTimeout, ReadTimeout: defaultReadTimeout,
		WriteTimeout: defaultWriteTimeout, IdleTimeout: defaultIdleTimeout,
	}
	if options.tlsEnabled() {
		certificate, err := newCertificateReloader(
			options.tlsCertFile, options.tlsKeyFile, options.tlsReloadInterval, time.Now,
		)
		if err != nil {
			return nil, err
		}
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12, GetCertificate: certificate.GetCertificate, SessionTicketsDisabled: true,
		}
	}
	return server, nil
}

func serve(server *http.Server, options options) error {
	if options.tlsEnabled() {
		return server.ListenAndServeTLS("", "")
	}
	return server.ListenAndServe()
}

func run(ctx context.Context, args []string) error {
	options, err := parseOptions(args)
	if err != nil {
		return err
	}
	inboundTokenProvider, err := newBearerTokenProvider(
		options.inboundTokenFile, "inbound-token-file", "ORKA_OMS_INBOUND_BEARER_TOKEN", "inbound OMS bearer token",
	)
	if err != nil {
		return err
	}
	kd6TokenProvider, err := newBearerTokenProvider(
		options.kd6TokenFile, "kd6-token-file", "ORKA_KD6_BEARER_TOKEN", "KD6 bearer token",
	)
	if err != nil {
		return err
	}
	contentStore, err := kd6adapter.NewHTTPSContentStore(kd6adapter.HTTPSContentStoreConfig{
		Endpoint: options.kd6Endpoint, BearerTokenProvider: kd6TokenProvider,
	})
	if err != nil {
		return err
	}
	adapter, err := kd6adapter.Open(ctx, kd6adapter.Config{
		DatabasePath: options.controlDB, BearerTokenProvider: inboundTokenProvider,
		ContentStore: contentStore, StoreMappings: map[string]string(options.storeMappings),
		EnableConformanceFailpoints: options.enableConformanceFailpoints,
	})
	if err != nil {
		return err
	}
	defer adapter.Close() //nolint:errcheck
	server, err := newHTTPServer(options, adapter.Handler())
	if err != nil {
		return err
	}
	errCh := make(chan error, 1)
	go func() { errCh <- serve(server, options) }()
	transport := "HTTP"
	if options.tlsEnabled() {
		transport = "HTTPS"
	}
	log.Printf("starting orka.oms.v0alpha1 KD6 adapter over %s on %s", transport, options.listenAddr)
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shutdown OMS KD6 adapter: %w", err)
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
