/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

// orka-admission is the standalone, stateless coexistence admission service.
// It serves only the fail-closed harness v1/v2 coexistence ValidatingWebhook
// handlers over TLS: no SQLite, no controller reconciliation, no runtime
// dispatch, and no Kubernetes API client. See
// docs/harness-v1-v2-coexistence-plan.md sections 5.4 and 9.7.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	orkaadmission "github.com/orka-agents/orka/internal/admission"
)

const (
	webhookCertName = "tls.crt"
	webhookKeyName  = "tls.key"

	certPollInterval        = 2 * time.Second
	healthShutdownTimeout   = 10 * time.Second
	healthReadHeaderTimeout = 5 * time.Second
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1alpha1.AddToScheme(scheme))
}

func main() {
	var webhookCertDir string
	var webhookPort int
	var probeAddr string
	var controllerServiceAccounts string
	var adminGroups string

	flag.StringVar(&webhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs",
		"The directory that contains the webhook serving certificate (tls.crt/tls.key). "+
			"Certificates are watched and reloaded on rotation.")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "The port the webhook server binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&controllerServiceAccounts, "controller-service-accounts",
		"system:serviceaccount:orka-system:orka-controller-manager",
		"Comma-separated fully qualified identities allowed to write Task execution provenance "+
			"(for example system:serviceaccount:orka-system:orka-controller-manager). "+
			"An empty list keeps provenance writes fail closed for every caller.")
	flag.StringVar(&adminGroups, "admin-groups", "system:masters",
		"Comma-separated groups allowed to author AgentExecutionControl, AgentExecutionPolicy, "+
			"and AgentExecutionAdjudication specs.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	ctx := ctrl.SetupSignalHandler()

	// HTTP/2 stays disabled to mirror the controller webhook posture
	// (GHSA-qppj-fm5r-hxr3, GHSA-4374-p667-p6c8).
	disableHTTP2 := func(c *tls.Config) {
		c.NextProtos = []string{"http/1.1"}
	}

	webhookServer := webhook.NewServer(webhook.Options{
		Port:     webhookPort,
		CertDir:  webhookCertDir,
		CertName: webhookCertName,
		KeyName:  webhookKeyName,
		TLSOpts:  []func(*tls.Config){disableHTTP2},
	})

	cfg := orkaadmission.NewCoexistenceConfig(controllerServiceAccounts, adminGroups)
	setupLog.Info("configuring coexistence admission",
		"controllerServiceAccounts", cfg.ControllerServiceAccounts,
		"adminGroups", cfg.AdminGroups)

	handlersRegistered := &atomic.Bool{}
	orkaadmission.RegisterCoexistenceWebhooks(webhookServer, scheme, cfg)
	handlersRegistered.Store(true)

	healthServer := newHealthServer(probeAddr, webhookCertDir, webhookServer, handlersRegistered)
	go func() {
		setupLog.Info("starting health probe server", "addr", probeAddr)
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			setupLog.Error(err, "health probe server failed")
			os.Exit(1)
		}
	}()

	// Stay alive but unready until the serving certificate Secret is mounted;
	// readiness fails and the Pod never enters Service endpoints.
	if err := waitForServingCertificates(ctx, webhookCertDir); err != nil {
		shutdownHealthServer(healthServer)
		if errors.Is(err, context.Canceled) {
			return
		}
		setupLog.Error(err, "failed waiting for webhook serving certificates")
		os.Exit(1)
	}

	setupLog.Info("starting coexistence admission webhook server",
		"port", webhookPort, "certDir", webhookCertDir)
	if err := webhookServer.Start(ctx); err != nil {
		setupLog.Error(err, "webhook server failed")
		shutdownHealthServer(healthServer)
		os.Exit(1)
	}
	shutdownHealthServer(healthServer)
}

// newHealthServer serves /healthz (liveness) and /readyz (readiness).
// Readiness fails until the certificate files exist, the handlers are
// registered, and the webhook server answers TLS connections.
func newHealthServer(addr, certDir string, webhookServer webhook.Server, handlersRegistered *atomic.Bool) *http.Server {
	livenessHandler := &healthz.Handler{Checks: map[string]healthz.Checker{
		"ping": healthz.Ping,
	}}
	readinessHandler := &healthz.Handler{Checks: map[string]healthz.Checker{
		"webhook-certificates": func(_ *http.Request) error {
			return checkServingCertificates(certDir)
		},
		"handlers-registered": func(_ *http.Request) error {
			if !handlersRegistered.Load() {
				return errors.New("coexistence admission handlers are not registered")
			}
			return nil
		},
		"webhook-server-started": webhookServer.StartedChecker(),
	}}

	mux := http.NewServeMux()
	mux.Handle("/healthz", http.StripPrefix("/healthz", livenessHandler))
	mux.Handle("/healthz/", http.StripPrefix("/healthz", livenessHandler))
	mux.Handle("/readyz", http.StripPrefix("/readyz", readinessHandler))
	mux.Handle("/readyz/", http.StripPrefix("/readyz", readinessHandler))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: healthReadHeaderTimeout,
	}
}

func checkServingCertificates(certDir string) error {
	for _, name := range []string{webhookCertName, webhookKeyName} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err != nil {
			return fmt.Errorf("webhook serving certificate %s unavailable: %w", name, err)
		}
	}
	return nil
}

func waitForServingCertificates(ctx context.Context, certDir string) error {
	if err := checkServingCertificates(certDir); err == nil {
		return nil
	}
	setupLog.Info("waiting for webhook serving certificates", "certDir", certDir)
	ticker := time.NewTicker(certPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		case <-ticker.C:
			if err := checkServingCertificates(certDir); err == nil {
				return nil
			}
		}
	}
}

func shutdownHealthServer(server *http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), healthShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		setupLog.Error(err, "health probe server shutdown failed")
	}
}
