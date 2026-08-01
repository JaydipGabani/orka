/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"
)

type certificateReloader struct {
	certFile        string
	keyFile         string
	reloadInterval  time.Duration
	now             func() time.Time
	mu              sync.Mutex
	certificate     *tls.Certificate
	reloadErr       error
	nextReloadCheck time.Time
}

func newCertificateReloader(
	certFile, keyFile string,
	reloadInterval time.Duration,
	now func() time.Time,
) (*certificateReloader, error) {
	if reloadInterval <= 0 {
		return nil, errors.New("TLS certificate reload interval must be positive")
	}
	if now == nil {
		now = time.Now
	}
	reloader := &certificateReloader{
		certFile: certFile, keyFile: keyFile, reloadInterval: reloadInterval, now: now,
	}
	certificate, err := loadCertificatePair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	reloader.certificate = certificate
	reloader.nextReloadCheck = now().Add(reloadInterval)
	return reloader, nil
}

// GetCertificate reloads the mounted certificate pair after a bounded cache
// interval. Once a refresh is due, reload failures fail the TLS handshake closed
// instead of serving the stale certificate indefinitely.
func (r *certificateReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	if now.Before(r.nextReloadCheck) {
		if r.reloadErr != nil {
			return nil, r.reloadErr
		}
		return r.certificate, nil
	}

	certificate, err := loadCertificatePair(r.certFile, r.keyFile)
	if err != nil {
		r.reloadErr = err
		r.nextReloadCheck = now.Add(min(r.reloadInterval, time.Second))
		return nil, err
	}
	r.certificate = certificate
	r.reloadErr = nil
	r.nextReloadCheck = now.Add(r.reloadInterval)
	return r.certificate, nil
}

func loadCertificatePair(certFile, keyFile string) (*tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate pair: %w", err)
	}
	return &certificate, nil
}
