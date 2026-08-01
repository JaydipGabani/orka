/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package kd6adapter

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// BearerTokenProvider supplies one validated bearer token at the point of use.
// Implementations must not include token values in returned errors.
type BearerTokenProvider interface {
	BearerToken() (string, error)
}

type staticBearerTokenProvider struct {
	value string
}

func (p staticBearerTokenProvider) BearerToken() (string, error) {
	return p.value, nil
}

type fileBearerTokenProvider struct {
	path string
	name string
}

// NewStaticBearerTokenProvider validates and stores a process-lifetime token.
// File-mounted Kubernetes Secrets should use NewFileBearerTokenProvider instead.
func NewStaticBearerTokenProvider(value, name string) (BearerTokenProvider, error) {
	value = strings.TrimSpace(value)
	if err := validateSecretValue(name, value); err != nil {
		return nil, err
	}
	return staticBearerTokenProvider{value: value}, nil
}

// NewFileBearerTokenProvider validates a token file and returns a provider that
// re-reads the file on every use. Kubernetes projected Secret updates therefore
// take effect without restarting the adapter.
func NewFileBearerTokenProvider(path, name string) (BearerTokenProvider, error) {
	path = strings.TrimSpace(path)
	name = strings.TrimSpace(name)
	if path == "" {
		return nil, errors.New("bearer token file path is required")
	}
	if name == "" {
		name = "bearer token"
	}
	provider := &fileBearerTokenProvider{path: path, name: name}
	if _, err := provider.BearerToken(); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *fileBearerTokenProvider) BearerToken() (string, error) {
	data, err := os.ReadFile(p.path)
	if err != nil {
		return "", fmt.Errorf("read %s file: %w", p.name, err)
	}
	value := strings.TrimSpace(string(data))
	if err := validateSecretValue(p.name, value); err != nil {
		return "", err
	}
	return value, nil
}

func resolveBearerTokenProvider(name, value string, provider BearerTokenProvider) (BearerTokenProvider, error) {
	value = strings.TrimSpace(value)
	if provider != nil && value != "" {
		return nil, fmt.Errorf("%s must use exactly one token source", name)
	}
	if provider == nil {
		return NewStaticBearerTokenProvider(value, name)
	}
	if _, err := bearerTokenFromProvider(name, provider); err != nil {
		return nil, err
	}
	return provider, nil
}

func bearerTokenFromProvider(name string, provider BearerTokenProvider) (string, error) {
	if provider == nil {
		return "", fmt.Errorf("%s provider is required", name)
	}
	value, err := provider.BearerToken()
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if err := validateSecretValue(name, value); err != nil {
		return "", err
	}
	return value, nil
}
