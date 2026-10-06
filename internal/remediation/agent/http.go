package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/cli/client"
)

const (
	requestTimeout   = 30 * time.Second
	maxResponseBytes = 2 << 20
	maxReadAttempts  = 3
)

var (
	errTransport = errors.New("proposal HTTP transport failed")
	errBodyRead  = errors.New("proposal HTTP response could not be read")
)

type transport struct {
	api          client.Client
	http         http.Client
	pollInterval time.Duration
}

type httpStatusError struct {
	code int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("proposal API returned HTTP %d", e.code)
}

func isHTTPStatus(err error, status int) bool {
	var responseErr *httpStatusError
	return errors.As(err, &responseErr) && responseErr.code == status
}

func (w *transport) request(ctx context.Context, method, path string, body []byte, expectedStatus int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	endpoint := w.api.BaseURL + path
	if method == http.MethodGet {
		endpoint += "?namespace=" + url.QueryEscape(w.api.Namespace)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot construct proposal HTTP request")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if w.api.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.api.Token)
	}
	if w.api.TxnToken != "" {
		req.Header.Set("Txn-Token", w.api.TxnToken)
	}
	resp, err := w.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, errTransport
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != expectedStatus {
		return nil, &httpStatusError{code: resp.StatusCode}
	}
	if resp.ContentLength > maxResponseBytes {
		return nil, errors.New("proposal HTTP response exceeds 2 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errBodyRead
	}
	if len(data) > maxResponseBytes {
		return nil, errors.New("proposal HTTP response exceeds 2 MiB")
	}
	return data, nil
}

func (w *transport) read(ctx context.Context, path string, reconcileCreate bool) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		body, err := w.request(ctx, http.MethodGet, path, nil, http.StatusOK)
		if err == nil {
			return body, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt+1 >= maxReadAttempts || !retryableRead(err, reconcileCreate) {
			return nil, err
		}
		if err := wait(ctx, w.pollInterval); err != nil {
			return nil, err
		}
	}
}

func retryableRead(err error, reconcileCreate bool) bool {
	if errors.Is(err, errTransport) || errors.Is(err, errBodyRead) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var responseErr *httpStatusError
	if !errors.As(err, &responseErr) {
		return false
	}
	switch responseErr.code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case http.StatusNotFound:
		return reconcileCreate
	default:
		return false
	}
}

func (w *transport) getRequester(ctx context.Context) (*corev1alpha1.RequestedBy, error) {
	body, err := w.read(ctx, "/api/v1/auth/whoami", false)
	if err != nil {
		return nil, fmt.Errorf("read proposal requester identity: %w", err)
	}
	var identity struct {
		corev1alpha1.RequestedBy
		Authenticated bool   `json:"authenticated"`
		AuthType      string `json:"authType"`
		UID           string `json:"uid"`
		Namespace     string `json:"namespace"`
		Transaction   *struct {
			Profile            string   `json:"profile"`
			Type               string   `json:"type"`
			ID                 string   `json:"id"`
			Issuer             string   `json:"issuer"`
			Subject            string   `json:"subject"`
			Audience           []string `json:"audience"`
			Scope              string   `json:"scope"`
			Scopes             []string `json:"scopes"`
			RequestingWorkload string   `json:"requestingWorkload"`
		} `json:"transaction"`
	}
	if err := decodeResponse(body, &identity); err != nil {
		return nil, err
	}
	if !identity.Authenticated {
		return nil, errors.New("proposal API did not establish an authenticated requester")
	}
	switch identity.AuthType {
	case "tokenReview":
		if strings.TrimSpace(identity.Username) == "" {
			return nil, errors.New("proposal requester identity is incomplete")
		}
		// Orka only stamps RequestedBy for OIDC and context-token callers.
		return nil, nil
	case "oidc", "contextToken":
		if strings.TrimSpace(identity.Subject) == "" || strings.TrimSpace(identity.Issuer) == "" {
			return nil, errors.New("proposal requester identity is incomplete")
		}
	default:
		return nil, errors.New("proposal requester authentication type is unsupported")
	}
	// RequestedBy omits empty groups and roles on the Task wire response.
	if len(identity.Groups) == 0 {
		identity.Groups = nil
	}
	if len(identity.Roles) == 0 {
		identity.Roles = nil
	}
	return &identity.RequestedBy, nil
}

func decodeResponse(body []byte, destination any) error {
	if !utf8.Valid(body) {
		return errors.New("proposal API returned invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("proposal API returned an invalid response shape")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("proposal API returned trailing response data")
	}
	return nil
}

func decodeResult(body []byte) (string, error) {
	invalid := errors.New("proposal API returned an invalid result shape")
	if !utf8.Valid(body) {
		return "", invalid
	}
	// Struct decoding alone accepts duplicate keys. The result endpoint has
	// exactly one field, so consume that shape without accepting ambiguity.
	decoder := json.NewDecoder(bytes.NewReader(body))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return "", invalid
	}
	if token, err := decoder.Token(); err != nil || token != "result" {
		return "", invalid
	}
	var output string
	if err := decoder.Decode(&output); err != nil {
		return "", invalid
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return "", invalid
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return "", invalid
	}
	// ACP substitutes this sentence when a completed prompt emitted no text.
	if text := strings.TrimSpace(output); text == "" || text == emptyProposalOutput {
		return "", errors.New("proposal result contains no textual output")
	}
	return output, nil
}

func wait(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
