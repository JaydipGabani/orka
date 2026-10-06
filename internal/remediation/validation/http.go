package validation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/orka-agents/orka/internal/cli/client"
	pv "github.com/orka-agents/orka/internal/patchverification"
)

const (
	maxSubmissionBytes = 2 << 20
	maxRecordBytes     = 8 << 20
	readTimeout        = 30 * time.Second
	createTimeout      = 2 * time.Minute
)

type transport struct {
	api  client.Client
	http http.Client
	base url.URL
}

type statusError struct {
	code int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("validation API returned HTTP %d", e.code)
}

func newTransport(api *client.Client) (*transport, error) {
	if api == nil {
		return nil, errors.New("validation API client is required")
	}
	base, err := url.Parse(api.BaseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" ||
		base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" ||
		base.Opaque != "" || base.RawPath != "" {
		return nil, errors.New("validation API URL must be an explicit HTTP(S) endpoint without credentials or query")
	}
	httpClient := api.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	copied := *httpClient
	// Redirects could replay a submission or disclose API credentials. Cookies
	// from unrelated client activity are not validation authentication.
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	copied.Jar = nil
	base.Path = strings.TrimSuffix(base.Path, "/")
	return &transport{api: *api, http: copied, base: *base}, nil
}

func (t *transport) open(ctx context.Context, method, endpoint string, body []byte) (*http.Response, error) {
	u := t.base
	u.Path += endpoint
	u.RawQuery = url.Values{"namespace": []string{t.api.Namespace}}.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot construct validation API request")
	}
	req.GetBody = nil
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if t.api.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.api.Token)
	}
	if t.api.TxnToken != "" {
		req.Header.Set("Txn-Token", t.api.TxnToken)
	}
	response, err := t.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Neither transport errors nor remote error bodies are safe diagnostics:
		// custom transports and proxies can include credentials in them.
		return nil, errors.New("validation HTTP transport failed")
	}
	return response, nil
}

func (t *transport) request(ctx context.Context, method, endpoint string, body []byte, status, limit int) ([]byte, error) {
	timeout := readTimeout
	if method == http.MethodPost && endpoint == "/api/v1/validations" {
		timeout = createTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := t.open(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode != status {
		return nil, &statusError{response.StatusCode}
	}
	if response.ContentLength > int64(limit) {
		return nil, errors.New("validation API response exceeds the transport limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("validation API response could not be read")
	}
	if len(data) > limit {
		return nil, errors.New("validation API response exceeds the transport limit")
	}
	return data, nil
}

func (t *transport) blob(ctx context.Context, endpoint string, reference pv.BlobReference) error {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	response, err := t.open(ctx, http.MethodGet, endpoint+"/evidence/"+reference.Digest, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode != http.StatusOK {
		return &statusError{response.StatusCode}
	}
	if response.ContentLength >= 0 && response.ContentLength != int64(reference.Bytes) {
		return pv.ErrIntegrity
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(response.Body, int64(reference.Bytes)+1))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || size != int64(reference.Bytes) ||
		"sha256:"+hex.EncodeToString(hash.Sum(nil)) != reference.Digest {
		return pv.ErrIntegrity
	}
	return nil
}

func definiteRejection(err error) bool {
	var status *statusError
	if !errors.As(err, &status) {
		return false
	}
	switch status.code {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusMethodNotAllowed, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		return true
	default:
		// The API maps every SubmitRequest failure to 422, including a failed
		// acknowledgement read after persistence. It is not a safe retry signal.
		return false
	}
}

func decodeJSON(data []byte, destination any) error {
	if !utf8.Valid(data) || uniqueJSON(json.NewDecoder(bytes.NewReader(data)), 0) != nil {
		return errors.New("validation API returned ambiguous or invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return errors.New("validation API returned an invalid response shape")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("validation API returned trailing response data")
	}
	return nil
}

func uniqueJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return pv.ErrLimit
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		if depth == 0 {
			return pv.ErrEvidence
		}
		return nil
	}
	if depth == 0 && delimiter != '{' {
		return pv.ErrEvidence
	}
	seen := make(map[string]bool)
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			name = strings.ToLower(name)
			if !ok || seen[name] {
				return pv.ErrEvidence
			}
			seen[name] = true
		}
		if err := uniqueJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
