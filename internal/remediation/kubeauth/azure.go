// Package kubeauth configures explicit authentication for trusted lab clients.
package kubeauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
	"k8s.io/client-go/rest"
)

const (
	aksScope          = "6dae42f8-4368-4678-94ff-3960e28e3630/.default"
	maxTokenBytes     = 64 << 10
	credentialTimeout = 15 * time.Second
)

var (
	ErrConfiguration = errors.New("invalid explicit Azure workload identity configuration")
	ErrCredentials   = errors.New("azure workload identity credentials are unavailable")
	ErrEndpoint      = errors.New("azure workload identity request is outside the approved AKS endpoint")
)

// AzureWorkloadIdentity identifies an operator-approved federation. It contains
// no token. The projected token file is read by the SDK as Kubernetes rotates it.
type AzureWorkloadIdentity struct {
	TenantID           string `json:"tenantID"`
	ClientID           string `json:"clientID"`
	FederatedTokenFile string `json:"federatedTokenFile"`
}

func (c AzureWorkloadIdentity) Validate() error {
	for _, value := range []string{c.TenantID, c.ClientID} {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return ErrConfiguration
		}
	}
	if !filepath.IsAbs(c.FederatedTokenFile) || filepath.Clean(c.FederatedTokenFile) != c.FederatedTokenFile ||
		strings.ContainsAny(c.FederatedTokenFile, "\x00\r\n") {
		return ErrConfiguration
	}
	return nil
}

// ConfigureAzure adds a renewable, endpoint-bound bearer transport without an
// executable kubeconfig plugin or ambient Azure credential fallback. Nil keeps
// the existing static kubeconfig path unchanged.
func ConfigureAzure(config *rest.Config, identity *AzureWorkloadIdentity) error {
	if identity == nil {
		return nil
	}
	if !anonymousTLSConfig(config) || identity.Validate() != nil {
		return ErrConfiguration
	}
	endpoint, err := url.Parse(config.Host)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil ||
		!strings.HasSuffix(endpoint.Hostname(), ".azmk8s.io") || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") || (endpoint.Port() != "" && endpoint.Port() != "443") {
		return ErrEndpoint
	}
	// Projected Kubernetes tokens use symlinks for atomic rotation.
	info, err := os.Stat(identity.FederatedTokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 ||
		info.Size() < 1 || info.Size() > maxTokenBytes {
		return ErrConfiguration
	}
	credential, err := newAzureCredential(*identity)
	if err != nil {
		return ErrConfiguration
	}
	origin := endpoint.Scheme + "://" + endpoint.Host
	config.WrapTransport = func(base http.RoundTripper) http.RoundTripper {
		return &azureBearerTransport{base: base, credential: credential, origin: origin}
	}
	return nil
}

func anonymousTLSConfig(config *rest.Config) bool {
	return config != nil && !config.Insecure && len(config.CAData) != 0 &&
		config.CAFile == "" && config.Username == "" && config.Password == "" &&
		config.BearerToken == "" && config.BearerTokenFile == "" &&
		config.CertFile == "" && config.KeyFile == "" && len(config.CertData) == 0 && len(config.KeyData) == 0 &&
		config.ExecProvider == nil && config.AuthProvider == nil && config.Transport == nil && config.WrapTransport == nil && config.Proxy == nil &&
		config.Impersonate.UserName == "" && config.Impersonate.UID == "" &&
		len(config.Impersonate.Groups) == 0 && len(config.Impersonate.Extra) == 0
}

func newAzureCredential(identity AzureWorkloadIdentity) (azcore.TokenCredential, error) {
	// MSAL's regional autodetection would bypass the configured HTTP transport.
	for _, name := range []string{"AZURE_REGIONAL_AUTHORITY_NAME", "MSAL_FORCE_REGION"} {
		if _, configured := os.LookupEnv(name); configured {
			return nil, ErrConfiguration
		}
	}
	client := &http.Client{
		Timeout: credentialTimeout,
		Transport: &http.Transport{
			Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout: 90 * time.Second, MaxIdleConns: 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	credential, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		TenantID: identity.TenantID, ClientID: identity.ClientID, TokenFilePath: identity.FederatedTokenFile,
		ClientOptions: azcore.ClientOptions{
			Cloud: cloud.AzurePublic, Transport: client,
			Retry: policy.RetryOptions{MaxRetries: 1},
		},
	})
	if err != nil {
		return nil, err
	}
	return &cancellableCredential{credential: credential, gate: make(chan struct{}, 1)}, nil
}

type cancellableCredential struct {
	credential azcore.TokenCredential
	gate       chan struct{}
}

func (c *cancellableCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	ctx, cancel := context.WithTimeout(ctx, credentialTimeout)
	defer cancel()
	// The SDK holds a non-cancellable mutex across token acquisition. Queue
	// callers here so a stalled exchange cannot trap a cancelled API request.
	select {
	case <-ctx.Done():
		return azcore.AccessToken{}, ctx.Err()
	case c.gate <- struct{}{}:
	}
	defer func() { <-c.gate }()
	if err := ctx.Err(); err != nil {
		return azcore.AccessToken{}, err
	}
	token, err := c.credential.GetToken(ctx, options)
	if ctx.Err() != nil {
		return azcore.AccessToken{}, ctx.Err()
	}
	return token, err
}

type azureBearerTransport struct {
	base       http.RoundTripper
	credential azcore.TokenCredential
	origin     string
}

func (t *azureBearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.URL.User != nil || request.URL.Fragment != "" ||
		request.URL.Scheme+"://"+request.URL.Host != t.origin ||
		(request.Host != "" && request.Host != request.URL.Host) || request.Header.Get("Authorization") != "" {
		return nil, refuse(request, ErrEndpoint)
	}
	if err := request.Context().Err(); err != nil {
		return nil, refuse(request, err)
	}
	token, err := t.credential.GetToken(request.Context(), policy.TokenRequestOptions{Scopes: []string{aksScope}})
	if err != nil {
		if request.Context().Err() != nil {
			return nil, refuse(request, request.Context().Err())
		}
		return nil, refuse(request, ErrCredentials)
	}
	if !token.ExpiresOn.After(time.Now()) || len(token.Token) == 0 || len(token.Token) > maxTokenBytes ||
		strings.ContainsFunc(token.Token, func(r rune) bool { return r <= ' ' || r > '~' }) {
		return nil, refuse(request, ErrCredentials)
	}
	authorized := request.Clone(request.Context())
	if authorized.Header == nil {
		authorized.Header = make(http.Header)
	}
	authorized.Header.Set("Authorization", "Bearer "+token.Token)
	return t.base.RoundTrip(authorized)
}

func (t *azureBearerTransport) WrappedRoundTripper() http.RoundTripper {
	return t.base
}

func refuse(request *http.Request, err error) error {
	if request != nil && request.Body != nil {
		_ = request.Body.Close()
	}
	return err
}
