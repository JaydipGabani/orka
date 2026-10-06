package kubeauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const testAKSOrigin = "https://approved.eastus2.azmk8s.io"

type credentialFunc func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error)

func (f credentialFunc) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return f(ctx, options)
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func azureFixture(t *testing.T) (*rest.Config, *AzureWorkloadIdentity) {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "projected-token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("synthetic-projected-assertion"), 0600))
	return &rest.Config{Host: testAKSOrigin, TLSClientConfig: rest.TLSClientConfig{CAData: []byte("operator-supplied-ca")}},
		&AzureWorkloadIdentity{
			TenantID: "11111111-1111-4111-8111-111111111111", ClientID: "22222222-2222-4222-8222-222222222222",
			FederatedTokenFile: tokenFile,
		}
}

func TestConfigureAzureIsExplicitAndDoesNotMutateLegacyConfig(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "unexpected-tenant")
	t.Setenv("AZURE_CLIENT_ID", "unexpected-client")
	t.Setenv("AZURE_AUTHORITY_HOST", "http://unexpected.invalid")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/unapproved-token")
	t.Setenv("HTTPS_PROXY", "http://unexpected.invalid")
	config, identity := azureFixture(t)
	require.NoError(t, ConfigureAzure(config, identity))
	require.NotNil(t, config.WrapTransport)
	require.Empty(t, config.BearerToken)
	require.Empty(t, config.BearerTokenFile)
	require.Nil(t, config.ExecProvider)
	require.Nil(t, config.AuthProvider)
	require.NoError(t, ConfigureAzure(nil, nil))
	legacy := &rest.Config{Host: "https://legacy.invalid", BearerToken: "synthetic-legacy-token"}
	before := rest.CopyConfig(legacy)
	require.NoError(t, ConfigureAzure(legacy, nil))
	require.Equal(t, before, legacy)
}

func TestConfigureAzureSharesCancellableCredentialAcrossTransports(t *testing.T) {
	config, identity := azureFixture(t)
	require.NoError(t, ConfigureAzure(config, identity))
	first := config.WrapTransport(http.DefaultTransport).(*azureBearerTransport)
	second := config.WrapTransport(http.DefaultTransport).(*azureBearerTransport)
	credential, ok := first.credential.(*cancellableCredential)
	require.True(t, ok)
	require.Same(t, credential, second.credential)
	require.Equal(t, 1, cap(credential.gate))
}

func TestAzureQueuedTokenRequestHonorsCallerDeadline(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	var workers sync.WaitGroup
	t.Cleanup(func() {
		unblock()
		workers.Wait()
	})
	var sdkMutex sync.Mutex
	var tokenCalls, networkCalls atomic.Int32
	credential := &cancellableCredential{
		gate: make(chan struct{}, 1),
		credential: credentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
			sdkMutex.Lock()
			defer sdkMutex.Unlock()
			if tokenCalls.Add(1) == 1 {
				close(entered)
				<-release
			}
			return azcore.AccessToken{Token: "synthetic-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
		}),
	}
	transport := &azureBearerTransport{
		origin: testAKSOrigin, credential: credential,
		base: transportFunc(func(*http.Request) (*http.Response, error) {
			networkCalls.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
	}
	firstDone := make(chan error, 1)
	workers.Go(func() {
		_, err := credential.GetToken(t.Context(), policy.TokenRequestOptions{Scopes: []string{aksScope}})
		firstDone <- err
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first token acquisition did not start")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	body := &closedBody{}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, testAKSOrigin+"/api", body)
	require.NoError(t, err)
	secondDone := make(chan error, 1)
	workers.Go(func() {
		_, err := transport.RoundTrip(request)
		secondDone <- err
	})
	select {
	case err := <-secondDone:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("queued token request outlived its deadline while another exchange remained active")
	}
	require.True(t, body.closed)
	require.EqualValues(t, 1, tokenCalls.Load())
	require.Zero(t, networkCalls.Load())
	unblock()
	require.NoError(t, <-firstDone)
	request, err = http.NewRequestWithContext(t.Context(), http.MethodGet, testAKSOrigin+"/api", nil)
	require.NoError(t, err)
	response, err := transport.RoundTrip(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.EqualValues(t, 2, tokenCalls.Load())
	require.EqualValues(t, 1, networkCalls.Load())
}

func TestAzureTokenAcquisitionHasTotalDeadline(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(strconv.FormatBool(cancelled), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if cancelled {
				cancel()
			}
			calls := 0
			credential := &cancellableCredential{
				gate: make(chan struct{}, 1),
				credential: credentialFunc(func(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
					calls++
					deadline, ok := ctx.Deadline()
					require.True(t, ok)
					require.Positive(t, time.Until(deadline))
					require.LessOrEqual(t, time.Until(deadline), credentialTimeout)
					return azcore.AccessToken{Token: "synthetic-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
				}),
			}
			_, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{aksScope}})
			if cancelled {
				require.ErrorIs(t, err, context.Canceled)
				require.Zero(t, calls)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, calls)
			}
		})
	}
}

func TestConfigureAzureRejectsAmbientRegionalAuthority(t *testing.T) {
	for _, name := range []string{"AZURE_REGIONAL_AUTHORITY_NAME", "MSAL_FORCE_REGION"} {
		for _, region := range []string{"eastus2", "TryAutoDetect", ""} {
			t.Run(name+"="+region, func(t *testing.T) {
				t.Setenv(name, region)
				config, identity := azureFixture(t)
				require.ErrorIs(t, ConfigureAzure(config, identity), ErrConfiguration)
				require.Nil(t, config.WrapTransport)
				legacy := &rest.Config{Host: "https://legacy.invalid", BearerToken: "synthetic-legacy-token"}
				before := rest.CopyConfig(legacy)
				require.NoError(t, ConfigureAzure(legacy, nil))
				require.Equal(t, before, legacy)
			})
		}
	}
}

func TestConfigureAzureRejectsMissingExplicitIdentityAndAmbientFallback(t *testing.T) {
	for _, field := range []string{"tenant", "client", "token-file", "noncanonical-id", "null-id", "relative-file", "unclean-file"} {
		t.Run(field, func(t *testing.T) {
			config, identity := azureFixture(t)
			switch field {
			case "tenant":
				identity.TenantID = ""
			case "client":
				identity.ClientID = ""
			case "token-file":
				identity.FederatedTokenFile = ""
			case "noncanonical-id":
				identity.ClientID = "urn:uuid:" + identity.ClientID
			case "null-id":
				identity.TenantID = "00000000-0000-0000-0000-000000000000"
			case "relative-file":
				identity.FederatedTokenFile = "token"
			case "unclean-file":
				identity.FederatedTokenFile += "/../token"
			}
			require.ErrorIs(t, ConfigureAzure(config, identity), ErrConfiguration)
			require.Nil(t, config.WrapTransport)
		})
	}
}

func TestConfigureAzureRejectsMixedCredentialsAndUnverifiedTransport(t *testing.T) {
	for _, change := range []struct {
		name   string
		mutate func(*rest.Config)
	}{
		{"bearer", func(c *rest.Config) { c.BearerToken = "synthetic-static-token" }},
		{"bearer-file", func(c *rest.Config) { c.BearerTokenFile = "/private/token" }},
		{"username", func(c *rest.Config) { c.Username = "synthetic-user" }},
		{"password", func(c *rest.Config) { c.Password = "synthetic-password" }},
		{"client-certificate", func(c *rest.Config) { c.CertData = []byte("certificate") }},
		{"client-key", func(c *rest.Config) { c.KeyData = []byte("private-key-marker") }},
		{"certificate-file", func(c *rest.Config) { c.CertFile = "/private/cert" }},
		{"key-file", func(c *rest.Config) { c.KeyFile = "/private/key" }},
		{"exec", func(c *rest.Config) { c.ExecProvider = &clientcmdapi.ExecConfig{Command: "must-not-run"} }},
		{"auth-provider", func(c *rest.Config) { c.AuthProvider = &clientcmdapi.AuthProviderConfig{Name: "azure"} }},
		{"impersonation", func(c *rest.Config) { c.Impersonate.UserName = "another-user" }},
		{"insecure", func(c *rest.Config) { c.Insecure = true }},
		{"missing-ca", func(c *rest.Config) { c.CAData = nil }},
		{"ca-file", func(c *rest.Config) { c.CAFile = "/private/ca" }},
		{"custom-transport", func(c *rest.Config) { c.Transport = http.DefaultTransport }},
		{"custom-wrapper", func(c *rest.Config) { c.WrapTransport = func(rt http.RoundTripper) http.RoundTripper { return rt } }},
		{"proxy", func(c *rest.Config) { c.Proxy = http.ProxyFromEnvironment }},
	} {
		t.Run(change.name, func(t *testing.T) {
			config, identity := azureFixture(t)
			change.mutate(config)
			require.ErrorIs(t, ConfigureAzure(config, identity), ErrConfiguration)
		})
	}
}

func TestConfigureAzureRestrictsAzurePublicAKSEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"http://approved.eastus2.azmk8s.io", "https://example.invalid", "https://azmk8s.io",
		"https://approved.eastus2.azmk8s.io.evil.invalid", testAKSOrigin + ":6443",
		testAKSOrigin + "/api", testAKSOrigin + "?redirect=other", testAKSOrigin + "#fragment",
		"https://synthetic-user@approved.eastus2.azmk8s.io",
	} {
		t.Run(endpoint, func(t *testing.T) {
			config, identity := azureFixture(t)
			config.Host = endpoint
			require.ErrorIs(t, ConfigureAzure(config, identity), ErrEndpoint)
			require.Nil(t, config.WrapTransport)
		})
	}
	for _, endpoint := range []string{testAKSOrigin, testAKSOrigin + "/", testAKSOrigin + ":443"} {
		config, identity := azureFixture(t)
		config.Host = endpoint
		require.NoError(t, ConfigureAzure(config, identity))
	}
}

func TestConfigureAzureProjectedFileShapeAndAtomicRotation(t *testing.T) {
	for _, mode := range []string{"missing", "empty", "oversized", "world-writable", "directory", "projected-symlink"} {
		t.Run(mode, func(t *testing.T) {
			config, identity := azureFixture(t)
			switch mode {
			case "missing":
				require.NoError(t, os.Remove(identity.FederatedTokenFile))
			case "empty":
				require.NoError(t, os.WriteFile(identity.FederatedTokenFile, nil, 0600))
			case "oversized":
				require.NoError(t, os.WriteFile(identity.FederatedTokenFile, []byte(strings.Repeat("a", maxTokenBytes+1)), 0600))
			case "world-writable":
				require.NoError(t, os.Chmod(identity.FederatedTokenFile, 0666))
			case "directory":
				identity.FederatedTokenFile = filepath.Dir(identity.FederatedTokenFile)
			case "projected-symlink":
				target := identity.FederatedTokenFile
				identity.FederatedTokenFile = filepath.Join(filepath.Dir(target), "current")
				require.NoError(t, os.Symlink(target, identity.FederatedTokenFile))
			}
			err := ConfigureAzure(config, identity)
			if mode == "projected-symlink" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrConfiguration)
			}
		})
	}
}

func TestAzureTransportRefreshesTokensAndPreservesRequest(t *testing.T) {
	calls := 0
	var observed []string
	base := transportFunc(func(r *http.Request) (*http.Response, error) {
		observed = append(observed, r.Header.Get("Authorization"))
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	transport := &azureBearerTransport{
		origin: testAKSOrigin, base: base,
		credential: credentialFunc(func(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
			require.Equal(t, []string{aksScope}, options.Scopes)
			require.Empty(t, options.TenantID)
			calls++
			return azcore.AccessToken{Token: strings.Repeat("a", calls), ExpiresOn: time.Now().Add(time.Hour)}, nil
		}),
	}
	request, err := http.NewRequest(http.MethodGet, testAKSOrigin+"/api/v1/namespaces", nil)
	require.NoError(t, err)
	for range 2 {
		response, err := transport.RoundTrip(request)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Empty(t, request.Header.Get("Authorization"))
	}
	require.Equal(t, []string{"Bearer a", "Bearer aa"}, observed)
	require.IsType(t, base, transport.WrappedRoundTripper())
}

func TestAzureTransportRefusesRedirectsAndMixedRequestAuthority(t *testing.T) {
	for _, change := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"different-host", func(r *http.Request) { r.URL.Host = "other.eastus2.azmk8s.io" }},
		{"downgrade", func(r *http.Request) { r.URL.Scheme = "http" }},
		{"userinfo", func(r *http.Request) { r.URL.User = url.User("synthetic-user") }},
		{"host-override", func(r *http.Request) { r.Host = "other.invalid" }},
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic-existing") }},
		{"fragment", func(r *http.Request) { r.URL.Fragment = "unexpected" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, testAKSOrigin+"/api", nil)
			require.NoError(t, err)
			change.mutate(request)
			transport := &azureBearerTransport{
				origin: testAKSOrigin,
				base: transportFunc(func(*http.Request) (*http.Response, error) {
					t.Error("out-of-scope request reached the network")
					return nil, ErrEndpoint
				}),
				credential: credentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
					t.Error("out-of-scope request requested a token")
					return azcore.AccessToken{}, ErrCredentials
				}),
			}
			_, err = transport.RoundTrip(request)
			require.ErrorIs(t, err, ErrEndpoint)
		})
	}
}

type closedBody struct{ closed bool }

func (b *closedBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *closedBody) Close() error             { b.closed = true; return nil }

func TestAzureTransportFailsClosedWithoutLeakingCredentialErrors(t *testing.T) {
	for _, mode := range []string{"error", "empty", "expired", "newline", "oversized", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			body := &closedBody{}
			request, err := http.NewRequest(http.MethodPost, testAKSOrigin+"/api", body)
			require.NoError(t, err)
			transport := &azureBearerTransport{
				origin: testAKSOrigin,
				base: transportFunc(func(*http.Request) (*http.Response, error) {
					t.Error("unusable credentials reached the network")
					return nil, ErrCredentials
				}),
				credential: credentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
					value := azcore.AccessToken{Token: "synthetic-access-token", ExpiresOn: time.Now().Add(time.Hour)}
					switch mode {
					case "error":
						return value, errors.New("private-provider-assertion-must-not-be-returned")
					case "empty":
						value.Token = ""
					case "expired":
						value.ExpiresOn = time.Now().Add(-time.Second)
					case "newline":
						value.Token += "\r\nunsafe"
					case "oversized":
						value.Token = strings.Repeat("a", maxTokenBytes+1)
					case "cancelled":
						t.Error("already cancelled request attempted a token exchange")
					}
					return value, nil
				}),
			}
			if mode == "cancelled" {
				ctx, cancel := context.WithCancel(request.Context())
				cancel()
				request = request.WithContext(ctx)
			}
			_, err = transport.RoundTrip(request)
			if mode == "cancelled" {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.ErrorIs(t, err, ErrCredentials)
			}
			require.NotContains(t, err.Error(), "private-provider-assertion")
			require.NotContains(t, err.Error(), "synthetic-access-token")
			require.True(t, body.closed)
		})
	}
}

func TestAzureTransportConcurrentRequestsDoNotShareHeaders(t *testing.T) {
	transport := &azureBearerTransport{
		origin: testAKSOrigin,
		credential: credentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
			return azcore.AccessToken{Token: "synthetic-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
		}),
		base: transportFunc(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("Authorization") != "Bearer synthetic-token" {
				t.Error("request lacks its scoped token")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
	}
	request, err := http.NewRequest(http.MethodGet, testAKSOrigin+"/api", nil)
	require.NoError(t, err)
	var workers sync.WaitGroup
	for range 12 {
		workers.Go(func() {
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Error(err)
				return
			}
			if err := response.Body.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	require.Empty(t, request.Header.Get("Authorization"))
}

func TestAzureTransportTokenSizeBoundaries(t *testing.T) {
	for _, size := range []int{0, maxTokenBytes - 1, maxTokenBytes, maxTokenBytes + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			calls := 0
			transport := &azureBearerTransport{
				origin: testAKSOrigin,
				credential: credentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
					return azcore.AccessToken{Token: strings.Repeat("x", size), ExpiresOn: time.Now().Add(time.Hour)}, nil
				}),
				base: transportFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					require.Len(t, request.Header.Get("Authorization"), len("Bearer ")+size)
					return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
				}),
			}
			request, err := http.NewRequest(http.MethodGet, testAKSOrigin+"/api", nil)
			require.NoError(t, err)
			response, err := transport.RoundTrip(request)
			if size > 0 && size <= maxTokenBytes {
				require.NoError(t, err)
				require.Equal(t, 1, calls)
				require.NoError(t, response.Body.Close())
			} else {
				require.ErrorIs(t, err, ErrCredentials)
				require.Zero(t, calls)
				require.Nil(t, response)
			}
		})
	}
}
