package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func azureControllerFixture(t *testing.T) (ControllerAdapterConfig, *clientcmdapi.Config) {
	t.Helper()
	root := t.TempDir()
	configFile := filepath.Join(root, "lab.kubeconfig")
	tokenFile := filepath.Join(root, "projected-token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("synthetic-projected-assertion"), 0600))
	raw := clientcmdapi.NewConfig()
	raw.CurrentContext = "verification"
	raw.Contexts["verification"] = &clientcmdapi.Context{Cluster: "verification", AuthInfo: "federated"}
	raw.Clusters["verification"] = &clientcmdapi.Cluster{
		Server: "https://verification.eastus2.azmk8s.io", CertificateAuthorityData: []byte("approved-cluster-ca"),
	}
	raw.AuthInfos["federated"] = &clientcmdapi.AuthInfo{}
	require.NoError(t, clientcmd.WriteToFile(*raw, configFile))
	require.NoError(t, os.Chmod(configFile, 0600))
	document, err := json.Marshal(map[string]any{
		"kubeconfig": configFile, "context": "verification",
		"azureWorkloadIdentity": map[string]string{
			"tenantID": "11111111-1111-4111-8111-111111111111",
			"clientID": "22222222-2222-4222-8222-222222222222", "federatedTokenFile": tokenFile,
		},
	})
	require.NoError(t, err)
	var config ControllerAdapterConfig
	require.NoError(t, json.Unmarshal(document, &config))
	return config, raw
}

func TestControllerAzureWorkloadIdentityInstallsRenewableTransport(t *testing.T) {
	config, _ := azureControllerFixture(t)
	rest, err := controllerRESTConfig(config)
	require.NoError(t, err)
	require.NotNil(t, rest.WrapTransport, "explicit Azure policy must not become an anonymous static client")
	require.Empty(t, rest.BearerToken)
	require.Empty(t, rest.BearerTokenFile)
	require.Nil(t, rest.ExecProvider)
	require.Nil(t, rest.AuthProvider)
}

func TestControllerAzureWorkloadIdentityRejectsMixedOrExecutableCredentials(t *testing.T) {
	for _, mutate := range []struct {
		name   string
		change func(*clientcmdapi.AuthInfo)
	}{
		{"static-token", func(auth *clientcmdapi.AuthInfo) { auth.Token = "synthetic-static-token" }},
		{"exec", func(auth *clientcmdapi.AuthInfo) { auth.Exec = &clientcmdapi.ExecConfig{Command: "must-not-run"} }},
		{"auth-provider", func(auth *clientcmdapi.AuthInfo) { auth.AuthProvider = &clientcmdapi.AuthProviderConfig{Name: "azure"} }},
		{"impersonate", func(auth *clientcmdapi.AuthInfo) { auth.Impersonate = "different-user" }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			config, raw := azureControllerFixture(t)
			mutate.change(raw.AuthInfos["federated"])
			require.NoError(t, clientcmd.WriteToFile(*raw, config.Kubeconfig))
			_, err := controllerRESTConfig(config)
			require.ErrorIs(t, err, ErrPolicy)
		})
	}
}

func TestControllerAzureConfigurationIsAbsentFromLegacyDigest(t *testing.T) {
	raw, err := json.Marshal(ControllerAdapterConfig{})
	require.NoError(t, err)
	require.NotContains(t, string(raw), "azureWorkloadIdentity")
}
