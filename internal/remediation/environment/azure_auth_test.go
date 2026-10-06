package environment

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestDedicatedClientDoesNotIgnoreExplicitAzureCredentials(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("configuration must not authenticate or execute a request")
	}))
	t.Cleanup(server.Close)
	root := t.TempDir()
	filename := filepath.Join(root, "lab.kubeconfig")
	raw := clientcmdapi.NewConfig()
	raw.CurrentContext = "verification"
	raw.Contexts["verification"] = &clientcmdapi.Context{Cluster: "verification", AuthInfo: "federated"}
	raw.Clusters["verification"] = &clientcmdapi.Cluster{
		Server: "https://verification.eastus2.azmk8s.io",
		CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
		}),
	}
	raw.AuthInfos["federated"] = &clientcmdapi.AuthInfo{}
	require.NoError(t, clientcmd.WriteToFile(*raw, filename))
	require.NoError(t, os.Chmod(filename, 0600))
	document, err := json.Marshal(map[string]any{
		"Kubeconfig": filename, "Context": "verification",
		"AzureWorkloadIdentity": map[string]string{
			"tenantID":           "11111111-1111-4111-8111-111111111111",
			"clientID":           "22222222-2222-4222-8222-222222222222",
			"federatedTokenFile": filepath.Join(root, "missing-token"),
		},
	})
	require.NoError(t, err)
	var config KubernetesConfig
	require.NoError(t, json.Unmarshal(document, &config))
	_, err = dedicatedClient(config)
	require.Equal(t, failure(NeedsAdapter, "invalid-azure-workload-identity"), err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "missing-token"), []byte("synthetic-projected-assertion"), 0600))
	client, err := dedicatedClient(config)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestAzureKubernetesConfigurationPreservesLegacySerialization(t *testing.T) {
	raw, err := json.Marshal(KubernetesConfig{Kubeconfig: "/private/lab", Context: "verification", ObserverCIDRs: []string{"10.0.0.1/32"}})
	require.NoError(t, err)
	require.Equal(t, `{"Kubeconfig":"/private/lab","Context":"verification","ObserverCIDRs":["10.0.0.1/32"]}`, string(raw))
}
