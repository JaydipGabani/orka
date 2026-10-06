package environment

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NewForCleanup uses the saved operator connection and run journal, without
// requiring current recipe files or permission to admit another workload.
func NewForCleanup(config Config) (*Adapter, error) {
	adapter, err := newCleanupAdapter(config)
	if err != nil {
		return nil, err
	}
	kube, err := dedicatedClient(*adapter.config.Kubernetes)
	if err != nil {
		return nil, err
	}
	adapter.kube = kube
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	namespace, err := kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || namespace.UID == "" {
		return nil, failure(Infrastructure, "cleanup-cluster-identity-unavailable")
	}
	adapter.clusterIdentity = isolationClusterIdentity(string(namespace.UID))
	return adapter, nil
}

func newCleanupAdapter(config Config) (*Adapter, error) {
	raw, err := json.Marshal(config)
	if err != nil || len(raw) > 2<<20 {
		return nil, failure(Unknown, "invalid-cleanup-configuration")
	}
	var saved Config
	if json.Unmarshal(raw, &saved) != nil || saved.Kubernetes == nil {
		return nil, failure(Unknown, "invalid-cleanup-configuration")
	}
	setDefaults(&saved.Limits)
	if saved.TemporaryRoot == "" {
		saved.TemporaryRoot = saved.OutputRoot
	}
	if validateLimits(saved.Limits) != nil || !exactDirectory(saved.OutputRoot) {
		return nil, failure(Unknown, "cleanup-journal-unavailable")
	}
	info, err := os.Stat(saved.OutputRoot)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return nil, failure(Unknown, "unsafe-cleanup-journal")
	}
	for i := range saved.ImageBindings {
		saved.ImageBindings[i].ChecksDigest = ""
	}
	raw, err = json.Marshal(saved)
	if err != nil {
		return nil, failure(Unknown, "invalid-cleanup-configuration")
	}
	return &Adapter{
		config: saved, digest: digest(raw), now: time.Now,
		http: &http.Client{Timeout: saved.Limits.ProbeTimeout, Transport: &http.Transport{Proxy: nil}},
	}, nil
}
