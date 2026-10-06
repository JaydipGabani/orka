package environment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/distribution/reference"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var (
	idPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
	commitPattern = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	argPattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	secretPattern = regexp.MustCompile(`(?i)(-----BEGIN .*PRIVATE KEY-----|(?:password|passwd|secret|token|credential|api[_-]?key|authorization|bearer|cookie)\s*[:= ]\s*[a-z0-9+/_.-]+|[a-z]+://[^ /]+@)`)
)

type Adapter struct {
	config          Config
	digest          string
	catalog         []catalogEntry
	clusterIdentity string
	kube            kubernetes.Interface
	http            *http.Client
	now             func() time.Time
}

func New(config Config) (*Adapter, error) {
	a, err := newAdapter(config)
	if err != nil {
		return nil, err
	}
	if a.config.Kubernetes != nil {
		client, err := dedicatedClient(*a.config.Kubernetes)
		if err != nil {
			return nil, err
		}
		a.kube = client
		probe, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cluster, err := client.CoreV1().Namespaces().Get(probe, "kube-system", metav1.GetOptions{})
		if err != nil || cluster.UID == "" {
			return nil, failure(NeedsAdapter, "approved-kubernetes-identity-unavailable")
		}
		a.clusterIdentity = jsonDigest(struct{ Domain, UID string }{
			"orka.remediation.environment.cluster.v1", string(cluster.UID),
		})
	}
	return a, nil
}

func newAdapter(config Config) (*Adapter, error) {
	// Configuration is copied once: a caller mutating slices after admission
	// cannot change the trust boundary or the digest of an active operation.
	data, err := json.Marshal(config)
	if err != nil || len(data) > 2<<20 {
		return nil, failure(NeedsAdapter, "invalid-operator-configuration")
	}
	var frozen Config
	if json.Unmarshal(data, &frozen) != nil {
		return nil, failure(NeedsAdapter, "invalid-operator-configuration")
	}
	for i := range frozen.ImageBindings {
		frozen.ImageBindings[i].ChecksDigest = ""
	}
	setDefaults(&frozen.Limits)
	if frozen.TemporaryRoot == "" {
		frozen.TemporaryRoot = frozen.OutputRoot
	}
	if err := validateConfig(frozen); err != nil {
		return nil, err
	}
	catalog, err := loadCatalog(frozen)
	if err != nil {
		return nil, err
	}
	data, _ = json.Marshal(frozen)
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: frozen.Limits.ProbeTimeout,
	}
	adapter := &Adapter{
		config: frozen, digest: digest(data), catalog: catalog, now: time.Now,
		http: &http.Client{
			Transport: transport, Timeout: frozen.Limits.ProbeTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if frozen.Kubernetes != nil {
		// Unit tests inject a fake client; public New replaces this with the
		// authenticated API-server namespace UID before exposing the adapter.
		adapter.clusterIdentity = jsonDigest(struct{ Domain, Context, Path string }{
			"orka.remediation.environment.injected-cluster.v1", frozen.Kubernetes.Context, frozen.Kubernetes.Kubeconfig,
		})
	}
	return adapter, nil
}

func setDefaults(l *Limits) {
	if l.MaxNamespaces == 0 {
		l.MaxNamespaces = 4
	}
	if l.MaxResources == 0 {
		l.MaxResources = 4
	}
	if l.MaxChecks == 0 {
		l.MaxChecks = 16
	}
	if l.MaxActiveRuns == 0 {
		l.MaxActiveRuns = 2
	}
	if l.MaxOperations == 0 {
		l.MaxOperations = 32
	}
	if l.MaxPlanBytes == 0 {
		l.MaxPlanBytes = 64 << 10
	}
	if l.MaxBodyBytes == 0 {
		l.MaxBodyBytes = 16 << 10
	}
	if l.MaxOutputBytes == 0 {
		l.MaxOutputBytes = 64 << 10
	}
	if l.OperationTimeout == 0 {
		l.OperationTimeout = 5 * time.Minute
	}
	if l.ProbeTimeout == 0 {
		l.ProbeTimeout = 5 * time.Second
	}
	if l.BuildTimeout == 0 {
		l.BuildTimeout = 20 * time.Minute
	}
	if l.PodCPU == "" {
		l.PodCPU = "250m"
	}
	if l.PodMemory == "" {
		l.PodMemory = "256Mi"
	}
}

func validateConfig(c Config) error {
	if err := validateLimits(c.Limits); err != nil {
		return err
	}
	if !idPattern.MatchString(c.SyntheticScope) || len(c.Repositories) > 32 ||
		len(c.AllowedGVKs) > 16 || len(c.ImageBindings) > 256 {
		return failure(NeedsAdapter, "invalid-operator-configuration")
	}
	for _, repo := range c.Repositories {
		for _, writable := range []string{c.OutputRoot, c.TemporaryRoot} {
			if overlappingRoots(repo.RecipeRoot, writable) {
				return failure(NeedsAdapter, "recipe-catalog-must-be-read-only")
			}
		}
	}
	for _, root := range []string{c.OutputRoot, c.TemporaryRoot} {
		if err := privateRoot(root); err != nil {
			return err
		}
	}
	if c.Kubernetes != nil {
		if err := validateObserverPolicy(*c.Kubernetes); err != nil {
			return err
		}
	}
	ids, urls := map[string]bool{}, map[string]bool{}
	for _, repo := range c.Repositories {
		if ids[repo.ID] || urls[repo.URL] {
			return failure(NeedsAdapter, "duplicate-repository-policy")
		}
		if err := validateRepositoryPolicy(repo); err != nil {
			return err
		}
		ids[repo.ID], urls[repo.URL] = true, true
	}
	if c.BuildKit != nil {
		if err := validateBuildKit(*c.BuildKit); err != nil {
			return err
		}
	}
	return validateImageBindings(c.ImageBindings)
}

func validateLimits(l Limits) error {
	if l.MaxNamespaces < 1 || l.MaxNamespaces > 4 || l.MaxResources < 1 || l.MaxResources > 8 ||
		l.MaxChecks < 1 || l.MaxChecks > 64 || l.MaxActiveRuns < 1 || l.MaxActiveRuns > 8 ||
		l.MaxOperations < 1 || l.MaxOperations > 128 ||
		l.MaxPlanBytes < 1024 || l.MaxPlanBytes > 256<<10 ||
		l.MaxBodyBytes < 1 || l.MaxBodyBytes > 64<<10 ||
		l.MaxOutputBytes < 1024 || l.MaxOutputBytes > 1<<20 ||
		l.OperationTimeout < time.Second || l.OperationTimeout > 30*time.Minute ||
		l.ProbeTimeout < time.Millisecond || l.ProbeTimeout > 30*time.Second ||
		l.BuildTimeout < time.Second || l.BuildTimeout > 60*time.Minute {
		return failure(NeedsAdapter, "invalid-operator-limits")
	}
	for _, bound := range []struct{ value, ceiling string }{{l.PodCPU, "2"}, {l.PodMemory, "2Gi"}} {
		q, err := resource.ParseQuantity(bound.value)
		if err != nil || q.Sign() <= 0 || q.Cmp(resource.MustParse(bound.ceiling)) > 0 {
			return failure(NeedsAdapter, "invalid-pod-resource-limits")
		}
	}
	return nil
}

func validateObserverPolicy(c KubernetesConfig) error {
	if len(c.ObserverCIDRs) == 0 || len(c.ObserverCIDRs) > 8 {
		return failure(NeedsAdapter, "approved-observer-cidrs-required")
	}
	for _, value := range c.ObserverCIDRs {
		ip, network, err := net.ParseCIDR(value)
		if err != nil || ip.IsUnspecified() || network.String() != value {
			return failure(NeedsAdapter, "invalid-observer-cidr")
		}
	}
	return nil
}

func validateRepositoryPolicy(repo RepositoryPolicy) error {
	if !idPattern.MatchString(repo.ID) || !repositoryURL(repo.URL) ||
		!repositoryURL(repo.RecipeRepository) || len(repo.Recipes) == 0 || len(repo.Recipes) > 32 ||
		len(repo.HTTPPorts) > 16 || len(repo.CheckCapabilities) > 16 {
		return failure(NeedsAdapter, "invalid-repository-policy")
	}
	if !exactDirectory(repo.RecipeRoot) || (repo.SourceRoot != "" && !exactDirectory(repo.SourceRoot)) {
		return failure(NeedsAdapter, "approved-repository-root-unavailable")
	}
	for _, capability := range repo.CheckCapabilities {
		if !idPattern.MatchString(capability) {
			return failure(NeedsAdapter, "invalid-check-capability-name")
		}
	}
	for _, port := range repo.HTTPPorts {
		if port < 1024 || port > 65535 {
			return failure(NeedsAdapter, "invalid-approved-http-port")
		}
	}
	ids := map[string]bool{}
	for _, recipe := range repo.Recipes {
		if ids[recipe.ID] {
			return failure(NeedsAdapter, "duplicate-recipe-policy")
		}
		if err := validateRecipePolicy(recipe); err != nil {
			return err
		}
		ids[recipe.ID] = true
	}
	return nil
}

func validateRecipePolicy(recipe RecipePolicy) error {
	if !idPattern.MatchString(recipe.ID) || !commitPattern.MatchString(recipe.Commit) ||
		(recipe.CatalogDirectory != "" && !relativePath(recipe.CatalogDirectory)) ||
		!relativePath(recipe.Path) || !digestPattern.MatchString(recipe.Files[recipe.Path]) ||
		len(recipe.Files) > 256 || !relativePath(recipe.Target) ||
		!regexp.MustCompile(`^linux/(amd64|arm64)(/v[0-9]+)?$`).MatchString(recipe.Platform) ||
		!immutableImage(recipe.FrontendImage) || !immutableImage(recipe.WorkerImage) ||
		!immutableImage(recipe.OriginalImage) {
		return failure(NeedsAdapter, "invalid-recipe-policy")
	}
	for name, sum := range recipe.Files {
		if !relativePath(name) || !digestPattern.MatchString(sum) {
			return failure(NeedsAdapter, "invalid-approved-recipe-file")
		}
	}
	return nil
}

func validateBuildKit(b BuildKitConfig) error {
	if len(b.Command) == 0 || len(b.Command) > 32 || !filepath.IsAbs(b.Command[0]) ||
		!digestPattern.MatchString(b.ExecutableDigest) || !argPattern.MatchString(b.WorkerImageArgument) ||
		!digestPattern.MatchString(b.WorkerEvidenceDigest) || !buildAddress(b.Address) {
		return failure(NeedsAdapter, "invalid-buildkit-configuration")
	}
	named, err := reference.ParseNormalizedNamed(b.OutputRepository)
	if err != nil || !reference.IsNameOnly(named) || named.String() != b.OutputRepository {
		return failure(NeedsAdapter, "invalid-build-output-repository")
	}
	for _, arg := range b.Command {
		if len(arg) > 1024 || strings.ContainsAny(arg, "\x00\r\n") || secretPattern.MatchString(arg) {
			return failure(NeedsAdapter, "invalid-buildctl-command")
		}
	}
	return nil
}

func validateImageBindings(images []ImageBinding) error {
	bindings := map[string]bool{}
	for _, b := range images {
		if !idPattern.MatchString(b.ID) || bindings[b.ID] || !immutableImage(b.Image) ||
			!digestPattern.MatchString(b.EvidenceDigest) ||
			!commitPattern.MatchString(b.SourceTarget.Commit) || !validRole(b.Role) ||
			(b.Role == Candidate && !digestPattern.MatchString(b.PatchDigest)) ||
			(b.Role != Candidate && b.PatchDigest != "") {
			return failure(NeedsAdapter, "invalid-external-image-binding")
		}
		bindings[b.ID] = true
	}
	return nil
}

func dedicatedClient(c KubernetesConfig) (kubernetes.Interface, error) {
	if !filepath.IsAbs(c.Kubeconfig) || c.Context == "" || len(c.Context) > 256 {
		return nil, failure(NeedsAdapter, "dedicated-kubeconfig-required")
	}
	file, err := os.Lstat(c.Kubeconfig)
	if err != nil || !file.Mode().IsRegular() || file.Mode().Perm()&0077 != 0 || file.Size() > 1<<20 {
		return nil, failure(NeedsAdapter, "private-kubeconfig-required")
	}
	data, err := os.ReadFile(c.Kubeconfig)
	if err != nil {
		return nil, failure(NeedsAdapter, "kubeconfig-unavailable")
	}
	raw, err := clientcmd.Load(data)
	if err != nil || raw.Contexts[c.Context] == nil {
		return nil, failure(NeedsAdapter, "approved-context-unavailable")
	}
	selected := raw.Contexts[c.Context]
	auth, cluster := raw.AuthInfos[selected.AuthInfo], raw.Clusters[selected.Cluster]
	if !selfContainedKubeconfig(auth, cluster) {
		return nil, failure(NeedsAdapter, "self-contained-kubeconfig-required")
	}
	server, err := url.Parse(cluster.Server)
	if err != nil || server.Scheme != "https" || server.User != nil || server.Hostname() == "" ||
		server.RawQuery != "" || server.Fragment != "" {
		return nil, failure(NeedsAdapter, "verified-kubernetes-tls-required")
	}
	rest, err := clientcmd.NewNonInteractiveClientConfig(*raw, c.Context, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil {
		return nil, failure(NeedsAdapter, "approved-context-unavailable")
	}
	rest.Timeout, rest.QPS, rest.Burst = 10*time.Second, 5, 10
	// Explicitly disable environment-controlled proxies for this dedicated
	// client. Kubeconfig material is never copied into a subject or builder.
	rest.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	client, err := kubernetes.NewForConfig(rest)
	if err != nil {
		return nil, failure(NeedsAdapter, "kubernetes-client-unavailable")
	}
	return client, nil
}

func selfContainedKubeconfig(auth *clientcmdapi.AuthInfo, cluster *clientcmdapi.Cluster) bool {
	return auth != nil && cluster != nil && auth.Exec == nil && auth.AuthProvider == nil &&
		auth.TokenFile == "" && auth.ClientCertificate == "" && auth.ClientKey == "" &&
		auth.Impersonate == "" && auth.ImpersonateUID == "" &&
		len(auth.ImpersonateGroups) == 0 && len(auth.ImpersonateUserExtra) == 0 &&
		!cluster.InsecureSkipTLSVerify && cluster.ProxyURL == "" && cluster.CertificateAuthority == ""
}

func privateRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || forbiddenTemporaryPath(root) {
		return failure(NeedsAdapter, "private-output-root-required")
	}
	if err := os.MkdirAll(root, 0700); err != nil || !exactDirectory(root) {
		return failure(Infrastructure, "private-output-root-unavailable")
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return failure(NeedsAdapter, "private-output-root-permissions")
	}
	return nil
}

func forbiddenTemporaryPath(root string) bool {
	return root == "/" || root == "/tmp" || root == "/var/tmp"
}

func exactDirectory(root string) bool {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return false
	}
	info, err := os.Stat(root)
	return err == nil && info.IsDir()
}

func overlappingRoots(first, second string) bool {
	inside := func(root, candidate string) bool {
		relative, err := filepath.Rel(root, candidate)
		return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	return inside(first, second) || inside(second, first)
}

func repositoryURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		u.RawQuery == "" && u.Fragment == "" && u.Path != "" && u.Path != "/" &&
		!strings.ContainsAny(value, "\x00\r\n\t ")
}

func buildAddress(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		u.Scheme == "unix" && u.Host == "" && filepath.IsAbs(u.Path)
}

func immutableImage(value string) bool {
	named, err := reference.ParseNormalizedNamed(value)
	if err != nil {
		return false
	}
	pinned, ok := named.(reference.Digested)
	return ok && digestPattern.MatchString(pinned.Digest().String()) && !secretPattern.MatchString(value)
}

func relativePath(value string) bool {
	if value == "" || len(value) > 512 || path.Clean(value) != value || path.IsAbs(value) ||
		strings.ContainsAny(value, "\\\x00\r\n\t :") || value == "." {
		return false
	}
	for part := range strings.SplitSeq(value, "/") {
		if part == ".." || strings.EqualFold(part, ".git") {
			return false
		}
	}
	return true
}

func validRole(role Role) bool {
	return slices.Contains([]Role{PublishedOriginal, RebuiltControl, Candidate}, role)
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func jsonDigest(value any) string {
	data, _ := json.Marshal(value)
	return digest(data)
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, failure(Infrastructure, "bounded-read-failed")
	}
	return data, nil
}
