package buildjob

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCanonicalInputDigestAndBoundedBundle(t *testing.T) {
	f := newFixture(t)
	want, err := CanonicalInputDigest(f.input)
	require.NoError(t, err)
	other := f.input
	other.Files = map[string][]byte{
		"source/main.go": f.input.Files["source/main.go"], "recipe.yml": f.input.Files["recipe.yml"],
	}
	other.RequireExisting, other.ExpectedJobUID = true, "previous-job"
	have, err := CanonicalInputDigest(other)
	require.NoError(t, err)
	require.Equal(t, want, have)
	other.InputDigest = "sha256:" + strings.Repeat("f", 64)
	_, err = CanonicalInputDigest(other)
	require.ErrorIs(t, err, ErrInvalid)
	input, policy, err := f.backend.admit(f.input)
	require.NoError(t, err)
	first, err := f.backend.bundle(input, policy)
	require.NoError(t, err)
	second, err := f.backend.bundle(input, policy)
	require.NoError(t, err)
	require.Equal(t, first, second)
	_, restored, err := unpackBundle(first)
	require.NoError(t, err)
	require.Equal(t, f.input.Files, restored.Files)
	require.Equal(t, want, restored.InputDigest)
	other.InputDigest = ""
	other.Files["source/main.go"] = []byte("package changed\n")
	changed, err := CanonicalInputDigest(other)
	require.NoError(t, err)
	require.NotEqual(t, want, changed)
}

func TestSourcePathRejectsTraversalCredentialAndNoncanonicalNames(t *testing.T) {
	for _, name := range []string{
		"", ".", "..", "../main.go", "a/../main.go", "/source/main.go", "a//b.go", "a/./b.go", "a/b/",
		"a\\b.go", "a:\nb.go", "a/.git/config", ".ssh/id_rsa", ".docker/config.json", ".env",
		"data/kubeconfig", "data/credentials", "data/token", "data/key.pem", "data/server.key",
		"first/second.", strings.Repeat("a", 241),
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, SourcePath(name), ErrInvalid)
		})
	}
	for _, name := range []string{"recipe.yml", "source/main.go", "patches/001-build+fix.patch", "file_with_under.go"} {
		require.NoError(t, SourcePath(name))
	}
}

func TestInputRejectsBinaryOversizeAndFileDirectoryCollisions(t *testing.T) {
	for _, test := range []struct {
		name  string
		files map[string][]byte
		kind  error
	}{
		{"binary", map[string][]byte{"payload": {0x7f, 'E', 'L', 'F', 0}}, ErrInvalid},
		{"invalid-utf8", map[string][]byte{"payload": {0xff, 0xfe}}, ErrInvalid},
		{"credential", map[string][]byte{"payload": []byte("-----BEGIN PRIVATE KEY-----\nnot-a-real-key")}, ErrInvalid},
		{"file-directory", map[string][]byte{"source": []byte("file"), "source/file": []byte("nested")}, ErrInvalid},
		{"per-file-bound", map[string][]byte{"large.patch": bytes.Repeat([]byte("x"), 385<<10)}, ErrInvalid},
		{"total-bound", map[string][]byte{
			"first.patch": bytes.Repeat([]byte("x"), 384<<10), "second.patch": bytes.Repeat([]byte("y"), 384<<10),
		}, ErrLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			maps.Copy(f.input.Files, test.files)
			_, err := f.backend.Start(context.Background(), f.input)
			require.ErrorIs(t, err, test.kind)
			require.Zero(t, countActions(f.kube, "create", "jobs"))
			require.Zero(t, countActions(f.kube, "create", "secrets"))
		})
	}
}

func TestOfflineDalecRecipeUsesNoneOrPinnedDefault(t *testing.T) {
	for _, text := range []string{
		"build: []\n",
		"build:\n  network_mode: host\n",
		"build:\n  network_mode: none\n  network_mode: host\n",
		"build:\n  network_mode: none\nother:\n  network_mode: host\n",
		"build:\n  network_mode: none\n  caches: {shared: {}}\n",
		"build: &original\n  network_mode: none\nother: *original\n",
		"build: {network_mode: none}\n---\nbuild: {network_mode: host}\n",
	} {
		require.Error(t, offlineRecipe([]byte(text)))
	}
	require.NoError(t, offlineRecipe([]byte("build:\n  network_mode: none\n  caches: {}\n")))
	require.NoError(t, offlineRecipe([]byte("build:\n  steps:\n    - command: make build\n")))
}

func TestOperatorPoliciesRejectArbitraryOptionsAndMutableImages(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Policy)
	}{
		{"mutable-frontend", func(p *Policy) { p.Frontend = "docker.io/orka/dalec:latest" }},
		{"mutable-worker", func(p *Policy) { p.Worker = "docker.io/orka/worker:latest" }},
		{"registry-export-injection", func(p *Policy) { p.OutputRepository += ",push=false" }},
		{"worker-argument-injection", func(p *Policy) { p.WorkerArg = "HTTP_PROXY" }},
		{"target-option-injection", func(p *Policy) { p.Target = "--allow=network.host" }},
		{"secret-build-arg", func(p *Policy) { p.Args = map[string]string{"TOKEN": "not-a-real-token"} }},
		{"proxy-build-arg", func(p *Policy) { p.Args = map[string]string{"HTTP_PROXY": "http://proxy.invalid"} }},
		{"arbitrary-build-arg", func(p *Policy) { p.Args = map[string]string{"COMMAND": "anything"} }},
		{"negative-epoch", func(p *Policy) { p.Args = map[string]string{"SOURCE_DATE_EPOCH": "-1"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			test.change(&f.config.Policies[0])
			_, err := New(f.config)
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
	f := newFixture(t)
	input := f.input
	input.Target = "another/container"
	_, err := f.backend.Start(context.Background(), input)
	require.ErrorIs(t, err, ErrInvalid)
	input = f.input
	input.Args = map[string]string{"SOURCE_DATE_EPOCH": "100"}
	_, err = f.backend.Start(context.Background(), input)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestBuildKitEndpointAndLimitsAreOperatorBounded(t *testing.T) {
	for _, address := range []string{
		"unix:///run/buildkit/buildkitd.sock", "tcp://127.0.0.1:1234", "tcp://remote.example:1234",
		"tcp://buildkit.other.svc:1234", "tcp://user:password@buildkit.builds.svc:1234",
		"tcp://buildkit.builds.svc:1234/path", "tcp://buildkit.builds.svc:1234?insecure=true",
		"tcp://buildkit.builds.svc:70000", "tcp://buildkit.builds.svc",
	} {
		require.Error(t, validateEndpoint("builds", address, nil))
	}
	require.NoError(t, validateEndpoint("builds", "tcp://buildkit.builds.svc.cluster.local:1234",
		&TLS{CASecretName: "buildkit-public-ca", ClientSecretName: "buildkit-client", ServerName: "buildkit.builds.svc.cluster.local"}))
	require.Error(t, validateEndpoint("builds", "tcp://buildkit.builds.svc:1234",
		&TLS{CASecretName: "ca", ClientSecretName: "client", ServerName: "another.builds.svc"}))
	for _, change := range []func(*Config){
		func(c *Config) { c.Namespace = "default" },
		func(c *Config) { c.Namespace = "kube-system" },
		func(c *Config) { c.WorkerImage = "docker.io/orka/trusted-client:latest" },
		func(c *Config) { c.Limits.CPU = "4001m" },
		func(c *Config) { c.Limits.Memory = "9Gi" },
		func(c *Config) { c.Limits.MaxInputBytes = MaxInputBytes + 1 },
		func(c *Config) { c.Limits.MaxFiles = 513 },
		func(c *Config) { c.Limits.MaxOperations = 65 },
		func(c *Config) { c.Limits.BuildTimeout = 61 * time.Minute },
	} {
		f := newFixture(t)
		change(&f.config)
		_, err := New(f.config)
		require.ErrorIs(t, err, ErrInvalid)
	}
	f := newFixture(t)
	f.config.Limits.CPU, f.config.Limits.Memory = "4", "8Gi"
	_, err := New(f.config)
	require.NoError(t, err)
}

func TestOperatorPolicySnapshotCannotBeMutatedByCaller(t *testing.T) {
	f := newFixture(t)
	config := f.config
	config.Policies = append([]Policy{}, config.Policies...)
	config.Policies[0].Args = map[string]string{"SOURCE_DATE_EPOCH": "100"}
	backend, err := New(config)
	require.NoError(t, err)
	input := f.input
	input.Args = maps.Clone(config.Policies[0].Args)
	config.Policies[0].Args["SOURCE_DATE_EPOCH"] = "200"
	config.Policies[0].SourcePaths[0] = "other/source.go"
	_, err = backend.Start(context.Background(), input)
	require.NoError(t, err)
	input.Args["SOURCE_DATE_EPOCH"] = "200"
	_, err = backend.Start(context.Background(), input)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestPinnedTagsAreImmutableButTagsAloneAreNot(t *testing.T) {
	image := strings.Replace(testImage("worker", "a"), "@sha256:", ":v1@sha256:", 1)
	require.True(t, immutableImage(image))
	require.False(t, immutableImage("docker.io/orka/worker:v1"))
	require.False(t, immutableImage("docker.io/orka/worker@sha256:short"))
}

func TestWorkerSelectorRequiresExactlyOneApprovedForm(t *testing.T) {
	for _, pair := range []struct{ argument, contextName string }{
		{"", ""}, {"DALEC_CUSTOM_WORKER", "dalec-azlinux3-worker"},
		{"", "context"}, {"", "dockerfile"}, {"", "source"},
		{"", "worker=anything"}, {"", "worker\n--allow"}, {"", strings.Repeat("a", 64)},
		{"TOKEN", ""},
	} {
		require.False(t, validWorkerSelector(pair.argument, pair.contextName))
	}
	f := newFixture(t)
	f.config.Policies[0].WorkerArg = ""
	f.config.Policies[0].WorkerContext = "dalec-azlinux3-worker"
	backend, err := New(f.config)
	require.NoError(t, err)
	f.input.WorkerArg, f.input.WorkerContext = "", "dalec-azlinux3-worker"
	r, err := backend.Start(t.Context(), f.input)
	require.NoError(t, err)
	require.Equal(t, backend.ConfigurationDigest(), r.ConfigurationDigest)
	f.input.WorkerContext = "another-worker"
	_, err = backend.Start(t.Context(), f.input)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestPerRunOperationLimitIncludesRetainedCleanupLedgers(t *testing.T) {
	f := newFixture(t, func(config *Config) { config.Limits.MaxOperations = 1 })
	r := f.start(t)
	_, err := f.backend.Start(context.Background(), f.input)
	require.NoError(t, err)
	next := f.input
	next.OperationID = "operation-two"
	_, err = f.backend.Start(context.Background(), next)
	require.ErrorIs(t, err, ErrLimit)
	f.pod(t, r, goodResult(r))
	require.NoError(t, f.backend.Cancel(context.Background(), r))
	_, err = f.backend.Start(context.Background(), next)
	require.ErrorIs(t, err, ErrLimit)
	_, err = f.backend.Start(context.Background(), f.input)
	require.ErrorIs(t, err, ErrLost)
}

func TestArchiveRejectsLinksDuplicatesAndTrailingData(t *testing.T) {
	limits := Limits{}
	defaultLimits(&limits)
	for _, entries := range [][]*tar.Header{
		{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "outside", Mode: 0600}},
		{{Name: "link", Typeflag: tar.TypeLink, Linkname: "outside", Mode: 0600}},
		{{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0600}},
		{{Name: "file", Typeflag: tar.TypeReg, Mode: 0600}, {Name: "file", Typeflag: tar.TypeReg, Mode: 0600}},
		{{Name: "file", Typeflag: tar.TypeReg, Mode: 0700}},
	} {
		var encoded bytes.Buffer
		zip := gzip.NewWriter(&encoded)
		archive := tar.NewWriter(zip)
		for _, entry := range entries {
			require.NoError(t, archive.WriteHeader(entry))
		}
		require.NoError(t, archive.Close())
		require.NoError(t, zip.Close())
		_, err := unpackArchive(encoded.Bytes(), limits)
		require.Error(t, err)
	}
	f := newFixture(t)
	input, policy, err := f.backend.admit(f.input)
	require.NoError(t, err)
	data, err := f.backend.bundle(input, policy)
	require.NoError(t, err)
	_, err = unpackArchive(append(bytes.Clone(data[archiveKey]), []byte("unbound-trailer")...), limits)
	require.Error(t, err)
	data[manifestKey] = bytes.Replace(data[manifestKey], []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	_, _, err = unpackBundle(data)
	require.Error(t, err)
}
