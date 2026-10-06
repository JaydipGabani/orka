//go:build linux

package buildjob

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv("ORKA_BUILDJOB_HELPER"); mode != "" {
		os.Exit(buildctlHelper(mode))
	}
	// Test filesystem operations stay inside this package, including child
	// process scratch files. No OS temporary directory or host source checkout
	// is mounted into a staged build context.
	root := ".buildjob-test-work-" + strconv.Itoa(os.Getpid())
	if os.Mkdir(root, 0700) != nil || os.Setenv("ORKA_BUILDJOB_TEST_ROOT", root) != nil {
		os.Exit(1)
	}
	code := m.Run()
	if os.RemoveAll(root) != nil && code == 0 {
		code = 1
	}
	os.Exit(code)
}

func testDirectory(t *testing.T) string {
	t.Helper()
	random := make([]byte, 16)
	_, err := rand.Read(random)
	require.NoError(t, err)
	directory := filepath.Join(os.Getenv("ORKA_BUILDJOB_TEST_ROOT"), hex.EncodeToString(random))
	require.NoError(t, os.Mkdir(directory, 0700))
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(directory)) })
	absolute, err := filepath.Abs(directory)
	require.NoError(t, err)
	return absolute
}

func workerFixture(t *testing.T, f *fixture) (WorkerOptions, *bytes.Buffer) {
	t.Helper()
	directory := testDirectory(t)
	bundle, workspace := filepath.Join(directory, "bundle"), filepath.Join(directory, "workspace")
	require.NoError(t, os.Mkdir(bundle, 0700))
	require.NoError(t, os.Mkdir(workspace, 0700))
	input, policy, err := f.backend.admit(f.input)
	require.NoError(t, err)
	data, err := f.backend.bundle(input, policy)
	require.NoError(t, err)
	for name, content := range data {
		require.NoError(t, os.WriteFile(filepath.Join(bundle, name), content, 0400))
	}
	termination := filepath.Join(directory, "termination.json")
	require.NoError(t, os.WriteFile(termination, nil, 0600))
	var output bytes.Buffer
	return WorkerOptions{
		BundleDirectory: bundle, WorkspaceDirectory: workspace, TerminationPath: termination, PhaseOutput: &output,
	}, &output
}

func helperProcess(t *testing.T, mode string) buildctlProcess {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)
	return buildctlProcess{executable: executable, environment: []string{"ORKA_BUILDJOB_HELPER=" + mode}}
}

func readTermination(t *testing.T, options WorkerOptions) WorkerResult {
	t.Helper()
	body, err := os.ReadFile(options.TerminationPath)
	require.NoError(t, err)
	require.LessOrEqual(t, len(body), MaxTerminationBytes)
	var result WorkerResult
	require.NoError(t, decodeStrict(body, &result))
	return result
}

func TestWorkerRealProcessMetadataAndLogBounds(t *testing.T) {
	for _, test := range []struct {
		mode    string
		outcome BuildOutcome
		exit    int
	}{
		{"success", Success, 0},
		{"worker-arg", Success, 0},
		{"mutual-tls", Success, 0},
		{"verbose", Success, 0},
		{"compile", CompileFailure, 1},
		{"infrastructure", Infrastructure, 1},
		{"output-forgery", Infrastructure, 1},
		{"metadata-missing", Infrastructure, 1},
		{"metadata-mutable", Infrastructure, 1},
		{"metadata-duplicate", Infrastructure, 1},
		{"metadata-symlink", Infrastructure, 1},
		{"metadata-hardlink", Infrastructure, 1},
		{"metadata-fifo", Infrastructure, 1},
		{"metadata-oversized", Infrastructure, 1},
	} {
		t.Run(test.mode, func(t *testing.T) {
			f := newFixture(t, func(config *Config) { config.Limits.MaxLogBytes = 1024 })
			options, output := workerFixture(t, f)
			t.Setenv("BUILD_JOB_MUST_NOT_INHERIT", "host-environment-marker")
			exit := runWorker(context.Background(), options, helperProcess(t, test.mode))
			require.Equal(t, test.exit, exit)
			result := readTermination(t, options)
			require.Equal(t, test.outcome, result.BuildOutcome)
			wantDigest, err := CanonicalInputDigest(f.input)
			require.NoError(t, err)
			require.Equal(t, wantDigest, result.InputDigest)
			require.NotContains(t, output.String(), "PRIVATE-SOURCE")
			require.NotContains(t, output.String(), "HiddenSymbol")
			require.NotContains(t, output.String(), "untrusted-success")
			require.Contains(t, output.String(), `"phase":"finished"`)
			if test.outcome == Success {
				require.Equal(t, "sha256:"+strings.Repeat("e", 64), result.ImmutableImageDigest)
			} else {
				require.Empty(t, result.ImmutableImageDigest)
			}
			if test.mode == "verbose" {
				require.True(t, result.OutputTruncated)
			}
			if test.mode == "compile" {
				require.Equal(t, []Diagnostic{{Path: "source/main.go", Line: 7, Column: 3}}, result.Diagnostics)
			}
			_, err = os.Stat(filepath.Join(options.WorkspaceDirectory, "build"))
			require.True(t, os.IsNotExist(err))
		})
	}
}

func TestWorkerTimesOutClientWithoutTreatingItAsCompileFailure(t *testing.T) {
	f := newFixture(t, func(config *Config) { config.Limits.BuildTimeout = time.Second })
	options, _ := workerFixture(t, f)
	start := time.Now()
	require.Equal(t, 1, runWorker(context.Background(), options, helperProcess(t, "sleep")))
	require.Less(t, time.Since(start), 5*time.Second)
	result := readTermination(t, options)
	require.Equal(t, Infrastructure, result.BuildOutcome)
	require.Empty(t, result.ImmutableImageDigest)
}

func TestWorkerCallerCancellationRecordsCancelledOutcome(t *testing.T) {
	f := newFixture(t)
	options, _ := workerFixture(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	options.PhaseOutput = writerFunc(func(body []byte) (int, error) {
		if bytes.Contains(body, []byte(`"phase":"building"`)) {
			cancel()
		}
		return len(body), nil
	})
	require.Equal(t, 1, runWorker(ctx, options, helperProcess(t, "sleep")))
	require.Equal(t, Cancelled, readTermination(t, options).BuildOutcome)
}

func TestWorkerCancellationStopsTheActualClientProcess(t *testing.T) {
	f := newFixture(t)
	options, _ := workerFixture(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan int, 1)
	process := helperProcess(t, "sleep-with-pid")
	go func() { done <- runWorker(ctx, options, process) }()
	pidFile := filepath.Join(options.WorkspaceDirectory, "build", "child.pid")
	var pid int
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(string(data))
		return err == nil && pid > 0
	}, 3*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case exit := <-done:
		require.Equal(t, 1, exit)
	case <-time.After(3 * time.Second):
		require.FailNow(t, "cancelled buildctl subprocess did not stop")
	}
	require.ErrorIs(t, unix.Kill(pid, 0), unix.ESRCH)
	require.Equal(t, Cancelled, readTermination(t, options).BuildOutcome)
	require.True(t, readTermination(t, options).DaemonSettled)
	require.Equal(t, "fixture-build-ref", readTermination(t, options).BuildRef)
}

type writerFunc func([]byte) (int, error)

func (write writerFunc) Write(body []byte) (int, error) { return write(body) }

func TestSourceBytesNeverExecuteAndExistingWorkspacesAreNotConsumed(t *testing.T) {
	f := newFixture(t)
	f.input.Files["candidate.sh"] = []byte("#!/bin/sh\nprintf unsafe > candidate-executed\n")
	options, _ := workerFixture(t, f)
	require.Equal(t, 0, runWorker(context.Background(), options, helperProcess(t, "source-mode")))
	_, err := os.Stat(filepath.Join(options.WorkspaceDirectory, "build", "candidate-executed"))
	require.True(t, os.IsNotExist(err))
	require.NoError(t, os.Mkdir(filepath.Join(options.WorkspaceDirectory, "build"), 0700))
	marker := filepath.Join(options.WorkspaceDirectory, "build", "existing")
	require.NoError(t, os.WriteFile(marker, []byte("must survive refused retry"), 0600))
	require.Equal(t, 1, runWorker(context.Background(), options, helperProcess(t, "success")))
	body, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, "must survive refused retry", string(body))
}

func TestWorkerBundleAllowsOnlyConfinedSecretProjectionSymlinks(t *testing.T) {
	f := newFixture(t)
	options, _ := workerFixture(t, f)
	projected := filepath.Join(options.BundleDirectory, "..data-version")
	require.NoError(t, os.Mkdir(projected, 0700))
	for _, name := range []string{manifestKey, archiveKey} {
		require.NoError(t, os.Rename(filepath.Join(options.BundleDirectory, name), filepath.Join(projected, name)))
		require.NoError(t, os.Symlink(filepath.Join("..data-version", name), filepath.Join(options.BundleDirectory, name)))
	}
	require.Equal(t, 0, runWorker(context.Background(), options, helperProcess(t, "success")))
	require.NoError(t, os.Remove(filepath.Join(options.BundleDirectory, manifestKey)))
	require.NoError(t, os.Symlink(options.TerminationPath, filepath.Join(options.BundleDirectory, manifestKey)))
	_, _, err := readBundle(options.BundleDirectory)
	require.Error(t, err)
}

func TestSourceAndTerminationWritesDoNotFollowLinks(t *testing.T) {
	directory := testDirectory(t)
	victim := filepath.Join(directory, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("untouched"), 0600))
	link := filepath.Join(directory, "link")
	require.NoError(t, os.Symlink("victim", link))
	root, err := os.OpenRoot(directory)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	require.Error(t, writeSource(root, "link", []byte("replace")))
	require.Error(t, writeTermination(link, []byte("replace")))
	hardlink := filepath.Join(directory, "hardlink")
	require.NoError(t, os.Link(victim, hardlink))
	require.Error(t, writeTermination(hardlink, []byte("replace")))
	body, err := os.ReadFile(victim)
	require.NoError(t, err)
	require.Equal(t, "untouched", string(body))
}

func TestBuildArgumentsCannotForwardAuthOrArbitraryCLIFlags(t *testing.T) {
	f := newFixture(t)
	f.input.Args = map[string]string{"SOURCE_DATE_EPOCH": "100", "BUILDKIT_MULTI_PLATFORM": "1"}
	f.input.InputDigest = "sha256:" + strings.Repeat("a", 64)
	m := manifest{BuildKitAddress: f.config.BuildKitAddress,
		TLS: &TLS{CASecretName: "ca", ClientSecretName: "client", ServerName: "buildkit.builds.svc"}}
	args := buildArguments(m, f.input, "/workspace/build")
	require.Equal(t, []string{
		"--addr", "tcp://buildkit.builds.svc:1234", "--tlscacert", "/buildkit-ca/ca.crt",
		"--tlsservername", "buildkit.builds.svc", "--tlscert", "/builder-client/tls.crt",
		"--tlskey", "/builder-client/tls.key", "build", "--frontend", "gateway.v0",
		"--opt", "source=" + f.input.Frontend, "--opt", "filename=recipe.yml",
		"--opt", "target=linux/container", "--opt", "platform=linux/amd64",
		"--opt", "build-arg:DALEC_CUSTOM_WORKER=" + f.input.Worker,
		"--opt", "build-arg:BUILDKIT_MULTI_PLATFORM=1", "--opt", "build-arg:SOURCE_DATE_EPOCH=100",
		"--local", "context=/workspace/build/context", "--local", "dockerfile=/workspace/build/context",
		"--output", "type=image,name=" + f.input.OutputRepository + ":rem-" + strings.Repeat("a", 64) + ",push=true",
		"--metadata-file", "/workspace/build/metadata.json", "--progress", "plain",
		"--ref-file", "/workspace/build/build.ref",
	}, args)
	for _, forbidden := range []string{"--secret", "--ssh", "--allow", "network.host", "security.insecure"} {
		require.NotContains(t, args, forbidden)
	}
}

func TestNamedWorkerContextUsesTheActualDalecSelector(t *testing.T) {
	f := newFixture(t)
	f.config.Policies[0].WorkerArg = ""
	f.config.Policies[0].WorkerContext = "dalec-azlinux3-worker"
	var err error
	f.backend, err = New(f.config)
	require.NoError(t, err)
	f.input.WorkerArg, f.input.WorkerContext = "", "dalec-azlinux3-worker"
	options, _ := workerFixture(t, f)
	require.Equal(t, 0, runWorker(t.Context(), options, helperProcess(t, "named-context")))
	result := readTermination(t, options)
	require.Equal(t, Success, result.BuildOutcome)
	args := buildArguments(manifest{BuildKitAddress: f.config.BuildKitAddress, TLS: f.config.TLS}, f.input, "/workspace/build")
	require.Contains(t, args, "context:dalec-azlinux3-worker=docker-image://"+f.input.Worker)
	for _, argument := range args {
		require.False(t, strings.HasPrefix(argument, "build-arg:"))
	}
}

func TestWorkerUsesValidatedRegistryProjectionWithoutExposingCredentials(t *testing.T) {
	f := registryFixture(t)
	options, output := workerFixture(t, f)
	home := filepath.Join(testDirectory(t), "trusted-home")
	dockerConfig := filepath.Join(home, ".docker")
	require.NoError(t, os.MkdirAll(dockerConfig, 0700))
	configFile := filepath.Join(dockerConfig, registryConfigFile)
	require.NoError(t, os.WriteFile(configFile, registryFixtureJSON("registry.builds.svc:5000"), 0400))
	process := helperProcess(t, "registry-auth")
	process.registryDirectory = dockerConfig
	require.Equal(t, 0, runWorker(t.Context(), options, process))
	result := readTermination(t, options)
	require.Equal(t, Success, result.BuildOutcome)
	require.NotContains(t, output.String(), "fixture-password-marker")
	wire, err := os.ReadFile(options.TerminationPath)
	require.NoError(t, err)
	require.NotContains(t, string(wire), "fixture-password-marker")
	require.NoError(t, os.Chmod(configFile, 0600))
	require.NoError(t, os.WriteFile(configFile,
		[]byte(`{"auths":{"registry.builds.svc:5000":{"username":"fixture","password":"fixture"}},"credsStore":"must-not-exec"}`), 0400))
	output.Reset()
	require.Equal(t, 1, runWorker(t.Context(), options, process))
	require.Equal(t, Infrastructure, readTermination(t, options).BuildOutcome)
	require.NotContains(t, output.String(), `"phase":"building"`)
}

func TestTailDrainsLargeConcurrentOutputWithBoundedRetention(t *testing.T) {
	tail := newTail(1024)
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			for range 64 {
				body := bytes.Repeat([]byte("a"), 4096)
				_, _ = tail.Write(body)
			}
		})
	}
	group.Wait()
	n, err := tail.Write([]byte("last-line"))
	require.NoError(t, err)
	require.Equal(t, len("last-line"), n)
	body, truncated := tail.snapshot()
	require.True(t, truncated)
	require.Len(t, body, 1024)
	require.True(t, bytes.HasSuffix(body, []byte("last-line")))
}

func TestCompilerDiagnosticsNeverEchoUnknownPathsOrSourceText(t *testing.T) {
	body := []byte("#1 0.1 ./source/main.go:7:3: undefined: HiddenSymbol\n" +
		"unknown/main.go:9:1: error: private text\n" +
		"/source/main.go:4:1: error: absolute paths forbidden\n" +
		"source/main.go:11:1: warning: ignore\n" +
		"source/main.go:7:3: undefined: duplicate\n")
	got := compilerDiagnostics(body, map[string]bool{"source/main.go": true})
	require.Equal(t, []Diagnostic{{Path: "source/main.go", Line: 7, Column: 3}}, got)
	raw, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "HiddenSymbol")
	require.NotContains(t, string(raw), "private text")
}

func buildctlHelper(mode string) int {
	if slices.Contains(os.Args, "histories") {
		return historyHelper(mode)
	}
	if os.Getenv("BUILD_JOB_MUST_NOT_INHERIT") != "" {
		return 90
	}
	metadata, contextDirectory, refFile := helperBuildPaths(os.Args[1:])
	if metadata == "" || contextDirectory == "" {
		return 91
	}
	if refFile != "" {
		defer func() { _ = os.WriteFile(refFile, []byte("fixture-build-ref"), 0600) }()
	}
	if !helperWorkerSelector(mode, os.Args[1:], contextDirectory) {
		return 97
	}
	if strings.HasPrefix(mode, "go-test-") {
		return goTestBuildctlHelper(mode, metadata)
	}
	if mode == "sleep" || mode == "sleep-with-pid" {
		ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGTERM, unix.SIGINT)
		defer cancel()
		if mode == "sleep-with-pid" {
			if err := os.WriteFile("child.pid", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
				return 96
			}
		}
		<-ctx.Done()
		return 2
	}

	if mode == "compile" {
		_, _ = fmt.Fprintln(os.Stderr, "#1 0.1 ./source/main.go:7:3: undefined: HiddenSymbol")
		return 2
	}
	if mode == "infrastructure" {
		_, _ = fmt.Fprintln(os.Stderr, "buildkit transport unavailable")
		return 3
	}
	if mode == "output-forgery" {
		_, _ = fmt.Fprintln(os.Stdout, `{"success":true,"proof":"untrusted-success"}`)
		return 4
	}
	if mode == "metadata-missing" {
		return 0
	}
	if mode == "metadata-symlink" {
		return helperError(os.Symlink(filepath.Join(contextDirectory, "source/main.go"), metadata))
	}
	if mode == "metadata-hardlink" {
		return helperError(os.Link(filepath.Join(contextDirectory, "source/main.go"), metadata))
	}
	if mode == "metadata-fifo" {
		return helperError(unix.Mkfifo(metadata, 0600))
	}
	if mode == "verbose" {
		for range 512 {
			_, _ = os.Stdout.Write(bytes.Repeat([]byte("PRIVATE-SOURCE"), 1024))
			_, _ = os.Stderr.Write(bytes.Repeat([]byte("PRIVATE-SOURCE"), 1024))
		}
	}
	if mode == "source-mode" {
		info, err := os.Stat(filepath.Join(contextDirectory, "candidate.sh"))
		if err != nil || info.Mode().Perm() != 0600 {
			return 94
		}
		_, err = os.Stat("candidate-executed")
		if !os.IsNotExist(err) {
			return 95
		}
	}
	digestValue := "sha256:" + strings.Repeat("e", 64)
	body := `{"containerimage.digest":"` + digestValue + `"}`
	switch mode {
	case "metadata-mutable":
		body = `{"containerimage.digest":"mutable:latest"}`
	case "metadata-duplicate":
		body = `{"containerimage.digest":"` + digestValue + `","containerimage.digest":"` + digestValue + `"}`
	case "metadata-oversized":
		body = `{"containerimage.digest":"` + digestValue + `","padding":"` + strings.Repeat("x", 65536) + `"}`
	}
	return helperError(os.WriteFile(metadata, []byte(body), 0600))
}

func helperError(err error) int {
	if err != nil {
		return 93
	}
	return 0
}

func helperWorkerSelector(mode string, arguments []string, contextDirectory string) bool {
	if mode == "registry-auth" {
		return helperRegistryEnvironment(contextDirectory)
	}
	if mode == "mutual-tls" {
		return helperTLSArguments(arguments)
	}
	if mode != "named-context" && mode != "worker-arg" {
		return true
	}
	want := "build-arg:DALEC_CUSTOM_WORKER=" + testImage("worker", "b")
	absent := "context:"
	if mode == "named-context" {
		want = "context:dalec-azlinux3-worker=docker-image://" + testImage("worker", "b")
		absent = "build-arg:"
	}
	found := false
	for _, argument := range arguments {
		found = found || argument == want
		if strings.HasPrefix(argument, absent) {
			return false
		}
	}
	return found
}

func helperTLSArguments(arguments []string) bool {
	required := map[string]string{
		"--tlscacert": "/buildkit-ca/ca.crt", "--tlsservername": "buildkit.builds.svc",
		"--tlscert": "/builder-client/tls.crt", "--tlskey": "/builder-client/tls.key",
	}

	for index, argument := range arguments {
		if expected, ok := required[argument]; ok {
			if index+1 >= len(arguments) || arguments[index+1] != expected {
				return false
			}
			delete(required, argument)
		}
		if strings.Contains(argument, "synthetic-key-material") {
			return false
		}
	}
	return len(required) == 0
}

func helperRegistryEnvironment(contextDirectory string) bool {
	directory := os.Getenv("DOCKER_CONFIG")
	if directory == "" || filepath.Dir(directory) != os.Getenv("HOME") ||
		strings.HasPrefix(directory, contextDirectory) {
		return false
	}
	body, err := os.ReadFile(filepath.Join(directory, registryConfigFile))
	return err == nil && validateRegistryAuth(body, "registry.builds.svc:5000/remediation/output") == nil
}
