//go:build linux

package buildjob

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
)

func TestWorkerRetainsEarlyGoTestFailureBeyondLogTail(t *testing.T) {
	f := newFixture(t, func(config *Config) {
		config.Policies[0].SourcePaths = append(config.Policies[0].SourcePaths, "source/main_test.go")
	})
	options, output := workerFixture(t, f)
	require.Equal(t, 7, runWorker(t.Context(), options, helperProcess(t, "go-test-verbose")))
	result := readTermination(t, options)
	require.Equal(t, TestFailure, result.BuildOutcome)
	require.Equal(t, 7, result.BuildExitCode)
	require.True(t, result.OutputTruncated)
	require.True(t, result.DaemonSettled)
	require.Empty(t, result.ImmutableImageDigest)
	require.Len(t, result.Diagnostics, 1)
	require.Equal(t, "source/main_test.go", result.Diagnostics[0].Path)
	require.Equal(t, 123, result.Diagnostics[0].Line)
	require.Equal(t, "TestMainResult", result.Diagnostics[0].TestName)
	require.NotContains(t, output.String(), "assertion-body")
	require.NotContains(t, output.String(), "goroutine")
}

func TestWorkerGoTestTimeoutIsNotBuildInfrastructureTimeout(t *testing.T) {
	for _, test := range []struct {
		mode        string
		diagnostics []Diagnostic
	}{
		{"go-test-timeout", []Diagnostic{
			{TestName: "TestMainResult"},
			{Path: "source/main_test.go", Line: 123},
		}},
		{"go-test-timeout-no-context", nil},
		{"go-test-unknown-path", []Diagnostic{{TestName: "TestMainResult"}}},
		{"go-test-no-final-newline", []Diagnostic{
			{Path: "source/main_test.go", Line: 123, TestName: "TestMainResult"},
		}},
		{"go-test-failure-with-image", []Diagnostic{
			{Path: "source/main_test.go", Line: 123, TestName: "TestMainResult"},
		}},
	} {
		t.Run(test.mode, func(t *testing.T) {
			f := newFixture(t, func(config *Config) {
				config.Policies[0].SourcePaths = append(config.Policies[0].SourcePaths, "source/main_test.go")
			})
			options, output := workerFixture(t, f)
			require.Equal(t, 7, runWorker(t.Context(), options, helperProcess(t, test.mode)))
			result := readTermination(t, options)
			require.Equal(t, TestFailure, result.BuildOutcome)
			require.Equal(t, 7, result.BuildExitCode)
			require.Equal(t, test.diagnostics, result.Diagnostics)
			require.True(t, result.DaemonSettled)
			if test.mode == "go-test-timeout" {
				require.True(t, result.OutputTruncated)
			}
			require.Empty(t, result.ImmutableImageDigest)
			require.NotContains(t, output.String(), "assertion-body")
			require.NotContains(t, output.String(), "/build/top/BUILD")
			body, err := os.ReadFile(options.TerminationPath)
			require.NoError(t, err)
			wire, err := readWorkerResult(&corev1.ContainerStateTerminated{ExitCode: 7, Message: string(body)},
				result.InputDigest, map[string]bool{"source/main_test.go": true})
			require.NoError(t, err)
			require.Equal(t, result, wire)
		})
	}
}

func TestWorkerIgnoresGoTestMarkersAfterCallerOrBuildCancellation(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(fmt.Sprintf("caller-cancelled=%t", external), func(t *testing.T) {
			f := newFixture(t, func(config *Config) {
				if !external {
					config.Limits.BuildTimeout = time.Second
				}
				config.Policies[0].SourcePaths = append(config.Policies[0].SourcePaths, "source/main_test.go")
			})
			options, _ := workerFixture(t, f)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan int, 1)
			process := helperProcess(t, "go-test-wait")
			go func() { done <- runWorker(ctx, options, process) }()
			require.Eventually(t, func() bool {
				_, err := os.Stat(filepath.Join(options.WorkspaceDirectory, "build", "child.pid"))
				return err == nil
			}, 2*time.Second, 5*time.Millisecond)
			if external {
				cancel()
			}
			select {
			case exit := <-done:
				require.Equal(t, 1, exit)
			case <-time.After(5 * time.Second):
				require.FailNow(t, "worker did not stop after cancellation")
			}
			result := readTermination(t, options)
			want := Infrastructure
			if external {
				want = Cancelled
			}
			require.Equal(t, want, result.BuildOutcome)
			require.Zero(t, result.BuildExitCode)
			require.Empty(t, result.Diagnostics)
			require.Empty(t, result.ImmutableImageDigest)
			require.True(t, result.DaemonSettled)
		})
	}
}

func TestWorkerGoTestFailureKeepsIndependentDaemonSettlement(t *testing.T) {
	for _, mode := range []string{"go-test-unsettled", "go-test-slow-settlement"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, func(config *Config) {
				config.Limits.BuildTimeout = time.Second
				config.Limits.SettlementTimeout = 4 * time.Second
				if mode == "go-test-unsettled" {
					config.Limits.SettlementTimeout = 200 * time.Millisecond
				}
			})
			options, _ := workerFixture(t, f)
			require.Equal(t, 7, runWorker(t.Context(), options, helperProcess(t, mode)))
			result := readTermination(t, options)
			require.Equal(t, TestFailure, result.BuildOutcome)
			require.Equal(t, mode != "go-test-unsettled", result.DaemonSettled)
			require.Equal(t, "fixture-build-ref", result.BuildRef)
			require.Empty(t, result.ImmutableImageDigest)
		})
	}
}

func TestWorkerGoDiagnosticsDoNotReplaceProcessAndMetadataVerdicts(t *testing.T) {
	for _, test := range []struct {
		mode    string
		outcome BuildOutcome
		exit    int
	}{
		{"go-test-success", Success, 0},
		{"go-test-success-without-metadata", Infrastructure, 1},
		{"go-test-deceptive", Infrastructure, 1},
		{"go-test-compiler-verbose", CompileFailure, 1},
	} {
		t.Run(test.mode, func(t *testing.T) {
			f := newFixture(t)
			options, output := workerFixture(t, f)
			require.Equal(t, test.exit, runWorker(t.Context(), options, helperProcess(t, test.mode)))
			result := readTermination(t, options)
			require.Equal(t, test.outcome, result.BuildOutcome)
			require.Zero(t, result.BuildExitCode)
			if test.outcome == Success {
				require.Equal(t, "sha256:"+strings.Repeat("e", 64), result.ImmutableImageDigest)
			} else {
				require.Empty(t, result.ImmutableImageDigest)
			}
			if test.outcome == CompileFailure {
				require.Equal(t, []Diagnostic{{Path: "source/main.go", Line: 7, Column: 3}}, result.Diagnostics)
				require.True(t, result.OutputTruncated)
			} else {
				require.Empty(t, result.Diagnostics)
			}
			require.NotContains(t, output.String(), "assertion-body")
			require.NotContains(t, output.String(), "HiddenSymbol")
		})
	}
}

func TestWorkerGoTestDiagnosticCountAndTerminationBounds(t *testing.T) {
	for _, count := range []int{MaxDiagnostics - 1, MaxDiagnostics, MaxDiagnostics + 1} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			f := newFixture(t, func(config *Config) {
				config.Policies[0].SourcePaths = nil
				for i := range count {
					config.Policies[0].SourcePaths = append(config.Policies[0].SourcePaths, longDiagnosticPath(i))
				}
			})
			options, _ := workerFixture(t, f)
			require.Equal(t, 7, runWorker(t.Context(), options, helperProcess(t, "go-test-count-"+strconv.Itoa(count))))
			result := readTermination(t, options)
			require.Equal(t, TestFailure, result.BuildOutcome)
			require.Len(t, result.Diagnostics, min(count, MaxDiagnostics))
			require.Equal(t, count > MaxDiagnostics, result.OutputTruncated)
			for i, diagnostic := range result.Diagnostics {
				require.Equal(t, Diagnostic{
					Path: longDiagnosticPath(i), Line: 10000000, TestName: longDiagnosticTestName(i),
				}, diagnostic)
			}
			body, err := json.Marshal(result)
			require.NoError(t, err)
			require.Less(t, len(body), MaxTerminationBytes)
			paths := make(map[string]bool)
			for _, name := range f.config.Policies[0].SourcePaths {
				paths[name] = true
			}
			_, err = readWorkerResult(&corev1.ContainerStateTerminated{ExitCode: 7, Message: string(body)}, result.InputDigest, paths)
			require.NoError(t, err)
		})
	}
}

func TestWorkerBundleGoTestDiagnosticsSurviveObservationAndExactCleanup(t *testing.T) {
	f := newFixture(t, func(config *Config) {
		config.Policies[0].SourcePaths = append(config.Policies[0].SourcePaths, "source/main_test.go")
	})
	receipt := f.start(t)
	options, _ := workerFixture(t, f)
	require.Equal(t, 7, runWorker(t.Context(), options, helperProcess(t, "go-test-verbose")))
	wire := readTermination(t, options)
	f.pod(t, receipt, &wire)
	result, err := f.backend.Observe(t.Context(), receipt)
	require.NoError(t, err)
	require.True(t, result.Done)
	require.Equal(t, TestFailure, result.BuildOutcome)
	require.Equal(t, wire, result.WorkerResult)
	require.Equal(t, result.BindingDigest(), result.ResultDigest)
	require.Empty(t, result.Image)
	require.Empty(t, result.ImmutableImageDigest)
	require.Equal(t, "source/main_test.go", result.Diagnostics[0].Path)
	require.NotContains(t, f.input.Files, "source/main_test.go")
	cleanup, err := f.backend.Cleanup(t.Context(), receipt)
	require.NoError(t, err)
	require.True(t, cleanup.Stopped)
	require.True(t, cleanup.DaemonSettled)
	require.True(t, cleanup.SubmissionSettled)
	restarted, err := New(f.config)
	require.NoError(t, err)
	replayed, err := restarted.Cleanup(t.Context(), receipt)
	require.NoError(t, err)
	require.Equal(t, cleanup, replayed)
	require.Equal(t, 1, countActions(f.kube, "create", "jobs"))
	for _, action := range f.kube.Actions() {
		require.NotEqual(t, "log", action.GetSubresource())
	}
}

func goTestBuildctlHelper(mode, metadata string) int {
	if raw, ok := strings.CutPrefix(mode, "go-test-count-"); ok {
		count, err := strconv.Atoi(raw)
		if err != nil || count < 0 || count > MaxDiagnostics+1 {
			return 91
		}
		for i := range count {
			_, _ = fmt.Fprintf(os.Stderr, "--- FAIL: %s (0.01s)\n    %s:10000000: synthetic-assertion-body\n",
				longDiagnosticTestName(i), longDiagnosticPath(i))
		}
		return 7
	}
	if mode == "go-test-deceptive" {
		_, _ = fmt.Fprintln(os.Stderr, `{"output":"--- FAIL: TestMainResult (0.01s)"}`)
		_, _ = fmt.Fprintln(os.Stderr, "build step: panic: test timed out after 1m0s")
		_, _ = fmt.Fprintln(os.Stderr, "--- FAIL: TestMainResult/unsafe-subtest (0.01s)")
		return 7
	}
	if mode == "go-test-compiler-verbose" {
		_, _ = fmt.Fprintln(os.Stderr, "#1 0.1 ./source/main.go:7:3: undefined: HiddenSymbol")
		verboseGoTestOutput()
		return 7
	}
	if mode == "go-test-timeout" || mode == "go-test-timeout-no-context" || mode == "go-test-wait" {
		_, _ = fmt.Fprintln(os.Stderr, "#1 0.1 panic: test timed out after 1m0s")
		if mode != "go-test-timeout-no-context" {
			_, _ = fmt.Fprintln(os.Stderr, "#1 0.1 \trunning tests:")
			_, _ = fmt.Fprintln(os.Stderr, "#1 0.1 \t\tTestMainResult (0s)")
			_, _ = fmt.Fprintln(os.Stderr, "#1 0.1 goroutine 99 [waiting]:")
			_, _ = fmt.Fprintln(os.Stderr, "#1 0.1 \t/usr/local/go/src/testing/testing.go:123 +0xabc")
			_, _ = fmt.Fprintln(os.Stderr, "#1 0.1 \t/build/top/BUILD/public-project/source/main_test.go:123 +0xabc")
		}
		if mode == "go-test-timeout" {
			verboseGoTestOutput()
		}
		if mode == "go-test-wait" {
			ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGTERM, unix.SIGINT)
			defer cancel()
			if os.WriteFile("child.pid", []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
				return 96
			}
			<-ctx.Done()
		}
		return 7
	}
	_, _ = fmt.Fprintln(os.Stderr, "#1 0.1 --- FAIL: TestMainResult (0.01s)")
	if mode == "go-test-no-final-newline" {
		_, _ = fmt.Fprint(os.Stderr, "#1 0.1     main_test.go:123: synthetic-assertion-body")
		return 7
	}
	if mode == "go-test-unknown-path" {
		_, _ = fmt.Fprintln(os.Stderr, "#1 0.1 \t/tmp/unapproved/main_test.go:123 +0xabc")
		return 7
	}
	_, _ = fmt.Fprintln(os.Stderr, "#1 0.1     main_test.go:123: synthetic-assertion-body")
	switch mode {
	case "go-test-verbose":
		verboseGoTestOutput()
	case "go-test-success":
		return helperError(os.WriteFile(metadata, []byte(`{"containerimage.digest":"sha256:`+strings.Repeat("e", 64)+`"}`), 0600))
	case "go-test-success-without-metadata":
		return 0
	case "go-test-failure-with-image":
		if os.WriteFile(metadata, []byte(`{"containerimage.digest":"sha256:`+strings.Repeat("e", 64)+`"}`), 0600) != nil {
			return 93
		}
	case "go-test-unsettled", "go-test-slow-settlement":
	default:
		return 91
	}
	return 7
}

func verboseGoTestOutput() {
	for range 2048 {
		_, _ = fmt.Fprintln(os.Stderr, "goroutine 99 [waiting]: "+strings.Repeat("synthetic-stack-frame ", 4))
	}
}
