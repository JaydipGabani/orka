package buildjob

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func testFailureWire() WorkerResult {
	return WorkerResult{
		Version: Version, InputDigest: "sha256:" + strings.Repeat("a", 64),
		BuildOutcome: TestFailure, BuildExitCode: 7, BuildRef: strings.Repeat("r", 128), DaemonSettled: true,
		Diagnostics: []Diagnostic{{Path: "pkg/foo/foo_test.go", Line: 123, TestName: "TestFoo"}},
	}
}

func TestGoTestFailureWireRejectsUnsafeMetadataAndSuccessClaims(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*WorkerResult, *corev1.ContainerStateTerminated)
	}{
		{"zero-worker-exit", func(_ *WorkerResult, term *corev1.ContainerStateTerminated) { term.ExitCode = 0 }},
		{"mismatched-exit", func(_ *WorkerResult, term *corev1.ContainerStateTerminated) { term.ExitCode = 8 }},
		{"signal", func(_ *WorkerResult, term *corev1.ContainerStateTerminated) { term.Signal = 9 }},
		{"missing-build-exit", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.BuildExitCode = 0 }},
		{"negative-build-exit", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.BuildExitCode = -1 }},
		{"oversized-build-exit", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.BuildExitCode = 256 }},
		{"success-image", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.ImmutableImageDigest = "sha256:" + strings.Repeat("b", 64)
		}},
		{"unsupported-outcome", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.BuildOutcome = "unrecognized" }},
		{"compiler-with-test-fields", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.BuildOutcome, w.BuildExitCode = CompileFailure, 0
		}},
		{"unbound-settlement", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.BuildRef = "" }},
		{"absolute", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.Diagnostics[0].Path = "/pkg/foo/foo_test.go"
		}},
		{"traversal", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.Diagnostics[0].Path = "pkg/../foo_test.go"
		}},
		{"hidden", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.Diagnostics[0].Path = ".git/foo_test.go" }},
		{"credential", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.Diagnostics[0].Path = "secrets/foo_test.go"
		}},
		{"unknown", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.Diagnostics[0].Path = "unapproved/foo_test.go"
		}},
		{"non-go", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.Diagnostics[0].Path = "recipe.yml" }},
		{"path-too-long", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.Diagnostics[0].Path = strings.Repeat("a", 233) + "_test.go"
		}},
		{"zero-line", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.Diagnostics[0].Line = 0 }},
		{"line-too-large", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.Diagnostics[0].Line = 10000001 }},
		{"column", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.Diagnostics[0].Column = 1 }},
		{"symbol", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.Diagnostics[0].Symbol = "InventedSymbol" }},
		{"dynamic-name", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.Diagnostics[0].TestName = "TestFoo/private-label"
		}},
		{"secret-bearing-name", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.Diagnostics[0].TestName = "Test_ghp_" + strings.Repeat("a", 25)
		}},
		{"long-name", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.Diagnostics[0].TestName = "Test" + strings.Repeat("A", 61)
		}},
		{"nameless-unknown-context", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.Diagnostics[0] = Diagnostic{} }},
		{"unknown-context-with-line", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) { w.Diagnostics[0].Path = "" }},
		{"duplicate", func(w *WorkerResult, _ *corev1.ContainerStateTerminated) {
			w.Diagnostics = append(w.Diagnostics, w.Diagnostics[0])
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := testFailureWire()
			term := corev1.ContainerStateTerminated{ExitCode: 7}
			test.change(&wire, &term)
			body, err := json.Marshal(wire)
			require.NoError(t, err)
			term.Message = string(body)
			_, err = readWorkerResult(&term, wire.InputDigest, map[string]bool{
				"pkg/foo/foo_test.go": true, "/pkg/foo/foo_test.go": true, "pkg/../foo_test.go": true,
				".git/foo_test.go": true, "secrets/foo_test.go": true, "recipe.yml": true,
			})
			require.ErrorIs(t, err, ErrIdentity)
		})
	}
}

func TestGoTestFailureWireAllowsOnlyBoundedStructuredUnknownContext(t *testing.T) {
	for _, diagnostics := range [][]Diagnostic{nil, {{TestName: "TestFoo"}}} {
		wire := testFailureWire()
		wire.Diagnostics = diagnostics
		body, err := json.Marshal(wire)
		require.NoError(t, err)
		got, err := readWorkerResult(&corev1.ContainerStateTerminated{ExitCode: 7, Message: string(body)}, wire.InputDigest, nil)
		require.NoError(t, err)
		require.Equal(t, wire, got)
	}
}

func TestGoTestDiagnosticsNeverExpandPreviouslyCapturedSourceScope(t *testing.T) {
	paths := diagnosticPaths(manifest{SourcePaths: []string{"pkg/foo/foo.go"}}, Input{})
	require.NotContains(t, paths, "pkg/foo/foo_test.go")
	output := "--- FAIL: TestFoo (0.01s)\n    foo_test.go:123: synthetic-assertion-body\n"
	captured := captureTestOutput(t, output, paths, 7).snapshot()
	require.Equal(t, []Diagnostic{{TestName: "TestFoo"}}, captured.tests)
	wire := testFailureWire()
	raw, err := json.Marshal(wire)
	require.NoError(t, err)
	_, err = readWorkerResult(&corev1.ContainerStateTerminated{ExitCode: 7, Message: string(raw)}, wire.InputDigest, paths)
	require.ErrorIs(t, err, ErrIdentity)
	wire.Diagnostics = captured.tests
	raw, err = json.Marshal(wire)
	require.NoError(t, err)
	_, err = readWorkerResult(&corev1.ContainerStateTerminated{ExitCode: 7, Message: string(raw)}, wire.InputDigest, paths)
	require.NoError(t, err)
}

func TestGoTestFailureWireDiagnosticCountBounds(t *testing.T) {
	for _, count := range []int{MaxDiagnostics - 1, MaxDiagnostics, MaxDiagnostics + 1} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			wire := testFailureWire()
			wire.Diagnostics = nil
			paths := make(map[string]bool)
			for i := range count {
				name := longDiagnosticPath(i)
				require.Len(t, name, 240)
				paths[name] = true
				wire.Diagnostics = append(wire.Diagnostics, Diagnostic{Path: name, Line: 10000000, TestName: longDiagnosticTestName(i)})
			}
			body, err := json.Marshal(wire)
			require.NoError(t, err)
			require.Less(t, len(body), MaxTerminationBytes)
			_, err = readWorkerResult(&corev1.ContainerStateTerminated{ExitCode: 7, Message: string(body)}, wire.InputDigest, paths)
			if count <= MaxDiagnostics {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrIdentity)
			}
		})
	}
}

func TestGoTestFailureWireEncodedTerminationByteBounds(t *testing.T) {
	wire := testFailureWire()
	body, err := json.Marshal(wire)
	require.NoError(t, err)
	for _, size := range []int{MaxTerminationBytes - 1, MaxTerminationBytes, MaxTerminationBytes + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			message := string(body) + strings.Repeat(" ", size-len(body))
			require.Len(t, message, size)
			_, err := readWorkerResult(&corev1.ContainerStateTerminated{ExitCode: 7, Message: message},
				wire.InputDigest, map[string]bool{"pkg/foo/foo_test.go": true})
			if size <= MaxTerminationBytes {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrIdentity)
			}
		})
	}
}

func TestGoTestFailureWireRejectsRawLogFieldsAndPreservesOldWorkers(t *testing.T) {
	wire := testFailureWire()
	body, err := json.Marshal(wire)
	require.NoError(t, err)
	for _, field := range []string{"message", "stack", "stdout", "headers"} {
		message := strings.Replace(string(body), `"testName":"TestFoo"`, `"testName":"TestFoo","`+field+`":"must-not-export"`, 1)
		_, err := readWorkerResult(&corev1.ContainerStateTerminated{ExitCode: 7, Message: message},
			wire.InputDigest, map[string]bool{"pkg/foo/foo_test.go": true})
		require.ErrorIs(t, err, ErrIdentity)
	}
	for _, outcome := range []BuildOutcome{Success, CompileFailure, Infrastructure, Cancelled} {
		legacy := WorkerResult{Version: Version, InputDigest: wire.InputDigest, BuildOutcome: outcome}
		exit := int32(1)
		if outcome == Success {
			legacy.ImmutableImageDigest = "sha256:" + strings.Repeat("b", 64)
			exit = 0
		}
		if outcome == CompileFailure {
			legacy.Diagnostics = []Diagnostic{{Path: "source/main.go", Line: 7, Column: 3}}
		}
		raw, err := json.Marshal(legacy)
		require.NoError(t, err)
		require.NotContains(t, string(raw), "buildExitCode")
		require.NotContains(t, string(raw), "testName")
		got, err := readWorkerResult(&corev1.ContainerStateTerminated{ExitCode: exit, Message: string(raw)},
			legacy.InputDigest, map[string]bool{"source/main.go": true})
		require.NoError(t, err)
		require.Equal(t, legacy, got)
	}
}
