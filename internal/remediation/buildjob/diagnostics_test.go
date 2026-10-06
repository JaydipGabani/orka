package buildjob

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func longDiagnosticPath(index int) string {
	return strings.Repeat("p", 229) + fmt.Sprintf("/f%d_test.go", index)
}

func longDiagnosticTestName(index int) string {
	return "Test" + strings.Repeat("A", 59) + strconv.Itoa(index)
}

func captureTestOutput(t *testing.T, output string, paths map[string]bool, chunk int) *diagnosticCapture {
	t.Helper()
	capture := newDiagnosticCapture(paths)
	for len(output) > 0 {
		size := min(chunk, len(output))
		n, err := capture.Write([]byte(output[:size]))
		require.NoError(t, err)
		require.Equal(t, size, n)
		output = output[size:]
	}
	return capture
}

func TestGoDiagnosticCaptureHandlesFragmentedAndRepeatedOutput(t *testing.T) {
	output := "#19 12.34 --- FAIL: TestFoo (0.01s)\r\n" +
		"#19 12.34     foo_test.go:123: synthetic-assertion-body\r\n"
	paths := map[string]bool{"pkg/foo/foo_test.go": true}
	for _, chunk := range []int{1, 2, 7, 4096} {
		t.Run(strconv.Itoa(chunk), func(t *testing.T) {
			capture := captureTestOutput(t, strings.Repeat(output, 100), paths, chunk)
			result := capture.snapshot()
			require.True(t, result.testFailure)
			require.False(t, result.truncated)
			require.Equal(t, []Diagnostic{{Path: "pkg/foo/foo_test.go", Line: 123, TestName: "TestFoo"}}, result.tests)
			require.Equal(t, result, capture.snapshot())
			require.LessOrEqual(t, cap(capture.line), maxDiagnosticLineBytes)
		})
	}
}

func TestGoDiagnosticLocationsAreConfinedToApprovedSourcePaths(t *testing.T) {
	for _, test := range []struct {
		name     string
		location string
		wantPath string
		extra    string
	}{
		{"project-relative", "pkg/foo/foo_test.go", "pkg/foo/foo_test.go", ""},
		{"dot-relative", "./pkg/foo/foo_test.go", "pkg/foo/foo_test.go", ""},
		{"unique-basename", "foo_test.go", "pkg/foo/foo_test.go", ""},
		{"ambiguous-basename", "foo_test.go", "", "other/foo_test.go"},
		{"ambiguous-root-basename", "foo_test.go", "", "foo_test.go"},
		{"exact-path-with-ambiguous-basename", "pkg/foo/foo_test.go", "pkg/foo/foo_test.go", "other/foo_test.go"},
		{"dalec-stack", "/build/top/BUILD/public-project/pkg/foo/foo_test.go", "pkg/foo/foo_test.go", ""},
		{"approved-source-stack", "/build/top/BUILD/public-project/pkg/foo/foo.go", "pkg/foo/foo.go", ""},
		{"unknown-relative", "other/foo_test.go", "", ""},
		{"unapproved-suffix", "unapproved/pkg/foo/foo_test.go", "", ""},
		{"unapproved-dalec-path", "/build/top/BUILD/public-project/other/foo_test.go", "", ""},
		{"no-absolute-basename-inference", "/build/top/BUILD/public-project/foo_test.go", "", ""},
		{"absolute", "/pkg/foo/foo_test.go", "", "/pkg/foo/foo_test.go"},
		{"stdlib", "/usr/local/go/src/testing/testing.go", "", "testing/testing.go"},
		{"other-build-root", "/tmp/public-project/pkg/foo/foo_test.go", "", ""},
		{"traversal", "pkg/../pkg/foo/foo_test.go", "", "pkg/../pkg/foo/foo_test.go"},
		{"dalec-traversal", "/build/top/BUILD/public-project/../pkg/foo/foo_test.go", "", ""},
		{"dalec-parent", "/build/top/BUILD/../pkg/foo/foo_test.go", "", ""},
		{"dalec-hidden-package", "/build/top/BUILD/.private/pkg/foo/foo_test.go", "", ""},
		{"dalec-credential-package", "/build/top/BUILD/credentials/pkg/foo/foo_test.go", "", ""},
		{"hidden", "pkg/.private/foo_test.go", "", "pkg/.private/foo_test.go"},
		{"credential", "credentials/foo_test.go", "", "credentials/foo_test.go"},
		{"secret-directory", "secrets/foo_test.go", "", "secrets/foo_test.go"},
		{"credential-shaped-path", "pkg/ghp_" + strings.Repeat("a", 25) + "/foo_test.go", "", ""},
		{"double-slash", "pkg//foo/foo_test.go", "", ""},
		{"backslash", `pkg\foo\foo_test.go`, "", ""},
		{"uri", "file:///pkg/foo/foo_test.go", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths := map[string]bool{"pkg/foo/foo.go": true, "pkg/foo/foo_test.go": true}
			if test.extra != "" {
				paths[test.extra] = true
			}
			output := "--- FAIL: TestFoo (0.01s)\n    " + test.location + ":123: synthetic-assertion-body\n"
			got := captureTestOutput(t, output, paths, 13).snapshot()
			require.True(t, got.testFailure)
			want := Diagnostic{TestName: "TestFoo"}
			if test.wantPath != "" {
				want.Path, want.Line = test.wantPath, 123
			}
			require.Equal(t, []Diagnostic{want}, got.tests)
			body, err := json.Marshal(got.tests)
			require.NoError(t, err)
			require.NotContains(t, string(body), "assertion-body")
			require.NotContains(t, string(body), "/build/")
			require.NotContains(t, string(body), "ghp_")
		})
	}
}

func TestGoDiagnosticCaptureRejectsDeceptiveMarkersAndDynamicNames(t *testing.T) {
	for _, marker := range []string{
		"output: --- FAIL: TestFoo (0.01s)",
		`{"message":"--- FAIL: TestFoo (0.01s)"}`,
		"#1 0.1 command: --- FAIL: TestFoo (0.01s)",
		"#1 malformed --- FAIL: TestFoo (0.01s)",
		"--- FAIL: TestFoo/private-label (0.01s)",
		"--- FAIL: TestFoo/Authorization_Bearer_value (0.01s)",
		"--- FAIL: Testlowercase (0.01s)",
		"--- FAIL: TestFoo (0.01s) arbitrary trailing text",
		"--- FAIL: TestFoo (no-duration)",
		"--- FAIL: TestFoo (-1s)",
		"--- FAIL: Test_ghp_" + strings.Repeat("a", 25) + " (0.01s)",
		"--- FAIL: Test" + strings.Repeat("A", 61) + " (0.01s)",
		"\x1b[0m--- FAIL: TestFoo (0.01s)",
		"arbitrary\r--- FAIL: TestFoo (0.01s)",
		"panic: test timed out after 0s",
		"panic: test timed out after invalid",
		"panic: test timed out after 1m0s arbitrary trailing text",
		"output: panic: test timed out after 1m0s",
	} {
		t.Run(strconv.Itoa(len(marker))+"-"+strconv.Itoa(strings.Count(marker, " ")), func(t *testing.T) {
			output := marker + "\n    pkg/foo/foo_test.go:123: synthetic-assertion-body\n"
			got := captureTestOutput(t, output, map[string]bool{"pkg/foo/foo_test.go": true}, 11).snapshot()
			require.False(t, got.testFailure)
			require.Empty(t, got.tests)
		})
	}
}

func TestGoDiagnosticCaptureOmitsUnsafeOptionalTestNames(t *testing.T) {
	for _, name := range []string{"TestTokenValue", "TestPasswordValue", "TestSecretValue", "TestAPIKeyValue"} {
		t.Run(name, func(t *testing.T) {
			output := "--- FAIL: " + name + " (0.01s)\n    pkg/foo/foo_test.go:123: synthetic-assertion-body\n"
			got := captureTestOutput(t, output, map[string]bool{"pkg/foo/foo_test.go": true}, 5).snapshot()
			require.True(t, got.testFailure)
			require.Equal(t, []Diagnostic{{Path: "pkg/foo/foo_test.go", Line: 123}}, got.tests)
			require.False(t, SafeTestName(name))
		})
	}
}

func TestGoDiagnosticCaptureDoesNotBindAcrossProgressStreams(t *testing.T) {
	output := "#1 0.1 --- FAIL: TestFoo (0.01s)\n#2 0.2     pkg/foo/foo_test.go:123: synthetic-assertion-body\n"
	got := captureTestOutput(t, output, map[string]bool{"pkg/foo/foo_test.go": true}, 1).snapshot()
	require.Equal(t, []Diagnostic{{TestName: "TestFoo"}}, got.tests)
}

func TestGoDiagnosticCaptureEnforcesWholeLineByteLimit(t *testing.T) {
	for _, size := range []int{maxDiagnosticLineBytes - 1, maxDiagnosticLineBytes, maxDiagnosticLineBytes + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			location := "    pkg/foo/foo_test.go:123: "
			line := location + strings.Repeat("x", size-len(location))
			output := "--- FAIL: TestFoo (0.01s)\n" + line + "\n"
			capture := captureTestOutput(t, output, map[string]bool{"pkg/foo/foo_test.go": true}, 7)
			got := capture.snapshot()
			require.Equal(t, size > maxDiagnosticLineBytes, got.truncated)
			want := Diagnostic{TestName: "TestFoo"}
			if size <= maxDiagnosticLineBytes {
				want.Path, want.Line = "pkg/foo/foo_test.go", 123
			}
			require.Equal(t, []Diagnostic{want}, got.tests)
			require.LessOrEqual(t, cap(capture.line), maxDiagnosticLineBytes)
		})
	}
	output := strings.Repeat("x", maxDiagnosticLineBytes+1) + "--- FAIL: TestInjected (0.01s)\n" +
		"--- FAIL: TestReal (0.01s)"
	got := captureTestOutput(t, output, nil, 5).snapshot()
	require.True(t, got.truncated)
	require.Equal(t, []Diagnostic{{TestName: "TestReal"}}, got.tests)
}

func TestGoDiagnosticCaptureEnforcesLineNumberBounds(t *testing.T) {
	for _, line := range []int{-1, 0, 1, 9999999, 10000000, 10000001} {
		t.Run(strconv.Itoa(line), func(t *testing.T) {
			output := fmt.Sprintf("--- FAIL: TestFoo (0.01s)\n    pkg/foo/foo_test.go:%d: synthetic-assertion-body\n", line)
			got := captureTestOutput(t, output, map[string]bool{"pkg/foo/foo_test.go": true}, 11).snapshot()
			want := Diagnostic{TestName: "TestFoo"}
			if line >= 1 && line <= 10000000 {
				want.Path, want.Line = "pkg/foo/foo_test.go", line
			}
			require.Equal(t, []Diagnostic{want}, got.tests)
		})
	}
}

func TestGoDiagnosticCaptureKeepsFixedMetadataBoundsUnderConcurrentFlood(t *testing.T) {
	capture := newDiagnosticCapture(map[string]bool{"pkg/foo/foo_test.go": true})
	var writers sync.WaitGroup
	for i := range 16 {
		writers.Go(func() {
			for j := range 64 {
				_, _ = fmt.Fprintf(capture, "--- FAIL: TestCase%d (0.01s)\n    pkg/foo/foo_test.go:%d: synthetic-assertion-body\n",
					i*64+j, i*64+j+1)
				_ = capture.snapshot()
			}
		})
	}
	writers.Wait()
	result := capture.snapshot()
	require.True(t, result.testFailure)
	require.True(t, result.truncated)
	require.Len(t, result.tests, MaxDiagnostics)
	require.LessOrEqual(t, cap(capture.tests), MaxDiagnostics)
	require.LessOrEqual(t, cap(capture.line), maxDiagnosticLineBytes)
}

func TestSafeTestNameLengthBoundaries(t *testing.T) {
	for _, size := range []int{63, 64, 65} {
		name := "Test" + strings.Repeat("A", size-4)
		require.Equal(t, size <= 64, SafeTestName(name))
	}
	require.True(t, SafeTestName("Test"))
	require.True(t, SafeTestName("Test_Foo"))
	require.False(t, SafeTestName("TestFoo/bar"))
}
