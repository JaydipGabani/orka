package environment

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/buildjob"
	"github.com/orka-agents/orka/internal/remediation/provenance"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

func TestBuildJobSourcePathsAddOnlyExactGoTestSiblings(t *testing.T) {
	snapshot := recipeSnapshot{
		files: map[string][]byte{
			"approved.patch": []byte(
				"--- a/pkg/foo/foo.go\n+++ b/pkg/foo/foo.go\n" +
					"--- a/pkg/foo/foo_test.go\n+++ b/pkg/foo/foo_test.go\n--- a/pkg/bar.go\n+++ b/pkg/bar.go\n" +
					"--- a/pkg/other.c\n+++ b/pkg/other.c\n--- a/pkg/.hidden/unsafe.go\n+++ b/pkg/.hidden/unsafe.go\n" +
					"--- a/credentials/unsafe.go\n+++ b/credentials/unsafe.go\n--- a/pkg/../unsafe.go\n+++ b/pkg/../unsafe.go\n" +
					"--- a/removed.go\n+++ /dev/null\n"),
			"strip.patch": []byte("--- upstream/a/pkg/second.go\n+++ upstream/b/pkg/second.go\tignored-timestamp\n" +
				"--- ../a/unapproved/traversal.go\n+++ ../b/unapproved/traversal.go\n" +
				"--- credentials/a/unapproved/credential.go\n+++ credentials/b/unapproved/credential.go\n" +
				"--- .hidden/a/unapproved/hidden.go\n+++ .hidden/b/unapproved/hidden.go\n" +
				"--- /a/unapproved/absolute.go\n+++ /b/unapproved/absolute.go\n"),
			"unlisted.patch": []byte("+++ b/unapproved/other.go\n"),
			"source/main.go": []byte("package main\n"),
			"irrelevant.txt": []byte("+++ b/unapproved/text.go\n"),
		},
		built: provenance.Recipe{OrderedPatches: []provenance.Patch{
			{Path: "approved.patch", Strip: 1}, {Path: "strip.patch", Strip: 2},
		}},
	}
	paths, err := buildJobSourcePaths(snapshot)
	require.NoError(t, err)
	require.Equal(t, []string{
		"pkg/bar.go", "pkg/bar_test.go", "pkg/foo/foo.go", "pkg/foo/foo_test.go",
		"pkg/other.c", "pkg/second.go", "pkg/second_test.go",
	}, paths)
	require.NotContains(t, snapshot.files, "pkg/foo/foo_test.go")
}

func TestBuildJobSourcePathSiblingMustMeetExistingPathBounds(t *testing.T) {
	name := strings.Repeat("a", 237) + ".go"
	require.NoError(t, buildjob.SourcePath(name))
	snapshot := recipeSnapshot{
		files: map[string][]byte{"approved.patch": []byte(diagnosticSourcePatch(name))},
		built: provenance.Recipe{OrderedPatches: []provenance.Patch{{Path: "approved.patch", Strip: 1}}},
	}
	paths, err := buildJobSourcePaths(snapshot)
	require.NoError(t, err)
	require.Equal(t, []string{name}, paths)
}

func TestBuildJobSourcePathsReserveCapacityForAllPrimaryHeaders(t *testing.T) {
	for _, count := range []int{256, 257, 300, 511, 512, 513} {
		t.Run(fmt.Sprintf("%d-primary-files", count), func(t *testing.T) {
			var patches [2]strings.Builder
			for i := range count {
				name := fmt.Sprintf("pkg/file-%03d.go", i)
				patches[i%2].WriteString(diagnosticSourcePatch(name))
			}
			snapshot := recipeSnapshot{
				files: map[string][]byte{
					"first.patch": []byte(patches[0].String()), "second.patch": []byte(patches[1].String()),
				},
				built: provenance.Recipe{OrderedPatches: []provenance.Patch{
					{Path: "first.patch", Strip: 1}, {Path: "second.patch", Strip: 1},
				}},
			}
			paths, err := buildJobSourcePaths(snapshot)
			require.NoError(t, err)
			require.Equal(t, max(count, 512), len(paths))
			require.True(t, slices.IsSorted(paths))
			for i := range count {
				require.True(t, slices.Contains(paths, fmt.Sprintf("pkg/file-%03d.go", i)), "primary file %d was dropped", i)
				require.Equal(t, i < max(0, 512-count), slices.Contains(paths, fmt.Sprintf("pkg/file-%03d_test.go", i)))
			}
			slices.Reverse(snapshot.built.OrderedPatches)
			reordered, err := buildJobSourcePaths(snapshot)
			require.NoError(t, err)
			require.Equal(t, paths, reordered)
			kube := fake.NewClientset()
			image := "registry.example.invalid/builder@sha256:" + strings.Repeat("a", 64)
			backend, err := buildjob.New(buildjob.Config{
				Kube: kube, Namespace: "builds", WorkerImage: image, BuildKitAddress: "tcp://buildkit.builds.svc:1234",
				TLS: &buildjob.TLS{CASecretName: "buildkit-ca", ClientSecretName: "buildkit-client", ServerName: "buildkit.builds.svc"},
				Policies: []buildjob.Policy{{
					RecipePath: "recipe.yml", Frontend: image, Worker: image, WorkerArg: "DALEC_CUSTOM_WORKER",
					Target: "linux/container", Platform: "linux/amd64",
					OutputRepository: "registry.example.invalid/results", SourcePaths: paths,
				}},
			})
			if count > 512 {
				require.ErrorIs(t, err, buildjob.ErrInvalid)
				require.Nil(t, backend)
			} else {
				require.NoError(t, err)
				require.NotNil(t, backend)
			}
			require.Empty(t, kube.Actions())
		})
	}
}

func TestBuildJobSourcePathsIgnoreHeaderLikeHunkContent(t *testing.T) {
	snapshot := recipeSnapshot{
		files: map[string][]byte{"approved.patch": []byte(
			"diff --git a/pkg/foo.go b/pkg/foo.go\n--- a/pkg/foo.go\n+++ b/pkg/foo.go\n" +
				"@@ -1,4 +1,4 @@\n keep\n--- a/injected.go\n+++ b/injected.go\n \n tail\n")},
		built: provenance.Recipe{OrderedPatches: []provenance.Patch{{Path: "approved.patch", Strip: 1}}},
	}
	paths, err := buildJobSourcePaths(snapshot)
	require.NoError(t, err)
	require.Equal(t, []string{"pkg/foo.go", "pkg/foo_test.go"}, paths)
}

func TestBuildJobSourcePathsAcceptPatchToolContextWhitespace(t *testing.T) {
	for _, test := range []struct {
		name    string
		context string
		tools   []string
	}{
		{"bare-empty-context", "", []string{"git", "patch"}},
		{"tab-leading-context", "\tcontext", []string{"patch"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			patch := "--- a/pkg/foo.go\n+++ b/pkg/foo.go\n@@ -1,4 +1,4 @@\n before\n" + test.context +
				"\n--- a/injected.go\n+++ b/injected.go\n after\n"
			original := "before\n" + test.context + "\n-- a/injected.go\nafter\n"
			want := "before\n" + test.context + "\n++ b/injected.go\nafter\n"
			for _, tool := range test.tools {
				t.Run(tool, func(t *testing.T) {
					applySyntheticDiagnosticPatch(t, tool, patch, original, want)
				})
			}
			snapshot := recipeSnapshot{
				files: map[string][]byte{"approved.patch": []byte(patch)},
				built: provenance.Recipe{OrderedPatches: []provenance.Patch{{Path: "approved.patch", Strip: 1}}},
			}
			paths, err := buildJobSourcePaths(snapshot)
			require.NoError(t, err)
			require.Equal(t, []string{"pkg/foo.go", "pkg/foo_test.go"}, paths)
		})
	}
}

func applySyntheticDiagnosticPatch(t *testing.T, tool, patch, original, want string) {
	t.Helper()
	executable, err := exec.LookPath(tool)
	if err != nil {
		t.Skipf("%s unavailable for synthetic patch comparison", tool)
	}
	directory := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(directory, "pkg"), 0700))
	source := filepath.Join(directory, "pkg", "foo.go")
	require.NoError(t, os.WriteFile(source, []byte(original), 0600))
	args := []string{"apply", "--no-index", "-p1", "-"}
	if tool == "patch" {
		args = []string{"--batch", "--fuzz=0", "--no-backup-if-mismatch", "-p1"}
	}
	command := exec.CommandContext(t.Context(), executable, args...)
	command.Dir = directory
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + directory, "LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CEILING_DIRECTORIES=" + directory,
	}
	command.Stdin = strings.NewReader(patch)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s synthetic patch application: %s", tool, output)
	actual, err := os.ReadFile(source)
	require.NoError(t, err)
	require.Equal(t, want, string(actual))
}

func TestBuildJobSourcePathsAcceptUnifiedPatchFormats(t *testing.T) {
	mail := "From " + strings.Repeat("a", 40) + " Mon Sep 17 00:00:00 2001\n" +
		"From: Example Author <author@example.invalid>\nSubject: [PATCH] Adjust public fixture\n\n" +
		"+++ b/cover-letter-only.go\n---\n pkg/foo.go | 2 +-\n 1 file changed, 1 insertion(+), 1 deletion(-)\n\n" +
		diagnosticSourcePatch("pkg/foo.go") + "-- \n2.50.0\n"
	for _, test := range []struct {
		name  string
		patch string
		want  []string
	}{
		{"mail", mail, []string{"pkg/foo.go", "pkg/foo_test.go"}},
		{"crlf-mail", strings.ReplaceAll(mail, "\n", "\r\n"), []string{"pkg/foo.go", "pkg/foo_test.go"}},
		{"git-multiple-files", diagnosticSourcePatch("pkg/foo.go") + diagnosticSourcePatch("pkg/bar.go"),
			[]string{"pkg/bar.go", "pkg/bar_test.go", "pkg/foo.go", "pkg/foo_test.go"}},
		{"multiple-hunks-with-context", "--- a/pkg/foo.go\n+++ b/pkg/foo.go\n" +
			"@@ -1,3 +1,3 @@ function context\n keep\n \n-old\n+new\n" +
			"@@ -10000000 +10000000 @@ another function\n-before\n+after\n",
			[]string{"pkg/foo.go", "pkg/foo_test.go"}},
		{"plain-unified-timestamps", "diff -u old/pkg/foo.go new/pkg/foo.go\n" +
			"--- old/pkg/foo.go\t2026-01-01 00:00:00 +0000\n+++ new/pkg/foo.go\t2026-01-02 00:00:00 +0000\n" +
			"@@ -1 +1 @@\n-before\n+after\n",
			[]string{"pkg/foo.go", "pkg/foo_test.go"}},
		{"insert-zero-original-lines", "--- /dev/null\n+++ b/pkg/new.go\n@@ -0,0 +1,2 @@\n+first\n+++ b/injected.go\n",
			[]string{"pkg/new.go", "pkg/new_test.go"}},
		{"delete-zero-patched-lines", "--- a/pkg/removed.go\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-first\n--- a/injected.go\n",
			[]string{}},
		{"no-newline-markers", "--- a/pkg/foo.go\n+++ b/pkg/foo.go\n@@ -1 +1 @@\n" +
			"-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n",
			[]string{"pkg/foo.go", "pkg/foo_test.go"}},
		{"no-final-patch-newline", strings.TrimSuffix(diagnosticSourcePatch("pkg/foo.go"), "\n"),
			[]string{"pkg/foo.go", "pkg/foo_test.go"}},
		{"bare-empty-final-context", "--- a/pkg/foo.go\n+++ b/pkg/foo.go\n@@ -1,2 +1,2 @@\n-old\n+new\n\n",
			[]string{"pkg/foo.go", "pkg/foo_test.go"}},
		{"standalone-header-after-hunk", "--- a/pkg/foo.go\n+++ b/pkg/foo.go\n" +
			"@@ -1 +0,0 @@\n--- a/injected.go\n+++ b/injected.go\n",
			[]string{"pkg/foo.go", "pkg/foo_test.go"}},
		{"zero-line-hunk", "--- a/pkg/foo.go\n+++ b/pkg/foo.go\n@@ -0,0 +0,0 @@\n+++ b/injected.go\n",
			[]string{"pkg/foo.go", "pkg/foo_test.go"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := recipeSnapshot{
				files: map[string][]byte{"approved.patch": []byte(test.patch)},
				built: provenance.Recipe{OrderedPatches: []provenance.Patch{{Path: "approved.patch", Strip: 1}}},
			}
			paths, err := buildJobSourcePaths(snapshot)
			require.NoError(t, err)
			require.Equal(t, test.want, paths)
		})
	}
}

func TestBuildJobSourcePathsFailClosedOnMalformedHunks(t *testing.T) {
	for _, test := range []struct {
		name string
		hunk string
	}{
		{"invalid-count", "@@ -1,nope +1 @@\n-old\n+new\n"},
		{"negative-count", "@@ -1,-1 +1 @@\n-old\n+new\n"},
		{"overflow-count", "@@ -1,18446744073709551616 +1 @@\n-old\n+new\n"},
		{"oversized-count", fmt.Sprintf("@@ -1,%d +1 @@\n-old\n+new\n", buildjob.MaxInputBytes+1)},
		{"truncated", "@@ -1,2 +1,2 @@\n context\n"},
		{"missing-context-at-eof", "@@ -1 +1 @@\n"},
		{"missing-prefix", "@@ -1 +1 @@\nunprefixed\n"},
		{"original-underflow", "@@ -0,0 +1 @@\n context\n"},
		{"patched-underflow", "@@ -1 +0,0 @@\n+unexpected\n"},
		{"empty-original-underflow", "@@ -0,0 +1 @@\n\n"},
		{"empty-patched-underflow", "@@ -1 +0,0 @@\n\n"},
		{"tab-original-underflow", "@@ -0,0 +1 @@\n\tcontext\n"},
		{"tab-patched-underflow", "@@ -1 +0,0 @@\n\tcontext\n"},
		{"combined-hunk", "@@@ -1 -1 +1 @@@\n-old\n+new\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := recipeSnapshot{
				files: map[string][]byte{
					"approved.patch": []byte("--- a/pkg/foo.go\n+++ b/pkg/foo.go\n" + test.hunk),
					"later.patch":    []byte(diagnosticSourcePatch("pkg/later.go")),
				},
				built: provenance.Recipe{OrderedPatches: []provenance.Patch{
					{Path: "approved.patch", Strip: 1}, {Path: "later.patch", Strip: 1},
				}},
			}
			paths, err := buildJobSourcePaths(snapshot)
			require.Nil(t, paths)
			var failure *Error
			require.ErrorAs(t, err, &failure)
			require.Equal(t, NeedsAdapter, failure.Kind)
			require.Equal(t, invalidBuildDiagnosticPatchCode, failure.Code)
		})
	}
}

func diagnosticSourcePatch(name string) string {
	return fmt.Sprintf("diff --git a/%s b/%s\nindex 1111111..2222222 100644\n--- a/%s\n+++ b/%s\n"+
		"@@ -1 +1 @@\n-old\n+new\n", name, name, name, name)
}

func TestBuildJobTestFailureIsAdviceNotAReproductionOrImage(t *testing.T) {
	for _, role := range []Role{RebuiltControl, Candidate} {
		t.Run(string(role), func(t *testing.T) {
			job := &buildJobRecord{
				Role: role, PatchDigest: "sha256:" + strings.Repeat("c", 64),
				Base: BuildResult{ID: "synthetic-build"},
				Outcome: &buildjob.Result{WorkerResult: buildjob.WorkerResult{
					BuildOutcome: buildjob.TestFailure, BuildExitCode: 7, OutputTruncated: true,
					BuildRef: "synthetic-ref", DaemonSettled: true,
					Diagnostics: []buildjob.Diagnostic{
						{Path: "pkg/foo/foo_test.go", Line: 123, TestName: "TestFoo"},
						{TestName: "TestUnknownContext"},
					},
				}, ResultDigest: "sha256:" + strings.Repeat("d", 64)},
			}
			result, err := buildJobResult(job)
			require.NotNil(t, err)
			require.Equal(t, BuildFailed, err.Kind)
			require.Equal(t, "build-job-tests-failed", err.Code)
			require.False(t, err.Retryable)
			require.Equal(t, Subject{}, result.Subject)
			require.True(t, result.OutputTruncated)
			require.Equal(t, job.Outcome.ResultDigest, result.WorkerEvidenceDigest)
			require.Equal(t, []Diagnostic{
				{Code: "go-test-failure", Count: 1, Path: "pkg/foo/foo_test.go", Line: 123, Identifier: "TestFoo"},
				{Code: "go-test-failure", Count: 1, Identifier: "TestUnknownContext"},
			}, result.Diagnostics)
			job.CancelRequested = true
			result, err = buildJobResult(job)
			require.Equal(t, Infrastructure, err.Kind)
			require.Empty(t, result.Diagnostics)
			require.Equal(t, Subject{}, result.Subject)
		})
	}
}
