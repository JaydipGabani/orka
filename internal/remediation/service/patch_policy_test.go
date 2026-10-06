package service

import (
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/source"
)

func TestCandidatePolicyBlocksExecutionControlChanges(t *testing.T) {
	for _, name := range []string{".github/workflows/ci.yml", "specs/build.yml", "vendor/library/main.go",
		"go.mod", "Dockerfile", "../outside.go", "pkg/../outside.go", ".kube/config"} {
		t.Run(name, func(t *testing.T) {
			patch := "diff --git a/" + name + " b/" + name + "\n--- a/" + name + "\n+++ b/" + name + "\n@@ -1 +1 @@\n-old\n+new\n"
			packet := source.Packet{Files: []source.PacketFile{{Path: name}}}
			if err := validateCandidatePaths(patch, packet); err == nil {
				t.Fatal("untrusted candidate gained execution/control authority")
			}
		})
	}
	name := "pkg/server.go"
	packet := source.Packet{Files: []source.PacketFile{{Path: name}}}
	patch := "diff --git a/" + name + " b/" + name + "\n--- a/" + name + "\n+++ b/" + name + "\n@@ -1 +1 @@\n-old\n+new\n"
	if err := validateCandidatePaths(patch, packet); err != nil {
		t.Fatal(err)
	}
	for _, addition := range []string{"\nnew mode 100755\n", "\nGIT binary patch\n", "\n--- a/../../secret\n"} {
		if err := validateCandidatePaths(patch+addition, packet); err == nil {
			t.Fatal("candidate path/mode escape accepted")
		}
	}
}

func TestCandidatePolicyDetectsTestMutations(t *testing.T) {
	for _, path := range []string{"pkg/server_test.go", "tests/check.py", "test/test_core.c", "src/file.test.ts", "pkg/test_handler.py"} {
		patch := "diff --git a/" + path + " b/" + path + "\n"
		if !touchesTests(patch) {
			t.Fatal("test change did not require review", path)
		}
	}
	if touchesTests(strings.Replace("diff --git a/server.go b/server.go\n", "server", "contest", 2)) {
		t.Fatal("ordinary source incorrectly treated as a test")
	}
}
