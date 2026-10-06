package patchverification

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var _ func(context.Context, Request) (*PreparedSources, error) = PrepareSources
var _ func(*PreparedSources) error = (*PreparedSources).Close

func TestSourcePath(test *testing.T) {
	for _, name := range []string{"main.go", "src/main.go", ".gitattributes", "nested/a file", "a-b/c.d"} {
		if !sourceValidPath(name) {
			test.Errorf("valid path rejected: %q", name)
		}
	}
	for _, name := range []string{"", ".", "..", "../escape", "a/../escape", "/absolute", "a//b", "a/", ".git", "a/.GIT/config", ".git./config", "a\\b", "C:/file", "a\x00b", "a\nb", string([]byte{0xff}), strings.Repeat("a", 256), strings.Repeat("a/", sourceMaxPathDepth) + "a"} {
		if sourceValidPath(name) {
			test.Errorf("unsafe path accepted: %q", name)
		}
	}
}

func TestSourceCommitIdentity(test *testing.T) {
	for _, identity := range []string{strings.Repeat("a", 40), strings.Repeat("f", 64)} {
		if !sourceValidCommit(identity) {
			test.Error("full commit identity rejected")
		}
	}
	for _, identity := range []string{"HEAD", "main", "refs/heads/main", "HEAD~1", "abc123", strings.Repeat("a", 39), strings.Repeat("A", 40), strings.Repeat("g", 64), "--help"} {
		if sourceValidCommit(identity) {
			test.Error("moving ref or malformed commit identity accepted")
		}
	}
}

func sourceFixtureGit(test *testing.T, directory string, input []byte, arguments ...string) []byte {
	test.Helper()
	command := exec.Command("/usr/bin/git", append([]string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"}, arguments...)...)
	command.Dir = directory
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + directory, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=Source Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=Source Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z"}
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	if err != nil {
		test.Fatalf("fixture git operation failed: %v", err)
	}
	return output
}

func sourceFixtureWrite(test *testing.T, filename, content string, mode os.FileMode) {
	test.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), mode); err != nil {
		test.Fatal(err)
	}
}

func TestSourceIsolatedObjects(test *testing.T) {
	repository := test.TempDir()
	sourceFixtureGit(test, repository, nil, "init", "--quiet", "--object-format=sha1")
	sourceFixtureWrite(test, filepath.Join(repository, ".gitattributes"), "hidden.txt export-ignore\nsubst.txt export-subst\n", 0600)
	sourceFixtureWrite(test, filepath.Join(repository, "hidden.txt"), "tracked bytes\n", 0600)
	sourceFixtureWrite(test, filepath.Join(repository, "subst.txt"), "$Format:%H$\n", 0600)
	sourceFixtureWrite(test, filepath.Join(repository, "bin/run"), "#!/bin/sh\nexit 0\n", 0700)
	sourceFixtureGit(test, repository, nil, "add", ".")
	sourceFixtureGit(test, repository, nil, "commit", "--quiet", "-m", "disposable source fixture")
	commit := strings.TrimSpace(string(sourceFixtureGit(test, repository, nil, "rev-parse", "HEAD")))
	expectedTree := strings.TrimSpace(string(sourceFixtureGit(test, repository, nil, "rev-parse", "HEAD^{tree}")))
	sourceFixtureWrite(test, filepath.Join(repository, "hidden.txt"), "dirty bytes\n", 0600)
	git, err := sourceNewGit(context.Background(), test.TempDir(), "sha1")
	if err != nil {
		test.Fatal(err)
	}
	tree, err := git.importCommit(context.Background(), filepath.Join(repository, ".git/objects"), commit)
	if err != nil || tree != expectedTree {
		test.Fatalf("isolated tree mismatch: %v", err)
	}
	archive, err := git.archive(context.Background(), tree)
	if err != nil {
		test.Fatal(err)
	}
	repeated, err := git.archive(context.Background(), tree)
	if err != nil || !bytes.Equal(archive, repeated) {
		test.Fatalf("archive is not deterministic: %v", err)
	}
	files := make(map[string]string)
	reader := tar.NewReader(bytes.NewReader(archive))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			test.Fatal(err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			test.Fatal(err)
		}
		files[header.Name] = string(content)
		if header.Name == "bin/run" && header.Mode != 0755 {
			test.Error("executable mode lost")
		}
	}
	if files["hidden.txt"] != "tracked bytes\n" || files["subst.txt"] != "$Format:%H$\n" || len(files) != 4 {
		test.Error("archive changed or omitted raw Git blobs")
	}
	if err := os.RemoveAll(filepath.Join(repository, ".git/objects")); err != nil {
		test.Fatal(err)
	}
	if _, err := git.archive(context.Background(), tree); err != nil {
		test.Fatalf("private objects still depend on the fixture repository: %v", err)
	}
}

func sourceRequestFixture(test *testing.T) Request {
	test.Helper()
	return sourceRequestFixtureFormat(test, "sha1")
}

func sourceRequestFixtureFormat(test *testing.T, format string) Request {
	test.Helper()
	repository, checks := test.TempDir(), test.TempDir()
	sourceFixtureGit(test, repository, nil, "init", "--quiet", "--object-format="+format)
	sourceFixtureWrite(test, filepath.Join(repository, "value.txt"), "original\n", 0600)
	sourceFixtureGit(test, repository, nil, "add", ".")
	sourceFixtureGit(test, repository, nil, "commit", "--quiet", "-m", "disposable original fixture")
	original := strings.TrimSpace(string(sourceFixtureGit(test, repository, nil, "rev-parse", "HEAD")))
	sourceFixtureWrite(test, filepath.Join(repository, "value.txt"), "patched\n", 0600)
	sourceFixtureGit(test, repository, nil, "add", ".")
	sourceFixtureGit(test, repository, nil, "commit", "--quiet", "-m", "disposable patched fixture")
	patched := strings.TrimSpace(string(sourceFixtureGit(test, repository, nil, "rev-parse", "HEAD")))
	sourceFixtureWrite(test, filepath.Join(checks, "verify.sh"), "#!/bin/sh\ncat /src/value.txt\n", 0700)
	sourceFixtureWrite(test, filepath.Join(checks, "inputs/expected.txt"), "patched\n", 0600)
	return Request{Problem: "local fixture", Scope: []string{"fixture"}, Repository: repository, OriginalCommit: original, PatchedCommit: patched, ChecksDir: checks, Image: "local/tool@" + Digest(nil), Platform: "linux/amd64", Profile: Offline, Checks: []Check{{ID: "reproduce", Kind: Reproduction, Command: []string{"/checks/verify.sh"}, Healthy: Expectation{Stdout: "patched\n"}, Failure: Expectation{Stdout: "original\n"}, TimeoutSeconds: 5}, {ID: "normal", Kind: Normal, Command: []string{"/checks/verify.sh"}, Healthy: Expectation{Stdout: "patched\n"}, Failure: Expectation{ExitCode: 1}, TimeoutSeconds: 5}}}
}

func sourceMustPrepare(test *testing.T, request Request) *PreparedSources {
	test.Helper()
	prepared, err := PrepareSources(context.Background(), request)
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() {
		if err := prepared.Close(); err != nil {
			test.Error(err)
		}
	})
	return prepared
}

func TestPrepareSourcesCommitAndPatch(test *testing.T) {
	request := sourceRequestFixture(test)
	committed := sourceMustPrepare(test, request)
	if committed.Sources.Original.Commit != request.OriginalCommit || committed.Sources.Patched.Commit != request.PatchedCommit || committed.Sources.Repository != request.Repository || committed.OriginalDir == committed.PatchedDir {
		test.Fatal("source identities or isolation do not match the request")
	}
	patch := sourceFixtureGit(test, request.Repository, nil, "diff", "--no-ext-diff", "--no-textconv", "--binary", request.OriginalCommit, request.PatchedCommit, "--")
	request.PatchedCommit = ""
	request.PatchFile = filepath.Join(test.TempDir(), "change.patch")
	sourceFixtureWrite(test, request.PatchFile, string(patch), 0600)
	patched := sourceMustPrepare(test, request)
	if patched.Sources.Original.Tree != committed.Sources.Original.Tree || patched.Sources.Patched.Tree != committed.Sources.Patched.Tree || patched.Sources.Patched.ArchiveDigest != committed.Sources.Patched.ArchiveDigest || patched.Sources.DiffDigest != committed.Sources.DiffDigest || patched.Sources.Patched.Commit != "" || patched.Sources.PatchDigest != Digest(patch) {
		test.Fatal("commit and patch modes produced different source evidence")
	}
	for _, prepared := range []*PreparedSources{committed, patched} {
		for digest, content := range prepared.Provenance {
			if digest != Digest(content) || len(content) > sourceMaxArchiveBytes {
				test.Error("invalid or oversized provenance")
			}
		}
		for directory, expected := range map[string]string{prepared.OriginalDir: "original\n", prepared.PatchedDir: "patched\n"} {
			content, err := os.ReadFile(filepath.Join(directory, "value.txt"))
			if err != nil || string(content) != expected {
				test.Fatalf("staged source mismatch: %v", err)
			}
			if err := dockerValidateDirectory(directory); err != nil {
				test.Fatalf("runner rejects source staging: %v", err)
			}
		}
		manifest := Manifest{Files: prepared.Files, Checks: request.Checks}
		if err := dockerValidateInputs(manifest, prepared.OriginalDir, prepared.ChecksDir); err != nil {
			test.Fatalf("runner rejects frozen checks: %v", err)
		}
		for name, mode := range map[string]os.FileMode{prepared.Root: 0700, prepared.OriginalDir: 0555, prepared.PatchedDir: 0555, prepared.ChecksDir: 0555, filepath.Join(prepared.ChecksDir, "verify.sh"): 0555, filepath.Join(prepared.ChecksDir, "inputs/expected.txt"): 0444} {
			info, err := os.Stat(name)
			if err != nil || info.Mode().Perm() != mode {
				test.Fatalf("snapshot permission mismatch: %v", err)
			}
		}
		root := prepared.Root
		if err := prepared.Close(); err != nil {
			test.Fatal(err)
		}
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			test.Fatal("read-only staging root was not cleaned")
		}
	}
}

func TestSourceOutputBound(test *testing.T) {
	output := &sourceBuffer{limit: 5}
	reader := struct{ io.Reader }{strings.NewReader("more than five bytes")}
	if _, err := io.Copy(output, reader); !errors.Is(err, errSourceLimit) || output.Len() > 5 {
		test.Fatalf("io.Copy bypassed the output bound: %v", err)
	}
	git, err := sourceNewGit(context.Background(), test.TempDir(), "sha1")
	if err != nil {
		test.Fatal(err)
	}
	if _, err := git.run(context.Background(), nil, 1, "--version"); !errors.Is(err, errSourceLimit) {
		test.Fatalf("Git stdout was not bounded: %v", err)
	}
}

func TestPrepareSourcesBinaryPatch(test *testing.T) {
	request := sourceRequestFixture(test)
	content := make([]byte, 32768)
	if _, err := rand.New(rand.NewSource(1)).Read(content); err != nil {
		test.Fatal(err)
	}
	sourceFixtureWrite(test, filepath.Join(request.Repository, "binary.dat"), string(content), 0600)
	sourceFixtureGit(test, request.Repository, nil, "add", ".")
	sourceFixtureGit(test, request.Repository, nil, "commit", "--quiet", "-m", "disposable binary original")
	request.OriginalCommit = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, nil, "rev-parse", "HEAD")))
	content[1000] ^= 0xff
	sourceFixtureWrite(test, filepath.Join(request.Repository, "binary.dat"), string(content), 0600)
	sourceFixtureWrite(test, filepath.Join(request.Repository, "added.dat"), string([]byte{0, 1, 2, 3}), 0600)
	sourceFixtureGit(test, request.Repository, nil, "add", ".")
	sourceFixtureGit(test, request.Repository, nil, "commit", "--quiet", "-m", "disposable binary patched")
	request.PatchedCommit = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, nil, "rev-parse", "HEAD")))
	committed := sourceMustPrepare(test, request)
	patch := sourceFixtureGit(test, request.Repository, nil, "diff", "--binary", request.OriginalCommit, request.PatchedCommit, "--")
	if !bytes.Contains(patch, []byte("delta ")) || !bytes.Contains(patch, []byte("literal ")) {
		test.Fatal("fixture must exercise both binary delta and literal patches")
	}
	request.PatchedCommit, request.PatchFile = "", filepath.Join(test.TempDir(), "binary.patch")
	sourceFixtureWrite(test, request.PatchFile, string(patch), 0600)
	patched := sourceMustPrepare(test, request)
	if patched.Sources.Patched.Tree != committed.Sources.Patched.Tree || patched.Sources.Patched.ArchiveDigest != committed.Sources.Patched.ArchiveDigest {
		test.Error("binary patch did not reproduce the committed tree")
	}
}

func TestSourcePatchExpansionBounds(test *testing.T) {
	for _, patch := range []string{"GIT binary patch\nliteral 4294967295\n", "GIT binary patch\ndelta 4294967295\n", "GIT binary patch\ndelta 10\nA~~~~~\n", "GIT binary patch\nliteral -1\n"} {
		if err := sourcePatchBounds(context.Background(), []byte(patch), 1024); err == nil {
			test.Error("malformed or unbounded binary patch accepted")
		}
	}
	if err := sourcePatchBounds(context.Background(), []byte(strings.Repeat("diff --git a/large b/copy\n", 5)), sourceMaxArchiveBytes); !errors.Is(err, errSourceLimit) {
		test.Fatalf("copy amplification was not bounded: %v", err)
	}
	if _, _, err := sourceDeltaSize([]byte{0xff, 0xff, 0xff, 0xff, 0x7f}); !errors.Is(err, errSourceLimit) {
		test.Fatalf("binary delta target was not bounded: %v", err)
	}
}

func TestSourcePatchIntermediateGrowth(test *testing.T) {
	for _, scenario := range []struct {
		name      string
		textBytes int
		modePairs int
		wantLimit bool
	}{
		{"tiny repeated target", 16, 2, false},
		{"added text reused by later sections", 1 << 20, 64, true},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			patch := "diff --git a/added b/added\nnew file mode 100644\n--- /dev/null\n+++ b/added\n@@ -0,0 +1 @@\n+" + strings.Repeat("x", scenario.textBytes) + "\n"
			patch += strings.Repeat("diff --git a/added b/added\nold mode 100644\nnew mode 100755\ndiff --git a/added b/added\nold mode 100755\nnew mode 100644\n", scenario.modePairs)
			err := sourcePatchBounds(context.Background(), []byte(patch), 2048)
			if scenario.wantLimit && !errors.Is(err, errSourceLimit) {
				test.Fatalf("intermediate file growth was not bounded: %v", err)
			}
			if !scenario.wantLimit && err != nil {
				test.Fatalf("tiny repeated-target patch was rejected: %v", err)
			}
		})
	}
}

func TestSourcePatchIntermediateBinaryGrowth(test *testing.T) {
	request := sourceRequestFixture(test)
	sourceFixtureWrite(test, filepath.Join(request.Repository, "binary.dat"), strings.Repeat("\x00", 1<<20), 0600)
	sourceFixtureGit(test, request.Repository, nil, "add", ".")
	patch := sourceFixtureGit(test, request.Repository, nil, "diff", "--cached", "--binary", "HEAD", "--")
	if !bytes.Contains(patch, []byte("literal 1048576\n")) {
		test.Fatal("fixture did not create a compact expanding binary literal")
	}
	if err := sourcePatchBounds(context.Background(), patch, 2048); err != nil {
		test.Fatalf("bounded binary addition was rejected: %v", err)
	}
	patch = append(patch, []byte(strings.Repeat("diff --git a/binary.dat b/binary.dat\nold mode 100644\nnew mode 100755\ndiff --git a/binary.dat b/binary.dat\nold mode 100755\nnew mode 100644\n", 64))...)
	if err := sourcePatchBounds(context.Background(), patch, 2048); !errors.Is(err, errSourceLimit) {
		test.Fatalf("binary output reused by later sections was not bounded: %v", err)
	}
}

func TestPrepareSourcesSHA256(test *testing.T) {
	request := sourceRequestFixtureFormat(test, "sha256")
	prepared := sourceMustPrepare(test, request)
	if len(prepared.Sources.Original.Commit) != 64 || len(prepared.Sources.Original.Tree) != 64 || len(prepared.Sources.Patched.Tree) != 64 {
		test.Fatal("SHA-256 Git identities were not preserved")
	}
	patch := prepared.Provenance[prepared.Sources.DiffDigest]
	request.PatchedCommit, request.PatchFile = "", filepath.Join(test.TempDir(), "change.patch")
	sourceFixtureWrite(test, request.PatchFile, string(patch), 0600)
	patched := sourceMustPrepare(test, request)
	if patched.Sources.Patched.Tree != prepared.Sources.Patched.Tree {
		test.Error("SHA-256 patch and commit modes disagree")
	}
}

func TestPrepareSourcesRejectsInputs(test *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *Request)
	}{
		{"network", func(_ *testing.T, request *Request) { request.Repository = "https://invalid.example/repo" }},
		{"file URL", func(_ *testing.T, request *Request) { request.Repository = "file://" + request.Repository }},
		{"relative repository", func(_ *testing.T, request *Request) { request.Repository = "." }},
		{"non repository", func(test *testing.T, request *Request) { request.Repository = test.TempDir() }},
		{"original ref", func(_ *testing.T, request *Request) { request.OriginalCommit = "HEAD" }},
		{"patched ref", func(_ *testing.T, request *Request) { request.PatchedCommit = "refs/heads/main" }},
		{"short original", func(_ *testing.T, request *Request) { request.OriginalCommit = request.OriginalCommit[:12] }},
		{"missing original", func(_ *testing.T, request *Request) { request.OriginalCommit = strings.Repeat("0", 40) }},
		{"missing patched", func(_ *testing.T, request *Request) { request.PatchedCommit = strings.Repeat("0", 40) }},
		{"tree is not commit", func(test *testing.T, request *Request) {
			request.OriginalCommit = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, nil, "rev-parse", "HEAD^{tree}")))
		}},
		{"neither patch choice", func(_ *testing.T, request *Request) { request.PatchedCommit = "" }},
		{"both patch choices", func(_ *testing.T, request *Request) { request.PatchFile = "/nonexistent/change.patch" }},
		{"nested checks", func(_ *testing.T, request *Request) { request.ChecksDir = request.Repository }},
		{"checks subdirectory", func(test *testing.T, request *Request) {
			request.ChecksDir = filepath.Join(request.Repository, "external-checks")
			sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "verify.sh"), "#!/bin/sh\nexit 0\n", 0700)
		}},
		{"symlink checks root", func(test *testing.T, request *Request) {
			link := filepath.Join(test.TempDir(), "checks")
			if err := os.Symlink(request.ChecksDir, link); err != nil {
				test.Fatal(err)
			}
			request.ChecksDir = link
		}},
		{"symlink file", func(test *testing.T, request *Request) {
			if err := os.Symlink(filepath.Join(request.Repository, "value.txt"), filepath.Join(request.ChecksDir, "link")); err != nil {
				test.Fatal(err)
			}
		}},
		{"symlink directory", func(test *testing.T, request *Request) {
			if err := os.Symlink(request.Repository, filepath.Join(request.ChecksDir, "link")); err != nil {
				test.Fatal(err)
			}
		}},
		{"git metadata in checks", func(test *testing.T, request *Request) {
			sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "nested/.GiT/config"), "metadata\n", 0600)
		}},
		{"fifo check", func(test *testing.T, request *Request) {
			if err := syscall.Mkfifo(filepath.Join(request.ChecksDir, "fifo"), 0600); err != nil {
				test.Fatal(err)
			}
		}},
		{"non executable", func(test *testing.T, request *Request) {
			if err := os.Chmod(filepath.Join(request.ChecksDir, "verify.sh"), 0600); err != nil {
				test.Fatal(err)
			}
		}},
		{"undeclared executable", func(_ *testing.T, request *Request) { request.Checks[0].Command = []string{"/checks/missing.sh"} }},
		{"image executable", func(_ *testing.T, request *Request) {
			request.Checks[0].Command = []string{"/bin/sh", "/checks/verify.sh"}
		}},
		{"command traversal", func(_ *testing.T, request *Request) {
			request.Checks[0].Command = []string{"/checks/inputs/../verify.sh"}
		}},
		{"undeclared service", func(_ *testing.T, request *Request) { request.Services = []Service{{Command: []string{"/bin/sh"}}} }},
		{"bad UTF8 check", func(test *testing.T, request *Request) {
			sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "bad"), string([]byte{0xff}), 0600)
		}},
		{"NUL check", func(test *testing.T, request *Request) {
			sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "bad"), "text\x00", 0600)
		}},
		{"credential check", func(test *testing.T, request *Request) {
			sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "bad"), "password=fixture-only-not-a-real-secret", 0600)
		}},
		{"credential input", func(_ *testing.T, request *Request) { request.Checks[0].Stdin = "authorization: bearer fixture-only" }},
		{"credential variable", func(_ *testing.T, request *Request) {
			request.Variables = map[string]string{"GITHUB_TOKEN": "fixture-only"}
		}},
		{"bad UTF8 stdin", func(_ *testing.T, request *Request) { request.Checks[0].Stdin = string([]byte{0xff}) }},
		{"NUL command", func(_ *testing.T, request *Request) {
			request.Checks[0].Command = append(request.Checks[0].Command, "arg\x00")
		}},
		{"oversized argument", func(_ *testing.T, request *Request) {
			request.Checks[0].Command = append(request.Checks[0].Command, strings.Repeat("x", 8193))
		}},
		{"oversized stdin", func(_ *testing.T, request *Request) { request.Checks[0].Stdin = strings.Repeat("x", (64<<10)+1) }},
		{"patch inside checks", func(test *testing.T, request *Request) {
			request.PatchedCommit, request.PatchFile = "", filepath.Join(request.ChecksDir, "change.patch")
			sourceFixtureWrite(test, request.PatchFile, "not a patch\n", 0600)
		}},
		{"symlink patch", func(test *testing.T, request *Request) {
			request.PatchedCommit, request.PatchFile = "", filepath.Join(test.TempDir(), "change.patch")
			if err := os.Symlink(filepath.Join(request.Repository, "value.txt"), request.PatchFile); err != nil {
				test.Fatal(err)
			}
		}},
		{"object alternates", func(test *testing.T, request *Request) {
			sourceFixtureWrite(test, filepath.Join(request.Repository, ".git/objects/info/alternates"), "/untrusted/objects\n", 0600)
		}},
	}
	for _, scenario := range cases {
		test.Run(scenario.name, func(test *testing.T) {
			request := sourceRequestFixture(test)
			scenario.change(test, &request)
			prepared, err := PrepareSources(context.Background(), request)
			if prepared != nil {
				_ = prepared.Close()
			}
			if err == nil || prepared != nil {
				test.Fatal("unsafe source request was prepared")
			}
			if strings.Contains(err.Error(), "fixture-only") || strings.Contains(err.Error(), request.Repository) {
				test.Fatal("error leaked request data")
			}
		})
	}
}

func sourceFixtureSnapshot(test *testing.T, root string) map[string]string {
	test.Helper()
	files := make(map[string]string)
	if err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		files[filename] = fmt.Sprintf("%s:%o", Digest(content), info.Mode())
		return nil
	}); err != nil {
		test.Fatal(err)
	}
	return files
}

func TestPrepareSourcesDoesNotTrustOrChangeRepository(test *testing.T) {
	request := sourceRequestFixture(test)
	sourceFixtureWrite(test, filepath.Join(request.Repository, "value.txt"), "dirty tracked bytes\n", 0600)
	sourceFixtureWrite(test, filepath.Join(request.Repository, "untracked.txt"), "untracked bytes\n", 0600)
	sourceFixtureGit(test, request.Repository, nil, "update-ref", "refs/replace/"+request.OriginalCommit, request.PatchedCommit)
	sourceFixtureGit(test, request.Repository, nil, "update-ref", "HEAD", request.OriginalCommit)
	sourceFixtureWrite(test, filepath.Join(request.Repository, ".git/config"), "[malformed untrusted config\n", 0600)
	sentinel := filepath.Join(test.TempDir(), "hook-ran")
	sourceFixtureWrite(test, filepath.Join(request.Repository, ".git/hooks/post-checkout"), "#!/bin/sh\nprintf unsafe > '"+sentinel+"'\n", 0700)
	for name, value := range map[string]string{"GIT_CONFIG_GLOBAL": "/not-a-real-config", "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": filepath.Join(request.Repository, ".git/hooks"), "GIT_WORK_TREE": request.Repository, "GIT_DIR": filepath.Join(request.Repository, ".git"), "GIT_INDEX_FILE": filepath.Join(request.Repository, "must-not-write"), "GIT_OBJECT_DIRECTORY": "/not-a-real-object-directory", "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/not-a-real-object-directory", "GIT_CONFIG_PARAMETERS": "invalid", "GIT_ASKPASS": "/not-an-askpass-program", "GITHUB_TOKEN": "fixture-only", "SSH_AUTH_SOCK": "/not-a-real-agent", "PATH": "/not-a-real-path"} {
		test.Setenv(name, value)
	}
	before := sourceFixtureSnapshot(test, request.Repository)
	prepared := sourceMustPrepare(test, request)
	if !reflect.DeepEqual(before, sourceFixtureSnapshot(test, request.Repository)) {
		test.Fatal("preparation wrote to the source repository")
	}
	content, err := os.ReadFile(filepath.Join(prepared.OriginalDir, "value.txt"))
	if err != nil || string(content) != "original\n" {
		test.Fatalf("replacement refs, HEAD, or dirty files changed the original: %v", err)
	}
	if _, err := os.Stat(sentinel); !errors.Is(err, os.ErrNotExist) {
		test.Fatal("source repository hook executed")
	}
}

func TestPrepareSourcesFrozenInputsAndExactCleanup(test *testing.T) {
	request := sourceRequestFixture(test)
	patch := sourceFixtureGit(test, request.Repository, nil, "diff", "--binary", request.OriginalCommit, request.PatchedCommit)
	request.PatchedCommit, request.PatchFile = "", filepath.Join(test.TempDir(), "change.patch")
	sourceFixtureWrite(test, request.PatchFile, string(patch), 0600)
	prepared := sourceMustPrepare(test, request)
	sourceFixtureWrite(test, request.PatchFile, "changed after freezing\n", 0600)
	sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "verify.sh"), "changed after freezing\n", 0600)
	sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "new.txt"), "not frozen\n", 0600)
	if !bytes.Equal(prepared.Provenance[prepared.Sources.PatchDigest], patch) {
		test.Fatal("patch bytes changed after preparation")
	}
	for _, file := range prepared.Files {
		content, err := os.ReadFile(filepath.Join(prepared.ChecksDir, filepath.FromSlash(file.Path)))
		if err != nil || !bytes.Equal(content, file.Content) || Digest(content) != file.Digest {
			test.Fatalf("frozen snapshot changed with the caller's directory: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(prepared.ChecksDir, "new.txt")); !errors.Is(err, os.ErrNotExist) {
		test.Fatal("new caller file entered the snapshot")
	}
	root := prepared.Root
	unrelated := test.TempDir()
	sourceFixtureWrite(test, filepath.Join(unrelated, "keep"), "keep\n", 0600)
	prepared.Root = unrelated
	if err := prepared.Close(); err != nil {
		test.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		test.Fatal("owned root leaked")
	}
	if _, err := os.Stat(filepath.Join(unrelated, "keep")); err != nil {
		test.Fatal("Close trusted a mutated public Root")
	}
	if err := prepared.Close(); err != nil {
		test.Fatal(err)
	}
	var empty *PreparedSources
	if err := empty.Close(); err != nil {
		test.Fatal(err)
	}
}

func TestPrepareSourcesUnsafeTrees(test *testing.T) {
	for _, scenario := range []struct{ name, mode, filename string }{
		{"symlink", "120000", "link"}, {"submodule", "160000", "module"}, {"traversal", "100644", "../escape"}, {"embedded slash", "100644", "dir/file"}, {"git metadata", "100644", ".git"}, {"case git metadata", "100644", ".GIT"}, {"absolute", "100644", "/absolute"}, {"dot", "100644", "."}, {"backslash", "100644", "dir\\file"}, {"special mode", "100600", "special"},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			request := sourceRequestFixture(test)
			blob := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte("content\n"), "hash-object", "-w", "--stdin")))
			identity, err := hex.DecodeString(blob)
			if err != nil {
				test.Fatal(err)
			}
			treeBytes := append([]byte(scenario.mode+" "+scenario.filename+"\x00"), identity...)
			tree := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, treeBytes, "hash-object", "-w", "--literally", "-t", "tree", "--stdin")))
			commitBytes := []byte("tree " + tree + "\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nfixture\n")
			request.PatchedCommit = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, commitBytes, "hash-object", "-w", "-t", "commit", "--stdin")))
			prepared, err := PrepareSources(context.Background(), request)
			if prepared != nil {
				_ = prepared.Close()
			}
			if err == nil {
				test.Fatal("unsafe Git tree was prepared")
			}
		})
	}
}

func TestPrepareSourcesLimitsAndCleanup(test *testing.T) {
	for _, scenario := range []string{"files", "check bytes", "manifest encoding", "conflicting patch", "credential source", "archive bytes", "tree entries", "aggregate tree entries", "tree depth", "cancelled", "cancel during git"} {
		test.Run(scenario, func(test *testing.T) {
			request := sourceRequestFixture(test)
			parent := test.TempDir()
			test.Setenv("TMPDIR", parent)
			ctx := context.Background()
			switch scenario {
			case "files":
				for index := range sourceMaxFrozenFiles {
					sourceFixtureWrite(test, filepath.Join(request.ChecksDir, fmt.Sprintf("extra-%03d", index)), "", 0600)
				}
			case "check bytes":
				sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "large"), strings.Repeat("x", sourceMaxManifestBytes+1), 0600)
			case "manifest encoding":
				sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "large"), strings.Repeat("x", 800<<10), 0600)
			case "conflicting patch":
				request.PatchedCommit, request.PatchFile = "", filepath.Join(test.TempDir(), "change.patch")
				sourceFixtureWrite(test, request.PatchFile, "diff --git a/value.txt b/value.txt\n--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-not original\n+patched\n", 0600)
			case "credential source":
				sourceFixtureWrite(test, filepath.Join(request.Repository, "credentials.txt"), "password=fixture-only-not-a-secret\n", 0600)
				sourceFixtureGit(test, request.Repository, nil, "add", ".")
				sourceFixtureGit(test, request.Repository, nil, "commit", "--quiet", "-m", "disposable credential fixture")
				request.PatchedCommit = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, nil, "rev-parse", "HEAD")))
			case "archive bytes":
				blob := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, bytes.Repeat([]byte{'x'}, sourceMaxArchiveBytes), "hash-object", "-w", "--stdin")))
				tree := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte("100644 blob "+blob+"\tlarge\n"), "mktree")))
				request.PatchedCommit = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte("fixture\n"), "commit-tree", tree)))
			case "tree entries":
				blob := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte(""), "hash-object", "-w", "--stdin")))
				var entries strings.Builder
				for index := 0; index <= sourceMaxTreeEntries; index++ {
					fmt.Fprintf(&entries, "100644 blob %s\tfile-%05d\n", blob, index)
				}
				tree := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte(entries.String()), "mktree")))
				request.PatchedCommit = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte("fixture\n"), "commit-tree", tree)))
			case "aggregate tree entries":
				blob := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, nil, "hash-object", "-w", "--stdin")))
				var entries strings.Builder
				for index := range sourceMaxTreeEntries / 2 {
					fmt.Fprintf(&entries, "100644 blob %s\tfile-%05d\n", blob, index)
				}
				subtree := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte(entries.String()), "mktree")))
				rootEntries := "040000 tree " + subtree + "\tleft\n040000 tree " + subtree + "\tright\n"
				tree := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte(rootEntries), "mktree")))
				request.PatchedCommit = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte("fixture\n"), "commit-tree", tree)))
			case "tree depth":
				tree := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, nil, "rev-parse", "HEAD^{tree}")))
				for range sourceMaxPathDepth {
					tree = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte("040000 tree "+tree+"\tnested\n"), "mktree")))
				}
				request.PatchedCommit = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, []byte("fixture\n"), "commit-tree", tree)))
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "cancel during git":
				cancelled, cancel := context.WithTimeout(ctx, 2*time.Millisecond)
				defer cancel()
				ctx = cancelled
			}
			before := sourceFixtureSnapshot(test, request.Repository)
			prepared, err := PrepareSources(ctx, request)
			if prepared != nil {
				_ = prepared.Close()
			}
			if err == nil || prepared != nil {
				test.Fatal("invalid or oversized source preparation succeeded")
			}
			if strings.HasPrefix(scenario, "cancel") && !errors.Is(err, ctx.Err()) {
				test.Fatalf("cancellation identity lost: %v", err)
			}
			if !reflect.DeepEqual(before, sourceFixtureSnapshot(test, request.Repository)) {
				test.Fatal("failed preparation changed source repository")
			}
			children, err := os.ReadDir(parent)
			if err != nil {
				test.Fatal(err)
			}
			for _, child := range children {
				if strings.HasPrefix(child.Name(), "orka-sources-") {
					test.Fatal("failed preparation leaked its staging root")
				}
			}
		})
	}
}

func TestSourceTarSafety(test *testing.T) {
	for _, scenario := range []struct {
		name    string
		headers []*tar.Header
	}{
		{"traversal", []*tar.Header{{Name: "../escape", Mode: 0644, Typeflag: tar.TypeReg}}},
		{"absolute", []*tar.Header{{Name: "/escape", Mode: 0644, Typeflag: tar.TypeReg}}},
		{"git", []*tar.Header{{Name: ".git/config", Mode: 0644, Typeflag: tar.TypeReg}}},
		{"symlink", []*tar.Header{{Name: "link", Mode: 0777, Typeflag: tar.TypeSymlink, Linkname: "../escape"}}},
		{"hardlink", []*tar.Header{{Name: "link", Mode: 0644, Typeflag: tar.TypeLink, Linkname: "../escape"}}},
		{"fifo", []*tar.Header{{Name: "fifo", Mode: 0644, Typeflag: tar.TypeFifo}}},
		{"device", []*tar.Header{{Name: "device", Mode: 0644, Typeflag: tar.TypeChar}}},
		{"setuid", []*tar.Header{{Name: "special", Mode: 04755, Typeflag: tar.TypeReg}}},
		{"extended attributes", []*tar.Header{{Name: "file", Mode: 0644, Typeflag: tar.TypeReg, PAXRecords: map[string]string{"SCHILY.xattr.user.test": "value"}}}},
		{"unknown metadata", []*tar.Header{{Name: "file", Mode: 0644, Typeflag: tar.TypeReg, PAXRecords: map[string]string{"ORKA.test": "value"}}}},
		{"duplicate", []*tar.Header{{Name: "same", Mode: 0644, Typeflag: tar.TypeReg}, {Name: "same", Mode: 0644, Typeflag: tar.TypeReg}}},
		{"file parent", []*tar.Header{{Name: "parent", Mode: 0644, Typeflag: tar.TypeReg}, {Name: "parent/child", Mode: 0644, Typeflag: tar.TypeReg}}},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			var content bytes.Buffer
			writer := tar.NewWriter(&content)
			for _, header := range scenario.headers {
				if err := writer.WriteHeader(header); err != nil {
					test.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				test.Fatal(err)
			}
			if err := sourceExtractArchive(context.Background(), content.Bytes(), filepath.Join(test.TempDir(), "source")); err == nil {
				test.Fatal("unsafe tar accepted")
			}
		})
	}
	if err := sourceExtractArchive(context.Background(), make([]byte, 512), filepath.Join(test.TempDir(), "truncated")); err == nil {
		test.Fatal("truncated archive accepted")
	}
}

func TestPrepareSourcesRepositoryForms(test *testing.T) {
	for _, form := range []string{"bare", "worktree", "canonical alias"} {
		test.Run(form, func(test *testing.T) {
			request := sourceRequestFixture(test)
			original := request.Repository
			switch form {
			case "bare":
				directory := filepath.Join(test.TempDir(), "bare.git")
				sourceFixtureGit(test, request.Repository, nil, "clone", "--quiet", "--bare", "--no-local", "--", request.Repository, directory)
				request.Repository = directory
			case "worktree":
				directory := filepath.Join(test.TempDir(), "worktree")
				sourceFixtureGit(test, request.Repository, nil, "worktree", "add", "--quiet", "--detach", directory, request.OriginalCommit)
				request.Repository = directory
			case "canonical alias":
				request.Repository = filepath.Join(test.TempDir(), "alias")
				if err := os.Symlink(original, request.Repository); err != nil {
					test.Fatal(err)
				}
			}
			prepared := sourceMustPrepare(test, request)
			expected := request.Repository
			if form == "canonical alias" {
				expected = original
			}
			if prepared.Sources.Repository != expected {
				test.Fatal("noncanonical repository identity")
			}
		})
	}
}

func TestPrepareSourcesTemporaryDirectorySafety(test *testing.T) {
	for _, location := range []string{"target", "other worktree", "bare", "checks", "unsafe canonical alias"} {
		test.Run(location, func(test *testing.T) {
			request := sourceRequestFixture(test)
			parent := test.TempDir()
			switch location {
			case "target":
				parent = request.Repository
			case "checks":
				parent = request.ChecksDir
			case "other worktree":
				sourceFixtureGit(test, parent, nil, "init", "--quiet")
			case "bare":
				sourceFixtureGit(test, parent, nil, "init", "--quiet", "--bare")
			case "unsafe canonical alias":
				unsafe := filepath.Join(parent, "unsafe,bind")
				if err := os.Mkdir(unsafe, 0700); err != nil {
					test.Fatal(err)
				}
				alias := filepath.Join(test.TempDir(), "alias")
				if err := os.Symlink(unsafe, alias); err != nil {
					test.Fatal(err)
				}
				parent = alias
			}
			test.Setenv("TMPDIR", parent)
			prepared, err := PrepareSources(context.Background(), request)
			if prepared != nil {
				_ = prepared.Close()
			}
			if err == nil {
				test.Fatal("unsafe staging location accepted")
			}
			children, err := os.ReadDir(parent)
			if err != nil {
				test.Fatal(err)
			}
			for _, child := range children {
				if strings.HasPrefix(child.Name(), "orka-sources-") {
					test.Fatal("preparation created a root in an unsafe location")
				}
			}
		})
	}
}

func TestPrepareSourcesFrozenFileLimit(test *testing.T) {
	request := sourceRequestFixture(test)
	for index := 2; index < sourceMaxFrozenFiles; index++ {
		sourceFixtureWrite(test, filepath.Join(request.ChecksDir, fmt.Sprintf("input-%03d", index)), "", 0600)
	}
	prepared := sourceMustPrepare(test, request)
	if len(prepared.Files) != sourceMaxFrozenFiles {
		test.Fatal("exact frozen-file limit rejected or files omitted")
	}
}

func TestSourceGitResourceLimits(test *testing.T) {
	root := test.TempDir()
	script := filepath.Join(root, "git-limits")
	sourceFixtureWrite(test, script, "#!/bin/sh\nexec /bin/cat /proc/self/limits\n", 0700)
	git := &sourceGit{binary: script, root: root, repository: filepath.Join(root, "git")}
	content, err := git.run(context.Background(), nil, 8192, "status")
	if err != nil {
		test.Fatal(err)
	}
	for _, expected := range []struct{ name, limit string }{
		{"Max address space", "536870912"},
		{"Max cpu time", "15"},
		{"Max core file size", "0"},
	} {
		found := false
		for line := range strings.SplitSeq(string(content), "\n") {
			if !strings.HasPrefix(line, expected.name+" ") {
				continue
			}
			found = true
			fields := strings.Fields(strings.TrimPrefix(line, expected.name))
			if len(fields) != 3 || fields[0] != expected.limit || fields[1] != expected.limit {
				test.Errorf("Git has no fixed soft and hard %s limit: %s", expected.name, line)
			}
		}
		if !found {
			test.Errorf("missing child resource limit: %s", expected.name)
		}
	}
}

func TestSourceGitImportOrdering(test *testing.T) {
	request := sourceRequestFixture(test)
	sourceFixtureWrite(test, filepath.Join(request.Repository, "nested/value.txt"), "nested\n", 0600)
	sourceFixtureGit(test, request.Repository, nil, "add", ".")
	sourceFixtureGit(test, request.Repository, nil, "commit", "--quiet", "-m", "nested source fixture")
	commit := strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, nil, "rev-parse", "HEAD")))
	root := test.TempDir()
	git, err := sourceNewGit(context.Background(), root, "sha1")
	if err != nil {
		test.Fatal(err)
	}
	script := filepath.Join(root, "git-ordering")
	sourceFixtureWrite(test, script, "#!/bin/sh\nprintf '%s\\n' \"$GIT_OBJECT_DIRECTORY|$*\" >> \"$HOME/operations\"\nexec /usr/bin/git \"$@\"\n", 0700)
	git.binary = script
	objects := filepath.Join(request.Repository, ".git/objects")
	if _, err := git.importCommit(context.Background(), objects, commit); err != nil {
		test.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, "operations"))
	if err != nil {
		test.Fatal(err)
	}
	copiedCommit, lastTree := false, ""
	copiedTrees := make(map[string]bool)
	for line := range strings.SplitSeq(strings.TrimSpace(string(content)), "\n") {
		fromSource := strings.HasPrefix(line, objects+"|")
		if fromSource && (strings.Contains(line, "^{") || strings.Contains(line, " rev-parse ") || strings.Contains(line, " ls-tree ")) {
			test.Fatalf("unbounded source object inspection before import: %s", line)
		}
		switch {
		case strings.HasSuffix(line, " hash-object -w --no-filters -t commit --stdin"):
			copiedCommit = true
		case strings.Contains(line, " rev-parse "):
			if !copiedCommit || len(copiedTrees) == 0 || fromSource {
				test.Fatal("commit peeled before bounded private commit and root-tree import")
			}
		case fromSource && strings.Contains(line, " cat-file tree "):
			fields := strings.Fields(line)
			lastTree = fields[len(fields)-1]
		case strings.HasSuffix(line, " hash-object -w --no-filters -t tree --stdin"):
			copiedTrees[lastTree] = true
		case strings.Contains(line, " ls-tree "):
			fields := strings.Fields(line)
			if strings.Contains(line, " -r ") || !copiedTrees[fields[len(fields)-1]] {
				test.Fatalf("tree traversed before bounded private import: %s", line)
			}
		}
	}
	if !copiedCommit || len(copiedTrees) != 2 {
		test.Fatal("fixture did not exercise commit and nested tree import")
	}
}

func TestSourceGitChildEnvironment(test *testing.T) {
	root := test.TempDir()
	script := filepath.Join(root, "git-environment")
	sourceFixtureWrite(test, script, "#!/bin/sh\nexec /usr/bin/env\n", 0700)
	for _, name := range []string{"SOURCE_TEST_SECRET", "GITHUB_TOKEN", "HTTP_PROXY", "HTTPS_PROXY", "SSH_AUTH_SOCK", "GIT_ASKPASS", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_ALTERNATE_OBJECT_DIRECTORIES"} {
		test.Setenv(name, "fixture-only-must-not-reach-git")
	}
	git := &sourceGit{binary: script, root: root, repository: filepath.Join(root, "git")}
	content, err := git.run(context.Background(), nil, 8192, "status")
	if err != nil {
		test.Fatal(err)
	}
	if bytes.Contains(content, []byte("fixture-only")) {
		test.Fatal("Git inherited an ambient credential or config environment variable")
	}
	for _, expected := range []string{"GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "PATH=/usr/bin:/bin"} {
		if !bytes.Contains(content, []byte(expected+"\n")) {
			test.Errorf("missing safe child environment: %s", expected)
		}
	}
}

func TestSourceGitCancellationReapsProcess(test *testing.T) {
	root := test.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "blocker"), 0600); err != nil {
		test.Fatal(err)
	}
	script := filepath.Join(root, "blocked-git")
	sourceFixtureWrite(test, script, "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$HOME/child.pid\"\nread ignored < \"$HOME/blocker\"\n", 0700)
	git := &sourceGit{binary: script, root: root, repository: filepath.Join(root, "git")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := git.run(ctx, nil, 0, "status"); !errors.Is(err, context.DeadlineExceeded) {
		test.Fatalf("Git cancellation identity lost: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(root, "child.pid"))
	if err != nil {
		test.Fatal("cancellation fixture never started its child")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		test.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		test.Fatal("cancelled Git process was not reaped")
	}
}
