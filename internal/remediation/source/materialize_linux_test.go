//go:build linux

package source

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

type gitFixture struct {
	directory string
	target    Target
	content   string
}

func fixtureGit(t *testing.T, directory string, input []byte, arguments ...string) []byte {
	t.Helper()
	command := exec.CommandContext(t.Context(), "/usr/bin/git", append([]string{
		"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "-c", "core.attributesFile=/dev/null",
	}, arguments...)...)
	command.Dir = directory
	command.Env = []string{
		"PATH=/usr/bin:/bin", "HOME=/dev/null", "XDG_CONFIG_HOME=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_AUTHOR_NAME=Source Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=Source Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	}
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "synthetic fixture Git: %s", output)
	return output
}

func writeFixture(t *testing.T, filename, content string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filename), 0700))
	require.NoError(t, os.WriteFile(filename, []byte(content), mode))
}

func newGitFixture(t *testing.T) gitFixture {
	t.Helper()
	fixture := gitFixture{directory: t.TempDir(), content: "selected synthetic source\n"}
	fixtureGit(t, fixture.directory, nil, "init", "--quiet", "--initial-branch=main", "--template=")
	writeFixture(t, filepath.Join(fixture.directory, "source.txt"), "parent revision\n", 0600)
	fixtureGit(t, fixture.directory, nil, "add", ".")
	fixtureGit(t, fixture.directory, nil, "commit", "--quiet", "-m", "synthetic parent")
	writeFixture(t, filepath.Join(fixture.directory, "source.txt"), fixture.content, 0600)
	writeFixture(t, filepath.Join(fixture.directory, ".gitattributes"), "*.txt filter=hostile text eol=crlf\n*.lfs filter=lfs\n", 0600)
	writeFixture(t, filepath.Join(fixture.directory, ".gitignore"), "ignored\n", 0600)
	writeFixture(t, filepath.Join(fixture.directory, "payload.lfs"), "version https://git-lfs.github.com/spec/v1\noid sha256:"+strings.Repeat("a", 64)+"\nsize 99999999\n", 0600)
	writeFixture(t, filepath.Join(fixture.directory, "bin/run"), "#!/bin/sh\nexit 0\n", 0700)
	fixtureGit(t, fixture.directory, nil, "add", ".")
	fixtureGit(t, fixture.directory, nil, "commit", "--quiet", "-m", "synthetic selected revision")
	fixture.target = targetAtHEAD(t, fixture.directory)
	writeFixture(t, filepath.Join(fixture.directory, "source.txt"), "newer unselected source\n", 0600)
	fixtureGit(t, fixture.directory, nil, "add", ".")
	fixtureGit(t, fixture.directory, nil, "commit", "--quiet", "-m", "synthetic later revision")
	return fixture
}

func targetAtHEAD(t *testing.T, repository string) Target {
	t.Helper()
	return Target{
		Repository: Repository{URL: fixtureURL, Owner: "source-fixtures", Name: "project", DefaultBranch: "main"},
		Ref:        "main",
		Commit:     strings.TrimSpace(string(fixtureGit(t, repository, nil, "rev-parse", "HEAD"))),
		Tree:       strings.TrimSpace(string(fixtureGit(t, repository, nil, "rev-parse", "HEAD^{tree}"))),
	}
}

func targetClient(t *testing.T, target Target) *apiFixture {
	t.Helper()
	return newAPIFixture(t, map[string]apiReply{
		fixturePrefix: {http.StatusOK, repositoryJSON()},
		fixturePrefix + "/commits/" + target.Commit: {http.StatusOK, commitJSON(target.Commit, target.Tree)},
	})
}

func localFetch(t *testing.T, repository string, inspect func(*exec.Cmd)) commandRunner {
	t.Helper()
	return func(command *exec.Cmd) error {
		if inspect != nil {
			inspect(command)
		}
		for index, argument := range command.Args {
			if argument == fixtureURL+".git" {
				require.Contains(t, command.Args, "fetch")
				command.Args[index] = (&url.URL{Scheme: "file", Path: repository}).String()
			}
			if argument == "protocol.https.allow=always" {
				command.Args[index] = "protocol.file.allow=always"
			}
		}
		for index, value := range command.Env {
			if value == "GIT_ALLOW_PROTOCOL=https" {
				command.Env[index] = "GIT_ALLOW_PROTOCOL=file"
			}
		}
		return command.Run()
	}
}

func TestMaterializeDetachedExactCommitWithoutHistoryOrAmbientExecution(t *testing.T) {
	fixture := newGitFixture(t)
	api := targetClient(t, fixture.target)
	poison := t.TempDir()
	marker := filepath.Join(poison, "must-not-run")
	hook := filepath.Join(poison, "hook")
	writeFixture(t, hook, "#!/bin/sh\nprintf 'unexpected' > '"+marker+"'\nexit 1\n", 0700)
	writeFixture(t, filepath.Join(poison, ".gitconfig"), fmt.Sprintf(
		"[core]\n\thooksPath = %s\n\tfsmonitor = %s\n[credential]\n\thelper = !%s\n[filter \"hostile\"]\n\tsmudge = %s\n\tprocess = %s\n[filter \"lfs\"]\n\tprocess = %s\n[url \"file:///not-the-source/\"]\n\tinsteadOf = https://github.com/\n",
		poison, hook, hook, hook, hook, hook), 0600)
	writeFixture(t, filepath.Join(poison, "post-checkout"), "#!/bin/sh\nprintf 'unexpected' > '"+marker+"'\n", 0700)
	for name, value := range map[string]string{
		"HOME": poison, "XDG_CONFIG_HOME": poison, "PATH": poison, "TMPDIR": poison,
		"GIT_CONFIG_GLOBAL": filepath.Join(poison, ".gitconfig"), "GIT_CONFIG_NOSYSTEM": "0",
		"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": poison,
		"GIT_CONFIG_PARAMETERS": "'core.hooksPath'='" + poison + "'", "GIT_TEMPLATE_DIR": poison,
		"GIT_ASKPASS": hook, "SSH_ASKPASS": hook, "GIT_DIR": filepath.Join(fixture.directory, ".git"),
		"GIT_WORK_TREE": fixture.directory, "GIT_INDEX_FILE": filepath.Join(poison, "index"),
		"GIT_OBJECT_DIRECTORY":             filepath.Join(fixture.directory, ".git", "objects"),
		"GIT_ALTERNATE_OBJECT_DIRECTORIES": "/not-a-source", "GIT_REPLACE_REF_BASE": "refs/replace/",
		"GIT_EXEC_PATH": poison, "GH_TOKEN": "synthetic-only", "GITHUB_TOKEN": "synthetic-only",
		"SSH_AUTH_SOCK": filepath.Join(poison, "agent"), "HTTP_PROXY": "http://127.0.0.1:1",
		"HTTPS_PROXY": "http://127.0.0.1:1", "LD_PRELOAD": filepath.Join(poison, "not-a-library"),
	} {
		t.Setenv(name, value)
	}
	destination := filepath.Join(t.TempDir(), "repository")
	fetches := 0
	run := localFetch(t, fixture.directory, func(command *exec.Cmd) {
		require.Equal(t, gitPrlimit, command.Path)
		require.NotNil(t, command.SysProcAttr)
		require.True(t, command.SysProcAttr.Setpgid)
		require.Equal(t, time.Second, command.WaitDelay)
		for _, option := range []string{
			"--as=536870912:536870912", "--cpu=30:30", "--fsize=134217728:134217728",
			"core.hooksPath=/dev/null", "credential.helper=", "protocol.allow=never", "protocol.https.allow=always",
			"http.followRedirects=false", "http.proxy=", "filter.lfs.process=", "fetch.unpackLimit=0",
		} {
			require.Contains(t, command.Args, option)
		}
		for _, expected := range []string{
			"PATH=/usr/bin:/bin", "HOME=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=https",
			"GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1",
		} {
			require.Contains(t, command.Env, expected)
		}
		for _, value := range command.Env {
			require.NotContains(t, value, "synthetic-only")
			require.NotContains(t, value, poison)
			require.NotContains(t, value, fixture.directory)
			require.False(t, strings.HasPrefix(value, "LD_"))
			require.False(t, strings.HasPrefix(value, "GIT_CONFIG_COUNT="))
		}
		if slices.Contains(command.Args, "fetch") {
			fetches++
			require.Contains(t, command.Args, "--depth=1")
			require.Contains(t, command.Args, "--no-tags")
			require.Contains(t, command.Args, "--no-recurse-submodules")
			require.Equal(t, []string{"--", fixtureURL + ".git", fixture.target.Commit}, command.Args[len(command.Args)-3:])
		}
	})
	require.NoError(t, materialize(t.Context(), fixture.target, destination, api.client, run))
	require.Equal(t, 1, fetches)
	require.NoFileExists(t, marker)
	require.NoFileExists(t, filepath.Join(poison, "index"))
	info, err := os.Stat(destination)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	content, err := os.ReadFile(filepath.Join(destination, "source.txt"))
	require.NoError(t, err)
	require.Equal(t, fixture.content, string(content))
	require.Equal(t, fixtureGit(t, destination, []byte(fixture.content), "hash-object", "--stdin"),
		fixtureGit(t, destination, nil, "rev-parse", "HEAD:source.txt"))
	require.Equal(t, fixture.target.Commit+"\n", string(fixtureGit(t, destination, nil, "rev-parse", "HEAD")))
	require.Equal(t, fixture.target.Tree+"\n", string(fixtureGit(t, destination, nil, "rev-parse", "HEAD^{tree}")))
	require.Equal(t, "1\n", string(fixtureGit(t, destination, nil, "rev-list", "--count", "HEAD")))
	require.Equal(t, "", string(fixtureGit(t, destination, nil, "status", "--porcelain")))
	require.NoDirExists(t, filepath.Join(destination, ".git", "hooks"))
	require.NoFileExists(t, filepath.Join(destination, ".git", "objects", "info", "alternates"))
	require.Equal(t, "origin\n", string(fixtureGit(t, destination, nil, "remote")))
	require.Equal(t, fixtureURL+".git\n", string(fixtureGit(t, destination, nil, "remote", "get-url", "origin")))
	require.Equal(t, fixture.target.Commit+"\n", string(mustRead(t, filepath.Join(destination, ".git", "HEAD"))))
	require.Equal(t, fixture.target.Commit+"\n", string(mustRead(t, filepath.Join(destination, ".git", "shallow"))))
	require.Contains(t, string(mustRead(t, filepath.Join(destination, "payload.lfs"))), "version https://git-lfs.github.com/spec/v1")
	requests := api.observed()
	require.Len(t, requests, 2)
	require.Equal(t, fixturePrefix+"/commits/"+fixture.target.Commit, requests[1].path)
	entries, err := os.ReadDir(filepath.Dir(destination))
	require.NoError(t, err)
	require.Len(t, entries, 1, "no materialization scratch directory should remain")
}

func mustRead(t *testing.T, filename string) []byte {
	t.Helper()
	content, err := os.ReadFile(filename)
	require.NoError(t, err)
	return content
}

func TestMaterializedGitCanPrepareFrozenSources(t *testing.T) {
	fixture := newGitFixture(t)
	api := targetClient(t, fixture.target)
	destination := filepath.Join(t.TempDir(), "repository")
	require.NoError(t, materialize(t.Context(), fixture.target, destination, api.client, localFetch(t, fixture.directory, nil)))
	checks := t.TempDir()
	writeFixture(t, filepath.Join(checks, "check.sh"), "#!/bin/sh\nexit 0\n", 0700)
	prepared, err := pv.PrepareSources(t.Context(), pv.Request{
		Action: pv.ValidateReport, Problem: "synthetic report only", Scope: []string{"source.txt"},
		Repository: destination, OriginalCommit: fixture.target.Commit, ChecksDir: checks,
		Image: "local/tool@" + pv.Digest(nil), Platform: "linux/amd64", Profile: pv.Offline,
		Checks: []pv.Check{{ID: "synthetic", Kind: pv.Reproduction, Command: []string{"/checks/check.sh"},
			Healthy: pv.Expectation{Stdout: "healthy\n"}, Failure: pv.Expectation{Stdout: "reported\n"}, TimeoutSeconds: 1}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, prepared.Close()) })
	require.Equal(t, fixture.target.Commit, prepared.Sources.Original.Commit)
	require.Equal(t, fixture.target.Tree, prepared.Sources.Original.Tree)
	require.Equal(t, fixture.content, string(mustRead(t, filepath.Join(prepared.OriginalDir, "source.txt"))))
}

func TestMaterializeRevalidatesPublicVisibilityBeforeAnyGit(t *testing.T) {
	target := Target{Repository: Repository{
		URL: fixtureURL, Owner: "source-fixtures", Name: "project", DefaultBranch: "main",
	}, Ref: "main", Commit: fixtureCommit, Tree: fixtureTree}
	for _, metadata := range []string{
		strings.Replace(repositoryJSON(), `"private":false`, `"private":true`, 1),
		strings.Replace(repositoryJSON(), `"visibility":"public"`, `"visibility":"private"`, 1),
	} {
		api := newAPIFixture(t, map[string]apiReply{fixturePrefix: {http.StatusOK, metadata}})
		parent := t.TempDir()
		err := materialize(t.Context(), target, filepath.Join(parent, "new"), api.client, func(*exec.Cmd) error {
			t.Fatal("Git must not start for an unconfirmed public repository")
			return nil
		})
		require.ErrorContains(t, err, "PUBLIC")
		require.Len(t, api.observed(), 1)
		entries, err := os.ReadDir(parent)
		require.NoError(t, err)
		require.Empty(t, entries)
	}
}

func TestMaterializeRejectsInvalidTargetsAndDestinationsWithoutIO(t *testing.T) {
	target := Target{Repository: Repository{
		URL: fixtureURL, Owner: "source-fixtures", Name: "project", DefaultBranch: "main",
	}, Ref: "main", Commit: fixtureCommit, Tree: fixtureTree}
	for _, mutate := range []func(*Target){
		func(target *Target) { *target = Target{} },
		func(target *Target) {
			target.Repository.URL = "https://user:fixture@github.com/source-fixtures/project"
		},
		func(target *Target) { target.Repository.URL += ".git" },
		func(target *Target) { target.Repository.Name = "other" },
		func(target *Target) { target.Repository.Owner = "other" },
		func(target *Target) { target.Ref = "" },
		func(target *Target) { target.Commit = "main" },
		func(target *Target) { target.Tree = strings.Repeat("0", 40) },
		func(target *Target) { target.Ref = strings.Repeat("f", 40) },
	} {
		invalid := target
		mutate(&invalid)
		require.Error(t, Materialize(t.Context(), invalid, filepath.Join(t.TempDir(), "new")))
	}
	parent := t.TempDir()
	existing := filepath.Join(parent, "existing")
	require.NoError(t, os.Mkdir(existing, 0700))
	file := filepath.Join(parent, "file")
	writeFixture(t, file, "preserve user bytes", 0600)
	symlink := filepath.Join(parent, "alias")
	require.NoError(t, os.Symlink(existing, symlink))
	gitParent := filepath.Join(parent, "worktree")
	require.NoError(t, os.Mkdir(gitParent, 0700))
	writeFixture(t, filepath.Join(gitParent, ".git"), "gitdir: /not-to-be-read\n", 0600)
	bare := filepath.Join(parent, "bare")
	writeFixture(t, filepath.Join(bare, "HEAD"), "ref: refs/heads/main\n", 0600)
	require.NoError(t, os.Mkdir(filepath.Join(bare, "objects"), 0700))
	shared := filepath.Join(parent, "unsafe-shared")
	require.NoError(t, os.Mkdir(shared, 0700))
	require.NoError(t, os.Chmod(shared, 0777))
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)
	for _, destination := range []string{
		"", ".", "relative", "/", parent + "/../elsewhere", parent + "/trailing/", filepath.Join(parent, "new\nline"),
		existing, file, symlink, filepath.Join(symlink, "new"), filepath.Join(gitParent, "new"),
		filepath.Join(bare, "new"), filepath.Join(workingDirectory, "must-not-create"),
		filepath.Join(parent, "absent", "new"), filepath.Join(parent, ".git"), filepath.Join(parent, ".GIT."),
	} {
		require.Error(t, Materialize(t.Context(), target, destination))
	}
	require.Equal(t, "preserve user bytes", string(mustRead(t, file)))
	entries, err := os.ReadDir(existing)
	require.NoError(t, err)
	require.Empty(t, entries)
	actualParent, err := destinationLocation(filepath.Join(shared, "new"))
	require.NoError(t, err, "a private ancestor protects permissive descendants")
	require.Equal(t, shared, actualParent)
}

func TestDestinationAncestorPermissions(t *testing.T) {
	for _, modes := range [][]os.FileMode{
		{0700, os.ModeSticky | 0777, 0755},
		{0777, 0700, os.ModeSticky | 0777, 0755},
		{0755, 0755},
	} {
		require.True(t, safeAncestorModes(modes))
	}
	for _, modes := range [][]os.FileMode{
		{0700, 0777, os.ModeSticky | 0777, 0755},
		{0755, 0775, 0755},
	} {
		require.False(t, safeAncestorModes(modes))
	}
}

func TestMaterializeRefusesWrongFetchedIdentityAndCleansOnlyStaging(t *testing.T) {
	fixture := newGitFixture(t)
	for _, change := range []string{"tree", "missing-commit"} {
		t.Run(change, func(t *testing.T) {
			target := fixture.target
			if change == "tree" {
				target.Tree = fixtureTree
			} else {
				target.Commit = fixtureCommit
			}
			api := targetClient(t, target)
			parent := t.TempDir()
			writeFixture(t, filepath.Join(parent, "user-file"), "user bytes", 0600)
			err := materialize(t.Context(), target, filepath.Join(parent, "new"), api.client, localFetch(t, fixture.directory, nil))
			require.Error(t, err)
			entries, err := os.ReadDir(parent)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			require.Equal(t, "user bytes", string(mustRead(t, filepath.Join(parent, "user-file"))))
		})
	}
}

func TestMaterializeRefusesDestinationCreatedDuringFetch(t *testing.T) {
	fixture := newGitFixture(t)
	for _, occupied := range []string{"empty-directory", "user-file"} {
		t.Run(occupied, func(t *testing.T) {
			api := targetClient(t, fixture.target)
			parent := t.TempDir()
			destination := filepath.Join(parent, "destination")
			run := localFetch(t, fixture.directory, func(command *exec.Cmd) {
				if slices.Contains(command.Args, "fetch") {
					if occupied == "empty-directory" {
						require.NoError(t, os.Mkdir(destination, 0700))
					} else {
						writeFixture(t, destination, "concurrent user bytes", 0600)
					}
				}
			})
			err := materialize(t.Context(), fixture.target, destination, api.client, run)
			require.ErrorContains(t, err, "already exists")
			entries, err := os.ReadDir(parent)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			if occupied == "empty-directory" {
				entries, err = os.ReadDir(destination)
				require.NoError(t, err)
				require.Empty(t, entries)
			} else {
				require.Equal(t, "concurrent user bytes", string(mustRead(t, destination)))
			}
		})
	}
}

func TestMaterializeCancellationRemovesOnlyOwnedStaging(t *testing.T) {
	fixture := newGitFixture(t)
	api := targetClient(t, fixture.target)
	parent := t.TempDir()
	writeFixture(t, filepath.Join(parent, "keep"), "keep", 0600)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	run := localFetch(t, fixture.directory, func(command *exec.Cmd) {
		if slices.Contains(command.Args, "fetch") {
			cancel()
		}
	})
	err := materialize(ctx, fixture.target, filepath.Join(parent, "destination"), api.client, run)
	require.ErrorIs(t, err, context.Canceled)
	entries, err := os.ReadDir(parent)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "keep", string(mustRead(t, filepath.Join(parent, "keep"))))
}

func TestOwnedCleanupAndAtomicPublicationNeverRemoveOtherData(t *testing.T) {
	parent := t.TempDir()
	original := filepath.Join(parent, "original")
	require.NoError(t, os.Mkdir(original, 0700))
	info, err := os.Lstat(original)
	require.NoError(t, err)
	moved := filepath.Join(parent, "moved")
	require.NoError(t, os.Rename(original, moved))
	require.NoError(t, os.Mkdir(original, 0700))
	writeFixture(t, filepath.Join(original, "keep"), "user bytes", 0600)
	require.ErrorContains(t, removeOwnedDirectory(original, info), "identity changed")
	require.Equal(t, "user bytes", string(mustRead(t, filepath.Join(original, "keep"))))
	require.Error(t, publishNoReplace(moved, original))
	require.DirExists(t, moved)
	require.DirExists(t, original)
}

func TestMaterializeRejectsSymlinksAndSubmodulesBeforeCheckout(t *testing.T) {
	for _, kind := range []string{"symlink", "submodule"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newGitFixture(t)
			if kind == "symlink" {
				require.NoError(t, os.Symlink("/outside-source", filepath.Join(fixture.directory, "unsafe")))
				fixtureGit(t, fixture.directory, nil, "add", "unsafe")
			} else {
				fixtureGit(t, fixture.directory, nil, "update-index", "--add", "--cacheinfo", "160000,"+fixture.target.Commit+",unsafe")
			}
			fixtureGit(t, fixture.directory, nil, "commit", "--quiet", "-m", "synthetic unsupported source entry")
			target := targetAtHEAD(t, fixture.directory)
			api := targetClient(t, target)
			destination := filepath.Join(t.TempDir(), "new")
			run := localFetch(t, fixture.directory, func(command *exec.Cmd) {
				require.NotContains(t, command.Args, "checkout")
			})
			err := materialize(t.Context(), target, destination, api.client, run)
			require.ErrorContains(t, err, "symlinks, submodules")
			require.NoDirExists(t, destination)
		})
	}
}

func TestCheckoutLimitsAndUnsafePaths(t *testing.T) {
	listing := func(mode, kind, size, name string) []byte {
		return fmt.Appendf(nil, "%s %s %s %s\t%s\x00", mode, kind, fixtureTree, size, name)
	}
	for _, size := range []int{maxCheckoutBytes - 1, maxCheckoutBytes} {
		require.NoError(t, validateCheckout(listing("100644", "blob", strconv.Itoa(size), "source"), 40))
	}
	require.ErrorIs(t, validateCheckout(listing("100644", "blob", strconv.Itoa(maxCheckoutBytes+1), "source"), 40), errSourceLimit)
	combined := append(listing("100644", "blob", strconv.Itoa(maxCheckoutBytes), "first"), listing("100644", "blob", "1", "second")...)
	require.ErrorIs(t, validateCheckout(combined, 40), errSourceLimit)
	entries := make([]byte, 0, maxTreeEntries*80)
	for index := range maxTreeEntries {
		entries = append(entries, listing("100644", "blob", "0", fmt.Sprintf("f%d", index))...)
	}
	require.NoError(t, validateCheckout(entries, 40))
	require.ErrorIs(t, validateCheckout(append(entries, listing("100644", "blob", "0", "overflow")...), 40), errSourceLimit)
	for _, path := range []string{
		"", ".", "..", "/absolute", "../escape", "a/../escape", "a//b", ".git/config", ".GIT/config",
		".git./config", "a\\b", "a:b", "bad\nname", strings.Repeat("a/", maxPathDepth) + "f", string([]byte{255}),
	} {
		require.Error(t, validateCheckout(listing("100644", "blob", "1", path), 40))
	}
	for _, malformed := range [][]byte{
		[]byte("not a tree listing"), listing("120000", "blob", "1", "link"),
		listing("160000", "commit", "-", "submodule"), listing("100644", "blob", "-1", "negative"),
		listing("100644", "blob", "overflow", "invalid"), listing("100644", "tree", "1", "wrong-type"),
		append(listing("100644", "blob", "0", "same"), listing("100644", "blob", "0", "same")...),
	} {
		require.Error(t, validateCheckout(malformed, 40))
	}
}

func TestDiskGuardAndOutputLimits(t *testing.T) {
	root := t.TempDir()
	file, err := os.Create(filepath.Join(root, "sparse"))
	require.NoError(t, err)
	require.NoError(t, file.Truncate(maxDiskBytes))
	require.NoError(t, file.Close())
	require.NoError(t, checkDisk(t.Context(), root))
	require.NoError(t, os.Truncate(filepath.Join(root, "sparse"), maxDiskBytes+1))
	require.ErrorIs(t, checkDisk(t.Context(), root), errSourceLimit)
	ctx, stop := guardDisk(t.Context(), root)
	defer stop()
	select {
	case <-ctx.Done():
		require.ErrorIs(t, context.Cause(ctx), errSourceLimit)
	case <-time.After(2 * time.Second):
		t.Fatal("aggregate disk guard did not cancel oversized staging")
	}
	outputContext, cancel := context.WithCancel(t.Context())
	defer cancel()
	output := &limitedOutput{limit: 3, cancel: cancel}
	_, err = output.Write([]byte("abc"))
	require.NoError(t, err)
	_, err = output.Write([]byte("d"))
	require.ErrorIs(t, err, errSourceLimit)
	require.Equal(t, "abc", output.buffer.String())
	require.ErrorIs(t, outputContext.Err(), context.Canceled)
}

func TestGitPrlimitActuallyConstrainsOutputFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".git", "tmp"), 0700))
	binary, err := trustedGit()
	require.NoError(t, err)
	git := sourceGit{root: root, binary: binary}
	command, err := git.command(t.Context(), []string{"--version"})
	require.NoError(t, err)
	separator := slices.Index(command.Args, "--")
	require.Positive(t, separator)
	// Exercise the real resource limiter without allocating 128 MiB or running
	// repository code. A file-size limit also bounds sparse-file expansion.
	command.Args = append(command.Args[:separator+1], "/usr/bin/truncate", "-s", strconv.Itoa(gitMaxFileBytes+1), "--", "limited")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	require.Error(t, command.Run())
	info, err := os.Stat(filepath.Join(root, "limited"))
	require.NoError(t, err)
	require.LessOrEqual(t, info.Size(), int64(gitMaxFileBytes))
}

func TestGitErrorsDoNotEchoRemoteContent(t *testing.T) {
	binary, err := trustedGit()
	require.NoError(t, err)
	git := sourceGit{root: t.TempDir(), binary: binary, runCommand: func(command *exec.Cmd) error {
		_, writeErr := command.Stderr.Write([]byte("synthetic-remote-content"))
		require.NoError(t, writeErr)
		return &exec.ExitError{}
	}}
	_, err = git.run(t.Context(), 32, "fetch")
	require.ErrorContains(t, err, "Git fetch failed")
	require.NotContains(t, err.Error(), "synthetic-remote-content")
	require.False(t, errors.Is(err, context.Canceled))
}

func TestGitCancellationStopsRunningSubprocess(t *testing.T) {
	binary, err := trustedGit()
	require.NoError(t, err)
	git := sourceGit{root: t.TempDir(), binary: binary, runCommand: func(command *exec.Cmd) error {
		separator := slices.Index(command.Args, "--")
		require.Positive(t, separator)
		command.Args = append(command.Args[:separator+1], "/usr/bin/sleep", "30")
		return command.Run()
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = git.run(ctx, 32, "fetch")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second, "cancellation must interrupt a running child, not wait for it")
}

func TestMaterializeSHA256ObjectIdentities(t *testing.T) {
	repository := t.TempDir()
	fixtureGit(t, repository, nil, "init", "--quiet", "--object-format=sha256", "--initial-branch=main", "--template=")
	writeFixture(t, filepath.Join(repository, "source.txt"), "synthetic SHA256 fixture\n", 0600)
	fixtureGit(t, repository, nil, "add", ".")
	fixtureGit(t, repository, nil, "commit", "--quiet", "-m", "synthetic SHA256 commit")
	target := targetAtHEAD(t, repository)
	require.Len(t, target.Commit, 64)
	require.Len(t, target.Tree, 64)
	api := targetClient(t, target)
	destination := filepath.Join(t.TempDir(), "new")
	require.NoError(t, materialize(t.Context(), target, destination, api.client, localFetch(t, repository, nil)))
	require.Equal(t, target.Commit+"\n", string(fixtureGit(t, destination, nil, "rev-parse", "HEAD")))
	require.Equal(t, target.Tree+"\n", string(fixtureGit(t, destination, nil, "rev-parse", "HEAD^{tree}")))
}
