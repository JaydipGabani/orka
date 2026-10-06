//go:build linux

package source

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func materializedFixture(t *testing.T) (gitFixture, string, Client) {
	t.Helper()
	fixture := newGitFixture(t)
	api := targetClient(t, fixture.target)
	destination := filepath.Join(t.TempDir(), "source")
	require.NoError(t, materialize(t.Context(), fixture.target, destination, api.client, localFetch(t, fixture.directory, nil)))
	return fixture, destination, api.client
}

func managedSnapshot(t *testing.T, directory string, target Target) string {
	t.Helper()
	root, _, err := openManagedRoot(directory)
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	digest, err := snapshotDigest(t.Context(), root, target, false)
	require.NoError(t, err)
	return digest
}

func TestMaterializeResumesExactSnapshotReadOnlyWithoutFetching(t *testing.T) {
	fixture, destination, client := materializedFixture(t)
	before := managedSnapshot(t, destination, fixture.target)
	marker := mustRead(t, filepath.Join(destination, sourceMarkerPath))
	info, err := os.Lstat(destination)
	require.NoError(t, err)
	for range 2 {
		gitCalls := 0
		run := func(command *exec.Cmd) error {
			gitCalls++
			require.NotEqual(t, destination, command.Dir)
			require.NotContains(t, command.Args, "--git-dir="+filepath.Join(destination, ".git"))
			require.NotContains(t, command.Args, "--work-tree="+destination)
			require.NotContains(t, command.Args, "fetch")
			require.NotContains(t, command.Args, "clone")
			return command.Run()
		}
		require.NoError(t, materialize(t.Context(), fixture.target, destination, client, run))
		require.Positive(t, gitCalls, "resume must independently inspect Git objects, not just trust a marker")
		require.Equal(t, before, managedSnapshot(t, destination, fixture.target))
		require.Equal(t, marker, mustRead(t, filepath.Join(destination, sourceMarkerPath)))
		after, err := os.Lstat(destination)
		require.NoError(t, err)
		require.True(t, os.SameFile(info, after))
		entries, err := os.ReadDir(filepath.Dir(destination))
		require.NoError(t, err)
		require.Len(t, entries, 1, "verification scratch must be removed")
	}
}

func TestMaterializeResumeRefusesEveryMutationWithoutOverwrite(t *testing.T) {
	for _, mutation := range []string{
		"tracked-content", "executable-mode", "untracked-file", "ignored-file", "extra-empty-directory",
		"missing-marker", "marker-target", "marker-version", "head", "origin", "attributes", "shallow",
		"hook", "alternate", "commondir", "symlink", "hardlink", "private-mode", "staged-index", "object-corruption",
	} {
		t.Run(mutation, func(t *testing.T) {
			fixture, destination, client := materializedFixture(t)
			keep := filepath.Join(filepath.Dir(destination), "user-data")
			writeFixture(t, keep, "preserve unrelated user data", 0600)
			applySourceMutation(t, mutation, fixture, destination, keep)
			state := captureSourceState(t, destination)
			_, pathErr := os.Lstat(destination)
			require.NoError(t, pathErr)
			err := materialize(t.Context(), fixture.target, destination, client, func(*exec.Cmd) error {
				t.Fatal("a changed snapshot must be rejected before starting Git")
				return nil
			})
			require.Error(t, err)
			require.Equal(t, state, captureSourceState(t, destination))
			require.Equal(t, "preserve unrelated user data", string(mustRead(t, keep)))
		})
	}
}

func applySourceMutation(t *testing.T, mutation string, fixture gitFixture, destination, keep string) {
	t.Helper()
	filename := filepath.Join(destination, "source.txt")
	switch mutation {
	case "tracked-content":
		writeFixture(t, filename, "changed source", 0600)
	case "executable-mode":
		require.NoError(t, os.Chmod(filename, 0755))
	case "untracked-file":
		writeFixture(t, filepath.Join(destination, "extra"), "untracked", 0600)
	case "ignored-file":
		writeFixture(t, filepath.Join(destination, ".gitignore"), "ignored\n", 0600)
		writeFixture(t, filepath.Join(destination, "ignored"), "must not be hidden", 0600)
	case "extra-empty-directory":
		require.NoError(t, os.Mkdir(filepath.Join(destination, "extra-directory"), 0700))
	case "missing-marker":
		require.NoError(t, os.Remove(filepath.Join(destination, sourceMarkerPath)))
	case "marker-target", "marker-version":
		var marker sourceMarker
		require.NoError(t, json.Unmarshal(mustRead(t, filepath.Join(destination, sourceMarkerPath)), &marker))
		if mutation == "marker-target" {
			marker.Target.Ref = "other"
		} else {
			marker.Version++
		}
		writeMarker(t, destination, marker)
	case "head":
		writeFixture(t, filepath.Join(destination, ".git", "HEAD"), "ref: refs/heads/main\n", 0600)
	case "origin":
		writeFixture(t, filepath.Join(destination, ".git", "config"), strings.Replace(checkoutConfig(fixture.target), fixtureURL, "https://github.com/other/project", 1), 0600)
	case "attributes":
		writeFixture(t, filepath.Join(destination, ".git", "info", "attributes"), "* filter=hostile\n", 0600)
	case "shallow":
		writeFixture(t, filepath.Join(destination, ".git", "shallow"), fixtureCommit+"\n", 0600)
	case "hook":
		writeFixture(t, filepath.Join(destination, ".git", "hooks", "post-checkout"), "#!/bin/sh\nexit 99\n", 0700)
	case "alternate":
		writeFixture(t, filepath.Join(destination, ".git", "objects", "info", "alternates"), "/not-a-source\n", 0600)
	case "commondir":
		writeFixture(t, filepath.Join(destination, ".git", "commondir"), "/not-a-source\n", 0600)
	case "symlink":
		require.NoError(t, os.Remove(filename))
		require.NoError(t, os.Symlink(keep, filename))
	case "hardlink":
		require.NoError(t, os.Remove(filename))
		require.NoError(t, os.Link(keep, filename))
	case "private-mode":
		require.NoError(t, os.Chmod(destination, 0755))
	case "staged-index":
		writeFixture(t, filename, "staged source", 0600)
		fixtureGit(t, destination, nil, "add", "source.txt")
		writeFixture(t, filename, fixture.content, 0600)
	case "object-corruption":
		packs, err := filepath.Glob(filepath.Join(destination, ".git", "objects", "pack", "*.pack"))
		require.NoError(t, err)
		require.Len(t, packs, 1)
		require.NoError(t, os.Chmod(packs[0], 0600))
		content := mustRead(t, packs[0])
		content[len(content)-1] ^= 1
		require.NoError(t, os.WriteFile(packs[0], content, 0600))
	default:
		t.Fatal("unknown synthetic mutation")
	}
}

func writeMarker(t *testing.T, destination string, marker sourceMarker) {
	t.Helper()
	content, err := json.Marshal(marker)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(destination, sourceMarkerPath), append(content, '\n'), 0600))
}

type recordedSourceFile struct {
	mode    os.FileMode
	content string
}

func captureSourceState(t *testing.T, directory string) map[string]recordedSourceFile {
	t.Helper()
	state := make(map[string]recordedSourceFile)
	require.NoError(t, filepath.WalkDir(directory, func(name string, entry os.DirEntry, err error) error {
		require.NoError(t, err)
		info, err := entry.Info()
		require.NoError(t, err)
		item := recordedSourceFile{mode: info.Mode()}
		switch {
		case info.Mode().IsRegular():
			item.content = string(mustRead(t, name))
		case info.Mode()&os.ModeSymlink != 0:
			item.content, err = os.Readlink(name)
			require.NoError(t, err)
		}
		relative, err := filepath.Rel(directory, name)
		require.NoError(t, err)
		state[relative] = item
		return nil
	}))
	return state
}

func TestMaterializeResumeMarkerIsNotObjectOrWorktreeAuthority(t *testing.T) {
	for _, mutation := range []string{"worktree", "ignored-file", "skip-worktree", "assume-unchanged", "staged-index", "pack"} {
		t.Run(mutation, func(t *testing.T) {
			fixture, destination, client := materializedFixture(t)
			switch mutation {
			case "pack":
				applySourceMutation(t, "object-corruption", fixture, destination, "")
			case "staged-index":
				otherBlob := strings.TrimSpace(string(fixtureGit(t, destination, nil, "rev-parse", "HEAD:payload.lfs")))
				fixtureGit(t, destination, nil, "update-index", "--cacheinfo", "100644,"+otherBlob+",source.txt")
			case "ignored-file":
				writeFixture(t, filepath.Join(destination, "ignored"), "hidden extra source\n", 0600)
			default:
				if mutation != "worktree" {
					fixtureGit(t, destination, nil, "update-index", "--"+mutation, "source.txt")
				}
				writeFixture(t, filepath.Join(destination, "source.txt"), "forged changed worktree\n", 0600)
			}
			var marker sourceMarker
			require.NoError(t, json.Unmarshal(mustRead(t, filepath.Join(destination, sourceMarkerPath)), &marker))
			marker.Snapshot = managedSnapshot(t, destination, fixture.target)
			writeMarker(t, destination, marker)
			before := captureSourceState(t, destination)
			err := materialize(t.Context(), fixture.target, destination, client, (*exec.Cmd).Run)
			require.Error(t, err, "a rewritten checksum must not authorize changed source")
			require.Equal(t, before, captureSourceState(t, destination))
		})
	}
}

func TestMaterializeResumeRevalidatesPublicOrigin(t *testing.T) {
	fixture, destination, _ := materializedFixture(t)
	before := captureSourceState(t, destination)
	private := newAPIFixture(t, map[string]apiReply{
		fixturePrefix: {http.StatusOK, strings.Replace(repositoryJSON(), `"private":false`, `"private":true`, 1)},
	})
	err := materialize(t.Context(), fixture.target, destination, private.client, func(*exec.Cmd) error {
		t.Fatal("Git cannot run after public visibility is lost")
		return nil
	})
	require.ErrorContains(t, err, "PUBLIC")
	require.Equal(t, before, captureSourceState(t, destination))
	require.Len(t, private.observed(), 1)
}

func TestMaterializeResumeCancellationPreservesSource(t *testing.T) {
	fixture, destination, client := materializedFixture(t)
	before := captureSourceState(t, destination)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	run := func(command *exec.Cmd) error {
		if slices.Contains(command.Args, "fsck") {
			cancel()
		}
		return command.Run()
	}
	err := materialize(ctx, fixture.target, destination, client, run)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, before, captureSourceState(t, destination))
	entries, err := os.ReadDir(filepath.Dir(destination))
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestMaterializeResumeDetectsMutationDuringVerification(t *testing.T) {
	fixture, destination, client := materializedFixture(t)
	changed := false
	run := func(command *exec.Cmd) error {
		if slices.Contains(command.Args, "fsck") {
			writeFixture(t, filepath.Join(destination, "source.txt"), "concurrent change\n", 0600)
			changed = true
		}
		return command.Run()
	}
	err := materialize(t.Context(), fixture.target, destination, client, run)
	require.ErrorIs(t, err, errSourceChanged)
	require.True(t, changed)
	require.Equal(t, "concurrent change\n", string(mustRead(t, filepath.Join(destination, "source.txt"))))
}

func TestMaterializeResumeDoesNotAdoptUnmarkedOrDifferentTargets(t *testing.T) {
	fixture, destination, client := materializedFixture(t)
	target := fixture.target
	target.Ref = "other"
	before := captureSourceState(t, destination)
	require.ErrorIs(t, materialize(t.Context(), target, destination, client, (*exec.Cmd).Run), errSourceChanged)
	require.Equal(t, before, captureSourceState(t, destination))

	require.NoError(t, os.Remove(filepath.Join(destination, sourceMarkerPath)))
	err := materialize(t.Context(), fixture.target, destination, client, (*exec.Cmd).Run)
	require.ErrorIs(t, err, errSourceChanged)
	require.True(t, errors.Is(err, os.ErrNotExist))
	require.NoFileExists(t, filepath.Join(destination, sourceMarkerPath))
	require.Equal(t, fixture.content, string(mustRead(t, filepath.Join(destination, "source.txt"))))
}

func TestMaterializeResumeMarkerBindsDirectoryIdentity(t *testing.T) {
	fixture, original, client := materializedFixture(t)
	copyRoot := filepath.Join(t.TempDir(), "copied")
	require.NoError(t, os.Mkdir(copyRoot, 0700))
	state := captureSourceState(t, original)
	names := make([]string, 0, len(state))
	for name := range state {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		entry := state[name]
		if name == "." {
			continue
		}
		copied := filepath.Join(copyRoot, name)
		if entry.mode.IsDir() {
			require.NoError(t, os.Mkdir(copied, entry.mode.Perm()))
		} else {
			require.NoError(t, os.WriteFile(copied, []byte(entry.content), entry.mode.Perm()))
		}
	}
	before := captureSourceState(t, copyRoot)
	err := materialize(t.Context(), fixture.target, copyRoot, client, func(*exec.Cmd) error {
		t.Fatal("a copied marker must not establish ownership of a different directory")
		return nil
	})
	require.ErrorIs(t, err, errSourceChanged)
	require.Equal(t, before, captureSourceState(t, copyRoot))
}

func TestMaterializeResumeSHA256AndArchivedMetadata(t *testing.T) {
	repository := t.TempDir()
	fixtureGit(t, repository, nil, "init", "--quiet", "--object-format=sha256", "--initial-branch=main", "--template=")
	writeFixture(t, filepath.Join(repository, "source.txt"), "synthetic SHA256 fixture\n", 0600)
	fixtureGit(t, repository, nil, "add", ".")
	fixtureGit(t, repository, nil, "commit", "--quiet", "-m", "synthetic SHA256 commit")
	target := targetAtHEAD(t, repository)
	target.Repository.Archived = true
	api := newAPIFixture(t, map[string]apiReply{
		fixturePrefix: {http.StatusOK, strings.Replace(repositoryJSON(), `"archived":false`, `"archived":true`, 1)},
		fixturePrefix + "/commits/" + target.Commit: {http.StatusOK, commitJSON(target.Commit, target.Tree)},
	})
	destination := filepath.Join(t.TempDir(), "new")
	require.NoError(t, materialize(t.Context(), target, destination, api.client, localFetch(t, repository, nil)))
	require.NoError(t, materialize(t.Context(), target, destination, api.client, (*exec.Cmd).Run))
}

func TestManagedDirectoryEnumerationIsBoundedBeforeLoadingAllEntries(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		writeFixture(t, filepath.Join(directory, name), name, 0600)
	}
	root, err := os.OpenRoot(directory)
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	for _, limit := range []int{2, 3, 4} {
		filesystem := &boundedSourceFS{root: root, ctx: t.Context(), remaining: limit}
		entries, err := fs.ReadDir(filesystem, ".")
		if limit < 3 {
			require.ErrorIs(t, err, errSourceLimit)
			require.Empty(t, entries)
		} else {
			require.NoError(t, err)
			require.Len(t, entries, 3)
			require.Equal(t, "a", entries[0].Name())
			require.Equal(t, "c", entries[2].Name())
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = (&boundedSourceFS{root: root, ctx: ctx, remaining: 3}).ReadDir(".")
	require.ErrorIs(t, err, context.Canceled)
}
