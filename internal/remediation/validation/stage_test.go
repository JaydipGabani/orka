package validation

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

func fixtureGit(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("/usr/bin/git", append([]string{
		"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
		"-c", "credential.helper=", "-c", "core.autocrlf=false",
	}, arguments...)...)
	command.Dir = directory
	command.Env = []string{
		"PATH=/usr/bin:/bin", "HOME=" + directory, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	}
	output, err := command.Output()
	require.NoError(t, err)
	return string(output)
}

func writeFixture(t *testing.T, filename, content string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filename), 0700))
	require.NoError(t, os.WriteFile(filename, []byte(content), mode))
	require.NoError(t, os.Chmod(filename, mode))
}

func sourceFixture(t *testing.T, action pv.Action) (pv.Request, Stager) {
	t.Helper()
	return sourceFixtureFormat(t, action, "sha1")
}

func sourceFixtureFormat(t *testing.T, action pv.Action, format string) (pv.Request, Stager) {
	t.Helper()
	root := t.TempDir()
	repository, checks := filepath.Join(root, "repository"), filepath.Join(root, "checks")
	require.NoError(t, os.Mkdir(repository, 0700))
	fixtureGit(t, repository, "init", "--quiet", "--template=", "--object-format="+format)
	writeFixture(t, filepath.Join(repository, "value.txt"), "old\n", 0600)
	writeFixture(t, filepath.Join(repository, ".hidden"), "must be present\n", 0600)
	writeFixture(t, filepath.Join(repository, "bin", "run"), "#!/bin/sh\nexit 0\n", 0700)
	fixtureGit(t, repository, "add", ".")
	fixtureGit(t, repository, "commit", "--quiet", "-m", "synthetic public source")
	commit := strings.TrimSpace(fixtureGit(t, repository, "rev-parse", "HEAD"))
	fixtureGit(t, repository, "checkout", "--quiet", "--detach", commit)
	writeFixture(t, filepath.Join(checks, "check.sh"), "#!/bin/sh\ncat /src/value.txt\n", 0700)
	writeFixture(t, filepath.Join(checks, "private-helper"), "#!/bin/sh\nprintf 'synthetic helper\\n'\n", 0700)
	writeFixture(t, filepath.Join(checks, "inputs", "expected.txt"), "new\n", 0600)
	request := validationFixture(t, action).request
	request.Repository, request.OriginalCommit, request.ChecksDir = repository, commit, checks
	if action != pv.ValidateReport {
		writeFixture(t, filepath.Join(repository, "value.txt"), "new\n", 0600)
		patch := fixtureGit(t, repository, "diff", "--no-ext-diff", "--binary", "--full-index", "--", "value.txt")
		writeFixture(t, filepath.Join(repository, "value.txt"), "old\n", 0600)
		request.PatchFile = filepath.Join(root, "candidate.diff")
		writeFixture(t, request.PatchFile, patch, 0600)
	}
	kubeconfig := filepath.Join(root, "private-kubeconfig")
	writeFixture(t, kubeconfig, "synthetic-kube-authentication-material", 0600)
	return request, Stager{Namespace: "fixture", Kubeconfig: kubeconfig, InputPod: "explicit-input-pod", InputRoot: "/validation/fixture"}
}

type archivedFile struct {
	mode int64
	data []byte
}

func captureArchive(t *testing.T, input io.Reader) map[string]archivedFile {
	t.Helper()
	result := make(map[string]archivedFile)
	reader := tar.NewReader(input)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		require.True(t, relativePath(header.Name))
		require.Empty(t, header.Linkname)
		require.Empty(t, header.Uname)
		require.Empty(t, header.Gname)
		require.Contains(t, []byte{tar.TypeReg, tar.TypeDir}, header.Typeflag)
		if header.Typeflag == tar.TypeDir {
			require.EqualValues(t, 0700, header.Mode)
			continue
		}
		content, err := io.ReadAll(reader)
		require.NoError(t, err)
		require.EqualValues(t, len(content), header.Size)
		result[header.Name] = archivedFile{header.Mode, content}
	}
	return result
}

func TestStageExactInputsMetadataModesAndExplicitExec(t *testing.T) {
	for _, action := range []pv.Action{pv.ValidateReport, pv.VerifyPatch} {
		t.Run(string(action), func(t *testing.T) {
			request, stager := sourceFixture(t, action)
			t.Setenv("OPENAI_API_KEY", "synthetic-model-secret-never-upload")
			t.Setenv("AZURE_CLIENT_SECRET", "synthetic-cloud-secret-never-inherit")
			t.Setenv("KUBECONFIG", "/ambient/config-must-not-be-used")
			writeFixture(t, filepath.Join(filepath.Dir(request.Repository), "incident-report.json"), "synthetic-incident-never-upload", 0600)
			commands := make([][]string, 0)
			directories := make([]string, 0)
			var captured map[string]archivedFile
			stager.Run = func(command *exec.Cmd) error {
				commands = append(commands, append([]string(nil), command.Args...))
				directories = append(directories, command.Dir)
				require.Equal(t, "/usr/bin/kubectl", command.Path)
				require.Equal(t, []string{"--kubeconfig", stager.Kubeconfig, "-n", "fixture", "exec"}, command.Args[1:6])
				require.NotContains(t, command.Args, "sh")
				require.NotContains(t, command.Args, "bash")
				require.NotContains(t, command.Args, "-c")
				require.Equal(t, []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + command.Dir,
					"XDG_CONFIG_HOME=" + command.Dir, "LANG=C", "LC_ALL=C"}, command.Env)
				require.Equal(t, io.Discard, command.Stdout)
				require.Equal(t, io.Discard, command.Stderr)
				for _, argument := range command.Args {
					require.NotContains(t, argument, request.Repository)
					require.NotContains(t, argument, request.ChecksDir)
				}
				switch len(commands) {
				case 1:
					require.Nil(t, command.Stdin)
					require.Equal(t, []string{"explicit-input-pod", "--", "mkdir", "-m", "0700", "--"}, command.Args[6:12])
					require.True(t, stageName.MatchString(filepath.Base(command.Args[12])))
				case 2:
					require.Equal(t, []string{"-i", "explicit-input-pod", "--", "tar", "--extract", "--file=-"}, command.Args[6:12])
					require.Equal(t, "--directory="+commands[0][12], command.Args[12])
					require.Equal(t, []string{"--keep-old-files", "--no-same-owner", "--no-same-permissions"}, command.Args[13:])
					captured = captureArchive(t, command.Stdin)
				default:
					t.Error("staging performed an unexpected subprocess operation")
				}
				return nil
			}
			staged, err := stager.Stage(t.Context(), request)
			require.NoError(t, err)
			require.Len(t, commands, 2)
			require.Equal(t, commands[0][12]+"/repository", staged.Request.Repository)
			require.Equal(t, commands[0][12]+"/checks", staged.Request.ChecksDir)
			require.Equal(t, request.OriginalCommit, staged.Sources.Original.Commit)
			require.Equal(t, staged.Request.Repository, staged.Sources.Repository)
			require.Equal(t, "old\n", string(captured["repository/value.txt"].data))
			require.Equal(t, "must be present\n", string(captured["repository/.hidden"].data))
			require.Equal(t, request.OriginalCommit+"\n", string(captured["repository/.git/HEAD"].data))
			require.Contains(t, captured, "repository/.git/config")
			require.Contains(t, captured, "repository/.git/index")
			objects := 0
			for name := range captured {
				if strings.HasPrefix(name, "repository/.git/objects/") {
					objects++
				}
			}
			require.Positive(t, objects)
			require.EqualValues(t, 0700, captured["repository/bin/run"].mode)
			require.EqualValues(t, 0700, captured["checks/private-helper"].mode)
			require.EqualValues(t, 0600, captured["checks/inputs/expected.txt"].mode)
			require.Len(t, staged.Files, 3)
			for _, frozen := range staged.Files {
				actual := captured["checks/"+frozen.Path]
				require.Equal(t, frozen.Content, actual.data)
				require.Equal(t, frozen.Digest, pv.Digest(actual.data))
				require.Equal(t, frozen.Executable, actual.mode&0111 != 0)
			}
			if action == pv.VerifyPatch {
				patch, err := os.ReadFile(request.PatchFile)
				require.NoError(t, err)
				require.Equal(t, patch, captured["candidate.patch"].data)
				require.Equal(t, pv.Digest(patch), staged.Sources.PatchDigest)
				require.Equal(t, commands[0][12]+"/candidate.patch", staged.Request.PatchFile)
			} else {
				require.Empty(t, staged.Request.PatchFile)
				require.NotContains(t, captured, "candidate.patch")
				require.Equal(t, pv.SourceIdentity{}, staged.Sources.Patched)
			}
			for name, file := range captured {
				for _, forbidden := range []string{"synthetic-model-secret", "synthetic-cloud-secret",
					"synthetic-incident-never-upload", "synthetic-kube-authentication-material"} {
					require.NotContains(t, name, forbidden)
					require.NotContains(t, string(file.data), forbidden)
				}
			}
			for _, directory := range directories {
				_, err := os.Stat(directory)
				require.ErrorIs(t, err, os.ErrNotExist, "local private copies must be removed")
			}
			normalized, err := normalizeRequest(request)
			require.NoError(t, err)
			require.NoError(t, validateStaged(stager.InputRoot, normalized, staged))
		})
	}
}

func TestStageRejectsUnsafeOrInexactInputsBeforeExec(t *testing.T) {
	for _, mutation := range []string{
		"symlink-file", "symlink-directory", "symlink-parent", "fifo", "hardlink", "setuid",
		"dirty", "missing", "untracked", "ignored", "mode", "head", "linked-git", "alternates",
		"checks-in-source", "patch-in-checks", "oversize", "credential", "url-credential",
		"known-api-credential", "unsafe-name", "kubeconfig-in-input", "kubeconfig-symlink",
	} {
		t.Run(mutation, func(t *testing.T) {
			request, stager := sourceFixture(t, pv.VerifyPatch)
			external := filepath.Join(filepath.Dir(request.Repository), "external")
			writeFixture(t, external, "private synthetic external bytes", 0600)
			switch mutation {
			case "symlink-file":
				require.NoError(t, os.Symlink(external, filepath.Join(request.ChecksDir, "linked")))
			case "symlink-directory":
				require.NoError(t, os.Symlink(filepath.Dir(external), filepath.Join(request.ChecksDir, "linked")))
			case "symlink-parent":
				link := filepath.Join(t.TempDir(), "linked")
				require.NoError(t, os.Symlink(filepath.Dir(request.ChecksDir), link))
				request.ChecksDir = filepath.Join(link, filepath.Base(request.ChecksDir))
			case "fifo":
				require.NoError(t, syscall.Mkfifo(filepath.Join(request.ChecksDir, "fifo"), 0600))
			case "hardlink":
				require.NoError(t, os.Link(external, filepath.Join(request.ChecksDir, "linked")))
			case "setuid":
				require.NoError(t, os.Chmod(filepath.Join(request.ChecksDir, "check.sh"), os.ModeSetuid|0700))
			case "dirty":
				writeFixture(t, filepath.Join(request.Repository, "value.txt"), "changed\n", 0600)
			case "missing":
				require.NoError(t, os.Remove(filepath.Join(request.Repository, "value.txt")))
			case "untracked", "ignored":
				writeFixture(t, filepath.Join(request.Repository, "private-report.json"), "synthetic report outside exact tree", 0600)
				if mutation == "ignored" {
					writeFixture(t, filepath.Join(request.Repository, ".git/info/exclude"), "private-report.json\n", 0600)
				}
			case "mode":
				require.NoError(t, os.Chmod(filepath.Join(request.Repository, "bin/run"), 0600))
			case "head":
				writeFixture(t, filepath.Join(request.Repository, ".git/HEAD"), strings.Repeat("f", 40)+"\n", 0600)
			case "linked-git":
				git := filepath.Join(request.Repository, ".git")
				require.NoError(t, os.Rename(git, filepath.Join(filepath.Dir(request.Repository), "private-git")))
				writeFixture(t, git, "gitdir: ../private-git\n", 0600)
			case "alternates":
				writeFixture(t, filepath.Join(request.Repository, ".git/objects/info/alternates"), filepath.Dir(external), 0600)
			case "checks-in-source":
				request.ChecksDir = request.Repository
			case "patch-in-checks":
				request.PatchFile = filepath.Join(request.ChecksDir, "check.sh")
			case "oversize":
				file, err := os.OpenFile(filepath.Join(request.Repository, ".git/oversize"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
				require.NoError(t, err)
				require.NoError(t, file.Truncate(MaxArchiveBytes+1))
				require.NoError(t, file.Close())
			case "credential":
				writeFixture(t, filepath.Join(request.ChecksDir, "bad"), "api_key = \"synthetic-secret-literal\"\n", 0600)
			case "url-credential":
				writeFixture(t, filepath.Join(request.Repository, ".git/config"), "[remote \"origin\"]\nurl = https://fixture:synthetic-secret@example.invalid/repo\n", 0600)
			case "known-api-credential":
				stager.credentials = []string{"opaque-synthetic-api-credential"}
				writeFixture(t, filepath.Join(request.ChecksDir, "bad"), "opaque-synthetic-api-credential", 0600)
			case "unsafe-name":
				writeFixture(t, filepath.Join(request.ChecksDir, "unsafe\nname"), "fixture", 0600)
			case "kubeconfig-in-input":
				stager.Kubeconfig = filepath.Join(request.ChecksDir, "check.sh")
			case "kubeconfig-symlink":
				link := filepath.Join(t.TempDir(), "kubeconfig")
				require.NoError(t, os.Symlink(stager.Kubeconfig, link))
				stager.Kubeconfig = link
			}
			calls := 0
			stager.Run = func(*exec.Cmd) error { calls++; return nil }
			_, err := stager.Stage(t.Context(), request)
			require.Error(t, err)
			require.Zero(t, calls)
			require.NotContains(t, err.Error(), "synthetic-secret")
			require.NotContains(t, err.Error(), "opaque-synthetic-api-credential")
		})
	}
}

func TestStageIsolatesCallsAndStopsOnSubprocessFailure(t *testing.T) {
	request, stager := sourceFixture(t, pv.ValidateReport)
	roots := make([]string, 0)
	stager.Run = func(command *exec.Cmd) error {
		if command.Stdin == nil {
			roots = append(roots, command.Args[len(command.Args)-1])
		} else {
			_, err := io.Copy(io.Discard, command.Stdin)
			require.NoError(t, err)
		}
		return nil
	}
	first, err := stager.Stage(t.Context(), request)
	require.NoError(t, err)
	second, err := stager.Stage(t.Context(), request)
	require.NoError(t, err)
	require.Len(t, roots, 2)
	require.NotEqual(t, roots[0], roots[1])
	require.NotEqual(t, first.Request.Repository, second.Request.Repository)
	require.Equal(t, first.Sources.Original, second.Sources.Original)
	require.Equal(t, first.Files, second.Files)
	require.Equal(t, first.Provenance, second.Provenance)

	calls := 0
	var localRoot string
	stager.Run = func(command *exec.Cmd) error {
		calls++
		localRoot = command.Dir
		return errors.New("synthetic-model-secret from subprocess must not escape")
	}
	_, err = stager.Stage(t.Context(), request)
	require.Error(t, err)
	require.Equal(t, 1, calls)
	require.NotContains(t, err.Error(), "synthetic-model-secret")
	_, statErr := os.Stat(localRoot)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestStageCancellationBeforeUpload(t *testing.T) {
	request, stager := sourceFixture(t, pv.ValidateReport)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	calls := 0
	stager.Run = func(*exec.Cmd) error { calls++; return nil }
	_, err := stager.Stage(ctx, request)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, calls)
}

func TestStagePairedCommitsKeepBothObjectIdentities(t *testing.T) {
	request, stager := sourceFixture(t, pv.VerifyPatch)
	writeFixture(t, filepath.Join(request.Repository, "value.txt"), "new\n", 0600)
	fixtureGit(t, request.Repository, "add", "value.txt")
	fixtureGit(t, request.Repository, "commit", "--quiet", "-m", "synthetic patched commit")
	request.PatchedCommit = strings.TrimSpace(fixtureGit(t, request.Repository, "rev-parse", "HEAD"))
	fixtureGit(t, request.Repository, "checkout", "--quiet", "--detach", request.OriginalCommit)
	request.PatchFile = ""
	var captured map[string]archivedFile
	stager.Run = func(command *exec.Cmd) error {
		if command.Stdin != nil {
			captured = captureArchive(t, command.Stdin)
		}
		return nil
	}
	staged, err := stager.Stage(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, request.OriginalCommit, staged.Sources.Original.Commit)
	require.Equal(t, request.PatchedCommit, staged.Sources.Patched.Commit)
	require.NotEqual(t, staged.Sources.Original.Tree, staged.Sources.Patched.Tree)
	require.NotEmpty(t, staged.Sources.DiffDigest)
	require.Empty(t, staged.Sources.PatchDigest)
	require.Empty(t, staged.Request.PatchFile)
	require.NotContains(t, captured, "candidate.patch")
	require.Equal(t, "old\n", string(captured["repository/value.txt"].data))
}

func TestStagePreservesShallowPackedGitMetadata(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		for _, action := range []pv.Action{pv.ValidateReport, pv.VerifyPatch} {
			t.Run(format+"/"+string(action), func(t *testing.T) {
				request, stager := sourceFixtureFormat(t, action, format)
				writeFixture(t, filepath.Join(request.Repository, "tracked.txt"), "shallow source fixture\n", 0600)
				fixtureGit(t, request.Repository, "add", "tracked.txt")
				fixtureGit(t, request.Repository, "commit", "--quiet", "-m", "synthetic shallow tip")
				request.OriginalCommit = strings.TrimSpace(fixtureGit(t, request.Repository, "rev-parse", "HEAD"))
				objectIDLength := 40
				if format == "sha256" {
					objectIDLength = 64
				}
				require.Len(t, request.OriginalCommit, objectIDLength)

				shallow := filepath.Join(filepath.Dir(request.Repository), "shallow")
				require.NoError(t, os.Mkdir(shallow, 0700))
				fixtureGit(t, shallow, "init", "--quiet", "--template=", "--object-format="+format)
				fixtureGit(t, shallow, "-c", "fetch.unpackLimit=1", "fetch", "--quiet", "--depth=1",
					"--no-tags", "--no-recurse-submodules", "--", request.Repository, request.OriginalCommit)
				attributes := "* -filter -text -eol -ident -working-tree-encoding\n"
				writeFixture(t, filepath.Join(shallow, ".git/info/attributes"), attributes, 0600)
				fixtureGit(t, shallow, "checkout", "--quiet", "--detach", request.OriginalCommit)
				fixtureGit(t, shallow, "-c", "pack.writeReverseIndex=true", "repack", "-a", "-d")
				require.NoError(t, os.Mkdir(filepath.Join(shallow, ".git/tmp"), 0700))
				require.Equal(t, "true\n", fixtureGit(t, shallow, "rev-parse", "--is-shallow-repository"))
				require.Equal(t, "1\n", fixtureGit(t, shallow, "rev-list", "--count", "HEAD"))
				require.Empty(t, fixtureGit(t, shallow, "remote"))
				request.Repository = shallow

				version, extensions := "0", ""
				if format == "sha256" {
					version, extensions = "1", "[extensions]\n\tobjectformat = sha256\n"
				}
				config := "[core]\n\trepositoryformatversion = " + version +
					"\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = false\n" +
					extensions + "[remote \"origin\"]\n\turl = https://github.com/fixture/public-source.git\n"
				tree := strings.TrimSpace(fixtureGit(t, shallow, "rev-parse", "HEAD^{tree}"))
				writeFixture(t, filepath.Join(shallow, ".git/config"), config, 0600)
				physical, err := os.Stat(shallow)
				require.NoError(t, err)
				identity, ok := physical.Sys().(*syscall.Stat_t)
				require.True(t, ok)
				// Staging treats this versioned source marker as opaque metadata;
				// it must not replace its original physical identity or checksum.
				marker := []byte(fmt.Sprintf(
					`{"version":1,"target":{"repository":{"url":"https://github.com/fixture/public-source",`+
						`"owner":"fixture","name":"public-source","defaultBranch":"main","archived":false},`+
						`"ref":"%s","commit":"%s","tree":"%s"},"identity":{"device":%d,"inode":%d},"snapshot":"%s"}`+"\n",
					request.OriginalCommit, request.OriginalCommit, tree, identity.Dev, identity.Ino, strings.Repeat("e", 64)))
				writeFixture(t, filepath.Join(shallow, ".git/orka-source.json"), string(marker), 0600)
				require.NoError(t, os.Chmod(filepath.Join(shallow, ".git/index"), 0400))
				expected := make(map[string][]byte)
				metadataInfo := make(map[string]os.FileInfo)
				gitDirectory := filepath.Join(shallow, ".git")
				require.NoError(t, filepath.WalkDir(gitDirectory, func(filename string, entry fs.DirEntry, err error) error {
					require.NoError(t, err)
					info, err := entry.Info()
					require.NoError(t, err)
					metadataInfo[filename] = info
					if entry.IsDir() {
						return nil
					}
					relative, err := filepath.Rel(shallow, filename)
					require.NoError(t, err)
					content, err := os.ReadFile(filename)
					require.NoError(t, err)
					expected["repository/"+filepath.ToSlash(relative)] = content
					return nil
				}))
				var captured map[string]archivedFile
				directories := make(map[string]bool)
				stager.Run = func(command *exec.Cmd) error {
					if command.Stdin == nil {
						return nil
					}
					content, err := io.ReadAll(command.Stdin)
					require.NoError(t, err)
					captured = captureArchive(t, bytes.NewReader(content))
					reader := tar.NewReader(bytes.NewReader(content))
					for {
						header, err := reader.Next()
						if errors.Is(err, io.EOF) {
							break
						}
						require.NoError(t, err)
						if header.Typeflag == tar.TypeDir {
							directories[header.Name] = true
						}
					}
					return nil
				}
				staged, err := stager.Stage(t.Context(), request)
				require.NoError(t, err)
				require.Equal(t, request.OriginalCommit, staged.Sources.Original.Commit)
				require.Len(t, staged.Sources.Original.Tree, objectIDLength)
				if action == pv.VerifyPatch {
					require.Len(t, staged.Sources.Patched.Tree, objectIDLength)
				}
				require.Equal(t, request.OriginalCommit+"\n", string(captured["repository/.git/shallow"].data))
				require.Equal(t, attributes, string(captured["repository/.git/info/attributes"].data))
				require.Equal(t, marker, captured["repository/.git/orka-source.json"].data)
				require.EqualValues(t, 0600, captured["repository/.git/orka-source.json"].mode)
				require.Equal(t, config, string(captured["repository/.git/config"].data))
				require.True(t, directories["repository/.git/tmp"], "empty Git metadata directories must survive")
				var packs, indexes, reverseIndexes, metadataFiles int
				for name, file := range captured {
					if !strings.HasPrefix(name, "repository/.git/") {
						continue
					}
					metadataFiles++
					require.Contains(t, expected, name)
					require.Equal(t, expected[name], file.data, "Git metadata must be transferred byte-for-byte")
					if strings.HasPrefix(name, "repository/.git/objects/pack/") {
						switch filepath.Ext(name) {
						case ".pack":
							packs++
						case ".idx":
							indexes++
						case ".rev":
							reverseIndexes++
						}
					}
				}
				require.Len(t, expected, metadataFiles)
				require.Positive(t, packs)
				require.Equal(t, packs, indexes)
				require.Equal(t, packs, reverseIndexes)
				for filename, before := range metadataInfo {
					after, err := os.Stat(filename)
					require.NoError(t, err)
					require.True(t, os.SameFile(before, after), "staging replaced original metadata")
					require.Equal(t, before.Mode(), after.Mode())
					require.Equal(t, before.ModTime(), after.ModTime())
					require.Equal(t, before.Size(), after.Size())
					if !before.IsDir() {
						content, err := os.ReadFile(filename)
						require.NoError(t, err)
						relative, err := filepath.Rel(shallow, filename)
						require.NoError(t, err)
						require.Equal(t, expected["repository/"+filepath.ToSlash(relative)], content)
					}
				}
			})
		}
	}
}

func TestArchiveEncodedByteAndPathLimits(t *testing.T) {
	require.EqualValues(t, 128<<20, MaxArchiveBytes)
	for _, remaining := range []int64{0, 1, 2} {
		var output bytes.Buffer
		writer := archiveLimit{out: &output, bytes: MaxArchiveBytes - remaining}
		n, err := writer.Write([]byte("xx"))
		if remaining == 2 {
			require.NoError(t, err)
			require.Equal(t, 2, n)
			require.Equal(t, MaxArchiveBytes, writer.bytes)
			_, err = writer.Write([]byte("x"))
			require.ErrorIs(t, err, errInputLimit)
		} else {
			require.ErrorIs(t, err, errInputLimit)
			require.Zero(t, n)
			require.Zero(t, output.Len())
		}
	}
	request, _ := sourceFixture(t, pv.ValidateReport)
	file, err := openInput(filepath.Join(request.Repository, "value.txt"))
	require.NoError(t, err)
	defer file.Close() //nolint:errcheck
	destination := filepath.Join(t.TempDir(), "copy")
	budget := inventory{paths: MaxArchivePaths - 1}
	require.NoError(t, budget.copyOpened(t.Context(), file, destination, "value.txt"))
	require.Equal(t, MaxArchivePaths, budget.paths)
	destination = filepath.Join(t.TempDir(), "overflow")
	require.ErrorIs(t, budget.copyOpened(t.Context(), file, destination, "value.txt"), errInputLimit)
	_, err = os.Stat(destination)
	require.ErrorIs(t, err, os.ErrNotExist)

	// Archive framing, not just file payload, consumes the 128 MiB allowance.
	for _, overhead := range []int64{2048, 1536, 1024} {
		root := t.TempDir()
		sparse, err := os.OpenFile(filepath.Join(root, "large"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		require.NoError(t, err)
		require.NoError(t, sparse.Truncate(MaxArchiveBytes-overhead))
		require.NoError(t, sparse.Close())
		var output byteCounter
		err = writeArchive(t.Context(), &output, root)
		if overhead < 1536 {
			require.ErrorIs(t, err, errInputLimit)
		} else {
			require.NoError(t, err)
			require.Equal(t, MaxArchiveBytes-overhead+1536, output.bytes)
		}
		require.LessOrEqual(t, output.bytes, MaxArchiveBytes)
	}
}

type byteCounter struct {
	bytes int64
}

func (w *byteCounter) Write(data []byte) (int, error) {
	w.bytes += int64(len(data))
	return len(data), nil
}

func TestStageRequiresExplicitSafeLocation(t *testing.T) {
	for _, configuration := range []Stager{
		{Kubeconfig: "/private/config", InputPod: "pod", InputRoot: "/validation/fixture"},
		{Namespace: "fixture", InputPod: "pod", InputRoot: "/validation/fixture"},
		{Namespace: "fixture", Kubeconfig: "/private/config", InputRoot: "/validation/fixture"},
		{Namespace: "fixture", Kubeconfig: "/private/config", InputPod: "pod"},
		{Namespace: "fixture", Kubeconfig: "/private/config", InputPod: "pod;false", InputRoot: "/validation/fixture"},
		{Namespace: "fixture", Kubeconfig: "/private/config", InputPod: "pod", InputRoot: "/validation/../fixture"},
		{Namespace: "fixture", Kubeconfig: "/private/config", InputPod: "pod", InputRoot: "/validation/other"},
	} {
		_, err := configuration.Stage(t.Context(), pv.Request{})
		require.Error(t, err)
	}
}
