package validation

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	kubevalidation "k8s.io/apimachinery/pkg/util/validation"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

const (
	// MaxArchiveBytes includes tar headers, padding, and the end-of-archive.
	MaxArchiveBytes int64 = 128 << 20
	MaxArchivePaths       = 32768
	stageTimeout          = 5 * time.Minute
)

var (
	credentialURL = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^/\s"'<>]+@`)
	stageName     = regexp.MustCompile(`^pv-[a-f0-9]{32}$`)
)

// Staged carries both rewritten storage paths and independently frozen local
// identities. A custom StageFunc is a trusted input-preparation boundary.
type Staged struct {
	Request    pv.Request
	Sources    pv.Sources
	Files      []pv.FrozenFile
	Provenance []pv.BlobReference
}

type StageFunc func(context.Context, pv.Request) (Staged, error)

// Stager only writes a generated directory in an explicitly provisioned PVC
// upload Pod. Run is an optional subprocess boundary for tests.
type Stager struct {
	Namespace  string
	Kubeconfig string
	InputPod   string
	InputRoot  string
	Run        func(*exec.Cmd) error

	credentials []string
}

func validateLocation(namespace, kubeconfig, pod, root string) error {
	if namespace == "" || len(kubevalidation.IsDNS1123Label(namespace)) != 0 ||
		!absolutePath(kubeconfig) || pod == "" || len(kubevalidation.IsDNS1123Subdomain(pod)) != 0 ||
		!path.IsAbs(root) || path.Clean(root) != root || !relativePath(strings.TrimPrefix(root, "/")) ||
		path.Base(root) != namespace {
		return errors.New("explicit namespace, kubeconfig, input Pod, and absolute namespace input root are required")
	}
	return nil
}

func (s Stager) Stage(ctx context.Context, request pv.Request) (_ Staged, resultErr error) {
	if ctx == nil {
		return Staged{}, errors.New("validation staging context is required")
	}
	ctx, cancel := context.WithTimeout(ctx, stageTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Staged{}, err
	}
	if err := validateLocation(s.Namespace, s.Kubeconfig, s.InputPod, s.InputRoot); err != nil {
		return Staged{}, err
	}
	request, err := normalizeRequest(request)
	if err != nil {
		return Staged{}, err
	}
	if err := s.validateLocalInputs(request); err != nil {
		return Staged{}, err
	}
	root, err := os.MkdirTemp("", "orka-validation-")
	if err != nil {
		return Staged{}, errors.New("cannot create private validation staging")
	}
	identity, err := os.Lstat(root)
	if err != nil {
		return Staged{}, errors.Join(errors.New("cannot identify private validation staging"), os.Remove(root))
	}
	defer func() { resultErr = errors.Join(resultErr, removeOwned(root, identity)) }()
	snapshot := filepath.Join(root, "inputs")
	if os.Mkdir(snapshot, 0700) != nil {
		return Staged{}, errors.New("cannot create private validation snapshot")
	}
	local := request
	local.Repository, local.ChecksDir = filepath.Join(snapshot, "repository"), filepath.Join(snapshot, "checks")
	if request.PatchFile != "" {
		local.PatchFile = filepath.Join(snapshot, "candidate.patch")
	}
	inventory := inventory{credentials: s.credentials}
	for _, pair := range [][2]string{{request.Repository, local.Repository}, {request.ChecksDir, local.ChecksDir}, {request.PatchFile, local.PatchFile}} {
		if pair[0] != "" {
			if err := inventory.copy(ctx, pair[0], pair[1]); err != nil {
				return Staged{}, err
			}
		}
	}
	if err := checkGitMetadata(local.Repository, request.OriginalCommit); err != nil {
		return Staged{}, err
	}
	prepared, err := pv.PrepareSources(ctx, local)
	if err != nil {
		if ctx.Err() != nil {
			return Staged{}, ctx.Err()
		}
		return Staged{}, errors.New("local validation source/check preparation failed")
	}
	defer func() { resultErr = errors.Join(resultErr, prepared.Close()) }()
	if err := cleanCheckout(ctx, local.Repository, prepared.Provenance[prepared.Sources.Original.ArchiveDigest]); err != nil {
		return Staged{}, err
	}
	staged := Staged{Request: request, Sources: prepared.Sources, Files: prepared.Files}
	for digest, content := range prepared.Provenance {
		staged.Provenance = append(staged.Provenance, pv.BlobReference{Digest: digest, Bytes: len(content)})
	}
	sort.Slice(staged.Provenance, func(i, j int) bool { return staged.Provenance[i].Digest < staged.Provenance[j].Digest })
	archive, err := os.OpenFile(filepath.Join(root, "inputs.tar"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return Staged{}, errors.New("cannot create private validation archive")
	}
	defer func() { resultErr = errors.Join(resultErr, safeClose(archive)) }()
	if err := writeArchive(ctx, archive, snapshot); err != nil {
		return Staged{}, err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return Staged{}, errors.New("cannot rewind private validation archive")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Staged{}, errors.New("cannot generate isolated validation directory")
	}
	remote := path.Join(s.InputRoot, "pv-"+hex.EncodeToString(nonce[:]))
	if err := s.exec(ctx, root, nil, "mkdir", "-m", "0700", "--", remote); err != nil {
		return Staged{}, err
	}
	if err := s.exec(ctx, root, archive, "tar", "--extract", "--file=-", "--directory="+remote,
		"--keep-old-files", "--no-same-owner", "--no-same-permissions"); err != nil {
		return Staged{}, err
	}
	staged.Request.Repository, staged.Sources.Repository = path.Join(remote, "repository"), path.Join(remote, "repository")
	staged.Request.ChecksDir = path.Join(remote, "checks")
	if request.PatchFile != "" {
		staged.Request.PatchFile = path.Join(remote, "candidate.patch")
	}
	return staged, nil
}

func (s Stager) validateLocalInputs(request pv.Request) error {
	inputs := []string{request.Repository, request.ChecksDir}
	if request.PatchFile != "" {
		inputs = append(inputs, request.PatchFile)
	}
	for index, input := range inputs {
		if !absolutePath(input) || within(input, s.Kubeconfig) {
			return errUnsafeInput
		}
		for _, other := range inputs[:index] {
			if within(input, other) || within(other, input) {
				return errUnsafeInput
			}
		}
	}
	config, err := openInput(s.Kubeconfig)
	if err != nil {
		return errors.New("explicit kubeconfig is unavailable or unsafe")
	}
	info, statErr := config.Stat()
	closeErr := safeClose(config)
	if statErr != nil || closeErr != nil || !regularInput(info) {
		return errors.New("explicit kubeconfig must be a regular unlinked file")
	}
	return nil
}

func checkGitMetadata(repository, commit string) error {
	git := filepath.Join(repository, ".git")
	info, err := os.Lstat(git)
	if err != nil || !info.IsDir() {
		return errors.New("validation requires a self-contained Git directory, not linked worktree metadata")
	}
	for _, name := range []string{"commondir", "worktrees", "objects/info/alternates", "objects/info/http-alternates"} {
		if _, err := os.Lstat(filepath.Join(git, name)); !errors.Is(err, os.ErrNotExist) {
			return errUnsafeInput
		}
	}
	head, err := os.ReadFile(filepath.Join(git, "HEAD"))
	if err != nil || string(head) != commit+"\n" {
		return errors.New("validation source must be detached at the exact original commit")
	}
	return nil
}

func cleanCheckout(ctx context.Context, repository string, archive []byte) error {
	type entry struct {
		digest     string
		executable bool
	}
	expected := make(map[string]entry)
	reader := tar.NewReader(bytes.NewReader(archive))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return pv.ErrIntegrity
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > MaxArchiveBytes {
			return pv.ErrIntegrity
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			return pv.ErrIntegrity
		}
		expected[header.Name] = entry{pv.Digest(content), header.Mode&0111 != 0}
	}
	err := filepath.WalkDir(repository, func(filename string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errUnsafeInput
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if filename == filepath.Join(repository, ".git") {
			return filepath.SkipDir
		}
		if item.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(repository, filename)
		if err != nil {
			return errUnsafeInput
		}
		want, found := expected[filepath.ToSlash(relative)]
		if !found {
			return errors.New("validation checkout contains untracked or ignored files")
		}
		file, err := openInput(filename)
		if err != nil {
			return err
		}
		content, mode, readErr := readInput(ctx, file, MaxArchiveBytes)
		if err := errors.Join(readErr, safeClose(file)); err != nil {
			return err
		}
		if pv.Digest(content) != want.digest || (mode.Perm()&0111 != 0) != want.executable {
			return errors.New("validation checkout differs from the exact original commit")
		}
		delete(expected, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return err
	}
	if len(expected) != 0 {
		return errors.New("validation checkout is missing files from the exact original commit")
	}
	return nil
}

type archiveLimit struct {
	out   io.Writer
	bytes int64
}

func (w *archiveLimit) Write(data []byte) (int, error) {
	if int64(len(data)) > MaxArchiveBytes-w.bytes {
		return 0, errInputLimit
	}
	n, err := w.out.Write(data)
	w.bytes += int64(n)
	return n, err
}

func writeArchive(ctx context.Context, output io.Writer, root string) error {
	writer := tar.NewWriter(&archiveLimit{out: output})
	count := 0
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errUnsafeInput
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if filename == root {
			return nil
		}
		count++
		name, err := filepath.Rel(root, filename)
		if err != nil || count > MaxArchivePaths || !relativePath(filepath.ToSlash(name)) {
			return errInputLimit
		}
		info, err := entry.Info()
		if err != nil {
			return errUnsafeInput
		}
		header := &tar.Header{Name: filepath.ToSlash(name), Mode: 0700, Typeflag: tar.TypeDir, Format: tar.FormatPAX}
		if info.IsDir() {
			return writer.WriteHeader(header)
		}
		if !regularInput(info) {
			return errUnsafeInput
		}
		header.Typeflag, header.Size, header.Mode = tar.TypeReg, info.Size(), int64(info.Mode().Perm())
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		file, err := openInput(filename)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(writer, contextReader{ctx, file})
		if err := errors.Join(copyErr, safeClose(file)); err != nil {
			return err
		}
		if n != header.Size {
			return errUnsafeInput
		}
		return nil
	})
	return errors.Join(err, writer.Close())
}

func (s Stager) exec(ctx context.Context, home string, input io.Reader, arguments ...string) error {
	binary := "/usr/bin/kubectl"
	run := s.Run
	if run == nil {
		binary = ""
		for _, candidate := range []string{"/usr/local/bin/kubectl", "/usr/bin/kubectl", "/bin/kubectl"} {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				binary = candidate
				break
			}
		}
		if binary == "" {
			return errors.New("kubectl is unavailable in the trusted system paths")
		}
		run = (*exec.Cmd).Run
	}
	args := []string{"--kubeconfig", s.Kubeconfig, "-n", s.Namespace, "exec"}
	if input != nil {
		args = append(args, "-i")
	}
	args = append(args, s.InputPod, "--")
	command := exec.CommandContext(ctx, binary, append(args, arguments...)...)
	command.Dir = home
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + home, "XDG_CONFIG_HOME=" + home, "LANG=C", "LC_ALL=C"}
	command.Stdin, command.Stdout, command.Stderr = input, io.Discard, io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	if err := run(command); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("validation input PVC upload failed")
	}
	return ctx.Err()
}
