package patchverification

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unicode/utf8"
)

const (
	sourceMaxArchiveBytes  = 32 << 20
	sourceMaxManifestBytes = 1 << 20
	sourceMaxFrozenFiles   = 128
	sourceMaxTreeEntries   = 8192
	sourceMaxPathBytes     = 1024
	sourceMaxPathDepth     = 32
	sourceMaxRunBlobBytes  = 128 << 20
	sourceManifestReserve  = 16 << 10
)

var sourceCredentials = CredentialMatcher{}

var sourceRoots sync.Map

type sourceRoot struct {
	mutex sync.Mutex
	name  string
	info  os.FileInfo
}

type sourceCheckFile struct {
	FrozenFile
	mode os.FileMode
}

func PrepareSources(ctx context.Context, request Request) (_ *PreparedSources, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := sourceValidateRequest(request); err != nil {
		return nil, err
	}
	repository, objects, metadata, err := sourceRepository(ctx, request.Repository)
	if err != nil {
		return nil, err
	}
	checksDirectory, err := sourceDirectory(request.ChecksDir, false)
	if err != nil {
		return nil, err
	}
	for _, directory := range append([]string{repository}, metadata...) {
		if sourcePathsOverlap(checksDirectory, directory) {
			return nil, errSourceChecks
		}
	}
	patch, err := sourceReadPatch(ctx, request.PatchFile, checksDirectory)
	if err != nil {
		return nil, err
	}
	checks, err := sourceFreezeChecks(ctx, checksDirectory, request)
	if err != nil {
		return nil, err
	}
	prepared, err := sourcePrepareRoot(repository, checksDirectory, metadata)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, prepared.Close())
		}
	}()
	format := "sha1"
	if len(request.OriginalCommit) == 64 {
		format = "sha256"
	}
	git, err := sourceNewGit(ctx, prepared.Root, format)
	if err != nil {
		return nil, err
	}
	originalTree, err := git.importCommit(ctx, objects, request.OriginalCommit)
	if err != nil {
		return nil, err
	}
	originalArchive, err := git.archive(ctx, originalTree)
	if err != nil {
		return nil, err
	}
	prepared.Sources = Sources{Repository: repository, Original: SourceIdentity{
		Commit: request.OriginalCommit, Tree: originalTree, ArchiveDigest: Digest(originalArchive),
	}}
	prepared.Provenance[prepared.Sources.Original.ArchiveDigest] = originalArchive
	if err := sourceExtractArchive(ctx, originalArchive, prepared.OriginalDir); err != nil {
		return nil, err
	}
	if request.Action == ValidateReport {
		prepared.PatchedDir = ""
	} else {
		patchedTree := ""
		if request.PatchedCommit != "" {
			patchedTree, err = git.importCommit(ctx, objects, request.PatchedCommit)
		} else {
			patchedTree, err = git.applyPatch(ctx, originalTree, patch, len(originalArchive))
		}
		if err != nil {
			return nil, err
		}
		archive, err := git.archive(ctx, patchedTree)
		if err != nil {
			return nil, err
		}
		prepared.Sources.Patched = SourceIdentity{
			Commit: request.PatchedCommit, Tree: patchedTree, ArchiveDigest: Digest(archive),
		}
		prepared.Provenance[prepared.Sources.Patched.ArchiveDigest] = archive
		if err := sourceExtractArchive(ctx, archive, prepared.PatchedDir); err != nil {
			return nil, err
		}
		diff, err := git.run(ctx, nil, sourceMaxArchiveBytes, "diff", "--no-ext-diff", "--no-textconv", "--binary", "--full-index", "--no-renames", "--no-color", "--src-prefix=a/", "--dst-prefix=b/", originalTree, patchedTree, "--")
		if err != nil {
			return nil, err
		}
		prepared.Sources.DiffDigest = Digest(diff)
		prepared.Provenance[prepared.Sources.DiffDigest] = diff
		if patch != nil {
			prepared.Sources.PatchDigest = Digest(patch)
			prepared.Provenance[prepared.Sources.PatchDigest] = patch
		}
	}
	if err := sourceFinishStaging(ctx, request, prepared, checks); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(git.repository); err != nil {
		return nil, errSourceCleanup
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return prepared, nil
}

func sourceReadPatch(ctx context.Context, filename, checksDirectory string) ([]byte, error) {
	if filename == "" {
		return nil, nil
	}
	if !sourceAbsolutePath(filename) || sourcePathsOverlap(checksDirectory, filepath.Clean(filename)) {
		return nil, errSourceChecks
	}
	patch, err := sourceReadFile(ctx, filepath.Clean(filename), sourceMaxArchiveBytes)
	if err != nil {
		return nil, err
	}
	if len(patch) == 0 {
		return nil, errSourceInput
	}
	if sourceCredentials.Match(patch) {
		return nil, errSourceSecret
	}
	return patch, nil
}

func sourceValidateRequest(request Request) error {
	if ValidateRequestAction(request) != nil || !sourceValidCommit(request.OriginalCommit) ||
		(request.PatchedCommit != "" && (!sourceValidCommit(request.PatchedCommit) ||
			len(request.PatchedCommit) != len(request.OriginalCommit))) {
		return errSourceInput
	}
	budget := sourceMaxManifestBytes
	if !sourceRequestText(reflect.ValueOf(request), &budget) || len(request.Checks) == 0 || len(request.Checks) > 100 || len(request.Services) > 8 {
		return errSourceChecks
	}
	requestBytes, err := json.Marshal(request)
	if err != nil || len(requestBytes) > sourceMaxManifestBytes {
		return errSourceLimit
	}
	if sourceCredentials.Match(requestBytes) {
		return errSourceSecret
	}
	for name := range request.Variables {
		for _, marker := range []string{"TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY", "AUTHORIZATION"} {
			if strings.Contains(strings.ToUpper(name), marker) {
				return errSourceSecret
			}
		}
	}
	return nil
}

func sourcePrepareRoot(repository, checksDirectory string, metadata []string) (*PreparedSources, error) {
	parent, err := sourceDirectory(os.TempDir(), true)
	if err != nil || sourceOutsideWorktree(parent) != nil {
		return nil, errSourcePath
	}
	for _, directory := range append([]string{repository, checksDirectory}, metadata...) {
		if sourceWithin(directory, parent) {
			return nil, errSourcePath
		}
	}
	root, err := os.MkdirTemp(parent, "orka-sources-")
	if err != nil {
		return nil, errSourcePath
	}
	prepared := &PreparedSources{Root: root, OriginalDir: filepath.Join(root, "original"), PatchedDir: filepath.Join(root, "patched"), ChecksDir: filepath.Join(root, "checks"), Provenance: make(map[string][]byte)}
	info, err := os.Lstat(root)
	if err != nil {
		if os.Remove(root) != nil {
			return nil, errSourceCleanup
		}
		return nil, errSourcePath
	}
	sourceRoots.Store(prepared, &sourceRoot{name: root, info: info})
	return prepared, nil
}

func sourceFinishStaging(ctx context.Context, request Request, prepared *PreparedSources, checks []sourceCheckFile) error {
	if err := os.Mkdir(prepared.ChecksDir, 0700); err != nil {
		return errSourcePath
	}
	for _, file := range checks {
		if err := ctx.Err(); err != nil {
			return err
		}
		prepared.Files = append(prepared.Files, file.FrozenFile)
		prepared.Provenance[file.Digest] = file.Content
		if err := sourceWriteSnapshot(prepared.ChecksDir, file.Path, file.Content, file.mode); err != nil {
			return err
		}
	}
	if err := sourceSealDirectories(prepared.ChecksDir); err != nil {
		return err
	}
	if err := sourceManifestBounds(request, prepared); err != nil {
		return err
	}
	total := 0
	for _, content := range prepared.Provenance {
		if len(content) > sourceMaxArchiveBytes || len(content) > sourceMaxRunBlobBytes-total {
			return errSourceLimit
		}
		if sourceCredentials.Match(content) {
			return errSourceSecret
		}
		total += len(content)
	}
	return nil
}

func (prepared *PreparedSources) Close() error {
	value, found := sourceRoots.Load(prepared)
	if !found {
		return nil
	}
	root := value.(*sourceRoot)
	root.mutex.Lock()
	defer root.mutex.Unlock()
	info, err := os.Lstat(root.name)
	if errors.Is(err, os.ErrNotExist) {
		sourceRoots.Delete(prepared)
		return nil
	}
	if err != nil || !info.IsDir() || !os.SameFile(info, root.info) {
		return errSourceCleanup
	}
	if err := filepath.WalkDir(root.name, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errSourceCleanup
		}
		if entry.IsDir() {
			opened, err := sourceOpenPath(filename, true)
			if err != nil {
				return errSourceCleanup
			}
			chmodErr, closeErr := opened.Chmod(0700), opened.Close()
			if chmodErr != nil || closeErr != nil {
				return errSourceCleanup
			}
		}
		return nil
	}); err != nil {
		return errSourceCleanup
	}
	if err := os.RemoveAll(root.name); err != nil {
		return errSourceCleanup
	}
	sourceRoots.Delete(prepared)
	return nil
}

func sourceAbsolutePath(filename string) bool {
	return filepath.IsAbs(filename) && filename != "/" && len(filename) <= 4096 && utf8.ValidString(filename) && !strings.ContainsFunc(filename, unicode.IsControl) && !strings.ContainsAny(filename, "\\:,?#")
}

func sourceDirectory(directory string, allowSymlinks bool) (string, error) {
	if !sourceAbsolutePath(directory) {
		return "", errSourcePath
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(directory))
	if err != nil || !sourceAbsolutePath(resolved) || (!allowSymlinks && resolved != filepath.Clean(directory)) {
		return "", errSourcePath
	}
	opened, err := sourceOpenPath(resolved, true)
	if err != nil {
		return "", err
	}
	if err := opened.Close(); err != nil {
		return "", errSourcePath
	}
	return resolved, nil
}

func sourceWithin(parent, child string) bool {
	return parent == child || strings.HasPrefix(child, parent+string(filepath.Separator))
}

func sourcePathsOverlap(first, second string) bool {
	return sourceWithin(first, second) || sourceWithin(second, first)
}

func sourceOutsideWorktree(directory string) error {
	for ancestor := directory; ; ancestor = filepath.Dir(ancestor) {
		if _, err := os.Lstat(filepath.Join(ancestor, ".git")); !errors.Is(err, os.ErrNotExist) {
			return errSourcePath
		}
		if head, err := os.Lstat(filepath.Join(ancestor, "HEAD")); err == nil && head.Mode().IsRegular() {
			if objects, err := os.Lstat(filepath.Join(ancestor, "objects")); err == nil && objects.IsDir() {
				return errSourcePath
			}
		}
		if ancestor == "/" {
			return nil
		}
	}
}

func sourceRepository(ctx context.Context, directory string) (string, string, []string, error) {
	repository, err := sourceDirectory(directory, true)
	if err != nil {
		return "", "", nil, err
	}
	metadata := filepath.Join(repository, ".git")
	info, err := os.Lstat(metadata)
	if errors.Is(err, os.ErrNotExist) {
		metadata = repository
	} else if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", "", nil, errSourcePath
	} else if info.Mode().IsRegular() {
		content, err := sourceReadFile(ctx, metadata, 4096)
		if err != nil || !bytes.HasPrefix(content, []byte("gitdir: ")) {
			return "", "", nil, errSourcePath
		}
		metadata = strings.TrimSuffix(string(content[len("gitdir: "):]), "\n")
		if !filepath.IsAbs(metadata) {
			metadata = filepath.Join(repository, metadata)
		}
	}
	metadata, err = sourceDirectory(metadata, false)
	if err != nil {
		return "", "", nil, err
	}
	common := metadata
	commonFile := filepath.Join(metadata, "commondir")
	if _, err := os.Lstat(commonFile); err == nil {
		content, err := sourceReadFile(ctx, commonFile, 4096)
		if err != nil {
			return "", "", nil, err
		}
		common = strings.TrimSuffix(string(content), "\n")
		if !filepath.IsAbs(common) {
			common = filepath.Join(metadata, common)
		}
		common, err = sourceDirectory(common, false)
		if err != nil {
			return "", "", nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", nil, errSourcePath
	}
	objects, err := sourceDirectory(filepath.Join(common, "objects"), false)
	if err != nil {
		return "", "", nil, err
	}
	for _, name := range []string{"alternates", "http-alternates"} {
		if _, err := os.Lstat(filepath.Join(objects, "info", name)); !errors.Is(err, os.ErrNotExist) {
			return "", "", nil, errSourcePath
		}
	}
	return repository, objects, []string{metadata, common}, nil
}

func sourceOpenPath(filename string, directory bool) (*os.File, error) {
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		return nil, errSourcePath
	}
	parent, err := os.Open("/")
	if err != nil {
		return nil, errSourcePath
	}
	components := strings.Split(strings.TrimPrefix(filename, "/"), "/")
	for index, component := range components {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if index != len(components)-1 || directory {
			flags |= syscall.O_DIRECTORY
		}
		fd, err := syscall.Openat(int(parent.Fd()), component, flags, 0)
		closeErr := parent.Close()
		if err != nil {
			return nil, errSourcePath
		}
		parent = os.NewFile(uintptr(fd), filename)
		if closeErr != nil {
			_ = parent.Close()
			return nil, errSourcePath
		}
	}
	return parent, nil
}

type sourceContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader sourceContextReader) Read(content []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(content)
}

func sourceReadOpened(ctx context.Context, opened *os.File, limit int) ([]byte, os.FileMode, error) {
	info, err := opened.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, 0, errSourcePath
	}
	if info.Size() < 0 || info.Size() > int64(limit) {
		return nil, 0, errSourceLimit
	}
	content, err := io.ReadAll(io.LimitReader(sourceContextReader{ctx: ctx, reader: opened}, int64(limit)+1))
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	after, statErr := opened.Stat()
	if err != nil || statErr != nil || int64(len(content)) != info.Size() || after.Size() != info.Size() || after.ModTime() != info.ModTime() || after.Mode() != info.Mode() {
		return nil, 0, errSourceIntegrity
	}
	return content, info.Mode(), nil
}

func sourceReadFile(ctx context.Context, filename string, limit int) ([]byte, error) {
	opened, err := sourceOpenPath(filename, false)
	if err != nil {
		return nil, err
	}
	content, _, readErr := sourceReadOpened(ctx, opened, limit)
	closeErr := opened.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, errSourcePath
	}
	return content, nil
}

func sourceCleanText(content string) bool {
	return utf8.ValidString(content) && !strings.ContainsFunc(content, func(character rune) bool {
		return unicode.IsControl(character) && character != '\n' && character != '\r' && character != '\t'
	})
}

func sourceRequestText(value reflect.Value, budget *int) bool {
	*budget -= 16
	if *budget < 0 {
		return false
	}
	switch value.Kind() {
	case reflect.Pointer:
		return value.IsNil() || sourceRequestText(value.Elem(), budget)
	case reflect.String:
		*budget -= len(value.String())
		return *budget >= 0 && sourceCleanText(value.String())
	case reflect.Struct:
		for _, field := range value.Fields() {
			if !sourceRequestText(field, budget) {
				return false
			}
		}
	case reflect.Slice:
		for index := 0; index < value.Len(); index++ {
			if !sourceRequestText(value.Index(index), budget) {
				return false
			}
		}
	case reflect.Map:
		entries := value.MapRange()
		for entries.Next() {
			if !sourceRequestText(entries.Key(), budget) || !sourceRequestText(entries.Value(), budget) {
				return false
			}
		}
	}
	return true
}

func sourceFreezeChecks(ctx context.Context, directory string, request Request) ([]sourceCheckFile, error) {
	root, err := sourceOpenPath(directory, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	files := make([]sourceCheckFile, 0)
	budget, entries := sourceMaxManifestBytes, 0
	var visit func(*os.File, string) error
	visit = func(parent *os.File, prefix string) error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			children, err := parent.ReadDir(1)
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return errSourceChecks
			}
			entry := children[0]
			name := entry.Name()
			if prefix != "" {
				name = prefix + "/" + name
			}
			entries++
			if !sourceValidPath(name) || (!entry.IsDir() && !entry.Type().IsRegular()) {
				return errSourcePath
			}
			if entries > sourceMaxFrozenFiles*sourceMaxPathDepth {
				return errSourceLimit
			}
			flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
			if entry.IsDir() {
				flags |= syscall.O_DIRECTORY
			}
			fd, err := syscall.Openat(int(parent.Fd()), entry.Name(), flags, 0)
			if err != nil {
				return errSourcePath
			}
			opened := os.NewFile(uintptr(fd), name)
			var visitErr error
			if entry.IsDir() {
				visitErr = visit(opened, name)
			} else if len(files) >= sourceMaxFrozenFiles {
				visitErr = errSourceLimit
			} else {
				content, mode, err := sourceReadOpened(ctx, opened, budget)
				visitErr = err
				if err == nil {
					if !sourceCleanText(string(content)) {
						visitErr = errSourceChecks
					} else if sourceCredentials.Match(content) {
						visitErr = errSourceSecret
					} else {
						budget -= len(content)
						files = append(files, sourceCheckFile{FrozenFile: FrozenFile{Path: name, Content: content, Digest: Digest(content), Executable: mode.Perm()&0111 != 0}, mode: mode})
					}
				}
			}
			closeErr := opened.Close()
			if visitErr != nil {
				return visitErr
			}
			if closeErr != nil {
				return errSourceChecks
			}
		}
	}
	if err := visit(root, ""); err != nil {
		return nil, err
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	if err := sourceValidateCommands(request, files); err != nil {
		return nil, err
	}
	return files, nil
}

func ValidateFrozenChecks(ctx context.Context, directory string, manifest Manifest) error {
	canonical, err := sourceDirectory(directory, false)
	if err != nil || sourcePathsOverlap(canonical, manifest.Sources.Repository) {
		return errSourceChecks
	}
	files, err := sourceFreezeChecks(ctx, canonical, Request{Checks: manifest.Checks, Services: manifest.Environment.Services})
	if err != nil {
		return err
	}
	if len(files) != len(manifest.Files) {
		return errSourceIntegrity
	}
	for index, file := range files {
		if !reflect.DeepEqual(file.FrozenFile, manifest.Files[index]) {
			return errSourceIntegrity
		}
	}
	return nil
}

func RestoreFrozenChecks(ctx context.Context, manifest Manifest) (_ *PreparedSources, resultErr error) {
	if len(manifest.Files) > MaxFrozenFiles || ValidateManifest(manifest) != nil {
		return nil, errSourceChecks
	}
	prepared, err := sourcePrepareRoot(manifest.Sources.Repository, manifest.Sources.Repository, nil)
	if err != nil {
		return nil, err
	}
	prepared.OriginalDir, prepared.PatchedDir = "", ""
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, prepared.Close())
		}
	}()
	if err := os.Mkdir(prepared.ChecksDir, 0700); err != nil {
		return nil, errSourcePath
	}
	total := 0
	for _, file := range manifest.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		total += len(file.Content)
		if !sourceValidPath(file.Path) || file.Digest != Digest(file.Content) || total > MaxManifestBytes ||
			!sourceCleanText(string(file.Content)) || sourceCredentials.Match(file.Content) {
			return nil, errSourceChecks
		}
		mode := os.FileMode(0444)
		if file.Executable {
			mode = 0555
		}
		if err := sourceWriteSnapshot(prepared.ChecksDir, file.Path, file.Content, mode); err != nil {
			return nil, err
		}
	}
	if err := sourceSealDirectories(prepared.ChecksDir); err != nil {
		return nil, err
	}
	return prepared, nil
}

func sourceValidateCommands(request Request, files []sourceCheckFile) error {
	commands := make([][]string, 0, len(request.Checks)+len(request.Services))
	for _, check := range request.Checks {
		if len(check.Stdin) > 64<<10 {
			return errSourceChecks
		}
		if check.HTTP != nil && ValidateHTTPCheck(check) != nil {
			return errSourceChecks
		}
		commands = append(commands, CheckExecutable(check))
	}
	for _, service := range request.Services {
		commands = append(commands, service.Command)
	}
	declared := make(map[string]os.FileMode, len(files))
	for _, file := range files {
		declared[file.Path] = file.mode
	}
	for _, command := range commands {
		if len(command) == 0 || !strings.HasPrefix(command[0], "/checks/") || !sourceValidPath(strings.TrimPrefix(command[0], "/checks/")) || declared[strings.TrimPrefix(command[0], "/checks/")]&0111 == 0 {
			return errSourceChecks
		}
		for _, argument := range command {
			if len(argument) > 8192 {
				return errSourceChecks
			}
		}
	}
	return nil
}

func sourceManifestBounds(request Request, prepared *PreparedSources) error {
	environment := Environment{
		Image: request.Image, ImageID: Digest(nil), Platform: request.Platform, Profile: request.Profile,
		Variables: request.Variables, Dependencies: request.Dependencies, Services: request.Services,
		Requirements: request.RequiredEnvironment,
	}
	manifest, err := RequestManifest(request, prepared, environment)
	if err != nil {
		return err
	}
	content, err := json.Marshal(manifest)
	if err != nil || len(content) > sourceMaxManifestBytes-sourceManifestReserve {
		return errSourceLimit
	}
	if sourceCredentials.Match(content) {
		return errSourceSecret
	}
	return nil
}

func sourceWriteSnapshot(directory, name string, content []byte, mode os.FileMode) error {
	filename := filepath.Join(directory, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return errSourcePath
	}
	opened, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errSourcePath
	}
	_, writeErr := opened.Write(content)
	readonly := os.FileMode(0444)
	if mode.Perm()&0111 != 0 {
		readonly = 0555
	}
	chmodErr, closeErr := opened.Chmod(readonly), opened.Close()
	if writeErr != nil || chmodErr != nil || closeErr != nil {
		return errSourcePath
	}
	return nil
}

func sourceSealDirectories(directory string) error {
	return filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || (entry.IsDir() && os.Chmod(filename, 0555) != nil) {
			return errSourcePath
		}
		return nil
	})
}

func sourceExtractArchive(ctx context.Context, content []byte, directory string) error {
	if len(content) > sourceMaxArchiveBytes {
		return errSourceLimit
	}
	trailer := [1024]byte{}
	if len(content) < len(trailer) || len(content)%512 != 0 || !bytes.Equal(content[len(content)-len(trailer):], trailer[:]) {
		return errSourceIntegrity
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return errSourcePath
	}
	input := bytes.NewReader(content)
	reader := tar.NewReader(sourceContextReader{ctx: ctx, reader: input})
	seen := make(map[string]bool)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			if input.Len() != 0 {
				return errSourceIntegrity
			}
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return errSourceIntegrity
		}
		if err := sourceValidateArchiveHeader(header); err != nil {
			return err
		}
		name := header.Name
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if !sourceValidPath(name) || seen[name] || len(seen) >= sourceMaxTreeEntries {
			return errSourcePath
		}
		seen[name] = true
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Mode != 0755 || header.Size != 0 || os.MkdirAll(filepath.Join(directory, filepath.FromSlash(name)), 0700) != nil {
				return errSourcePath
			}
		case tar.TypeReg:
			if header.Mode != 0644 && header.Mode != 0755 {
				return errSourcePath
			}
			blob, err := io.ReadAll(reader)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil || int64(len(blob)) != header.Size {
				return errSourceIntegrity
			}
			if err := sourceWriteSnapshot(directory, name, blob, os.FileMode(header.Mode)); err != nil {
				return err
			}
		default:
			return errSourcePath
		}
	}
	return sourceSealDirectories(directory)
}

func sourceValidateArchiveHeader(header *tar.Header) error {
	if header.Linkname != "" || header.Size < 0 || header.Size > sourceMaxArchiveBytes {
		return errSourceIntegrity
	}
	for name := range header.PAXRecords {
		if strings.HasPrefix(name, "SCHILY.xattr.") && header.Typeflag != tar.TypeXGlobalHeader {
			return errSourceIntegrity
		}
	}
	for name := range header.PAXRecords {
		if name != "path" {
			return errSourcePath
		}
	}
	return nil
}

func sourceValidPath(name string) bool {
	if name == "" || len(name) > sourceMaxPathBytes || !utf8.ValidString(name) || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\:") {
		return false
	}
	if strings.ContainsFunc(name, unicode.IsControl) {
		return false
	}
	components := strings.Split(name, "/")
	if len(components) > sourceMaxPathDepth {
		return false
	}
	for _, component := range components {
		if component == "." || component == ".." || len(component) > 255 || strings.EqualFold(strings.TrimRight(component, " ."), ".git") {
			return false
		}
	}
	return true
}

func sourceValidCommit(commit string) bool {
	return gitIdentityPattern.MatchString(commit)
}
