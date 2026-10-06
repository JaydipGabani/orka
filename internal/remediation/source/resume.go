package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

const (
	sourceMarkerPath  = ".git/orka-source.json"
	sourceGitDir      = ".git"
	sourceObjectPacks = ".git/objects/pack"
	maxMarkerBytes    = 32 << 10
)

var errSourceChanged = errors.New("existing source is unmarked, mismatched, or modified; refusing overwrite")

type directoryIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type sourceMarker struct {
	Version  int               `json:"version"`
	Target   Target            `json:"target"`
	Identity directoryIdentity `json:"identity"`
	Snapshot string            `json:"snapshot"`
}

func sealMaterialized(ctx context.Context, directory string, target Target) (resultErr error) {
	root, info, err := openManagedRoot(directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	identity, err := sourceFileIdentity(info)
	if err != nil {
		return err
	}
	snapshot, err := snapshotDigest(ctx, root, target, false)
	if err != nil {
		return err
	}
	content, err := json.Marshal(sourceMarker{Version: 1, Target: target, Identity: identity, Snapshot: snapshot})
	if err != nil {
		return fmt.Errorf("encode managed source marker: %w", err)
	}
	content = append(content, '\n')
	if len(content) > maxMarkerBytes {
		return errSourceLimit
	}
	file, err := root.OpenFile(sourceMarkerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create managed source marker: %w", err)
	}
	_, writeErr := file.Write(content)
	return errors.Join(writeErr, file.Close())
}

func resumeMaterialized(
	ctx context.Context, target Target, destination, parent, binary string, client Client, run commandRunner,
) (resultErr error) {
	root, info, err := openManagedRoot(destination)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	markerBytes, err := readManagedFile(ctx, root, sourceMarkerPath, maxMarkerBytes)
	if err != nil {
		return errors.Join(errSourceChanged, err)
	}
	marker, err := verifyMarker(markerBytes, target, info)
	if err != nil {
		return err
	}
	if err := verifyManagedMetadata(ctx, root, target); err != nil {
		return err
	}
	before, err := snapshotDigest(ctx, root, target, false)
	if err != nil {
		return err
	}
	if before != marker.Snapshot {
		return errSourceChanged
	}
	if err := revalidatePublic(ctx, client, target); err != nil {
		return err
	}
	scratch, err := os.MkdirTemp(parent, ".orka-source-verify-")
	if err != nil {
		return fmt.Errorf("create isolated source verifier: %w", err)
	}
	scratchInfo, err := os.Lstat(scratch)
	if err != nil {
		return errors.Join(err, os.Remove(scratch))
	}
	defer func() { resultErr = errors.Join(resultErr, removeOwnedDirectory(scratch, scratchInfo)) }()
	if err := os.Chmod(scratch, 0700); err != nil {
		return fmt.Errorf("restrict isolated source verifier: %w", err)
	}
	guarded, stopGuard := guardDisk(ctx, scratch)
	defer stopGuard()

	// Never run Git against existing metadata. Copy only bounded object/index
	// data into a fresh repository with trusted configuration and no hooks.
	git := sourceGit{root: scratch, binary: binary, runCommand: run}
	if err := git.initialize(guarded, target); err != nil {
		return err
	}
	if err := copyVerificationState(guarded, root, git.root, target); err != nil {
		return err
	}
	if _, err := git.run(guarded, 4096, "fsck", "--full", "--strict", "--no-reflogs", "--no-dangling", target.Commit); err != nil {
		return err
	}
	staged, err := git.run(guarded, maxTreeListingBytes, "diff-index", "--cached", "--no-ext-diff", "--no-textconv",
		"--ignore-submodules=none", "--raw", "-z", target.Commit, "--")
	if err != nil {
		return err
	}
	if len(staged) != 0 {
		return errSourceChanged
	}
	// A fresh index makes assume-unchanged/skip-worktree bits and stale cached
	// stat data irrelevant to the independent expected-worktree comparison.
	if err := os.Remove(filepath.Join(scratch, ".git", "index")); err != nil {
		return fmt.Errorf("reset isolated verification index: %w", err)
	}
	if err := git.checkout(guarded, target); err != nil {
		return err
	}
	expected, err := digestWorktree(guarded, scratch, target)
	if err != nil {
		return err
	}
	actual, err := snapshotDigest(guarded, root, target, true)
	if err != nil {
		return err
	}
	if actual != expected {
		return errSourceChanged
	}
	after, err := snapshotDigest(guarded, root, target, false)
	if err != nil {
		return err
	}
	currentMarker, err := readManagedFile(guarded, root, sourceMarkerPath, maxMarkerBytes)
	if err != nil {
		return err
	}
	currentInfo, err := os.Lstat(destination)
	if err != nil {
		return fmt.Errorf("recheck source directory identity: %w", err)
	}
	if after != marker.Snapshot || !bytes.Equal(currentMarker, markerBytes) || !os.SameFile(currentInfo, info) {
		return errSourceChanged
	}
	if _, err := destinationLocation(destination); err != nil {
		return err
	}
	if guarded.Err() != nil {
		return context.Cause(guarded)
	}
	return nil
}

func openManagedRoot(directory string) (*os.Root, os.FileInfo, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect managed source: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, nil, errSourceChanged
	}
	if _, err := sourceFileIdentity(info); err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, fmt.Errorf("open managed source: %w", err)
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(openedInfo, info) {
		return nil, nil, errors.Join(errSourceChanged, err, root.Close())
	}
	return root, info, nil
}

func verifyMarker(content []byte, target Target, info os.FileInfo) (sourceMarker, error) {
	var marker sourceMarker
	if !unambiguousJSON(content) || json.Unmarshal(content, &marker) != nil {
		return sourceMarker{}, errSourceChanged
	}
	identity, err := sourceFileIdentity(info)
	if err != nil {
		return sourceMarker{}, err
	}
	canonical, err := json.Marshal(marker)
	if err != nil {
		return sourceMarker{}, fmt.Errorf("validate managed source marker: %w", err)
	}
	if marker.Version != 1 || marker.Target != target || marker.Identity != identity ||
		len(marker.Snapshot) != 64 || !validObjectID(marker.Snapshot) ||
		!bytes.Equal(content, append(canonical, '\n')) {
		return sourceMarker{}, errSourceChanged
	}
	return marker, nil
}

func verifyManagedMetadata(ctx context.Context, root *os.Root, target Target) error {
	for _, expected := range []struct{ name, content string }{
		{".git/HEAD", target.Commit + "\n"},
		{".git/config", checkoutConfig(target)},
		{".git/info/attributes", checkoutAttributes},
	} {
		content, err := readManagedFile(ctx, root, expected.name, 4096)
		if err != nil {
			return errors.Join(errSourceChanged, err)
		}
		if string(content) != expected.content {
			return errSourceChanged
		}
	}
	if _, err := root.Lstat(".git/shallow"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	content, err := readManagedFile(ctx, root, ".git/shallow", 128)
	if err != nil {
		return err
	}
	if string(content) != target.Commit+"\n" {
		return errSourceChanged
	}
	return nil
}

func validMetadataEntry(name string, info os.FileInfo, target Target) bool {
	if info.IsDir() {
		switch name {
		case sourceGitDir, ".git/info", ".git/tmp", ".git/objects", ".git/objects/info", sourceObjectPacks,
			".git/refs", ".git/refs/heads", ".git/refs/tags":
			return true
		}
		return false
	}
	switch name {
	case ".git/config", ".git/HEAD", ".git/index", ".git/info/attributes", ".git/shallow":
		return true
	case sourceMarkerPath:
		return info.Mode().Perm() == 0600
	}
	if !strings.HasPrefix(name, ".git/objects/pack/pack-") {
		return false
	}
	filename := strings.TrimPrefix(name, ".git/objects/pack/pack-")
	identity, extension, found := strings.Cut(filename, ".")
	return found && validObjectID(identity) && len(identity) == len(target.Commit) &&
		(extension == "pack" || extension == "idx" || extension == "rev")
}

func snapshotDigest(ctx context.Context, root *os.Root, target Target, worktreeOnly bool) (string, error) {
	digest := sha256.New()
	var totalBytes int64
	count := 0
	maxBytes, maxEntries := int64(maxDiskBytes), 4*maxTreeEntries
	if worktreeOnly {
		maxBytes, maxEntries = maxCheckoutBytes, maxTreeEntries+1
	}
	filesystem := &boundedSourceFS{root: root, ctx: ctx, remaining: maxEntries}
	err := fs.WalkDir(filesystem, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("inspect managed source snapshot: %w", walkErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if worktreeOnly && name == sourceGitDir {
			return fs.SkipDir
		}
		count++
		if count > maxEntries || entry.Type()&os.ModeSymlink != 0 {
			return errSourceChanged
		}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if (!info.IsDir() && !info.Mode().IsRegular()) || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errSourceChanged
		}
		if _, err := sourceFileIdentity(info); err != nil {
			return err
		}
		if name != "." {
			if name == sourceGitDir || strings.HasPrefix(name, ".git/") {
				if !validMetadataEntry(name, info, target) {
					return errSourceChanged
				}
			} else if !validSourcePath(name) {
				return errSourceChanged
			}
		}
		size := int64(0)
		if !info.IsDir() {
			size = info.Size()
			if size < 0 || size > gitMaxFileBytes || size > maxBytes-totalBytes {
				return errSourceLimit
			}
			totalBytes += size
		}
		if name == sourceMarkerPath {
			return nil
		}
		mode := uint32(info.Mode())
		if worktreeOnly {
			switch {
			case info.IsDir():
				mode = 040000
			case info.Mode().Perm()&0100 != 0:
				mode = 0100755
			default:
				mode = 0100644
			}
		}
		header := fmt.Appendf(nil, "%d:%s:%o:%d\n", len(name), name, mode, size)
		_, _ = digest.Write(header)
		if info.IsDir() {
			return nil
		}
		_, err = streamManagedFile(ctx, root, name, digest, size)
		return err
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func digestWorktree(ctx context.Context, directory string, target Target) (result string, resultErr error) {
	root, _, err := openManagedRoot(directory)
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	return snapshotDigest(ctx, root, target, true)
}

func readManagedFile(ctx context.Context, root *os.Root, name string, limit int64) ([]byte, error) {
	var output bytes.Buffer
	if _, err := streamManagedFile(ctx, root, name, &output, limit); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func streamManagedFile(ctx context.Context, root *os.Root, name string, output io.Writer, limit int64) (count int64, resultErr error) {
	file, err := openSourceFile(root, name)
	if err != nil {
		return 0, fmt.Errorf("open bounded managed source file: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return 0, errSourceChanged
	}
	if _, err := sourceFileIdentity(info); err != nil {
		return 0, err
	}
	count, err = io.Copy(output, &sourceContextReader{ctx: ctx, reader: io.LimitReader(file, info.Size()+1)})
	if err != nil {
		return count, err
	}
	after, err := root.Lstat(name)
	if err != nil {
		return count, err
	}
	if count != info.Size() || !os.SameFile(after, info) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return count, errSourceChanged
	}
	return count, nil
}

type sourceContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *sourceContextReader) Read(content []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(content)
}

func copyVerificationState(ctx context.Context, source *os.Root, destination string, target Target) error {
	filesystem := &boundedSourceFS{root: source, ctx: ctx, remaining: 4 * maxTreeEntries}
	entries, err := filesystem.ReadDir(sourceObjectPacks)
	if err != nil {
		return fmt.Errorf("inspect source object packs: %w", err)
	}
	names := make([]string, 0, len(entries)+2)
	for _, entry := range entries {
		name := path.Join(sourceObjectPacks, entry.Name())
		info, err := source.Lstat(name)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || !validMetadataEntry(name, info, target) {
			return errSourceChanged
		}
		names = append(names, name)
	}
	names = append(names, ".git/index")
	if _, err := source.Lstat(".git/shallow"); err == nil {
		names = append(names, ".git/shallow")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	remaining := int64(maxDiskBytes)
	for _, name := range names {
		written, err := copyVerificationFile(ctx, source, name, filepath.Join(destination, filepath.FromSlash(name)), min(remaining, gitMaxFileBytes))
		if err != nil {
			return err
		}
		remaining -= written
	}
	return nil
}

func copyVerificationFile(ctx context.Context, source *os.Root, name, destination string, limit int64) (count int64, resultErr error) {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, fmt.Errorf("copy isolated verification data: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	return streamManagedFile(ctx, source, name, file, limit)
}

type boundedSourceFS struct {
	root      *os.Root
	ctx       context.Context
	remaining int
}

func (filesystem *boundedSourceFS) Open(name string) (fs.File, error) {
	return openSourceFile(filesystem.root, name)
}

func (filesystem *boundedSourceFS) ReadDir(name string) (entries []fs.DirEntry, resultErr error) {
	directory, err := openSourceFile(filesystem.root, name)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()
	for {
		if err := filesystem.ctx.Err(); err != nil {
			return nil, err
		}
		batch, err := directory.ReadDir(min(64, filesystem.remaining+1))
		if len(batch) > filesystem.remaining {
			return nil, errSourceLimit
		}
		filesystem.remaining -= len(batch)
		entries = append(entries, batch...)
		if errors.Is(err, io.EOF) {
			slices.SortFunc(entries, func(first, second fs.DirEntry) int {
				return strings.Compare(first.Name(), second.Name())
			})
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
