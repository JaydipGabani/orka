//go:build linux

package lab

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const directoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

type directoryID struct {
	device uint64
	inode  uint64
}

type runDisk struct {
	path string
	file *os.File
}

// Resolve every component using directory descriptors, never EvalSymlinks plus
// a second pathname open. A root-owned sticky ancestor (such as /tmp) is allowed;
// the selected directory itself must be owned by this user and private.
func openDirectory(path string) (*os.File, error) {
	if path != "/" && !safeAbsolutePath(path) {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Open("/", directoryFlags, 0)
	if err != nil {
		return nil, ErrIO
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		next, err := unix.Openat(fd, component, directoryFlags, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, ErrUnsafePath
		}
		fd = next
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || !safeAncestor(stat) {
			_ = unix.Close(fd)
			return nil, ErrUnsafePath
		}
	}
	return os.NewFile(uintptr(fd), "lab-directory"), nil
}

func safeAncestor(stat unix.Stat_t) bool {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return false
	}
	return stat.Mode&0022 == 0 || (stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0)
}

func privateDirectory(file *os.File) (directoryID, error) {
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil {
		return directoryID{}, ErrIO
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return directoryID{}, ErrUnsafePath
	}
	return directoryID{device: stat.Dev, inode: stat.Ino}, nil
}

func inspectRoot(path string) (directoryID, error) {
	file, err := openDirectory(path)
	if err != nil {
		return directoryID{}, err
	}
	defer func() { _ = file.Close() }()
	return privateDirectory(file)
}

func readApproved(file FileIdentity, limit int, executable bool) ([]byte, error) {
	if !validFileIdentity(file) {
		return nil, ErrInvalidInput
	}
	directory, err := openDirectory(filepath.Dir(file.Path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	content, err := readAt(directory, filepath.Base(file.Path), limit, executable)
	if err != nil {
		return nil, err
	}
	if digest(content) != file.Digest {
		return nil, ErrDigestMismatch
	}
	return content, nil
}

func safeFile(stat unix.Stat_t, executable bool) bool {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07022 != 0 || stat.Nlink != 1 {
		return false
	}
	if executable {
		return (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())) && stat.Mode&0111 != 0
	}
	return stat.Uid == uint32(os.Geteuid()) && stat.Mode&0177 == 0 && stat.Mode&0400 != 0
}

func readAt(directory *os.File, name string, limit int, executable bool) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	file := os.NewFile(uintptr(fd), "lab-input")
	defer func() { _ = file.Close() }()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil {
		return nil, ErrIO
	}
	if !safeFile(before, executable) {
		return nil, ErrUnsafePath
	}
	if before.Size < 0 || before.Size > int64(limit) {
		return nil, ErrTooLarge
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, ErrIO
	}
	if len(content) > limit {
		return nil, ErrTooLarge
	}
	if unix.Fstatat(int(directory.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size ||
		before.Mtim != after.Mtim || before.Ctim != after.Ctim || !safeFile(after, executable) ||
		int64(len(content)) != before.Size {
		return nil, ErrUnsafePath
	}
	return content, nil
}

func (bridge *Bridge) openRun(name string, create bool) (*runDisk, error) {
	if bridge == nil || !namePattern.MatchString(name) {
		return nil, ErrInvalidInput
	}
	root, err := openDirectory(bridge.root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	identity, err := privateDirectory(root)
	if err != nil || identity != bridge.rootID {
		return nil, ErrUnsafePath
	}
	if create {
		if err := unix.Mkdirat(int(root.Fd()), name, 0700); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return nil, ErrRunExists
			}
			return nil, ErrIO
		}
		if err := root.Sync(); err != nil {
			return nil, ErrIO
		}
	}
	fd, err := unix.Openat(int(root.Fd()), name, directoryFlags, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	file := os.NewFile(uintptr(fd), "lab-run")
	if _, err := privateDirectory(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &runDisk{path: filepath.Join(bridge.root, name), file: file}, nil
}

func (disk *runDisk) close() {
	_ = disk.file.Close()
}

func (disk *runDisk) create(name string, mode uint32) (*os.File, error) {
	fd, err := unix.Openat(int(disk.file.Fd()), name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, ErrIO
	}
	return os.NewFile(uintptr(fd), "lab-artifact"), nil
}

func (disk *runDisk) write(name string, content []byte, mode uint32) error {
	file, err := disk.create(name, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	directoryErr := disk.file.Sync()
	if writeErr != nil || syncErr != nil || closeErr != nil || directoryErr != nil {
		return ErrIO
	}
	return nil
}

func (disk *runDisk) read(name string, limit int) ([]byte, error) {
	return readAt(disk.file, name, limit, false)
}

func (disk *runDisk) hasReceipt() (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(disk.file.Fd()), "receipt.json", &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, ErrIO
	}
	if !safeFile(stat, false) {
		return false, ErrUnsafePath
	}
	return true, nil
}

func (disk *runDisk) validatePath() error {
	current, err := openDirectory(disk.path)
	if err != nil {
		return err
	}
	defer func() { _ = current.Close() }()
	pinned, pinnedErr := privateDirectory(disk.file)
	named, namedErr := privateDirectory(current)
	if pinnedErr != nil || namedErr != nil || pinned != named {
		return ErrUnsafePath
	}
	return nil
}
