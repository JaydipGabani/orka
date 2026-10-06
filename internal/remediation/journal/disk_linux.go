//go:build linux

package journal

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const directoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

func (d *disk) close() error {
	var unlockErr, closeErr error
	// CLOEXEC closes inherited descriptors only at exec. Explicitly unlock so
	// a child between fork and exec cannot retain ownership after Close.
	if err := unix.Flock(int(d.file.Fd()), unix.LOCK_UN); err != nil {
		unlockErr = fmt.Errorf("%w: release ownership lock", ErrIO)
	}
	if err := d.file.Close(); err != nil {
		closeErr = fmt.Errorf("%w: close journal", ErrIO)
	}
	return errors.Join(unlockErr, closeErr)
}

func openDisk(path string, create bool) (*disk, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return nil, ErrUnsafePath
	}
	parent, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }()
	if create {
		if err := unix.Mkdirat(int(parent.Fd()), filepath.Base(path), 0700); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return nil, fmt.Errorf("%w: directory already exists", ErrConflict)
			}
			return nil, fmt.Errorf("%w: create journal directory", ErrIO)
		}
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), directoryFlags, 0)
	if err != nil {
		return nil, pathError(err)
	}
	d := &disk{path: path, file: os.NewFile(uintptr(fd), "journal-directory")}
	if err := privateDirectory(fd); err != nil {
		return nil, errors.Join(err, d.close())
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		result := fmt.Errorf("%w: acquire ownership lock", ErrIO)
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			result = ErrLocked
		}
		return nil, errors.Join(result, d.close())
	}
	if err := d.validate(); err != nil {
		return nil, errors.Join(err, d.close())
	}
	if create {
		if err := parent.Sync(); err != nil {
			return nil, errors.Join(fmt.Errorf("%w: sync parent directory", ErrIO), d.close())
		}
	}
	return d, nil
}

// Walk every component with O_NOFOLLOW; resolving symlinks and then opening the
// resulting pathname would still permit an alias or an ancestor replacement.
func openDirectory(path string) (*os.File, error) {
	fd, err := unix.Open("/", directoryFlags, 0)
	if err != nil {
		return nil, pathError(err)
	}
	if path != "/" {
		for component := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
			next, err := unix.Openat(fd, component, directoryFlags, 0)
			_ = unix.Close(fd)
			if err != nil {
				return nil, pathError(err)
			}
			fd = next
		}
	}
	return os.NewFile(uintptr(fd), "journal-ancestor"), nil
}

func (d *disk) validate() error {
	fd := int(d.file.Fd())
	if err := privateDirectory(fd); err != nil {
		return err
	}
	current, err := openDirectory(d.path)
	if err != nil {
		return fmt.Errorf("%w: journal path changed", ErrUnsafePath)
	}
	defer func() { _ = current.Close() }()
	var pinned, named unix.Stat_t
	if unix.Fstat(fd, &pinned) != nil || unix.Fstat(int(current.Fd()), &named) != nil {
		return fmt.Errorf("%w: inspect journal directory", ErrIO)
	}
	if pinned.Dev != named.Dev || pinned.Ino != named.Ino {
		return fmt.Errorf("%w: journal directory replaced", ErrUnsafePath)
	}
	return nil
}

func privateDirectory(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%w: inspect directory", ErrIO)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		return ErrUnsafePath
	}
	return nil
}

func privateFile(st *unix.Stat_t) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 ||
		st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return ErrUnsafePath
	}
	return nil
}

func (d *disk) entries() ([]entry, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(d.file.Fd()), ".", directoryFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open directory listing", ErrIO)
	}
	listing := os.NewFile(uintptr(fd), "journal-listing")
	defer func() { _ = listing.Close() }()
	names, err := listing.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("%w: list journal", ErrIO)
	}
	entries := make([]entry, 0, len(names))
	for _, name := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, fmt.Errorf("%w: inspect journal entry", ErrIO)
		}
		if err := privateFile(&st); err != nil {
			return nil, err
		}
		entries = append(entries, entry{name: name, size: st.Size})
	}
	return entries, nil
}

func (d *disk) read(name string, limit int) ([]byte, error) {
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, ErrUnsafePath
		}
		return nil, fmt.Errorf("%w: open published record", ErrIO)
	}
	file := os.NewFile(uintptr(fd), "journal-record")
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: inspect published record", ErrIO)
	}
	if err := privateFile(&st); err != nil {
		return nil, err
	}
	if st.Size > int64(limit) {
		return nil, ErrTooLarge
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read published record", ErrIO)
	}
	if len(content) > limit {
		return nil, ErrTooLarge
	}
	var after unix.Stat_t
	if err := unix.Fstatat(int(d.file.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, fmt.Errorf("%w: recheck published record", ErrIO)
	}
	if err := privateFile(&after); err != nil {
		return nil, err
	}
	if after.Dev != st.Dev || after.Ino != st.Ino || after.Size != st.Size || int64(len(content)) != st.Size {
		return nil, fmt.Errorf("%w: published record changed while reading", ErrCorrupt)
	}
	return content, nil
}

func (d *disk) publish(name string, content []byte) (result error) {
	if err := d.validate(); err != nil {
		return err
	}
	nonce, err := randomHex()
	if err != nil {
		return err
	}
	pending := pendingPrefix + nonce
	fd, err := unix.Openat(int(d.file.Fd()), pending, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("%w: create staged record", ErrIO)
	}
	file := os.NewFile(uintptr(fd), "journal-staging")
	published := false
	defer func() {
		if file != nil {
			if err := file.Close(); err != nil {
				result = errors.Join(result, fmt.Errorf("%w: close staged record", ErrIO))
			}
		}
		if !published {
			if err := unix.Unlinkat(int(d.file.Fd()), pending, 0); err != nil {
				result = errors.Join(result, fmt.Errorf("%w: remove staged record", ErrIO))
			}
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%w: inspect staged record", ErrIO)
	}
	if err := privateFile(&st); err != nil {
		return err
	}
	if n, err := file.Write(content); err != nil || n != len(content) {
		return fmt.Errorf("%w: write staged record", ErrIO)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("%w: sync staged record", ErrIO)
	}
	err = file.Close()
	file = nil
	if err != nil {
		return fmt.Errorf("%w: close staged record", ErrIO)
	}
	if err := unix.Renameat2(int(d.file.Fd()), pending, int(d.file.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: record already published", ErrConflict)
		}
		return fmt.Errorf("%w: publish staged record", ErrIO)
	}
	published = true
	if err := d.file.Sync(); err != nil {
		return fmt.Errorf("%w: sync published record", ErrIO)
	}
	return d.validate()
}

func (d *disk) discardPending(names []string) error {
	if len(names) == 0 {
		return nil
	}
	if err := d.validate(); err != nil {
		return err
	}
	for _, name := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(int(d.file.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("%w: inspect abandoned staging file", ErrIO)
		}
		if err := privateFile(&st); err != nil {
			return err
		}
		if err := unix.Unlinkat(int(d.file.Fd()), name, 0); err != nil {
			return fmt.Errorf("%w: remove abandoned staging file", ErrIO)
		}
	}
	if err := d.file.Sync(); err != nil {
		return fmt.Errorf("%w: sync staging recovery", ErrIO)
	}
	return nil
}

func pathError(err error) error {
	if errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("%w: journal directory", fs.ErrNotExist)
	}
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EACCES) {
		return ErrUnsafePath
	}
	return fmt.Errorf("%w: open journal directory", ErrIO)
}
