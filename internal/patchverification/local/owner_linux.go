package local

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"golang.org/x/sys/unix"
)

var ErrLiveOwner = errors.New("verification supervisor is still running")

var runIDPattern = regexp.MustCompile(`^pv-[a-f0-9]{64}$`)

type OwnerLock struct {
	file *os.File
	once sync.Once
	err  error
}

func AcquireOwner(dbPath, runID string) (*OwnerLock, error) {
	if !filepath.IsAbs(dbPath) || !runIDPattern.MatchString(runID) {
		return nil, errors.New("absolute database path and canonical run ID are required")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(dbPath))
	if err != nil {
		return nil, errors.New("database directory is unavailable")
	}
	dbPath = filepath.Join(parent, filepath.Base(dbPath))
	if err := validateDatabaseFile(dbPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("database must be a private, owned, single-link regular file")
	}
	lockDir := dbPath + ".patchverify-locks"
	if err := os.Mkdir(lockDir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("cannot create owner lock directory")
	}
	var directory unix.Stat_t
	if err := unix.Lstat(lockDir, &directory); err != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Mode&0077 != 0 || directory.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("owner lock directory must be private and owned by this user")
	}
	descriptor, err := unix.Open(filepath.Join(lockDir, runID), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open owner lock")
	}
	file := os.NewFile(uintptr(descriptor), "patchverify-owner")
	var info unix.Stat_t
	if err := unix.Fstat(descriptor, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&0077 != 0 || info.Uid != uint32(os.Geteuid()) || info.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("owner lock must be a private regular file")
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLiveOwner
		}
		return nil, errors.New("cannot acquire owner lock")
	}
	lock := &OwnerLock{file: file}
	if err := file.Truncate(0); err != nil {
		_ = lock.Close()
		return nil, errors.New("cannot record supervisor identity")
	}
	if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
		_ = lock.Close()
		return nil, errors.New("cannot record supervisor identity")
	}
	return lock, nil
}

func (lock *OwnerLock) Close() error {
	lock.once.Do(func() { lock.err = lock.file.Close() })
	return lock.err
}

func validateDatabaseFile(filename string) error {
	var info unix.Stat_t
	if err := unix.Lstat(filename, &info); err != nil {
		return err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&0077 != 0 || info.Uid != uint32(os.Geteuid()) || info.Nlink != 1 {
		return errors.New("database is not a private owned single-link regular file")
	}
	return nil
}
