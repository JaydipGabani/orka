package validation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

var (
	errUnsafeInput = errors.New("validation inputs must be self-contained regular files and directories without links")
	errInputLimit  = errors.New("validation staging exceeds its byte or pathname limit")
	errInputSecret = errors.New("validation inputs contain credential material")
)

type inventory struct {
	bytes       int64
	paths       int
	credentials []string
}

func absolutePath(name string) bool {
	return filepath.IsAbs(name) && filepath.Clean(name) == name && name != "/" &&
		len(name) <= 4096 && utf8.ValidString(name) &&
		!strings.ContainsAny(name, "\\:\x00") && !strings.ContainsFunc(name, unicode.IsControl)
}

func relativePath(name string) bool {
	if name == "" || len(name) > 1024 || !utf8.ValidString(name) ||
		strings.ContainsAny(name, "\\:") || strings.ContainsFunc(name, unicode.IsControl) {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 32 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return false
		}
	}
	return true
}

func within(root, name string) bool {
	return name == root || strings.HasPrefix(name, root+string(filepath.Separator))
}

// Opening every component without following links also protects parent
// directories; a preceding Lstat or EvalSymlinks alone would leave a race.
func openInput(name string) (*os.File, error) {
	if !absolutePath(name) {
		return nil, errUnsafeInput
	}
	parent, err := os.Open("/")
	if err != nil {
		return nil, errUnsafeInput
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	for index, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if index < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		fd, err := syscall.Openat(int(parent.Fd()), part, flags, 0)
		closeErr := parent.Close()
		if err != nil {
			return nil, errUnsafeInput
		}
		parent = os.NewFile(uintptr(fd), name)
		if closeErr != nil {
			_ = parent.Close()
			return nil, errUnsafeInput
		}
	}
	return parent, nil
}

func regularInput(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && info.Mode().IsRegular() &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

type contextReader struct {
	ctx context.Context
	in  io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.in.Read(data)
}

func readInput(ctx context.Context, file *os.File, limit int64) ([]byte, os.FileMode, error) {
	before, err := file.Stat()
	if err != nil || !regularInput(before) {
		return nil, 0, errUnsafeInput
	}
	if before.Size() < 0 || before.Size() > limit {
		return nil, 0, errInputLimit
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, file}, before.Size()+1))
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	after, statErr := file.Stat()
	if err != nil || statErr != nil || !regularInput(after) || int64(len(data)) != before.Size() ||
		after.Size() != before.Size() || after.ModTime() != before.ModTime() || after.Mode() != before.Mode() {
		return nil, 0, errUnsafeInput
	}
	return data, before.Mode(), nil
}

func (i *inventory) screen(data []byte) error {
	if (pv.CredentialMatcher{}).Match(data) {
		return errInputSecret
	}
	for _, credential := range i.credentials {
		if credential != "" && bytes.Contains(data, []byte(credential)) {
			return errInputSecret
		}
	}
	// URL userinfo is not a scalar credential assignment understood by the
	// shared matcher. In particular, it must not escape inside Git config.
	if credentialURL.Match(data) {
		return errInputSecret
	}
	return nil
}

func (i *inventory) copy(ctx context.Context, source, destination string) error {
	file, err := openInput(source)
	if err != nil {
		return err
	}
	copyErr := i.copyOpened(ctx, file, destination, "")
	return errors.Join(copyErr, safeClose(file))
}

func (i *inventory) copyOpened(ctx context.Context, file *os.File, destination, relative string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	i.paths++
	if i.paths > MaxArchivePaths || (relative != "" && !relativePath(relative)) {
		return errInputLimit
	}
	if err := i.screen([]byte(relative)); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errUnsafeInput
	}
	if !info.IsDir() {
		data, mode, err := readInput(ctx, file, MaxArchiveBytes-i.bytes)
		if err != nil {
			return err
		}
		if err := i.screen(data); err != nil {
			return err
		}
		i.bytes += int64(len(data))
		frozenMode := os.FileMode(0600)
		if mode.Perm()&0111 != 0 {
			frozenMode = 0700
		}
		if err := os.WriteFile(destination, data, frozenMode); err != nil {
			return errors.New("cannot write private validation snapshot")
		}
		return nil
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return errors.New("cannot create private validation snapshot")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := file.ReadDir(1)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(entries) != 1 {
			return errUnsafeInput
		}
		entry := entries[0]
		name := entry.Name()
		if !relativePath(name) || (!entry.IsDir() && !entry.Type().IsRegular()) {
			return errUnsafeInput
		}
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if entry.IsDir() {
			flags |= syscall.O_DIRECTORY
		}
		fd, err := syscall.Openat(int(file.Fd()), name, flags, 0)
		if err != nil {
			return errUnsafeInput
		}
		child := os.NewFile(uintptr(fd), name)
		next := name
		if relative != "" {
			next = relative + "/" + name
		}
		copyErr := i.copyOpened(ctx, child, filepath.Join(destination, name), next)
		if err := errors.Join(copyErr, safeClose(child)); err != nil {
			return err
		}
	}
	after, err := file.Stat()
	if err != nil || after.ModTime() != info.ModTime() || after.Mode() != info.Mode() {
		return errUnsafeInput
	}
	return nil
}

func safeClose(file *os.File) error {
	if file.Close() != nil {
		return errors.New("cannot close private validation input")
	}
	return nil
}

func removeOwned(root string, identity os.FileInfo) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || !os.SameFile(info, identity) {
		return errors.New("private validation staging identity changed; refusing cleanup")
	}
	if os.RemoveAll(root) != nil {
		return errors.New("cannot clean up private validation staging")
	}
	return nil
}
