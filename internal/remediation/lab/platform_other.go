//go:build !linux

package lab

import "context"

type directoryID struct{}

type runDisk struct {
	path string
}

func inspectRoot(string) (directoryID, error) {
	return directoryID{}, ErrUnsupported
}

func readApproved(FileIdentity, int, bool) ([]byte, error) {
	return nil, ErrUnsupported
}

func (*Bridge) openRun(string, bool) (*runDisk, error) {
	return nil, ErrUnsupported
}

func (*runDisk) close() {}

func (*runDisk) write(string, []byte, uint32) error {
	return ErrUnsupported
}

func (*runDisk) read(string, int) ([]byte, error) {
	return nil, ErrUnsupported
}

func (*runDisk) hasReceipt() (bool, error) {
	return false, ErrUnsupported
}

func runDriver(context.Context, *runDisk, Operation) ([]byte, error) {
	return nil, ErrUnsupported
}
