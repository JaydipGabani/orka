//go:build !linux

package local

import "errors"

var ErrLiveOwner = errors.New("verification supervisor is still running")

type OwnerLock struct{}

func AcquireOwner(string, string) (*OwnerLock, error) {
	return nil, errors.New("local patch verification requires Linux")
}

func (*OwnerLock) Close() error { return nil }

func validateDatabaseFile(string) error {
	return errors.New("local patch verification requires Linux")
}
