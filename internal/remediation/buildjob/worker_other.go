//go:build !linux

package buildjob

import (
	"context"
	"io"
	"os"
	"regexp"
)

var (
	diagnosticPattern      = regexp.MustCompile(`a\A`)
	compilerFailurePattern = regexp.MustCompile(`a\A`)
)

type buildctlProcess struct {
	executable        string
	registryDirectory string
}

func (buildctlProcess) run(context.Context, []string, string, io.Writer) error {
	return failure(ErrInvalid, "linux-build-worker-required")
}

func (buildctlProcess) command(context.Context, []string, string, io.Writer, io.Writer) error {
	return failure(ErrInvalid, "linux-build-worker-required")
}

func writeSource(*os.Root, string, []byte) error {
	return failure(ErrInvalid, "linux-build-worker-required")
}

func readPrivateMetadata(*os.Root, string, int64) ([]byte, error) {
	return nil, failure(ErrInvalid, "linux-build-worker-required")
}

func writeTermination(string, []byte) error {
	return failure(ErrInvalid, "linux-build-worker-required")
}

func singleLink(os.FileInfo) bool { return false }

func LimitWorkerProcess() error {
	return failure(ErrInvalid, "linux-build-worker-required")
}
