//go:build !linux

package source

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

func trustedGit() (string, error) {
	return "", errors.New("public source materialization requires Linux resource limits and atomic no-replace publication")
}

func (*sourceGit) command(context.Context, []string) (*exec.Cmd, error) {
	return nil, errors.New("public source Git resource limits are not supported on this platform")
}

func publishNoReplace(string, string) error {
	return errors.New("atomic no-replace source publication is not supported on this platform")
}

func sourceFileIdentity(os.FileInfo) (directoryIdentity, error) {
	return directoryIdentity{}, errors.New("managed source identity checks require Linux")
}

func openSourceFile(*os.Root, string) (*os.File, error) {
	return nil, errors.New("managed source file access requires Linux")
}
