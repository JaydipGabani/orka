package patchverification

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDockerFrozenSpecialFiles(test *testing.T) {
	for _, filename := range []string{"run", "extra"} {
		test.Run(filename, func(test *testing.T) {
			manifest, sourceDir, checksDir := dockerTestStaging(test)
			if filename == "run" {
				if err := os.Remove(filepath.Join(checksDir, filename)); err != nil {
					test.Fatal(err)
				}
			}
			if err := syscall.Mkfifo(filepath.Join(checksDir, filename), 0600); err != nil {
				test.Fatal(err)
			}
			if err := dockerValidateInputs(manifest, sourceDir, checksDir); err == nil {
				test.Fatal("staged special file accepted")
			}
		})
	}
}
