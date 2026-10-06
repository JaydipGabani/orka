package remediation

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/orka-agents/orka/internal/remediation/intake"
)

func requireCompleteReport(report intake.Report) error {
	for _, warning := range report.Warnings {
		if warning == "missing_technical_details" || warning == "discussion_snapshot_incomplete" {
			return errors.New("report lacks complete technical evidence; acquire a complete input snapshot before model or execution work")
		}
	}
	return nil
}

func ensurePrivateDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("staging requires a canonical absolute private directory")
	}
	for existing := directory; ; existing = filepath.Dir(existing) {
		info, err := os.Lstat(existing)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		resolved, err := filepath.EvalSymlinks(existing)
		if err != nil || resolved != existing || !info.IsDir() {
			return errors.New("staging directory must not contain symlink aliases")
		}
		break
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("staging directory must be private with mode 0700")
	}
	return nil
}
