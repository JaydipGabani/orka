package provenance

import (
	"errors"
	"path"
	"strings"
	"time"
)

type dalecChangelog struct {
	Date    string   `yaml:"date"`
	Author  string   `yaml:"author"`
	Changes []string `yaml:"changes"`
}

type dalecFileTest struct {
	Name  string                    `yaml:"name"`
	Files map[string]dalecFileCheck `yaml:"files"`
}

type dalecFileCheck struct {
	Permissions uint32 `yaml:"permissions"`
	IsDir       bool   `yaml:"is_dir"`
	NotExist    bool   `yaml:"not_exist"`
	NoFollow    bool   `yaml:"no_follow"`
}

func validatePackageMetadata(spec dalecSpec) error {
	for _, entry := range spec.Changelog {
		if _, err := time.Parse(time.DateOnly, entry.Date); err != nil {
			return errors.New("provenance changelog date must be an explicit calendar date")
		}
		if entry.Author == "" || len(entry.Changes) == 0 {
			return errors.New("provenance changelog entries require author and changes")
		}
	}
	names := make(map[string]bool)
	for _, test := range spec.Tests {
		if test.Name == "" || names[test.Name] || len(test.Files) == 0 {
			return errors.New("provenance file tests require unique names and file assertions")
		}
		names[test.Name] = true
		for filename, check := range test.Files {
			if !path.IsAbs(filename) || path.Clean(filename) != filename || !safePath(strings.TrimPrefix(filename, "/")) ||
				check.Permissions > 07777 || (check.NotExist && (check.Permissions != 0 || check.IsDir || check.NoFollow)) {
				return errors.New("provenance file assertions require safe image paths and consistent metadata")
			}
		}
	}
	return nil
}
