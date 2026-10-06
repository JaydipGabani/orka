package local

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/orka-agents/orka/internal/store/sqlite"
)

func openDatabase(ctx context.Context, filename string) (*sql.DB, *sqlite.Store, string, error) {
	if !filepath.IsAbs(filename) || strings.ContainsAny(filename, "?#\x00\r\n") {
		return nil, nil, "", errors.New("database path must be absolute and contain no URI parameters")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(filename))
	if err != nil {
		return nil, nil, "", errors.New("database parent directory must already exist")
	}
	filename = filepath.Join(parent, filepath.Base(filename))
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		err = file.Close()
	} else if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(filename)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, nil, "", errors.New("database must be a private regular file, not a symlink")
		}
		err = nil
	}
	if err != nil {
		return nil, nil, "", errors.New("cannot open private evidence database")
	}
	if err := validateDatabaseFile(filename); err != nil {
		return nil, nil, "", errors.New("database must be private, owned by this user, and have exactly one filesystem link")
	}
	database, err := sqlite.NewDB(filename)
	if err != nil {
		return nil, nil, "", errors.New("cannot initialize SQLite evidence database")
	}
	storage := sqlite.NewStore(database, filename)
	if err := storage.InitializePatchVerificationStore(ctx); err != nil {
		_ = database.Close()
		return nil, nil, "", errors.New("cannot initialize dedicated verification tables")
	}
	return database, storage, filename, nil
}

func within(directory, filename string) bool {
	if directory == "" {
		return false
	}
	relative, err := filepath.Rel(directory, filename)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
