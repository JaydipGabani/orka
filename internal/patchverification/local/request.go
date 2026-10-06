package local

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

const MaxRequestBytes = 1 << 20

func ReadRequest(filename string) (pv.Request, error) {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return pv.Request{}, errors.New("invalid request file path")
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return pv.Request{}, errors.New("request file is unavailable")
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxRequestBytes {
		return pv.Request{}, errors.New("request must be a regular file of at most 1 MiB")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return pv.Request{}, errors.New("request file is unavailable")
	}
	defer func() { _ = file.Close() }()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxRequestBytes {
		return pv.Request{}, errors.New("request must be a regular file of at most 1 MiB")
	}
	return DecodeRequest(file, absolute)
}

func DecodeRequest(reader io.Reader, requestFile string) (pv.Request, error) {
	var request pv.Request
	if !filepath.IsAbs(requestFile) {
		return request, errors.New("request file path must be absolute for relative path resolution")
	}
	content, err := io.ReadAll(io.LimitReader(reader, MaxRequestBytes+1))
	if err != nil || len(content) > MaxRequestBytes {
		return request, errors.New("request must be valid UTF-8 JSON of at most 1 MiB")
	}
	request, err = pv.DecodeRequestJSON(content)
	if err != nil {
		return request, err
	}
	for _, path := range []*string{&request.Repository, &request.ChecksDir, &request.PatchFile} {
		if *path == "" {
			continue
		}
		if strings.ContainsAny(*path, "\x00\r\n") || strings.Contains(*path, "://") {
			return request, errors.New("sources and checks must use local filesystem paths")
		}
		if !filepath.IsAbs(*path) {
			*path = filepath.Join(filepath.Dir(requestFile), *path)
		}
		*path = filepath.Clean(*path)
	}
	return request, nil
}

func (service *Service) linkedRequest(ctx context.Context, request pv.Request) (pv.Request, *pv.Record, *pv.PreparedSources, error) {
	if request.EarlierValidation == "" {
		return request, nil, nil, nil
	}
	if validateDatabaseFile(service.dbPath) != nil {
		return request, nil, nil, errors.New("earlier validation requires access to this private owned database")
	}
	earlier, err := service.storage.GetCompletedReportValidation(ctx, request.EarlierValidation)
	if err != nil {
		return request, nil, nil, errors.New("earlier validation is unavailable or is not an intact completed report validation")
	}
	if err := pv.MatchLinkedRequest(request, earlier.Manifest); err != nil {
		return request, nil, nil, err
	}
	if request.ChecksDir != "" || request.ProvidedFields["checksDir"] {
		if pv.ValidateFrozenChecks(ctx, request.ChecksDir, earlier.Manifest) != nil {
			return request, nil, nil, errors.New("supplied checksDir does not match the earlier frozen files and executable modes")
		}
	}
	request = pv.HydrateLinkedRequest(request, earlier.Manifest)
	restored, err := pv.RestoreFrozenChecks(ctx, earlier.Manifest)
	if err != nil {
		return request, nil, nil, errors.New("earlier frozen checks could not be restored")
	}
	request.ChecksDir = restored.ChecksDir
	return request, earlier, restored, nil
}
