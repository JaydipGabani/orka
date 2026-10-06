package patchverification

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceFrozenHelperModes(test *testing.T) {
	request := sourceRequestFixture(test)
	sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "helper"), "#!/bin/sh\nprintf 'helper ran\\n'\n", 0700)
	sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "instructions.txt"), "#!/bin/sh\nprintf 'not an executable attestation\\n'\n", 0600)
	prepared := sourceMustPrepare(test, request)
	manifest := Manifest{Files: prepared.Files, Checks: request.Checks}
	for _, file := range manifest.Files {
		wantExecutable := file.Path == "helper" || file.Path == "verify.sh"
		if file.Executable != wantExecutable {
			test.Errorf("%s executable metadata = %t, want %t", file.Path, file.Executable, wantExecutable)
		}
	}
	staged, _, err := dockerStageFrozenFiles(test.TempDir(), manifest, nil)
	if err != nil {
		test.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{
		"verify.sh":           0555,
		"helper":              0555,
		"inputs/expected.txt": 0444,
		"instructions.txt":    0444,
	} {
		for _, directory := range []string{prepared.ChecksDir, staged} {
			info, err := os.Stat(filepath.Join(directory, name))
			if err != nil {
				test.Fatal(err)
			}
			if info.Mode().Perm() != mode {
				test.Errorf("%s: %s mode = %04o, want %04o", directory, name, info.Mode().Perm(), mode)
			}
		}
	}
}

func TestSourceFrozenModeTampering(test *testing.T) {
	for _, scenario := range []struct {
		name string
		mode os.FileMode
	}{
		{"helper", 0700},
		{"instructions.txt", 0600},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			request := sourceRequestFixture(test)
			sourceFixtureWrite(test, filepath.Join(request.ChecksDir, scenario.name), "#!/bin/sh\nexit 0\n", scenario.mode)
			prepared := sourceMustPrepare(test, request)
			manifest := Manifest{Files: prepared.Files, Checks: request.Checks}
			if err := dockerValidateInputs(manifest, prepared.OriginalDir, prepared.ChecksDir); err != nil {
				test.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(prepared.ChecksDir, scenario.name), scenario.mode^0100); err != nil {
				test.Fatal(err)
			}
			if err := dockerValidateInputs(manifest, prepared.OriginalDir, prepared.ChecksDir); err == nil {
				test.Fatal("mode-only change accepted against the frozen inventory")
			}
			before, err := ManifestDigest(manifest)
			if err != nil {
				test.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(request.ChecksDir, scenario.name), scenario.mode^0100); err != nil {
				test.Fatal(err)
			}
			refrozen, err := sourceFreezeChecks(context.Background(), request.ChecksDir, request)
			if err != nil {
				test.Fatal(err)
			}
			for index, file := range refrozen {
				if file.Digest != manifest.Files[index].Digest {
					test.Fatal("mode-only change altered content identity")
				}
				manifest.Files[index] = file.FrozenFile
			}
			after, err := ManifestDigest(manifest)
			if err != nil || before == after {
				test.Fatal("executable metadata did not change the manifest digest")
			}
		})
	}
}

func TestFrozenFileHistoricJSON(test *testing.T) {
	legacy := struct {
		Path    string `json:"path"`
		Content []byte `json:"content"`
		Digest  string `json:"digest"`
	}{Path: "helper", Content: []byte("#!/bin/sh\nexit 0\n"), Digest: Digest([]byte("#!/bin/sh\nexit 0\n"))}
	original, err := json.Marshal(legacy)
	if err != nil {
		test.Fatal(err)
	}
	var restored FrozenFile
	if err := json.Unmarshal(original, &restored); err != nil {
		test.Fatal(err)
	}
	current, err := json.Marshal(restored)
	if err != nil || restored.Executable || !bytes.Equal(original, current) || Digest(original) != Digest(current) {
		test.Fatal("historic omitted-false metadata changed JSON or its digest")
	}
}
