package patchverification

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDockerLiveExecutableHelper(test *testing.T) {
	runner, environment := dockerLiveRunner(test, dockerTestAlpine)
	manifest, sourceDir, checksDir := dockerTestStaging(test)
	manifest.Environment = environment
	for index := range manifest.Checks {
		manifest.Checks[index].Command = []string{"/checks/check"}
	}
	dockerLiveScript(test, &manifest, checksDir, "check", "#!/bin/sh\nexec /checks/helper\n")
	dockerLiveScript(test, &manifest, checksDir, "helper", "#!/bin/sh\nset -eu\n/bin/sh /src/patch.sh\nprintf 'helper-ran\\n'\n")
	patch := "#!/bin/sh\nset -eu\nfor target in /checks/check /checks/helper; do\n  if (printf 'rewritten\\n' > \"$target\") 2>/dev/null; then exit 1; fi\ndone\n"
	if err := os.WriteFile(filepath.Join(sourceDir, "patch.sh"), []byte(patch), 0644); err != nil {
		test.Fatal(err)
	}
	binding, _ := testEvidence(manifest)
	evidence, err := runner.RunCheck(context.Background(), manifest, binding, Original, manifest.Checks[0], sourceDir, checksDir)
	if err != nil || !usable(evidence.Observation) || *evidence.Observation.ExitCode != 0 || evidence.Observation.StdoutDigest != Digest([]byte("helper-ran\n")) {
		test.Fatalf("frozen helper execution failed: %v: %s", err, evidence.Blobs[evidence.Observation.StderrDigest])
	}
	for _, file := range manifest.Files {
		content, err := os.ReadFile(filepath.Join(checksDir, file.Path))
		if err != nil || Digest(content) != file.Digest {
			test.Fatal("source patch rewrote an external check or helper")
		}
	}
	dockerLiveBlobCheck(test, evidence)
}
