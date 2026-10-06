package service

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"strings"

	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
)

// Automatic builds may change only selected ordinary source files. Build
// recipes, credential/configuration surfaces, dependencies and vendored code
// require a separately reviewed policy rather than model-generated authority.
func validateCandidatePaths(patch string, packet source.Packet) error {
	allowed := make(map[string]bool, len(packet.Files))
	for _, file := range packet.Files {
		allowed[file.Path] = true
	}
	sections := 0
	current := ""
	var hunk patchHunk
	for line := range strings.SplitSeq(patch, "\n") {
		if hunk.active() {
			if err := hunk.consume(line); err != nil {
				return err
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "diff --git "):
			fields := strings.Fields(line)
			if len(fields) != 4 || !strings.HasPrefix(fields[2], "a/") || !strings.HasPrefix(fields[3], "b/") {
				return ErrInvalid
			}
			name := strings.TrimPrefix(fields[2], "a/")
			if name != strings.TrimPrefix(fields[3], "b/") || !allowed[name] ||
				!ordinarySourcePath(name) {
				return ErrNeedsInput
			}
			current = name
			sections++
		case strings.HasPrefix(line, "@@ "):
			var err error
			hunk, err = parsePatchHunk(line)
			if err != nil || current == "" {
				return ErrInvalid
			}
		case strings.HasPrefix(line, "--- "):
			if current == "" || line != "--- a/"+current {
				return ErrInvalid
			}
		case strings.HasPrefix(line, "+++ "):
			if current == "" || line != "+++ b/"+current {
				return ErrInvalid
			}
		case strings.HasPrefix(line, "GIT binary patch"), strings.HasPrefix(line, "Binary files "),
			strings.HasPrefix(line, "rename "), strings.HasPrefix(line, "copy "),
			strings.HasPrefix(line, "old mode "), strings.HasPrefix(line, "new mode "),
			strings.HasPrefix(line, "new file mode "), strings.HasPrefix(line, "deleted file mode "):
			return ErrNeedsInput
		}
	}
	if sections == 0 || sections > 32 || hunk.active() {
		return errors.New("candidate requires a bounded source-only Git diff")
	}
	return nil
}

func ordinarySourcePath(name string) bool {
	if name == "" || path.Clean(name) != name || path.IsAbs(name) || strings.ContainsAny(name, "\\\x00\r\n\t\" ") {
		return false
	}
	for component := range strings.SplitSeq(name, "/") {
		if component == ".." || strings.HasPrefix(component, ".") {
			return false
		}
		switch strings.ToLower(component) {
		case "vendor", "node_modules", "specs", "recipes", "deploy", "charts":
			return false
		}
	}
	base := strings.ToLower(path.Base(name))
	switch base {
	case "makefile", "gnumakefile", "dockerfile", "containerfile", "go.mod", "go.sum", "go.work", "go.work.sum", "package.json",
		"package-lock.json", "yarn.lock", "bun.lock", "cargo.toml", "cargo.lock", "pyproject.toml",
		"requirements.txt", "gemfile", "gemfile.lock", "setup.py", "setup.cfg", "build.rs", "cmakelists.txt",
		"poetry.lock", "pnpm-lock.yaml", "pom.xml", "build.bazel", "workspace", "workspace.bazel",
		"build.gradle", "build.gradle.kts", "gradle.lockfile":
		return false
	}
	return !strings.HasPrefix(base, "dockerfile.") && !strings.HasPrefix(base, "containerfile.") &&
		!strings.HasSuffix(base, ".mk") && !strings.HasPrefix(base, "requirements-")
}

func touchesTests(patch string) bool {
	for line := range strings.SplitSeq(patch, "\n") {
		if !strings.HasPrefix(line, "diff --git ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(fields[2], "a/"))
		base := path.Base(name)
		if strings.HasSuffix(base, "_test.go") || strings.HasPrefix(base, "test_") ||
			strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") ||
			strings.Contains("/"+name, "/test/") || strings.Contains("/"+name, "/tests/") ||
			strings.Contains("/"+name, "/testdata/") || strings.Contains("/"+name, "/__tests__/") ||
			strings.HasSuffix(base, "_test.py") || strings.HasSuffix(base, "_spec.rb") ||
			strings.HasSuffix(base, "test.java") || base == "conftest.py" {
			return true
		}
	}
	return false
}

func (p *Pipeline) approveCandidateTests(ctx context.Context, session *Session, state *pipelineState, index int, patch string) error {
	run, err := session.Current(ctx)
	if err != nil {
		return err
	}
	request := struct {
		Reason, PlanDigest, PatchDigest string
		Attempt                         int
	}{"repository-test-changes", state.PlanDigest, Digest([]byte(patch)), index}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	digest := Digest(raw)
	if run.ApprovedDigest == digest {
		return nil
	}
	if _, err := p.putJSON(ctx, session, "approval-required", request); err != nil {
		return err
	}
	state.Stage = "review-test-changes"
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := session.Checkpoint(ctx, store.RemediationPhaseNeedsApproval, "repository-test-changes-require-approval", encoded, digest); err != nil {
		return err
	}
	return ErrAwaitApproval
}
