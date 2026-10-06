package buildjob

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
)

type WorkerOptions struct {
	BundleDirectory    string
	WorkspaceDirectory string
	TerminationPath    string
	PhaseOutput        io.Writer
}

// RunWorker executes only the image's fixed buildctl binary. Its input bytes
// never become host commands. Non-success outcomes always produce a nonzero
// process exit, independently of Job-controller status.
func RunWorker(ctx context.Context, options WorkerOptions) int {
	return runWorker(ctx, options, buildctlProcess{executable: "/usr/bin/buildctl"})
}

func runWorker(ctx context.Context, options WorkerOptions, process buildctlProcess) int {
	wire := WorkerResult{Version: Version, BuildOutcome: Infrastructure}
	if options.PhaseOutput == nil {
		options.PhaseOutput = io.Discard
	}
	emitPhase(options.PhaseOutput, "starting", 0)
	m, input, err := readBundle(options.BundleDirectory)
	if err == nil {
		wire.InputDigest = input.InputDigest
		wire = executeWorker(ctx, options, m, input, process)
	}
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) > MaxTerminationBytes || writeTermination(options.TerminationPath, raw) != nil {
		emitPhase(options.PhaseOutput, "result-unavailable", 0)
		return 1
	}
	emitPhase(options.PhaseOutput, "finished", len(wire.Diagnostics))
	if wire.BuildOutcome == TestFailure {
		return wire.BuildExitCode
	}
	if wire.BuildOutcome != Success {
		return 1
	}
	return 0
}

func executeWorker(
	ctx context.Context, options WorkerOptions, m manifest, input Input, process buildctlProcess,
) WorkerResult {
	result := WorkerResult{Version: Version, InputDigest: input.InputDigest, BuildOutcome: Infrastructure}
	if m.RegistrySecretName != "" {
		if process.registryDirectory == "" {
			process.registryDirectory = registryConfigDirectory
		}
		if validateRegistryConfig(process.registryDirectory, input.OutputRepository) != nil {
			return result
		}
	} else {
		process.registryDirectory = ""
	}
	root, directory, err := stageWorkspace(options.WorkspaceDirectory, input.Files)
	if err != nil {
		return result
	}
	defer func() {
		_ = root.Close()
		// This tree was created exclusively for this invocation. Never consume
		// or remove a pre-existing workspace on retry.
		_ = removeWorkspace(options.WorkspaceDirectory)
	}()
	tail := newTail(m.Limits.MaxLogBytes)
	capture := newDiagnosticCapture(diagnosticPaths(m, input))
	bounded, cancel := context.WithTimeout(ctx, m.Limits.BuildTimeout)
	defer cancel()
	emitPhase(options.PhaseOutput, "building", len(input.Files))
	err = process.run(bounded, buildArguments(m, input, directory), directory, io.MultiWriter(tail, capture))
	completedInTime := bounded.Err() == nil
	_, truncated := tail.snapshot()
	diagnostics := capture.snapshot()
	result.OutputTruncated = truncated || diagnostics.truncated
	result.BuildRef, result.DaemonSettled = process.settle(m, root, directory)
	if ctx.Err() != nil {
		result.BuildOutcome = Cancelled
		return result
	}
	if err != nil {
		if completedInTime {
			var exit *exec.ExitError
			if diagnostics.testFailure && errors.As(err, &exit) && exit.ExitCode() > 0 && exit.ExitCode() <= 255 {
				result.BuildOutcome, result.BuildExitCode = TestFailure, exit.ExitCode()
				result.Diagnostics = diagnostics.tests
			} else if len(diagnostics.compiler) != 0 {
				result.Diagnostics = diagnostics.compiler
				result.BuildOutcome = CompileFailure
			}
		}
		return result
	}
	imageDigest, err := readImageDigest(root)
	if err != nil || !result.DaemonSettled {
		return result
	}
	result.BuildOutcome, result.ImmutableImageDigest = Success, imageDigest
	return result
}

func readBundle(directory string) (manifest, Input, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return manifest{}, Input{}, failure(ErrInvalid, "worker-input-mount-unavailable")
	}
	defer func() { _ = root.Close() }()
	data := make(map[string][]byte, 2)
	for _, key := range []string{manifestKey, archiveKey} {
		// Kubernetes Secret projections use symlinks. os.Root permits only
		// symlinks confined to the read-only projection, not arbitrary targets.
		file, err := root.Open(key)
		if err != nil {
			return manifest{}, Input{}, failure(ErrInvalid, "worker-input-unavailable")
		}
		info, statErr := file.Stat()
		body, readErr := io.ReadAll(io.LimitReader(file, MaxInputBytes+1))
		closeErr := file.Close()
		if statErr != nil || !info.Mode().IsRegular() || readErr != nil || closeErr != nil || len(body) > MaxInputBytes {
			return manifest{}, Input{}, failure(ErrInvalid, "worker-input-size-or-type-invalid")
		}
		data[key] = body
	}
	return unpackBundle(data)
}

func stageWorkspace(directory string, files map[string][]byte) (*os.Root, string, error) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", failure(ErrInvalid, "private-worker-workspace-required")
	}
	parent, err := os.OpenRoot(directory)
	if err != nil {
		return nil, "", failure(ErrInvalid, "private-worker-workspace-unavailable")
	}
	defer func() { _ = parent.Close() }()
	if err := parent.Mkdir("build", 0700); err != nil {
		return nil, "", failure(ErrInvalid, "worker-workspace-already-consumed")
	}
	root, err := parent.OpenRoot("build")
	if err != nil {
		_ = parent.RemoveAll("build")
		return nil, "", failure(ErrInvalid, "worker-workspace-open-failed")
	}
	fail := func() (*os.Root, string, error) {
		_ = root.Close()
		_ = parent.RemoveAll("build")
		return nil, "", failure(ErrInvalid, "worker-source-staging-failed")
	}
	for _, name := range []string{"context", "home", "scratch"} {
		if root.Mkdir(name, 0700) != nil {
			return fail()
		}
	}
	for name, body := range files {
		if SourcePath(name) != nil || root.MkdirAll(path.Join("context", path.Dir(name)), 0700) != nil {
			return fail()
		}
		if writeSource(root, path.Join("context", name), body) != nil {
			return fail()
		}
	}
	absolute, err := filepath.Abs(filepath.Join(directory, "build"))
	if err != nil {
		return fail()
	}
	return root, absolute, nil
}

func removeWorkspace(directory string) error {
	parent, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	return parent.RemoveAll("build")
}

func buildArguments(m manifest, input Input, directory string) []string {
	args := connectionArguments(m)
	contextRoot := filepath.Join(directory, "context")
	args = append(args,
		"build", "--frontend", "gateway.v0",
		"--opt", "source="+input.Frontend,
		"--opt", "filename="+input.RecipePath,
		"--opt", "target="+input.Target,
		"--opt", "platform="+input.Platform,
	)
	if input.WorkerContext != "" {
		args = append(args, "--opt", "context:"+input.WorkerContext+"=docker-image://"+input.Worker)
	} else {
		args = append(args, "--opt", "build-arg:"+input.WorkerArg+"="+input.Worker)
	}
	keys := make([]string, 0, len(input.Args))
	for key := range input.Args {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		args = append(args, "--opt", "build-arg:"+key+"="+input.Args[key])
	}
	return append(args,
		"--local", "context="+contextRoot, "--local", "dockerfile="+contextRoot,
		"--output", "type=image,name="+input.OutputRepository+":rem-"+strings.TrimPrefix(input.InputDigest, "sha256:")+",push=true",
		"--metadata-file", filepath.Join(directory, "metadata.json"), "--progress", "plain",
		"--ref-file", filepath.Join(directory, buildRefFile),
	)
}

func connectionArguments(m manifest) []string {
	return []string{"--addr", m.BuildKitAddress,
		"--tlscacert", "/buildkit-ca/ca.crt", "--tlsservername", m.TLS.ServerName,
		"--tlscert", "/builder-client/tls.crt", "--tlskey", "/builder-client/tls.key"}
}

func readImageDigest(root *os.Root) (string, error) {
	body, err := readPrivateMetadata(root, "metadata.json", 64<<10)
	if err != nil {
		return "", failure(ErrInvalid, "trusted-buildkit-metadata-unavailable")
	}
	var fields map[string]json.RawMessage
	var value string
	if decodeStrict(body, &fields) != nil || json.Unmarshal(fields["containerimage.digest"], &value) != nil ||
		!digestPattern.MatchString(value) {
		return "", failure(ErrInvalid, "trusted-buildkit-immutable-digest-required")
	}
	return value, nil
}

func emitPhase(writer io.Writer, phase string, count int) {
	_ = json.NewEncoder(writer).Encode(struct {
		Phase string `json:"phase"`
		Count int    `json:"count"`
	}{phase, count})
}

type boundedTail struct {
	mu        sync.Mutex
	data      []byte
	maximum   int
	truncated bool
}

func newTail(maximum int) *boundedTail {
	return &boundedTail{maximum: maximum}
}

func (tail *boundedTail) Write(body []byte) (int, error) {
	tail.mu.Lock()
	defer tail.mu.Unlock()
	size := len(body)
	if len(tail.data)+size > tail.maximum {
		tail.truncated = true
	}
	if size >= tail.maximum {
		tail.data = append(tail.data[:0], body[size-tail.maximum:]...)
	} else {
		if overflow := len(tail.data) + size - tail.maximum; overflow > 0 {
			copy(tail.data, tail.data[overflow:])
			tail.data = tail.data[:len(tail.data)-overflow]
		}
		tail.data = append(tail.data, body...)
	}
	// Drain all child output. Reaching the retention bound is not a reason to
	// kill a legitimate, verbose build or close its stdout/stderr pipes.
	return size, nil
}

func (tail *boundedTail) snapshot() ([]byte, bool) {
	tail.mu.Lock()
	defer tail.mu.Unlock()
	return bytes.Clone(tail.data), tail.truncated
}

func compilerDiagnostics(body []byte, paths map[string]bool) []Diagnostic {
	var result []Diagnostic
	seen := make(map[Diagnostic]bool)
	for line := range bytes.SplitSeq(body, []byte("\n")) {
		if len(line) > 4096 || secretPattern.Match(line) {
			continue
		}
		match := diagnosticPattern.FindSubmatch(line)
		if len(match) == 0 || !paths[string(match[1])] || !compilerFailurePattern.Match(match[4]) {
			continue
		}
		lineNumber, _ := strconv.Atoi(string(match[2]))
		column, _ := strconv.Atoi(string(match[3]))
		item := Diagnostic{Path: string(match[1]), Line: lineNumber, Column: column}
		if seen[item] {
			continue
		}
		// Do not echo free-form error text or identifiers. Symbol is reserved for
		// a future operator-approved symbol inventory, not stderr extraction.
		result = append(result, item)
		seen[item] = true
		if len(result) == MaxDiagnostics {
			break
		}
	}
	return result
}

func readBounded(file *os.File, maximum int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum || !singleLink(info) {
		return nil, failure(ErrInvalid, "private-file-type-or-size-invalid")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, failure(ErrInvalid, "private-file-read-failed")
	}
	return body, nil
}

func closeFile(file *os.File, err error) error {
	return errors.Join(err, file.Close())
}
