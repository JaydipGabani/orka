package patchverification

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type dockerState struct {
	Status     string
	Running    bool
	Dead       bool
	OOMKilled  bool
	ExitCode   int
	Error      string
	StartedAt  time.Time
	FinishedAt time.Time
}

type dockerInspection struct {
	ID     string `json:"Id"`
	Image  string
	Name   string
	State  dockerState
	Config struct {
		User       string
		Entrypoint []string
		Cmd        []string
		Labels     map[string]string
		Tty        bool
	}
	HostConfig struct {
		ReadonlyRootfs bool
		Privileged     bool
		PidMode        string
		IpcMode        string
		NetworkMode    string
		CapDrop        []string
		CapAdd         []string
		SecurityOpt    []string
		Memory         int64
		MemorySwap     int64
		NanoCpus       int64
		PidsLimit      int64
		LogConfig      struct{ Type string }
	}
	Mounts []struct {
		Type        string
		Source      string
		Destination string
		RW          bool
	}
}

type dockerContainer struct {
	id      string
	spec    dockerContainerSpec
	process *dockerProcess
}

type dockerProcess struct {
	stdout *dockerOutput
	stderr *dockerOutput
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

type dockerExecution struct {
	runner     DockerRunner
	owner      string
	containers []*dockerContainer
	subject    *dockerContainer
	anchor     *dockerContainer
	services   map[string]*dockerContainer
	exited     chan *dockerContainer
	overflow   chan struct{}
}

func (runner DockerRunner) RunCheck(ctx context.Context, manifest Manifest, binding Binding, side string, check Check, sourceDir, checksDir string) (evidence ExecutionEvidence, resultErr error) {
	taskID, sourceTree := binding.OriginalTaskID, manifest.Sources.Original.Tree
	if side == Patched {
		taskID, sourceTree = binding.PatchedTaskID, manifest.Sources.Patched.Tree
	}
	evidence = ExecutionEvidence{Observation: Observation{RunID: binding.RunID, AttemptID: binding.AttemptID, TaskID: taskID, ManifestDigest: binding.ManifestDigest, Side: side, CheckID: check.ID, SourceTree: sourceTree, ImageID: manifest.Environment.ImageID, Origin: "runner"}, Blobs: make(map[string][]byte)}
	defer func() {
		if resultErr != nil {
			evidence.Observation.SetupError = resultErr.Error()
		}
	}()
	if ValidateManifest(manifest) != nil || ValidateObservation(manifest, binding, evidence.Observation) != nil {
		return evidence, errors.New("invalid frozen manifest or execution binding")
	}
	if missing := MissingRequirements(manifest.Environment); len(missing) != 0 {
		return evidence, errors.New(strings.Join(missing, "; "))
	}
	manifest, check, err := dockerFreezeCheck(manifest, check)
	if err != nil {
		return evidence, err
	}
	if runner.MaxOutputBytes == 0 {
		runner.MaxOutputBytes = dockerDefaultOutputBytes
	}
	if runner.SetupTimeout == 0 {
		runner.SetupTimeout = 30 * time.Second
	}
	if runner.MaxOutputBytes < 1 || runner.MaxOutputBytes > 1024*1024 || runner.SetupTimeout < time.Second || runner.SetupTimeout > 30*time.Second {
		return evidence, errors.New("invalid local runner limits")
	}
	if err := dockerValidateInputs(manifest, sourceDir, checksDir); err != nil {
		return evidence, err
	}
	launcher, err := runner.validateFrozenProfile(manifest.Environment, sourceDir, checksDir)
	if err != nil {
		return evidence, err
	}
	staging, err := os.MkdirTemp("/tmp", "orka-patch-frozen-*")
	if err != nil {
		return evidence, errors.New("runner-owned input staging is unavailable")
	}
	defer func() {
		if os.RemoveAll(staging) != nil {
			resultErr = errors.Join(resultErr, errors.New("runner-owned input cleanup failed"))
		}
	}()
	checksDir, launcherPath, err := dockerStageFrozenFiles(staging, manifest, launcher)
	if err != nil {
		return evidence, err
	}
	setup, cancelSetup := context.WithTimeout(ctx, runner.SetupTimeout)
	defer cancelSetup()
	environment, err := runner.ResolveImage(setup, manifest.Environment.Image, manifest.Environment.Platform)
	if err != nil || environment.ImageID != manifest.Environment.ImageID {
		return evidence, errors.New("frozen image identity or platform is unavailable locally")
	}
	if err := runner.requireIsolation(setup, environment.Platform); err != nil {
		return evidence, err
	}
	clearEnv, err := runner.imageEnvironment(setup, environment.ImageID)
	if err != nil {
		return evidence, err
	}
	profile, err := dockerSeccomp(environment.Platform, manifest.Environment.Profile)
	if err != nil {
		return evidence, err
	}
	profileFile, err := os.CreateTemp("/tmp", "orka-patch-seccomp-*.json")
	if err != nil {
		return evidence, errors.New("host seccomp profile could not be staged")
	}
	defer func() {
		if os.Remove(profileFile.Name()) != nil {
			resultErr = errors.Join(resultErr, errors.New("host seccomp profile cleanup failed"))
		}
	}()
	_, writeErr := profileFile.Write(profile)
	closeErr := profileFile.Close()
	if writeErr != nil || closeErr != nil {
		return evidence, errors.New("host seccomp profile could not be frozen")
	}
	execution := &dockerExecution{runner: runner, owner: strings.ToLower(rand.Text()), services: make(map[string]*dockerContainer), exited: make(chan *dockerContainer, 16), overflow: make(chan struct{}, 1)}
	defer func() {
		resultErr = execution.completeEvidence(&evidence, resultErr)
	}()
	spec := dockerContainerSpec{environment: manifest.Environment, seccompPath: profileFile.Name(), network: dockerNetworkNone, clearEnv: clearEnv, launcherPath: launcherPath}
	if manifest.Environment.Profile == LocalServices {
		spec, err = execution.startServices(setup, spec, checksDir)
		if err != nil {
			return evidence, err
		}
	}
	spec.sourceDir, spec.checksDir, spec.command = sourceDir, checksDir, check.Command
	if manifest.Environment.Profile == LocalServices {
		spec.command = dockerGuardCommand("-", dockerServicePorts(manifest.Environment.Services), check.Command)
	}
	resultErr = execution.runSubject(ctx, setup, spec, check, &evidence.Observation)
	return evidence, resultErr
}

func dockerFreezeCheck(manifest Manifest, check Check) (Manifest, Check, error) {
	matched := false
	for _, frozen := range manifest.Checks {
		matched = matched || reflect.DeepEqual(frozen, check)
	}
	if !matched {
		return Manifest{}, Check{}, errors.New("check does not match the frozen manifest")
	}
	encoded, err := json.Marshal(manifest)
	var frozenManifest Manifest
	if err != nil || json.Unmarshal(encoded, &frozenManifest) != nil {
		return Manifest{}, Check{}, errors.New("manifest could not be frozen for execution")
	}
	for _, frozen := range frozenManifest.Checks {
		if frozen.ID == check.ID {
			check = frozen
		}
	}
	return frozenManifest, check, nil
}

func (runner DockerRunner) validateFrozenProfile(environment Environment, sourceDir, checksDir string) ([]byte, error) {
	frozenEnvironment, launcher, err := runner.freezeProfile(environment)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{dockerPolicyKey, dockerSeccompKey, dockerLauncherKey} {
		if environment.Dependencies[key] != frozenEnvironment.Dependencies[key] {
			return nil, errors.New("runner policy or launcher identity does not match the frozen environment")
		}
	}
	if len(launcher) != 0 && (strings.HasPrefix(runner.LauncherPath, sourceDir+"/") || strings.HasPrefix(runner.LauncherPath, checksDir+"/")) {
		return nil, errors.New("trusted launcher must be separate from source and check inputs")
	}
	return launcher, nil
}

func (execution *dockerExecution) completeEvidence(evidence *ExecutionEvidence, resultErr error) error {
	if err := execution.cleanup(); err != nil {
		resultErr = errors.Join(resultErr, err)
	}
	if execution.subject != nil && execution.subject.process != nil {
		stdout := dockerCapture(evidence, execution.subject.process.stdout)
		stderr := dockerCapture(evidence, execution.subject.process.stderr)
		evidence.Observation.StdoutDigest, evidence.Observation.StdoutBytes = stdout.Digest, stdout.Bytes
		evidence.Observation.StderrDigest, evidence.Observation.StderrBytes = stderr.Digest, stderr.Bytes
	}
	if len(execution.services) != 0 {
		evidence.Observation.ServiceOutputs = make(map[string]CapturedOutput)
	}
	for serviceID, container := range execution.services {
		if container.process != nil {
			if err := dockerCaptureService(evidence, serviceID, container.process.stdout, container.process.stderr); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
		}
	}
	if evidence.Observation.OutputTruncated {
		resultErr = errors.Join(resultErr, errors.New("execution output exceeded the capture limit"))
	}
	return resultErr
}

func (execution *dockerExecution) startServices(ctx context.Context, spec dockerContainerSpec, checksDir string) (dockerContainerSpec, error) {
	spec.command = []string{dockerLauncherMount, "--anchor"}
	anchor, err := execution.create(ctx, spec)
	execution.anchor = anchor
	if err != nil {
		return spec, err
	}
	if err := execution.start(ctx, anchor, "", dockerLauncherReady); err != nil {
		return spec, err
	}
	select {
	case <-anchor.process.stdout.ready:
	case <-execution.exited:
		return spec, errors.New("local-services requires enabled Landlock TCP support (ABI 4, Linux 6.7 or newer)")
	case <-execution.overflow:
		return spec, errors.New("trusted network launcher returned unexpected output")
	case <-ctx.Done():
		return spec, errors.New("trusted network launcher startup timed out or was canceled")
	}
	if err := execution.requireRunning(ctx, anchor); err != nil {
		return spec, err
	}
	spec.network = "container:" + anchor.id
	for _, service := range spec.environment.Services {
		spec.checksDir, spec.command = checksDir, dockerGuardCommand(strconv.Itoa(service.Port), "-", service.Command)
		container, err := execution.create(ctx, spec)
		if err != nil {
			return spec, err
		}
		execution.services[service.ID] = container
		if err := execution.start(ctx, container, "", service.ReadyOutput); err != nil {
			return spec, err
		}
		select {
		case <-container.process.stdout.ready:
		case <-execution.exited:
			return spec, errors.New("local fixture exited before readiness")
		case <-execution.overflow:
			return spec, errors.New("local fixture output was truncated before readiness")
		case <-ctx.Done():
			return spec, errors.New("local fixture readiness timed out or was canceled")
		}
		if err := execution.requireRunning(ctx, container); err != nil {
			return spec, err
		}
	}
	return spec, nil
}

func (execution *dockerExecution) runSubject(ctx, setup context.Context, spec dockerContainerSpec, check Check, observation *Observation) error {
	subject, err := execution.create(setup, spec)
	execution.subject = subject
	if err != nil {
		return err
	}
	observation.ContainerID = subject.id
	for _, container := range execution.containers {
		if container != subject {
			if err := execution.requireRunning(setup, container); err != nil {
				return err
			}
		}
	}
	select {
	case <-execution.overflow:
		return errors.New("local fixture output was truncated")
	default:
	}
	running, cancelRunning := context.WithTimeout(ctx, time.Duration(check.TimeoutSeconds)*time.Second)
	defer cancelRunning()
	if err := execution.start(running, subject, check.Stdin, ""); err != nil {
		return err
	}
	var resultErr error
	select {
	case finished := <-execution.exited:
		if finished != subject {
			resultErr = errors.New("local fixture exited while the check was running")
		}
	case <-execution.overflow:
		resultErr = errors.New("execution output exceeded the capture limit")
	case <-running.Done():
		observation.TimedOut = errors.Is(running.Err(), context.DeadlineExceeded)
		resultErr = errors.New("check timed out or was canceled")
	}
	if running.Err() != nil {
		observation.TimedOut = errors.Is(running.Err(), context.DeadlineExceeded)
		resultErr = errors.New("check timed out or was canceled")
	}
	finish, cancelFinish := context.WithTimeout(context.WithoutCancel(ctx), dockerOperationTimeout)
	defer cancelFinish()
	if resultErr != nil {
		if _, err := execution.runner.control(finish, "kill", "--signal", "KILL", subject.id); err != nil {
			resultErr = errors.Join(resultErr, errors.New("subject termination could not be confirmed"))
		}
	}
	attachErr := execution.drain(finish, subject)
	if attachErr != nil {
		resultErr = errors.Join(resultErr, attachErr)
	} else {
		attachErr = subject.process.err
	}
	inspection, inspectErr := execution.inspect(finish, subject)
	if inspectErr != nil {
		resultErr = errors.Join(resultErr, inspectErr)
	} else if err := dockerObserveSubject(observation, inspection.State, attachErr); err != nil {
		resultErr = errors.Join(resultErr, err)
	}
	for _, service := range spec.environment.Services {
		container := execution.services[service.ID]
		if err := execution.stopService(container); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}
	if execution.anchor != nil {
		anchorContext, cancelAnchor := context.WithTimeout(context.WithoutCancel(ctx), dockerOperationTimeout)
		defer cancelAnchor()
		if err := execution.requireRunning(anchorContext, execution.anchor); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}
	return resultErr
}

func (runner DockerRunner) requireIsolation(ctx context.Context, platform string) error {
	content, err := runner.control(ctx, "info", "--format", "{{json .}}")
	if err != nil {
		return errors.New("docker isolation capabilities are unavailable")
	}
	var info struct {
		OSType          string
		Architecture    string
		MemoryLimit     bool
		SwapLimit       bool
		PidsLimit       bool
		CPUCfsQuota     bool
		SecurityOptions []string
	}
	if json.Unmarshal(content, &info) != nil {
		return errors.New("docker isolation capabilities could not be verified")
	}
	architecture := map[string]string{"x86_64": dockerArchitectureAMD64, dockerArchitectureAMD64: dockerArchitectureAMD64, "aarch64": dockerArchitectureARM64, dockerArchitectureARM64: dockerArchitectureARM64}[info.Architecture]
	seccomp := false
	for _, option := range info.SecurityOptions {
		seccomp = seccomp || strings.HasPrefix(option, "name=seccomp")
	}
	if info.OSType+"/"+architecture != platform || !info.MemoryLimit || !info.SwapLimit || !info.PidsLimit || !info.CPUCfsQuota || !seccomp {
		return errors.New("native platform, seccomp, and resource limits are required")
	}
	return nil
}

func (runner DockerRunner) imageEnvironment(ctx context.Context, imageID string) ([]string, error) {
	content, err := runner.control(ctx, "image", "inspect", "--format", "{{json .Config.Env}}", imageID)
	if err != nil {
		return nil, errors.New("image environment could not be inspected")
	}
	var variables []string
	if json.Unmarshal(content, &variables) != nil {
		return nil, errors.New("image environment could not be decoded")
	}
	validName := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,127}$`)
	names := make([]string, 0, len(variables))
	for _, variable := range variables {
		name, _, found := strings.Cut(variable, "=")
		if !found || !validName.MatchString(name) {
			return nil, errors.New("image environment cannot be safely cleared")
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

func (execution *dockerExecution) create(ctx context.Context, spec dockerContainerSpec) (*dockerContainer, error) {
	if ctx.Err() != nil {
		return nil, errors.New("container setup was canceled or timed out")
	}
	spec.owner = execution.owner
	spec.name = "orka-patch-" + strings.ToLower(rand.Text())
	container := &dockerContainer{spec: spec}
	execution.containers = append(execution.containers, container)
	content, err := execution.runner.control(context.WithoutCancel(ctx), dockerCreateArguments(spec)...)
	if err != nil {
		return container, errors.New("isolated container could not be created")
	}
	identifier := strings.TrimSpace(string(content))
	if !sha256Pattern.MatchString("sha256:" + identifier) {
		return container, errors.New("docker did not return an exact container identity")
	}
	container.id = identifier
	if _, err := execution.inspect(ctx, container); err != nil {
		return container, err
	}
	return container, nil
}

func (execution *dockerExecution) inspect(ctx context.Context, container *dockerContainer) (dockerInspection, error) {
	identifier := container.id
	if identifier == "" {
		identifier = container.spec.name
	}
	content, err := execution.runner.control(ctx, "container", "inspect", "--format", "{{json .}}", identifier)
	if err != nil {
		return dockerInspection{}, errors.New("container identity or state could not be inspected")
	}
	var inspection dockerInspection
	if json.Unmarshal(content, &inspection) != nil || !sha256Pattern.MatchString("sha256:"+inspection.ID) || (container.id != "" && inspection.ID != container.id) || inspection.Name != "/"+container.spec.name || inspection.Config.Labels[dockerOwnerLabel] != container.spec.owner || inspection.Image != container.spec.environment.ImageID {
		return dockerInspection{}, errors.New("container does not match the frozen image and ownership identity")
	}
	if err := dockerValidateContainerIsolation(inspection, container.spec); err != nil {
		return dockerInspection{}, err
	}
	if err := dockerValidateContainerMounts(inspection, container.spec); err != nil {
		return dockerInspection{}, err
	}
	return inspection, nil
}

func dockerValidateContainerIsolation(inspection dockerInspection, spec dockerContainerSpec) error {
	config := inspection.HostConfig
	if !config.ReadonlyRootfs || config.Privileged || config.PidMode != "" || config.IpcMode != dockerPrivateNamespace || config.NetworkMode != spec.network || !slices.Contains(config.CapDrop, "ALL") || len(config.CapAdd) != 0 || config.Memory != 512*1024*1024 || config.MemorySwap != config.Memory || config.PidsLimit != 128 || config.NanoCpus != 1000000000 || config.LogConfig.Type != dockerLogDriverNone || inspection.Config.User != "65532:65532" || inspection.Config.Tty || !slices.Equal(inspection.Config.Entrypoint, []string{"/usr/bin/env"}) {
		return errors.New("container isolation configuration could not be verified")
	}
	arguments := dockerCreateArguments(spec)
	command := arguments[slices.Index(arguments, spec.environment.Image)+1:]
	profile, err := dockerSeccomp(spec.environment.Platform, spec.environment.Profile)
	if err != nil || !slices.Equal(inspection.Config.Cmd, command) || !dockerSecurityOptionsMatch(config.SecurityOpt, profile) {
		return errors.New("container command or security policy does not match the frozen runner")
	}
	return nil
}

func dockerValidateContainerMounts(inspection dockerInspection, spec dockerContainerSpec) error {
	wanted := make(map[string]string)
	if spec.sourceDir != "" {
		wanted["/src"] = spec.sourceDir
	}
	if spec.checksDir != "" {
		wanted["/checks"] = spec.checksDir
	}
	if spec.launcherPath != "" {
		wanted[dockerLauncherMount] = spec.launcherPath
	}
	for _, mount := range inspection.Mounts {
		if mount.Type == "tmpfs" && mount.Destination == "/tmp" {
			continue
		}
		if wanted[mount.Destination] == "" || wanted[mount.Destination] != mount.Source || mount.RW || mount.Type != "bind" {
			return errors.New("unexpected writable or host mount in isolated container")
		}
		delete(wanted, mount.Destination)
	}
	if len(wanted) != 0 {
		return errors.New("frozen container mounts are missing")
	}
	return nil
}

func (execution *dockerExecution) start(ctx context.Context, container *dockerContainer, input, readyText string) error {
	if ctx.Err() != nil {
		return errors.New("container start was canceled or timed out")
	}
	attached, cancel := context.WithCancel(context.WithoutCancel(ctx))
	process := &dockerProcess{done: make(chan struct{}), cancel: cancel}
	limit := execution.runner.MaxOutputBytes
	notifyOverflow := func() {
		select {
		case execution.overflow <- struct{}{}:
		default:
		}
	}
	process.stdout = &dockerOutput{limit: limit, readyText: readyText, ready: make(chan struct{}), onOverflow: notifyOverflow}
	process.stderr = &dockerOutput{limit: limit, onOverflow: notifyOverflow}
	command := execution.runner.dockerCommand(attached, "start", "--attach", "--interactive", "--detach-keys", "", container.id)
	command.Stdin, command.Stdout, command.Stderr = strings.NewReader(input), process.stdout, process.stderr
	container.process = process
	if err := command.Start(); err != nil {
		process.err = errors.New("docker attach process could not start")
		close(process.done)
		cancel()
		return process.err
	}
	go func() {
		process.err = command.Wait()
		close(process.done)
		execution.exited <- container
	}()
	return nil
}

func (execution *dockerExecution) requireRunning(ctx context.Context, container *dockerContainer) error {
	inspection, err := execution.inspect(ctx, container)
	if err != nil || !inspection.State.Running || inspection.State.Dead || inspection.State.OOMKilled || inspection.State.Error != "" {
		return errors.New("local fixture exited unexpectedly or could not be observed")
	}
	select {
	case <-container.process.done:
		return errors.New("local fixture output observer disconnected")
	default:
		return nil
	}
}

func (execution *dockerExecution) drain(ctx context.Context, container *dockerContainer) error {
	select {
	case <-container.process.done:
		return nil
	case <-ctx.Done():
		container.process.cancel()
		return errors.New("container output could not be drained completely")
	}
}

func (execution *dockerExecution) stopService(container *dockerContainer) error {
	ctx, cancel := context.WithTimeout(context.Background(), dockerOperationTimeout)
	defer cancel()
	if err := execution.requireRunning(ctx, container); err != nil {
		return err
	}
	stopping := time.Now()
	if _, err := execution.runner.control(ctx, "stop", "--signal", "SIGTERM", "--time", "2", container.id); err != nil {
		return errors.New("local fixture could not be stopped orderly")
	}
	if err := execution.drain(ctx, container); err != nil {
		return err
	}
	inspection, err := execution.inspect(ctx, container)
	if err != nil || inspection.State.Running || inspection.State.Dead || inspection.State.OOMKilled || inspection.State.Error != "" || inspection.State.ExitCode != 0 || inspection.State.FinishedAt.Before(stopping) || container.process.err != nil {
		return errors.New("local fixture did not complete an observed orderly shutdown")
	}
	return nil
}

func (execution *dockerExecution) cleanup() error {
	var cleanupErr error
	for _, container := range slices.Backward(execution.containers) {

		ctx, cancel := context.WithTimeout(context.Background(), dockerOperationTimeout)
		if container.id == "" {
			inspection, err := execution.inspect(ctx, container)
			if err == nil {
				container.id = inspection.ID
			} else {
				cleanupErr = errors.New("container creation or cleanup could not be confirmed")
			}
		}
		if container.id != "" {
			if _, err := execution.runner.control(ctx, "rm", "--force", "--volumes", container.id); err != nil {
				cleanupErr = errors.New("isolated container cleanup could not be confirmed")
			}
		}
		if container.process != nil {
			container.process.cancel()
			if execution.drain(ctx, container) != nil {
				cleanupErr = errors.New("docker output observer cleanup could not be confirmed")
			}
		}
		cancel()
	}
	return cleanupErr
}

func dockerObserveSubject(observation *Observation, state dockerState, attachErr error) error {
	observation.StartedAt, observation.FinishedAt = state.StartedAt, state.FinishedAt
	observation.Executed = !state.StartedAt.IsZero()
	if observation.Executed && !state.Running {
		observation.ExitCode = new(state.ExitCode)
	}
	if !observation.Executed || state.Running || state.Dead || state.OOMKilled || state.Error != "" || state.FinishedAt.Before(state.StartedAt) || state.ExitCode < 0 || state.ExitCode >= 125 {
		return errors.New("check did not complete with usable container exit evidence")
	}
	attachExitCode := 0
	if attachErr != nil {
		var exitError *exec.ExitError
		if !errors.As(attachErr, &exitError) {
			return errors.New("docker output observer did not complete reliably")
		}
		attachExitCode = exitError.ExitCode()
	}
	if attachExitCode != state.ExitCode {
		return errors.New("docker output observer exit status did not match the container")
	}
	return nil
}

func dockerCapture(evidence *ExecutionEvidence, output *dockerOutput) CapturedOutput {
	content, truncated := output.snapshot()
	digest := Digest(content)
	evidence.Blobs[digest] = content
	evidence.Observation.OutputTruncated = evidence.Observation.OutputTruncated || truncated
	return CapturedOutput{Digest: digest, Bytes: len(content), Truncated: truncated}
}

func dockerCaptureService(evidence *ExecutionEvidence, serviceID string, stdout, stderr *dockerOutput) error {
	if evidence.Observation.ServiceOutputs == nil {
		evidence.Observation.ServiceOutputs = make(map[string]CapturedOutput)
	}
	evidence.Observation.ServiceOutputs[serviceID] = dockerCapture(evidence, stdout)
	diagnostics, truncated := stderr.snapshot()
	evidence.Observation.OutputTruncated = evidence.Observation.OutputTruncated || truncated
	if len(diagnostics) != 0 || truncated {
		return errors.New("local fixture wrote unexpected diagnostic output")
	}
	return nil
}
