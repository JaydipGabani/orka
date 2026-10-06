package patchverification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type DockerRunner struct {
	DockerBinary   string
	SocketPath     string
	LauncherPath   string
	LauncherDigest string
	MaxOutputBytes int
	SetupTimeout   time.Duration
	command        func(context.Context, ...string) *exec.Cmd
}

const dockerOperationTimeout = 15 * time.Second
const dockerDefaultOutputBytes = 64 * 1024
const dockerArchitectureAMD64 = "amd64"
const dockerArchitectureARM64 = "arm64"
const dockerPlatformAMD64 = "linux/" + dockerArchitectureAMD64
const dockerPlatformARM64 = "linux/" + dockerArchitectureARM64

type dockerImage struct {
	ID           string `json:"Id"`
	OS           string `json:"Os"`
	Architecture string
	Variant      string
	RepoDigests  []string
	Config       struct {
		Volumes map[string]json.RawMessage
	}
}

func ResolveImage(ctx context.Context, image, platform string) (Environment, error) {
	return (DockerRunner{}).ResolveImage(ctx, image, platform)
}

func (runner DockerRunner) ResolveImage(ctx context.Context, image, platform string) (Environment, error) {
	parts := strings.Split(image, "@")
	if len(parts) != 2 || parts[0] == "" || strings.HasPrefix(image, "-") || strings.ContainsAny(image, " \t\r\n\x00") || !sha256Pattern.MatchString(parts[1]) {
		return Environment{}, errors.New("a digest-pinned local image is required")
	}
	if platform != dockerPlatformAMD64 && platform != dockerPlatformARM64 {
		return Environment{}, errors.New("unsupported Docker platform")
	}
	content, err := runner.control(ctx, "image", "inspect", "--platform", platform, "--format", "{{json .}}", image)
	if err != nil {
		return Environment{}, errors.New("pinned image or Docker platform is unavailable locally")
	}
	var inspected dockerImage
	if json.Unmarshal(content, &inspected) != nil || !sha256Pattern.MatchString(inspected.ID) || inspected.OS+"/"+inspected.Architecture != platform || (inspected.Variant != "" && inspected.Variant != "v8") || len(inspected.Config.Volumes) != 0 {
		return Environment{}, errors.New("local image identity, platform, or volume configuration is unsupported")
	}
	found := false
	for _, candidate := range inspected.RepoDigests {
		found = found || strings.HasSuffix(candidate, "@"+parts[1])
	}
	if !found {
		return Environment{}, errors.New("local image digest could not be verified")
	}
	return runner.FreezeEnvironment(Environment{Image: image, ImageID: inspected.ID, Platform: platform, Profile: Offline})
}

func (runner DockerRunner) dockerCommand(ctx context.Context, arguments ...string) *exec.Cmd {
	if runner.command != nil {
		return runner.command(ctx, arguments...)
	}
	binary := runner.DockerBinary
	if binary == "" {
		binary = "docker"
	}
	socket := runner.SocketPath
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	if !filepath.IsAbs(socket) || strings.ContainsAny(socket, "\x00\r\n") {
		binary = "/nonexistent/orka-invalid-docker-socket"
	}
	command := exec.CommandContext(ctx, binary, append([]string{"--host", "unix://" + socket}, arguments...)...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "DOCKER_CONFIG=/nonexistent"}
	command.WaitDelay = time.Second
	return command
}

func (runner DockerRunner) control(ctx context.Context, arguments ...string) ([]byte, error) {
	operation, cancel := context.WithTimeout(ctx, dockerOperationTimeout)
	defer cancel()
	output := &dockerOutput{limit: 128 * 1024}
	command := runner.dockerCommand(operation, arguments...)
	command.Stdout, command.Stderr = output, io.Discard
	err := command.Run()
	content, truncated := output.snapshot()
	if err != nil || truncated {
		return nil, errors.New("docker operation failed or returned incomplete output")
	}
	return content, nil
}

type dockerOutput struct {
	mu         sync.Mutex
	content    []byte
	limit      int
	truncated  bool
	readyText  string
	ready      chan struct{}
	overflow   chan struct{}
	onOverflow func()
}

func (output *dockerOutput) Write(content []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	remaining := max(0, output.limit-len(output.content))
	output.content = append(output.content, content[:min(remaining, len(content))]...)
	if len(content) > remaining && !output.truncated {
		output.truncated = true
		if output.overflow != nil {
			close(output.overflow)
		}
		if output.onOverflow != nil {
			output.onOverflow()
		}
	}
	if output.ready != nil && output.readyText != "" && bytes.Contains(output.content, []byte(output.readyText)) {
		close(output.ready)
		output.readyText = ""
	}
	return len(content), nil
}

func (output *dockerOutput) snapshot() ([]byte, bool) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return bytes.Clone(output.content), output.truncated
}
