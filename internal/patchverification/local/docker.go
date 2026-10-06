package local

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
	"time"
)

type nonemptyOutput struct {
	mu       sync.Mutex
	nonempty bool
}

func (output *nonemptyOutput) Write(content []byte) (int, error) {
	output.mu.Lock()
	output.nonempty = output.nonempty || len(content) != 0
	output.mu.Unlock()
	return len(content), nil
}

func DockerQuiescent(ctx context.Context) error {
	operation, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(operation, "docker", "--host", "unix:///var/run/docker.sock", "container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "label=ai.orka.patchverification.owner")
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "DOCKER_CONFIG=/nonexistent"}
	command.WaitDelay = time.Second
	output := &nonemptyOutput{}
	command.Stdout, command.Stderr = output, io.Discard
	if err := command.Run(); err != nil {
		return errors.New("docker quiescence could not be established")
	}
	if output.nonempty {
		return errors.New("runner-owned containers remain; inspect and remove only proven orphan containers before recovery")
	}
	return nil
}
