package patchverification

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDockerResolveImage(test *testing.T) {
	image := testManifest().Environment.Image
	for _, scenario := range []string{"valid", "missing", "platform", "digest", "volume", "malformed"} {
		test.Run(scenario, func(test *testing.T) {
			runner := DockerRunner{command: func(ctx context.Context, arguments ...string) *exec.Cmd {
				if strings.Join(arguments[:2], " ") != "image inspect" || arguments[len(arguments)-1] != image {
					test.Fatalf("unexpected Docker command: %v", arguments)
				}
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDockerImageHelper$")
				command.Env = []string{"ORKA_DOCKER_IMAGE_HELPER=" + scenario}
				return command
			}}
			environment, err := runner.ResolveImage(context.Background(), image, "linux/amd64")
			if scenario == "valid" {
				if err != nil || environment.ImageID != Digest([]byte("image-config")) || environment.Image != image || environment.Platform != "linux/amd64" {
					test.Fatalf("unexpected resolved identity: %+v, %v", environment, err)
				}
			} else if err == nil || strings.Contains(err.Error(), "private-diagnostic") {
				test.Fatalf("unsafe resolution result: %+v, %v", environment, err)
			}
		})
	}
	for _, input := range []struct{ image, platform string }{{"alpine:latest", "linux/amd64"}, {"--help@" + Digest(nil), "linux/amd64"}, {image, "windows/amd64"}} {
		if _, err := ResolveImage(context.Background(), input.image, input.platform); err == nil {
			test.Fatal("invalid resolution input accepted")
		}
	}
	if _, err := (DockerRunner{DockerBinary: "/nonexistent/orka-docker"}).ResolveImage(context.Background(), image, "linux/amd64"); err == nil {
		test.Fatal("missing Docker executable accepted")
	}
}

func TestDockerImageHelper(test *testing.T) {
	scenario := os.Getenv("ORKA_DOCKER_IMAGE_HELPER")
	if scenario == "" {
		return
	}
	if scenario == "missing" {
		fmt.Fprintln(os.Stderr, "private-diagnostic")
		os.Exit(1)
	}
	if scenario == "malformed" {
		if _, err := fmt.Fprintln(os.Stdout, "not-json"); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	image := dockerImage{ID: Digest([]byte("image-config")), OS: "linux", Architecture: "amd64", RepoDigests: []string{testManifest().Environment.Image}}
	switch scenario {
	case "platform":
		image.Architecture = "arm64"
	case "digest":
		image.RepoDigests = nil
	case "volume":
		image.Config.Volumes = map[string]json.RawMessage{"/workspace": json.RawMessage(`{}`)}
	}
	if err := json.NewEncoder(os.Stdout).Encode(image); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestDockerBoundedOutput(test *testing.T) {
	output := &dockerOutput{limit: 8, readyText: "ready\n", ready: make(chan struct{}), overflow: make(chan struct{})}
	for _, text := range []string{"rea", "dy\n", "123456789"} {
		if count, err := output.Write([]byte(text)); err != nil || count != len(text) {
			test.Fatalf("capture blocked draining: %d, %v", count, err)
		}
	}
	content, truncated := output.snapshot()
	if string(content) != "ready\n12" || !truncated {
		test.Fatalf("incorrect bounded output: %q, %v", content, truncated)
	}
	select {
	case <-output.ready:
	default:
		test.Fatal("readiness spanning writes was missed")
	}
	select {
	case <-output.overflow:
	default:
		test.Fatal("overflow not signaled")
	}
	content[0] = 'X'
	unchanged, _ := output.snapshot()
	if unchanged[0] != 'r' {
		test.Fatal("capture snapshot aliases mutable evidence")
	}
}

func TestDockerHostEnvironment(test *testing.T) {
	test.Setenv("DOCKER_HOST", "tcp://untrusted.invalid:2375")
	test.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-forward")
	command := (DockerRunner{}).dockerCommand(context.Background(), "version")
	if strings.Join(command.Args[1:3], " ") != "--host unix:///var/run/docker.sock" || strings.Contains(strings.Join(command.Env, "\n"), "must-not-forward") {
		test.Fatal("Docker inherited host endpoint or credentials")
	}
}
