package patchverification

import (
	"bytes"
	"debug/elf"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const DockerRunnerPolicyVersion = "local-docker-v3-socket-activation"

const dockerPolicyKey = "orka.local-runner.policy"
const dockerSeccompKey = "orka.local-runner.seccomp"
const dockerLauncherKey = "orka.local-runner.launcher"
const dockerLauncherMount = "/orka-runner/network-launcher"
const dockerLauncherReady = "landlock-tcp-ready\n"
const dockerMaxLauncherBytes = 8 * 1024 * 1024

func (runner DockerRunner) FreezeEnvironment(environment Environment) (Environment, error) {
	frozen, _, err := runner.freezeProfile(environment)
	return frozen, err
}

func (runner DockerRunner) freezeProfile(environment Environment) (Environment, []byte, error) {
	profile, err := dockerSeccomp(environment.Platform, environment.Profile)
	if err != nil {
		return Environment{}, nil, err
	}
	environment.Dependencies = maps.Clone(environment.Dependencies)
	if environment.Dependencies == nil {
		environment.Dependencies = make(map[string]string)
	}
	environment.Dependencies[dockerPolicyKey] = DockerRunnerPolicyVersion
	environment.Dependencies[dockerSeccompKey] = Digest(profile)
	delete(environment.Dependencies, dockerLauncherKey)
	var launcher []byte
	if environment.Profile == LocalServices {
		launcher, err = runner.readLauncher(environment.Platform)
		if err != nil {
			return Environment{}, nil, err
		}
		environment.Dependencies[dockerLauncherKey] = runner.LauncherDigest
	}
	return environment, launcher, nil
}

func (runner DockerRunner) readLauncher(platform string) ([]byte, error) {
	filename := runner.LauncherPath
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename || strings.ContainsAny(filename, ",\r\n\x00") || !sha256Pattern.MatchString(runner.LauncherDigest) {
		return nil, errors.New("local-services requires a trusted static Landlock launcher path and SHA-256 digest")
	}
	resolved, err := filepath.EvalSymlinks(filename)
	if err != nil || resolved != filename {
		return nil, errors.New("trusted launcher is unavailable or symlinked")
	}
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() > dockerMaxLauncherBytes {
		return nil, errors.New("trusted launcher must be a bounded regular executable")
	}
	opened, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("trusted launcher could not be opened")
	}
	content, readErr := io.ReadAll(io.LimitReader(opened, dockerMaxLauncherBytes+1))
	closeErr := opened.Close()
	if readErr != nil || closeErr != nil || len(content) > dockerMaxLauncherBytes || Digest(content) != runner.LauncherDigest {
		return nil, errors.New("trusted launcher content does not match its frozen digest")
	}
	binary, err := elf.NewFile(bytes.NewReader(content))
	if err != nil {
		return nil, errors.New("trusted launcher must be a static native ELF executable")
	}
	defer func() { _ = binary.Close() }()
	architecture := map[string]elf.Machine{dockerPlatformAMD64: elf.EM_X86_64, dockerPlatformARM64: elf.EM_AARCH64}[platform]
	if binary.Class != elf.ELFCLASS64 || binary.Data != elf.ELFDATA2LSB || binary.Type != elf.ET_EXEC || binary.Machine != architecture {
		return nil, errors.New("trusted launcher must be a static native ELF executable")
	}
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP || program.Type == elf.PT_DYNAMIC {
			return nil, errors.New("trusted launcher cannot load a dynamic interpreter or libraries")
		}
	}
	return content, nil
}

func dockerStageFrozenFiles(root string, manifest Manifest, launcher []byte) (string, string, error) {
	checksDir := filepath.Join(root, "checks")
	for _, file := range manifest.Files {
		filename := filepath.Join(checksDir, file.Path)
		if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
			return "", "", errors.New("frozen checks could not be staged")
		}
		for directory := filepath.Dir(filename); directory != root; directory = filepath.Dir(directory) {
			if err := os.Chmod(directory, 0755); err != nil {
				return "", "", errors.New("frozen check directories could not be prepared")
			}
		}
		mode := os.FileMode(0444)
		if file.Executable {
			mode = 0555
		}
		if err := os.WriteFile(filename, file.Content, mode); err != nil {
			return "", "", errors.New("frozen check content could not be staged")
		}
		if err := os.Chmod(filename, mode); err != nil {
			return "", "", errors.New("frozen check permissions could not be prepared")
		}
	}
	launcherPath := ""
	if len(launcher) != 0 {
		launcherPath = filepath.Join(root, "network-launcher")
		if err := os.WriteFile(launcherPath, launcher, 0555); err != nil {
			return "", "", errors.New("trusted launcher could not be staged")
		}
		if err := os.Chmod(launcherPath, 0555); err != nil {
			return "", "", errors.New("trusted launcher permissions could not be prepared")
		}
	}
	return checksDir, launcherPath, nil
}

func dockerGuardCommand(bindPorts, connectPorts string, command []string) []string {
	return append([]string{dockerLauncherMount, "--bind-tcp", bindPorts, "--connect-tcp", connectPorts, "--"}, command...)
}

func dockerServicePorts(services []Service) string {
	ports := make([]string, 0, len(services))
	for _, service := range services {
		ports = append(ports, strconv.Itoa(service.Port))
	}
	return strings.Join(ports, ",")
}
