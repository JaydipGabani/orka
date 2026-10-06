package patchverification

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDockerFreezeEnvironment(test *testing.T) {
	environment := testManifest().Environment
	environment.Dependencies = map[string]string{"toolchain": "frozen"}
	frozen, err := (DockerRunner{}).FreezeEnvironment(environment)
	if err != nil {
		test.Fatal(err)
	}
	profile, err := dockerSeccomp(environment.Platform, environment.Profile)
	if err != nil || frozen.Dependencies[dockerPolicyKey] != DockerRunnerPolicyVersion || frozen.Dependencies[dockerSeccompKey] != Digest(profile) || frozen.Dependencies["toolchain"] != "frozen" {
		test.Fatal("runner policy was not frozen alongside existing toolchain identities")
	}
	if len(environment.Dependencies) != 1 {
		test.Fatal("freezing mutated the caller's dependency map")
	}
	environment.Profile = LocalServices
	if _, err := (DockerRunner{}).FreezeEnvironment(environment); err == nil {
		test.Fatal("local services accepted without a trusted launcher")
	}
}

func TestDockerFrozenPolicyMismatch(test *testing.T) {
	for _, key := range []string{dockerPolicyKey, dockerSeccompKey, dockerLauncherKey} {
		test.Run(key, func(test *testing.T) {
			manifest, sourceDir, checksDir := dockerTestStaging(test)
			runner := DockerRunner{command: func(ctx context.Context, arguments ...string) *exec.Cmd {
				test.Fatal("Docker was called before rejecting the mismatched frozen policy")
				return nil
			}}
			var err error
			manifest.Environment, err = runner.FreezeEnvironment(manifest.Environment)
			if err != nil {
				test.Fatal(err)
			}
			manifest.Environment.Dependencies[key] = "different"
			binding, _ := testEvidence(manifest)
			evidence, err := runner.RunCheck(context.Background(), manifest, binding, Original, manifest.Checks[0], sourceDir, checksDir)
			if err == nil || evidence.Observation.SetupError == "" || evidence.Observation.Executed {
				test.Fatal("mismatched policy was accepted")
			}
		})
	}
}

func TestDockerLauncherRejectsUntrustedInputs(test *testing.T) {
	for _, scenario := range []string{"missing", "digest", "script", "symlink", "non-executable", "oversized"} {
		test.Run(scenario, func(test *testing.T) {
			content := []byte("#!/bin/sh\nexit 0\n")
			filename := filepath.Join(test.TempDir(), "launcher")
			if err := os.WriteFile(filename, content, 0755); err != nil {
				test.Fatal(err)
			}
			runner := DockerRunner{LauncherPath: filename, LauncherDigest: Digest(content)}
			var err error
			switch scenario {
			case "missing":
				runner.LauncherPath += "-missing"
			case "digest":
				runner.LauncherDigest = Digest(nil)
			case "symlink":
				runner.LauncherPath += "-link"
				err = os.Symlink(filename, runner.LauncherPath)
			case "non-executable":
				err = os.Chmod(filename, 0644)
			case "oversized":
				err = os.Truncate(filename, dockerMaxLauncherBytes+1)
			}
			if err != nil {
				test.Fatal(err)
			}
			if _, err := runner.readLauncher("linux/amd64"); err == nil {
				test.Fatal("untrusted launcher preparation was accepted")
			}
		})
	}
}

func TestDockerSecurityOptionsMatch(test *testing.T) {
	profile, err := dockerSeccomp("linux/amd64", LocalServices)
	if err != nil {
		test.Fatal(err)
	}
	if !dockerSecurityOptionsMatch([]string{"no-new-privileges=true", "seccomp=" + string(profile)}, profile) {
		test.Fatal("exact confined policy rejected")
	}
	for _, options := range [][]string{
		{"no-new-privileges=true", "seccomp=unconfined"},
		{"no-new-privileges=false", "seccomp=" + string(profile)},
		{"no-new-privileges=true", `seccomp={"defaultAction":"SCMP_ACT_ALLOW"}`},
		{"no-new-privileges=true"},
		{"no-new-privileges=true", "seccomp=" + string(profile), "apparmor=unconfined"},
	} {
		if dockerSecurityOptionsMatch(options, profile) {
			test.Fatal("weakened or unknown container security options accepted")
		}
	}
}
