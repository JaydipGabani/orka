package patchverification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDockerIsolationArguments(test *testing.T) {
	for _, network := range []string{"none", "container:" + strings.Repeat("a", 64)} {
		arguments := dockerCreateArguments(dockerContainerSpec{name: "owned", owner: "token", environment: testManifest().Environment, network: network, sourceDir: "/staged/source", checksDir: "/staged/checks", seccompPath: "/tmp/profile", command: []string{"/checks/run", "--privileged"}})
		for _, flag := range []string{"--read-only", "--init", "--no-healthcheck", "--interactive"} {
			if !slices.Contains(arguments, flag) {
				test.Fatalf("missing isolation flag %s", flag)
			}
		}
		for flag, value := range map[string]string{"--pull": "never", "--user": "65532:65532", "--cap-drop": "ALL", "--memory": "512m", "--memory-swap": "512m", "--cpus": "1", "--pids-limit": "128", "--entrypoint": "/usr/bin/env", "--network": network, "--ipc": "private", "--cgroupns": "private", "--log-driver": "none"} {
			position := slices.Index(arguments, flag)
			if position < 0 || arguments[position+1] != value {
				test.Fatalf("missing fixed option %s=%s", flag, value)
			}
		}
		for _, value := range []string{"no-new-privileges=true", "seccomp=/tmp/profile", "type=bind,src=/staged/source,dst=/src,readonly,bind-recursive=disabled", "type=bind,src=/staged/checks,dst=/checks,readonly,bind-recursive=disabled", "/tmp:rw,exec,nosuid,nodev,size=268435456,mode=1777"} {
			if !slices.Contains(arguments, value) {
				test.Fatalf("missing isolation value %s", value)
			}
		}
		imagePosition := slices.Index(arguments, testManifest().Environment.Image)
		if arguments[imagePosition+1] != "-i" || slices.Index(arguments, "--privileged") < imagePosition {
			test.Fatal("image environment or subject arguments can affect Docker flags")
		}
		for _, argument := range arguments[:imagePosition] {
			if strings.Contains(argument, "docker.sock") || strings.Contains(argument, "store") || argument == "--publish" || argument == "--pid" || argument == "--volumes-from" {
				test.Fatalf("unexpected authority shared with subject: %s", argument)
			}
		}
	}
}

func TestDockerSeccomp(test *testing.T) {
	for _, network := range []string{Offline, LocalServices} {
		encoded, err := dockerSeccomp("linux/amd64", network)
		if err != nil {
			test.Fatal(err)
		}
		var profile dockerSeccompProfile
		if json.Unmarshal(encoded, &profile) != nil || profile.DefaultAction != "SCMP_ACT_ERRNO" {
			test.Fatal("profile is not default deny")
		}
		families := []uint64{}
		for _, rule := range profile.Syscalls {
			for _, forbidden := range []string{"socketcall", "io_uring_setup", "unshare", "setns", "ptrace", "bpf", "mount"} {
				if rule.Action == "SCMP_ACT_ALLOW" && slices.Contains(rule.Names, forbidden) {
					test.Fatalf("seccomp permits bypass syscall %s", forbidden)
				}
			}
			if slices.Contains(rule.Names, "socket") {
				if len(rule.Args) == 0 || rule.Args[0].Index != 0 || rule.Args[0].Op != "SCMP_CMP_EQ" {
					test.Fatal("socket family not constrained")
				}
				if network == LocalServices && (len(rule.Args) != 3 || rule.Args[1] != (dockerSeccompArgument{Index: 1, Value: 15, ValueTwo: 1, Op: "SCMP_CMP_MASKED_EQ"}) || rule.Args[2].Index != 2 || rule.Args[2].Op != "SCMP_CMP_EQ" || (rule.Args[2].Value != 0 && rule.Args[2].Value != 6)) {
					test.Fatal("local sockets must be TCP streams, not UDP, raw, or SCTP")
				}
				families = append(families, rule.Args[0].Value)
			}
			if slices.Contains(rule.Names, "clone") && (len(rule.Args) != 1 || rule.Args[0].Value != 0x7e020000 || rule.Args[0].Op != "SCMP_CMP_MASKED_EQ" || rule.Args[0].ValueTwo != 0) {
				test.Fatal("clone permits namespace creation")
			}
		}
		wanted := []uint64{1}
		if network == LocalServices {
			wanted = []uint64{2, 2, 10, 10}
		}
		if !slices.Equal(families, wanted) {
			test.Fatalf("unexpected socket families: %v", families)
		}
	}
}

func dockerTestStaging(test *testing.T) (Manifest, string, string) {
	test.Helper()
	root := test.TempDir()
	sourceDir, checksDir := filepath.Join(root, "source"), filepath.Join(root, "checks")
	for _, directory := range []string{sourceDir, checksDir} {
		if err := os.Mkdir(directory, 0755); err != nil {
			test.Fatal(err)
		}
	}
	manifest := testManifest()
	content := []byte("#!/bin/sh\nprintf 'accepted\\n'\n")
	if err := os.WriteFile(filepath.Join(checksDir, "run"), content, 0755); err != nil {
		test.Fatal(err)
	}
	manifest.Files = []FrozenFile{{Path: "run", Content: content, Digest: Digest(content), Executable: true}}
	return manifest, sourceDir, checksDir
}

func TestDockerStagedInputs(test *testing.T) {
	manifest, sourceDir, checksDir := dockerTestStaging(test)
	if err := dockerValidateInputs(manifest, sourceDir, checksDir); err != nil {
		test.Fatal(err)
	}
	manifest.Environment.Variables = map[string]string{"AWS_SECRET_ACCESS_KEY": "do-not-forward"}
	if err := dockerValidateInputs(manifest, sourceDir, checksDir); err == nil {
		test.Fatal("credential variable accepted")
	}
	manifest.Environment.Variables = nil
	if err := dockerValidateInputs(manifest, sourceDir, sourceDir); err == nil {
		test.Fatal("overlapping staging directories accepted")
	}
	manifest.Checks[0].Command[0] = "/src/run"
	if err := dockerValidateInputs(manifest, sourceDir, checksDir); err == nil {
		test.Fatal("project executable substituted for frozen check")
	}
	manifest.Checks[0].Command[0] = "/checks/run"
	if err := os.WriteFile(filepath.Join(sourceDir, ".git"), []byte("gitdir: private"), 0600); err != nil {
		test.Fatal(err)
	}
	if err := dockerValidateInputs(manifest, sourceDir, checksDir); err == nil {
		test.Fatal("Git metadata accepted in staged source")
	}
}

func TestDockerFrozenCheckFiles(test *testing.T) {
	for _, scenario := range []string{"executable changed", "data changed", "data missing", "extra file", "extra symlink", "declared symlink", "extra directory"} {
		test.Run(scenario, func(test *testing.T) {
			manifest, sourceDir, checksDir := dockerTestStaging(test)
			content := []byte("frozen input")
			manifest.Files = append(manifest.Files, FrozenFile{Path: "data", Content: content, Digest: Digest(content)})
			if err := os.WriteFile(filepath.Join(checksDir, "data"), content, 0644); err != nil {
				test.Fatal(err)
			}
			if err := dockerValidateInputs(manifest, sourceDir, checksDir); err != nil {
				test.Fatal(err)
			}
			var err error
			switch scenario {
			case "executable changed":
				err = os.WriteFile(filepath.Join(checksDir, "run"), []byte("#!/bin/sh\nexit 0\n"), 0755)
			case "data changed":
				err = os.WriteFile(filepath.Join(checksDir, "data"), []byte("forged input"), 0644)
			case "data missing":
				err = os.Remove(filepath.Join(checksDir, "data"))
			case "extra file":
				err = os.WriteFile(filepath.Join(checksDir, "extra"), []byte("not frozen"), 0644)
			case "extra symlink":
				err = os.Symlink("/etc/passwd", filepath.Join(checksDir, "extra"))
			case "declared symlink":
				if err := os.Remove(filepath.Join(checksDir, "data")); err != nil {
					test.Fatal(err)
				}
				err = os.Symlink("run", filepath.Join(checksDir, "data"))
			case "extra directory":
				err = os.Mkdir(filepath.Join(checksDir, "extra"), 0755)
			}
			if err != nil {
				test.Fatal(err)
			}
			if err := dockerValidateInputs(manifest, sourceDir, checksDir); err == nil {
				test.Fatal("unfrozen staged checks accepted")
			}
		})
	}
}
