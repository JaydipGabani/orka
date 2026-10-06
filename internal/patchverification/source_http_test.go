package patchverification

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sourceHTTPFixture(test *testing.T, action Action) Request {
	test.Helper()
	request := sourceRequestFixture(test)
	request.Action = action
	request.Profile = LocalServices
	request.Dependencies = map[string]string{"orka.kubernetes.policy": KubernetesPolicyVersion}
	marker := filepath.Join(test.TempDir(), "must-not-execute")
	sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "http-server.sh"), "#!/bin/sh\nprintf unexpected > \"$1\"\n", 0700)
	for index, check := range request.Checks {
		request.Checks[index] = httpCheck(test)
		request.Checks[index].ID, request.Checks[index].Kind = check.ID, check.Kind
		request.Checks[index].HTTP.ServerCommand = []string{"/checks/http-server.sh", marker}
	}
	if action == ValidateReport {
		request.PatchedCommit = ""
		request.Checks = request.Checks[:1]
	} else {
		request.DeclaredChanges = []DeclaredChange{{Kind: "source", Paths: []string{"value.txt"}, Description: "synthetic patch"}}
	}
	return request
}

func TestSourceHTTPCommandAdmission(test *testing.T) {
	for _, action := range []Action{ValidateReport, VerifyPatch} {
		test.Run(string(action), func(test *testing.T) {
			request := sourceHTTPFixture(test, action)
			before, err := json.Marshal(request)
			if err != nil {
				test.Fatal(err)
			}
			prepared := sourceMustPrepare(test, request)
			manifest, err := RequestManifest(request, prepared, Environment{
				Image: request.Image, ImageID: Digest(nil), Platform: request.Platform,
				Profile: request.Profile, Dependencies: request.Dependencies,
			})
			if err != nil {
				test.Fatal(err)
			}
			if err := ValidateManifest(manifest); err != nil {
				test.Fatal(err)
			}
			frozen, err := json.Marshal(manifest)
			if err != nil {
				test.Fatal(err)
			}
			patchedTask := "patched-task"
			if action == ValidateReport {
				patchedTask = ""
			}
			binding, err := NewRunBinding(manifest, "source-http", "original-task", patchedTask)
			if err != nil {
				test.Fatal(err)
			}
			restored, err := RestoreFrozenChecks(test.Context(), manifest)
			if err != nil {
				test.Fatal(err)
			}
			test.Cleanup(func() {
				if err := restored.Close(); err != nil {
					test.Error(err)
				}
			})
			for _, directory := range []string{prepared.ChecksDir, restored.ChecksDir} {
				if err := ValidateFrozenChecks(test.Context(), directory, manifest); err != nil {
					test.Fatal(err)
				}
				info, err := os.Stat(filepath.Join(directory, "http-server.sh"))
				if err != nil || info.Mode().Perm() != 0555 {
					test.Fatal("HTTP server executable was not frozen read-only")
				}
			}
			after, err := json.Marshal(request)
			if err != nil || !bytes.Equal(before, after) {
				test.Fatal("HTTP source admission mutated the request")
			}
			after, err = json.Marshal(manifest)
			if err != nil || !bytes.Equal(frozen, after) {
				test.Fatal("HTTP check validation changed the frozen manifest")
			}
			repeated, err := NewRunBinding(manifest, "source-http", "original-task", patchedTask)
			if err != nil || repeated != binding {
				test.Fatal("HTTP check validation changed the run binding")
			}
			if _, err := os.Stat(request.Checks[0].HTTP.ServerCommand[1]); !errors.Is(err, os.ErrNotExist) {
				test.Fatal("HTTP source admission executed the subject server")
			}
		})
	}
}

func TestSourceHTTPCommandAdmissionRejectsUnsafeInputs(test *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *Request)
	}{
		{"missing server", func(_ *testing.T, request *Request) { request.Checks[0].HTTP.ServerCommand = nil }},
		{"undeclared server", func(_ *testing.T, request *Request) {
			request.Checks[0].HTTP.ServerCommand[0] = "/checks/missing"
		}},
		{"source executable", func(_ *testing.T, request *Request) {
			request.Checks[0].HTTP.ServerCommand[0] = "/src/server"
		}},
		{"image executable", func(_ *testing.T, request *Request) {
			request.Checks[0].HTTP.ServerCommand[0] = "/bin/sh"
		}},
		{"traversal", func(_ *testing.T, request *Request) {
			request.Checks[0].HTTP.ServerCommand[0] = "/checks/../http-server.sh"
		}},
		{"non-executable", func(test *testing.T, request *Request) {
			if err := os.Chmod(filepath.Join(request.ChecksDir, "http-server.sh"), 0600); err != nil {
				test.Fatal(err)
			}
		}},
		{"symlink", func(test *testing.T, request *Request) {
			if err := os.Symlink(filepath.Join(request.ChecksDir, "http-server.sh"), filepath.Join(request.ChecksDir, "link")); err != nil {
				test.Fatal(err)
			}
			request.Checks[0].HTTP.ServerCommand[0] = "/checks/link"
		}},
		{"raw command", func(_ *testing.T, request *Request) { request.Checks[0].Command = []string{"/checks/verify.sh"} }},
		{"stdin", func(_ *testing.T, request *Request) { request.Checks[0].Stdin = "input" }},
		{"lifecycle", func(_ *testing.T, request *Request) { request.Checks[0].Lifecycle = []string{"reconcile"} }},
		{"version", func(_ *testing.T, request *Request) { request.Checks[0].HTTP.Version++ }},
		{"external URL", func(_ *testing.T, request *Request) { request.Checks[0].HTTP.Path = "https://example.invalid/" }},
		{"external authority", func(_ *testing.T, request *Request) { request.Checks[0].HTTP.Path = "//example.invalid/" }},
		{"credential argument", func(_ *testing.T, request *Request) {
			request.Checks[0].HTTP.ServerCommand = append(request.Checks[0].HTTP.ServerCommand, `password="synthetic-fixture-only"`)
		}},
		{"credential helper", func(test *testing.T, request *Request) {
			sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "http-server.sh"), "password=\"synthetic-fixture-only\"\n", 0700)
		}},
	}
	for _, scenario := range cases {
		test.Run(scenario.name, func(test *testing.T) {
			request := sourceHTTPFixture(test, ValidateReport)
			scenario.change(test, &request)
			prepared, err := PrepareSources(test.Context(), request)
			if prepared != nil {
				if closeErr := prepared.Close(); closeErr != nil {
					test.Error("failed to clean up unexpected prepared sources")
				}
				test.Error("unsafe HTTP source inputs were prepared")
			}
			if err == nil || (!errors.Is(err, errSourceChecks) && !errors.Is(err, errSourcePath) && !errors.Is(err, errSourceSecret)) {
				test.Fatal("unsafe HTTP source input did not return a source-admission sentinel")
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-fixture-only") {
				test.Fatal("HTTP source admission exposed rejected input")
			}
		})
	}
}

func TestSourceHTTPRequestTextValidation(test *testing.T) {
	for _, scenario := range []struct {
		name   string
		change func(*HTTPCheck)
	}{
		{"NUL argument", func(check *HTTPCheck) { check.ServerCommand = append(check.ServerCommand, "\x00") }},
		{"invalid UTF8 argument", func(check *HTTPCheck) {
			check.ServerCommand = append(check.ServerCommand, string([]byte{0xff}))
		}},
		{"control character path", func(check *HTTPCheck) { check.Path = "/\x01" }},
		{"aggregate budget", func(check *HTTPCheck) {
			check.ServerCommand = []string{"/checks/http-server.sh"}
			for range 127 {
				check.ServerCommand = append(check.ServerCommand, strings.Repeat("x", 8192))
			}
		}},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			request := sourceHTTPFixture(test, VerifyPatch)
			scenario.change(request.Checks[0].HTTP)
			if scenario.name == "aggregate budget" {
				request.Checks[1].HTTP = request.Checks[0].HTTP
			}
			if err := sourceValidateRequest(request); !errors.Is(err, errSourceChecks) {
				test.Fatal("HTTP fields bypassed pre-serialization request text or size validation")
			}
		})
	}
}

func TestSourceHTTPCommandBounds(test *testing.T) {
	for _, scenario := range []struct {
		name    string
		bytes   int
		count   int
		allowed bool
	}{
		{"argument at limit", 8192, 1, true},
		{"argument above limit", 8193, 1, false},
		{"count at limit", 1, 127, true},
		{"count above limit", 1, 128, false},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			request := sourceHTTPFixture(test, ValidateReport)
			request.Checks[0].HTTP.ServerCommand = request.Checks[0].HTTP.ServerCommand[:1]
			for range scenario.count {
				request.Checks[0].HTTP.ServerCommand = append(request.Checks[0].HTTP.ServerCommand, strings.Repeat("x", scenario.bytes))
			}
			prepared, err := PrepareSources(test.Context(), request)
			if prepared != nil {
				if closeErr := prepared.Close(); closeErr != nil {
					test.Error(closeErr)
				}
			}
			if scenario.allowed {
				if err != nil || prepared == nil {
					test.Fatal("supported HTTP command boundary rejected")
				}
			} else if !errors.Is(err, errSourceChecks) || prepared != nil {
				test.Fatal("oversized HTTP command admitted")
			}
		})
	}
}
