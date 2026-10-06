package local

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

const validRequestJSON = `{"problem":"boundary error","scope":["bounds"],"repository":"repo","originalCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","patchFile":"fix.patch","checksDir":"checks","image":"golang@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"linux/amd64","profile":"offline","checks":[{"id":"boundary","kind":"reproduction","command":["/bin/sh","/checks/test.sh"],"healthy":{"exitCode":0,"stdout":"ok"},"failure":{"exitCode":1,"stdout":"bad"},"timeoutSeconds":10}]}`

func TestDecodeRequest(t *testing.T) {
	requestFile := filepath.Join(t.TempDir(), "request.json")
	request, err := DecodeRequest(strings.NewReader(validRequestJSON), requestFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{request.Repository, request.ChecksDir, request.PatchFile} {
		if !filepath.IsAbs(path) || filepath.Dir(path) != filepath.Dir(requestFile) {
			t.Fatalf("path was not resolved relative to request file: %q", path)
		}
	}
	for name, content := range map[string]string{
		"unknown":          strings.Replace(validRequestJSON, `"problem":`, `"unknown":true,"problem":`, 1),
		"nested unknown":   strings.Replace(validRequestJSON, `"exitCode":0`, `"unknown":0,"exitCode":0`, 1),
		"duplicate":        strings.Replace(validRequestJSON, `"problem":`, `"problem":"ignored","problem":`, 1),
		"nested duplicate": strings.Replace(validRequestJSON, `"exitCode":0`, `"exitCode":1,"exitCode":0`, 1),
		"trailing object":  validRequestJSON + `{}`,
		"trailing junk":    validRequestJSON + `x`,
		"malformed":        `{"problem":`,
		"null":             `null`,
		"array":            `[]`,
		"empty":            `{}`,
		"oversized":        strings.Repeat(" ", MaxRequestBytes+1),
		"invalid UTF8":     validRequestJSON + "\xff",
		"symbolic ref":     strings.Replace(validRequestJSON, strings.Repeat("a", 40), "HEAD", 1),
		"both inputs":      strings.Replace(validRequestJSON, `"patchFile":`, `"patchedCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","patchFile":`, 1),
		"remote source":    strings.Replace(validRequestJSON, `"repository":"repo"`, `"repository":"https://example.invalid/repo"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(strings.NewReader(content), requestFile); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestRequestActions(test *testing.T) {
	request := fixtureRequest()
	request.Action, request.PatchedCommit = pv.ValidateReport, ""
	content, err := json.Marshal(request)
	if err != nil {
		test.Fatal(err)
	}
	decoded, err := DecodeRequest(strings.NewReader(string(content)), "/tmp/request.json")
	if err != nil || decoded.Action != pv.ValidateReport || decoded.PatchedCommit != "" {
		test.Fatalf("report request: %+v, %v", decoded, err)
	}
	linked := `{"action":"verify-patch","earlierValidation":"pv-earlier","patchFile":"fix.patch","declaredChanges":[{"kind":"configuration","paths":["config.json"],"description":"retain the managed setting"}]}`
	decoded, err = DecodeRequest(strings.NewReader(linked), "/tmp/request.json")
	if err != nil || decoded.Repository != "" || decoded.ChecksDir != "" || decoded.PatchFile != "/tmp/fix.patch" {
		test.Fatalf("minimal linked request: %+v, %v", decoded, err)
	}
	for name, invalid := range map[string]string{
		"report patch": strings.Replace(string(content), `"action":"validate-report"`,
			`"action":"validate-report","patchFile":"fix.patch"`, 1),
		"verify declaration": strings.Replace(validRequestJSON, `"problem":`, `"action":"verify-patch","problem":`, 1),
		"foreign identity":   strings.Replace(linked, `"action":`, `"principal":"another-user","action":`, 1),
		"unknown action":     strings.Replace(linked, "verify-patch", "scan", 1),
	} {
		test.Run(name, func(test *testing.T) {
			if _, err := DecodeRequest(strings.NewReader(invalid), "/tmp/request.json"); err == nil {
				test.Fatal("invalid action request accepted")
			}
		})
	}
}

func TestExampleRequests(t *testing.T) {
	script, err := filepath.Abs("../../../examples/patch-verification/demo.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, project := range []string{"go", "c", "http"} {
		for _, variant := range []string{"fixed", "notfixed", "partial", "regression"} {
			for _, mode := range []string{"patch", "commit"} {
				t.Run(project+"/"+variant+"/"+mode, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, "bash", script, project, variant, mode)
					output, err := command.Output()
					if err != nil {
						t.Fatalf("example generation failed: %v", err)
					}
					filename := strings.TrimSpace(string(output))
					root := filepath.Dir(filename)
					if filepath.Dir(root) != "/tmp" || !strings.HasPrefix(filepath.Base(root), "patchverify-demo.") {
						t.Fatal("example did not create an isolated fixture directory")
					}
					t.Cleanup(func() { _ = os.RemoveAll(root) })
					request, err := ReadRequest(filename)
					if err != nil {
						t.Fatal(err)
					}
					if len(request.Checks) != 3 || len(request.Scope) != 3 || request.Repository != filepath.Join(root, "repo") {
						t.Fatal("example request changed its required checks or repository")
					}
					for _, commit := range []string{request.OriginalCommit, request.PatchedCommit} {
						if commit == "" {
							continue
						}
						if err := exec.CommandContext(ctx, "git", "-C", request.Repository, "cat-file", "-e", commit+"^{commit}").Run(); err != nil {
							t.Fatal("request commit does not exist", err)
						}
					}
					for _, check := range request.Checks {
						info, err := os.Stat(filepath.Join(request.ChecksDir, strings.TrimPrefix(check.Command[0], "/checks/")))
						if err != nil || info.Mode().Perm()&0111 == 0 {
							t.Fatal("generated frozen check is not executable", err)
						}
					}
					if (project == "http") != (request.Profile == "local-services" && len(request.Services) == 1) {
						t.Fatal("incorrect HTTP fixture profile")
					}
				})
			}
		}
	}
}
