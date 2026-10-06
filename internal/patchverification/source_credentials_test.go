package patchverification

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sourceCredentialRequest(test *testing.T, content, surface string) Request {
	test.Helper()
	request := sourceRequestFixture(test)
	switch surface {
	case "report archive", "patched archive", "patch":
		sourceFixtureWrite(test, filepath.Join(request.Repository, "main.c"), "int main(void) { return 0; }\n", 0600)
		sourceFixtureWrite(test, filepath.Join(request.Repository, "config.json"), content, 0600)
		sourceFixtureGit(test, request.Repository, nil, "add", ".")
		sourceFixtureGit(test, request.Repository, nil, "commit", "--quiet", "-m", "synthetic screening fixture")
		request.PatchedCommit = strings.TrimSpace(string(sourceFixtureGit(test, request.Repository, nil, "rev-parse", "HEAD")))
		switch surface {
		case "report archive":
			request.Action = ValidateReport
			request.OriginalCommit, request.PatchedCommit = request.PatchedCommit, ""
			request.Checks = request.Checks[:1]
		case "patch":
			patch := sourceFixtureGit(test, request.Repository, nil, "diff", "--no-ext-diff", "--no-textconv", "--binary", request.OriginalCommit, request.PatchedCommit, "--")
			request.PatchedCommit = ""
			request.PatchFile = filepath.Join(test.TempDir(), "change.patch")
			sourceFixtureWrite(test, request.PatchFile, string(patch), 0600)
		}
	case "checks":
		sourceFixtureWrite(test, filepath.Join(request.ChecksDir, "config.json"), content, 0600)
	case "request":
		request.Checks[0].Stdin = content
	default:
		test.Fatal("unknown screening surface")
	}
	return request
}

func TestPrepareSourcesBenignCredentialSyntax(test *testing.T) {
	cases := []struct {
		name, content string
	}{
		{"schema", `{"password":{"type":"string"}}`},
		{"empty", `{"password":"","client_secret":""}`},
		{"environment lookup", `password := os.Getenv("PASSWORD")`},
		{"environment placeholder", `password="${PASSWORD}"`},
		{"identifiers", "type Credentials struct { Password string }\nfunc read(password string) {}\n"},
	}
	for _, scenario := range cases {
		for _, surface := range []string{"report archive", "patched archive", "patch", "checks", "request"} {
			test.Run(scenario.name+"/"+surface, func(test *testing.T) {
				request := sourceCredentialRequest(test, scenario.content, surface)
				prepared := sourceMustPrepare(test, request)
				manifest, err := RequestManifest(request, prepared, Environment{
					Image: request.Image, ImageID: Digest(nil), Platform: request.Platform, Profile: request.Profile,
				})
				if err != nil {
					test.Fatal(err)
				}
				directory := prepared.PatchedDir
				switch surface {
				case "request":
					if manifest.Checks[0].Stdin != scenario.content {
						test.Fatal("screening changed the frozen request")
					}
					return
				case "report archive":
					directory = prepared.OriginalDir
				case "checks":
					restored, err := RestoreFrozenChecks(test.Context(), manifest)
					if err != nil {
						test.Fatal(err)
					}
					test.Cleanup(func() {
						if err := restored.Close(); err != nil {
							test.Error(err)
						}
					})
					if err := ValidateFrozenChecks(test.Context(), restored.ChecksDir, manifest); err != nil {
						test.Fatal(err)
					}
					directory = restored.ChecksDir
				}
				content, err := os.ReadFile(filepath.Join(directory, "config.json"))
				if err != nil || !bytes.Equal(content, []byte(scenario.content)) {
					test.Fatal("screening changed the staged source or check bytes")
				}
			})
		}
	}
}

func TestPrepareSourcesRejectsEmbeddedCredentials(test *testing.T) {
	cases := []struct {
		name, content string
	}{
		{"literal", `password = "synthetic-fixture-only"`},
		{"short literal", `password = "x"`},
		{"environment fallback", `password="${PASSWORD:-synthetic-fixture-only}"`},
		{"authorization", "Authorization: Bearer synthetic-fixture-only"},
		{"private key", "-----BEGIN " + "PRIVATE KEY-----\nsynthetic-fixture-only\n"},
		{"token", "gh" + "p_" + strings.Repeat("a", 20)},
		{"literal after schema", "{\"password\":{\"type\":\"string\"}}\npassword = \"synthetic-fixture-only\""},
		{"schema default", `{"password":{"type":"string","default":"synthetic-fixture-only"}}`},
		{"schema enum", `{"password":{"type":"string","enum":["synthetic-fixture-only"]}}`},
	}
	for _, scenario := range cases {
		for _, surface := range []string{"report archive", "patched archive", "patch", "checks", "request"} {
			test.Run(scenario.name+"/"+surface, func(test *testing.T) {
				request := sourceCredentialRequest(test, scenario.content, surface)
				prepared, err := PrepareSources(context.Background(), request)
				if prepared != nil {
					if closeErr := prepared.Close(); closeErr != nil {
						test.Error("failed to clean up unexpected prepared sources")
					}
					test.Error("credential-bearing sources were prepared")
				}
				if !errors.Is(err, errSourceSecret) || err.Error() != errSourceSecret.Error() {
					test.Fatal("credential screening did not return its redacted sentinel")
				}
			})
		}
	}
}
