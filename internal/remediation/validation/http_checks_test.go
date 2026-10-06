package validation

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

func protectedHTTPChecks(t *testing.T) []pv.Check {
	t.Helper()
	healthy, err := pv.HTTPExpectation(http.StatusOK, "healthy\n")
	require.NoError(t, err)
	failure, err := pv.HTTPExpectation(http.StatusInternalServerError, "broken\n")
	require.NoError(t, err)
	return []pv.Check{
		{ID: "reproduce", Kind: pv.Reproduction, TimeoutSeconds: 5,
			HTTP:    &pv.HTTPCheck{Version: pv.HTTPCheckVersion, ServerCommand: []string{"/checks/check.sh", "serve"}, Path: "/quantity?value=-1"},
			Healthy: healthy, Failure: failure},
		{ID: "normal", Kind: pv.Normal, TimeoutSeconds: 5,
			HTTP:    &pv.HTTPCheck{Version: pv.HTTPCheckVersion, ServerCommand: []string{"/checks/check.sh", "serve"}, Path: "/quantity?value=1"},
			Healthy: healthy, Failure: failure},
	}
}

func protectedHTTPFixture(t *testing.T, action pv.Action) fixture {
	t.Helper()
	f := validationFixture(t, action)
	checks := protectedHTTPChecks(t)
	f.request.Checks, f.staged.Request.Checks, f.record.Manifest.Checks = checks, checks, checks
	f.request.Profile, f.staged.Request.Profile, f.record.Manifest.Environment.Profile = pv.LocalServices, pv.LocalServices, pv.LocalServices
	f.request.Dependencies[policyKey], f.staged.Request.Dependencies[policyKey] = pv.KubernetesPolicyVersion, pv.KubernetesPolicyVersion
	require.NoError(t, pv.ValidateManifest(f.record.Manifest))
	binding, err := pv.NewRunBinding(f.record.Manifest, f.submission.AttemptID, f.submission.OriginalTaskUID, f.submission.PatchedTaskUID)
	require.NoError(t, err)
	f.record.Binding = binding
	f.submission.Manifest, f.submission.Binding, f.submission.RunID = f.record.Manifest, &binding, binding.RunID
	for index := range f.record.Evidence {
		observation := &f.record.Evidence[index].Observation
		for _, check := range checks {
			if check.ID != observation.CheckID {
				continue
			}
			expected := check.Healthy
			if observation.Side == pv.Original && check.Kind == pv.Reproduction {
				expected = check.Failure
			}
			observation.StdoutDigest, observation.StdoutBytes = f.addBlob(expected.Stdout), len(expected.Stdout)
			observation.ExitCode = new(expected.ExitCode)
		}
		observation.RunID, observation.ManifestDigest, observation.HTTPCompleted = binding.RunID, binding.ManifestDigest, true
	}
	f.reseal(t)
	return f
}

func TestValidateProtectedHTTPFieldsRoundTrip(t *testing.T) {
	for _, action := range []pv.Action{pv.ValidateReport, pv.VerifyPatch} {
		t.Run(string(action), func(t *testing.T) {
			f := protectedHTTPFixture(t, action)
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					request, err := pv.DecodeRequestJSON(body)
					require.NoError(t, err)
					require.Equal(t, f.request.Checks, request.Checks)
					require.Equal(t, pv.LocalServices, request.Profile)
					require.Equal(t, pv.KubernetesPolicyVersion, request.Dependencies[policyKey])
					for _, check := range request.Checks {
						require.Empty(t, check.Command)
						require.Empty(t, check.Stdin)
						require.NoError(t, pv.ValidateHTTPCheck(check))
					}
					writeJSON(t, w, http.StatusAccepted, f.submission)
					return
				}
				evidenceHandler(t, &f, w, r)
			}))
			defer server.Close()
			record, err := fakeClient(f, server).Validate(t.Context(), f.request)
			require.NoError(t, err)
			require.Equal(t, f.record, *record)
			require.EqualValues(t, 1, posts.Load())
			expected := pv.Verified
			if action == pv.ValidateReport {
				expected = pv.Reproduced
			}
			require.Equal(t, expected, record.Assessment.Conclusion)
			for _, entry := range record.Evidence {
				require.True(t, entry.Observation.HTTPCompleted)
			}
		})
	}
}

func TestValidateProtectedHTTPCompletionUsesCoreAssessment(t *testing.T) {
	for _, forged := range []bool{false, true} {
		name := "honest-incomplete"
		if forged {
			name = "forged-favorable"
		}
		t.Run(name, func(t *testing.T) {
			f := protectedHTTPFixture(t, pv.VerifyPatch)
			favorable := f.record.Assessment
			f.record.Evidence[0].Observation.HTTPCompleted = false
			f.reseal(t)
			require.Equal(t, pv.UnableToVerify, f.record.Assessment.Conclusion)
			if forged {
				f.record.Assessment, f.record.Seal.Assessment = favorable, favorable
				f.submission.Assessment = &f.record.Assessment
				var seal map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(f.record.Seal.Content, &seal))
				seal["assessment"] = jsonBytes(t, favorable)
				f.record.Seal.Content = jsonBytes(t, seal)
				f.record.Seal.Digest = pv.Digest(f.record.Seal.Content)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					writeJSON(t, w, http.StatusAccepted, f.submission)
					return
				}
				evidenceHandler(t, &f, w, r)
			}))
			defer server.Close()
			record, err := fakeClient(f, server).Validate(t.Context(), f.request)
			if forged {
				require.ErrorContains(t, err, "assessment contradicts the frozen observations")
				require.NotEqual(t, pv.RunFinalized, record.State)
			} else {
				require.NoError(t, err)
				require.Equal(t, pv.RunFinalized, record.State)
				require.False(t, record.Evidence[0].Observation.HTTPCompleted)
			}
			require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
		})
	}
}

func TestValidatePinsProtectedHTTPDeclarationAndPolicy(t *testing.T) {
	for _, mutation := range []string{"version", "server", "path", "command", "stdin", "old-policy"} {
		t.Run(mutation, func(t *testing.T) {
			f := protectedHTTPFixture(t, pv.VerifyPatch)
			first := f.submission
			first.State, first.RecordedChecks, first.Assessment = pv.SubmissionRunning, 0, nil
			var next pv.KubernetesSubmission
			require.NoError(t, json.Unmarshal(jsonBytes(t, f.submission), &next))
			switch mutation {
			case "version":
				next.Manifest.Checks[0].HTTP.Version++
			case "server":
				next.Manifest.Checks[0].HTTP.ServerCommand[1] = "different-server"
			case "path":
				next.Manifest.Checks[0].HTTP.Path = "/other"
			case "command":
				next.Manifest.Checks[0].Command = []string{"/checks/check.sh"}
			case "stdin":
				next.Manifest.Checks[0].Stdin = "untrusted observation"
			case "old-policy":
				next.Manifest.Environment.Dependencies[policyKey] = "kubernetes-v2-process-seccomp"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					writeJSON(t, w, http.StatusAccepted, first)
					return
				}
				require.Equal(t, "/api/v1/validations/vr-fixture", r.URL.Path)
				writeJSON(t, w, http.StatusOK, next)
			}))
			defer server.Close()
			record, err := fakeClient(f, server).Validate(t.Context(), f.request)
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrSubmissionUnknown)
			require.Equal(t, first.RunID, record.Binding.RunID)
			require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
		})
	}
}

func TestStageProtectedHTTPServerPreservesExecutableModeWithoutRunning(t *testing.T) {
	for _, executable := range []bool{true, false} {
		name := "executable"
		if !executable {
			name = "nonexecutable"
		}
		t.Run(name, func(t *testing.T) {
			request, stager := sourceFixture(t, pv.VerifyPatch)
			request.Checks, request.Profile = protectedHTTPChecks(t), pv.LocalServices
			request.Dependencies[policyKey] = pv.KubernetesPolicyVersion
			marker := filepath.Join(filepath.Dir(request.ChecksDir), "server-was-executed")
			mode := os.FileMode(0600)
			if executable {
				mode = 0700
			}
			writeFixture(t, filepath.Join(request.ChecksDir, "check.sh"), "#!/bin/sh\nprintf 'not an observer' > "+marker+"\n", mode)
			calls := 0
			var archive map[string]archivedFile
			stager.Run = func(command *exec.Cmd) error {
				calls++
				if command.Stdin != nil {
					archive = captureArchive(t, command.Stdin)
				}
				return nil
			}
			staged, err := stager.Stage(t.Context(), request)
			if executable {
				require.NoError(t, err)
				require.Equal(t, 2, calls)
				require.Equal(t, request.Checks, staged.Request.Checks)
				require.Equal(t, pv.KubernetesPolicyVersion, staged.Request.Dependencies[policyKey])
				require.EqualValues(t, 0700, archive["checks/check.sh"].mode)
				require.True(t, staged.Files[0].Executable)
			} else {
				require.Error(t, err)
				require.Zero(t, calls)
			}
			_, statErr := os.Stat(marker)
			require.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}
}
