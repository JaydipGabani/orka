package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/orka-agents/orka/internal/remediation/icm"
	"github.com/orka-agents/orka/internal/remediation/intake"
	remediationservice "github.com/orka-agents/orka/internal/remediation/service"
	"github.com/orka-agents/orka/internal/store"
)

func remoteRemediationFixtureStatus() remediationservice.Status {
	return remediationservice.Status{
		ID: "rm-" + strings.Repeat("1", 32), Namespace: "tenant-a", RequestID: "request-current",
		Mode: remediationservice.Generate, Policy: "approved", Phase: store.RemediationPhaseQueued, Revision: 1,
	}
}

func remoteRemediationCommand(t *testing.T, server string, arguments ...string) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	return remoteRemediationCommandWithCapture(t, server, remediationFixtureCaptureHooks(t), arguments...)
}

func remoteRemediationCommandWithCapture(t *testing.T, server string, hooks remediationCaptureHooks, arguments ...string) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	command := newRootCmd()
	remediate, _, err := command.Find([]string{"remediate"})
	require.NoError(t, err)
	start, _, err := remediate.Find([]string{"start"})
	require.NoError(t, err)
	remediate.RemoveCommand(start)
	remediate.AddCommand(newRemediationStartCmdWithCapture(hooks))
	output, diagnostics := &bytes.Buffer{}, &bytes.Buffer{}
	command.SetOut(output)
	command.SetErr(diagnostics)
	command.SetArgs(append([]string{
		"--server", server, "--namespace", "tenant-a", "--token", "synthetic-caller", "remediate",
	}, arguments...))
	return command, output, diagnostics
}

func remediationFixtureCaptureHooks(t *testing.T) remediationCaptureHooks {
	t.Helper()
	// Tests keep all fixtures inside the configured test scratch directory.
	// The production resolver's outside-checkout rule is tested separately.
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0o700))
	return remediationCaptureHooks{
		cacheRoot: func() (string, error) { return root, nil },
		capture: func(_ context.Context, _ icm.Exporter, incident, directory string) (icm.Receipt, error) {
			return writeRemediationCaptureFixture(t, incident, directory, nil), nil
		},
	}
}

func writeRemediationCaptureFixture(t *testing.T, incident, directory string, input []byte) icm.Receipt {
	t.Helper()
	var intent remediationCaptureIntent
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(directory), "intent.json"))
	require.NoError(t, err, "request ID must be persisted before acquisition")
	require.NoError(t, json.Unmarshal(raw, &intent))
	require.Equal(t, incident, intent.IncidentID)
	require.Equal(t, filepath.Base(filepath.Dir(directory)), intent.RequestID)
	require.NoError(t, os.Mkdir(directory, 0o700))
	details := []byte(fmt.Sprintf(`{"id":%s,"title":"Synthetic captured report","summary":"private-acquisition-marker","isRestricted":false,"lastModifiedDate":"2026-09-01T00:00:00Z"}`, incident))
	discussion := []byte(fmt.Sprintf(`{"incidentId":%s,"aggregatedDiagnosticResults":{"Data":[],"HasMoreData":false,"TotalCount":0}}`, incident))
	if input == nil {
		input = []byte(`{"details":` + string(details) + `,"discussion":` + string(discussion) + `}`)
	}
	receipt := icm.Receipt{
		Version: 1, IncidentID: incident, State: "complete",
		StartedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), FinishedAt: time.Date(2026, 9, 1, 0, 0, 1, 0, time.UTC),
		Artifacts: make(map[string]icm.Artifact),
	}
	files := map[string][]byte{
		"tools.json": []byte(`{"tools":[]}`), "details.json": details, "details-after.json": details,
		"discussion-0001.json": discussion, "input.json": input,
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), content, 0o600))
		receipt.Artifacts[name] = icm.Artifact{Digest: remediationservice.Digest(content), Bytes: len(content)}
	}
	raw, err = json.Marshal(receipt)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "receipt.json"), raw, 0o600))
	return receipt
}

type remediationTestWriter func([]byte) (int, error)

func (write remediationTestWriter) Write(raw []byte) (int, error) { return write(raw) }

func TestRemediationRemoteStartSingleSubmit(t *testing.T) {
	for _, mode := range []remediationservice.Mode{remediationservice.Generate, remediationservice.Validate, remediationservice.Verify} {
		t.Run(string(mode), func(t *testing.T) {
			var received remediationservice.Request
			var calls atomic.Int32
			var receiptWritten atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.True(t, receiptWritten.Load(), "request ID must be printed before the POST")
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "/api/v1/remediations", r.URL.Path)
				require.Equal(t, "tenant-a", r.URL.Query().Get("namespace"))
				require.Equal(t, "Bearer synthetic-caller", r.Header.Get("Authorization"))
				require.Equal(t, "synthetic-transaction", r.Header.Get("Txn-Token"))
				raw, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				received, err = remediationservice.DecodeRequest(raw)
				require.NoError(t, err)
				status := remoteRemediationFixtureStatus()
				status.RequestID, status.Mode = received.RequestID, received.Mode
				w.WriteHeader(http.StatusAccepted)
				require.NoError(t, json.NewEncoder(w).Encode(status))
			}))
			defer server.Close()
			arguments := []string{"start", "--incident", "123456", "--mode", string(mode), "--policy", "approved", "--txn-token", "synthetic-transaction"}
			if mode == remediationservice.Verify {
				patch := filepath.Join(t.TempDir(), "candidate.patch")
				require.NoError(t, os.WriteFile(patch, []byte("synthetic patch bytes"), 0o600))
				arguments = append(arguments, "--patch", patch)
			}
			command, output, diagnostics := remoteRemediationCommand(t, server.URL, arguments...)
			command.SetErr(remediationTestWriter(func(raw []byte) (int, error) {
				count, err := diagnostics.Write(raw)
				receiptWritten.Store(true)
				return count, err
			}))
			require.NoError(t, command.ExecuteContext(t.Context()))
			require.Equal(t, int32(1), calls.Load())
			require.Equal(t, mode, received.Mode)
			require.Equal(t, "approved", received.Policy)
			require.Empty(t, received.Incident)
			report, err := intake.Parse(received.Report)
			require.NoError(t, err)
			require.Equal(t, "123456", report.SourceID)
			require.Equal(t, "icm-export-bundle", report.SourceKind)
			require.True(t, remediationRemoteID(received.RequestID))
			require.Contains(t, diagnostics.String(), "requestID="+received.RequestID)
			require.NotContains(t, diagnostics.String(), "synthetic-caller")
			require.NotContains(t, diagnostics.String(), "synthetic-transaction")
			require.NotContains(t, output.String()+diagnostics.String(), "private-acquisition-marker")
			var status remediationservice.Status
			require.NoError(t, json.Unmarshal(output.Bytes(), &status))
			require.Equal(t, store.RemediationPhaseQueued, status.Phase)
			require.Equal(t, received.RequestID, status.RequestID)
		})
	}
}

func TestRemediationRemoteRetryUsesCallerRequestID(t *testing.T) {
	var calls atomic.Int32
	var captures atomic.Int32
	hooks := remediationFixtureCaptureHooks(t)
	original := hooks.capture
	hooks.capture = func(ctx context.Context, exporter icm.Exporter, incident, directory string) (icm.Receipt, error) {
		captures.Add(1)
		return original(ctx, exporter, incident, directory)
	}
	var submissions [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		submissions = append(submissions, raw)
		if calls.Load() == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "private server detail")
			return
		}
		w.WriteHeader(http.StatusAccepted)
		require.NoError(t, json.NewEncoder(w).Encode(remoteRemediationFixtureStatus()))
	}))
	defer server.Close()
	arguments := []string{"start", "--incident", "123456", "--request-id", "request-current"}
	first, _, diagnostics := remoteRemediationCommandWithCapture(t, server.URL, hooks, arguments...)
	err := first.ExecuteContext(t.Context())
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private server detail")
	require.Equal(t, int32(1), calls.Load(), "POST must not be retried automatically")
	require.Contains(t, diagnostics.String(), "requestID=request-current")
	retry, _, _ := remoteRemediationCommandWithCapture(t, server.URL, hooks, arguments...)
	require.NoError(t, retry.ExecuteContext(t.Context()))
	require.Equal(t, int32(2), calls.Load())
	require.Equal(t, submissions[0], submissions[1])
	require.Equal(t, int32(1), captures.Load(), "an identical retry must reuse its immutable incident capture")
}

func TestRemediationRemotePrivateInputAndTokenFile(t *testing.T) {
	root := t.TempDir()
	report := `{"title":"Synthetic report","problem":"synthetic report body","restricted":false}`
	input, token := filepath.Join(root, "report.json"), filepath.Join(root, "credential")
	require.NoError(t, os.WriteFile(input, []byte(report), 0o600))
	require.NoError(t, os.WriteFile(token, []byte("synthetic-file-credential\n"), 0o600))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer synthetic-file-credential", r.Header.Get("Authorization"))
		var request remediationservice.Request
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.JSONEq(t, report, string(request.Report))
		require.Empty(t, request.Incident)
		status := remoteRemediationFixtureStatus()
		status.RequestID = request.RequestID
		w.WriteHeader(http.StatusAccepted)
		require.NoError(t, json.NewEncoder(w).Encode(status))
	}))
	defer server.Close()
	command, output, diagnostics := remoteRemediationCommand(t, server.URL, "start", "--input", input, "--token-file", token)
	require.NoError(t, command.ExecuteContext(t.Context()))
	require.NotContains(t, output.String()+diagnostics.String(), "synthetic report body")
	require.NotContains(t, output.String()+diagnostics.String(), "synthetic-file-credential")

	require.NoError(t, os.Chmod(token, 0o644))
	command, _, _ = remoteRemediationCommand(t, server.URL, "start", "--input", input, "--token-file", token)
	require.ErrorContains(t, command.ExecuteContext(t.Context()), "authentication file")
	require.NoError(t, os.Chmod(input, 0o644))
	command, _, _ = remoteRemediationCommand(t, server.URL, "start", "--input", input)
	require.Error(t, command.ExecuteContext(t.Context()))
	link := filepath.Join(root, "linked-report")
	require.NoError(t, os.Symlink(input, link))
	command, _, _ = remoteRemediationCommand(t, server.URL, "start", "--input", link)
	require.Error(t, command.ExecuteContext(t.Context()))
}

func TestRemediationRemoteInputValidation(t *testing.T) {
	root := t.TempDir()
	invalid := filepath.Join(root, "invalid.json")
	require.NoError(t, os.WriteFile(invalid, []byte(`{"private-sentinel":`), 0o600))
	oversized := filepath.Join(root, "large.json")
	require.NoError(t, os.WriteFile(oversized, bytes.Repeat([]byte(" "), remediationservice.MaxRequestBytes+1), 0o600))
	binaryPatch := filepath.Join(root, "binary.patch")
	require.NoError(t, os.WriteFile(binaryPatch, []byte{0xff, 0xfe}, 0o600))
	for _, args := range [][]string{
		{"start"},
		{"start", "--incident", "123456", "--input", invalid},
		{"start", "--input", invalid},
		{"start", "--input", oversized},
		{"start", "--incident", "123456", "--mode", "unsafe-mode"},
		{"start", "--incident", "123456", "--icm-auth", "interactive-login"},
		{"start", "--incident", "123456", "--mode", "verify"},
		{"start", "--incident", "123456", "--mode", "verify", "--patch", binaryPatch},
		{"start", "--incident", "123456", "--policy", "../../private-sentinel"},
		{"start", "--incident", "123456", "--request-id", "private-sentinel/escape"},
	} {
		command, output, diagnostics := remoteRemediationCommand(t, "http://127.0.0.1:1", args...)
		err := command.ExecuteContext(t.Context())
		require.Error(t, err)
		require.NotContains(t, err.Error()+output.String()+diagnostics.String(), "private-sentinel")
		require.Empty(t, diagnostics.String(), "invalid input must fail before issuing a request ID")
	}
	start := newRemediationStartCmd()
	for _, name := range []string{"agent", "model", "driver", "profile", "source", "work-dir", "state-dir", "checks", "tool-image"} {
		require.Nil(t, start.Flags().Lookup(name))
	}
}

func TestRemediationRemoteStatusRetryAndBounds(t *testing.T) {
	for _, scenario := range []string{"recover", "exhaust", "denied", "oversized", "trailing", "wrong-namespace", "wrong-id"} {
		t.Run(scenario, func(t *testing.T) {
			var calls atomic.Int32
			status := remoteRemediationFixtureStatus()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count := calls.Add(1)
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/api/v1/remediations/"+status.ID, r.URL.Path)
				switch scenario {
				case "recover":
					if count < 3 {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
				case "exhaust":
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				case "denied":
					w.WriteHeader(http.StatusForbidden)
					_, _ = io.WriteString(w, "private-sentinel")
					return
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat(" ", remediationStatusLimit+1))
					return
				}
				response := status
				if scenario == "wrong-namespace" {
					response.Namespace = "other"
				}
				if scenario == "wrong-id" {
					response.ID = "another-run"
				}
				require.NoError(t, json.NewEncoder(w).Encode(response))
				if scenario == "trailing" {
					_, _ = io.WriteString(w, `{"private-sentinel":1}`)
				}
			}))
			defer server.Close()
			command, output, diagnostics := remoteRemediationCommand(t, server.URL, "status", status.ID)
			err := command.ExecuteContext(t.Context())
			wantCalls := int32(1)
			if scenario == "recover" || scenario == "exhaust" {
				wantCalls = 3
			}
			if scenario == "recover" {
				require.NoError(t, err)
				require.Contains(t, output.String(), status.ID)
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "private-sentinel")
			}
			require.Equal(t, wantCalls, calls.Load())
			require.NotContains(t, output.String()+diagnostics.String(), "private-sentinel")
		})
	}
}

func TestRemediationRemoteUnavailableAndRedirectNeverEchoCredentials(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	address := server.URL
	server.Close()
	command, output, diagnostics := remoteRemediationCommand(t, address, "status", remoteRemediationFixtureStatus().ID, "--txn-token", "synthetic-private-transaction")
	err := command.ExecuteContext(t.Context())
	require.Error(t, err)
	text := err.Error() + output.String() + diagnostics.String()
	require.NotContains(t, text, "synthetic-caller")
	require.NotContains(t, text, "synthetic-private-transaction")
	require.NotContains(t, text, address)

	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	command, _, _ = remoteRemediationCommand(t, redirect.URL, "status", remoteRemediationFixtureStatus().ID)
	require.Error(t, command.ExecuteContext(t.Context()))
	require.Zero(t, leaked.Load())
}

func TestRemediationRemoteApprovalAndCancellation(t *testing.T) {
	status := remoteRemediationFixtureStatus()
	digest := strings.Repeat("a", 64)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "tenant-a", r.URL.Query().Get("namespace"))
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		if strings.HasSuffix(r.URL.Path, "/approve") {
			require.JSONEq(t, `{"planDigest":"sha256:`+digest+`"}`, string(raw))
		} else {
			require.Equal(t, "/api/v1/remediations/"+status.ID+"/cancel", r.URL.Path)
			require.Empty(t, raw)
		}
		w.WriteHeader(http.StatusAccepted)
		require.NoError(t, json.NewEncoder(w).Encode(status))
	}))
	defer server.Close()
	command, _, _ := remoteRemediationCommand(t, server.URL, "approve", status.ID, "--plan-digest", digest)
	require.NoError(t, command.ExecuteContext(t.Context()))
	command, _, _ = remoteRemediationCommand(t, server.URL, "cancel", status.ID)
	require.NoError(t, command.ExecuteContext(t.Context()))
	require.Equal(t, int32(2), calls.Load())
	command, _, _ = remoteRemediationCommand(t, server.URL, "approve", status.ID)
	require.Error(t, command.ExecuteContext(t.Context()))
	require.Equal(t, int32(2), calls.Load())
}

func TestRemediationRemoteWaitPausedOrInterrupted(t *testing.T) {
	for _, phase := range []string{
		store.RemediationPhaseNeedsApproval, store.RemediationPhaseNeedsInput, store.RemediationPhaseNeedsAdapter,
		store.RemediationPhaseFailed, store.RemediationPhaseCancelled, store.RemediationPhaseTimedOut,
		store.RemediationPhaseSucceeded, store.RemediationPhaseQueued,
	} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "/api/v1/remediations", r.URL.Path)
				status := remoteRemediationFixtureStatus()
				status.Phase = phase
				w.WriteHeader(http.StatusAccepted)
				require.NoError(t, json.NewEncoder(w).Encode(status))
			}))
			defer server.Close()
			command, output, _ := remoteRemediationCommand(t, server.URL, "start", "--incident", "123456", "--request-id", "request-current", "--wait")
			if phase == store.RemediationPhaseQueued {
				command.SetOut(remediationTestWriter(func(raw []byte) (int, error) {
					count, err := output.Write(raw)
					cancel()
					return count, err
				}))
			}
			err := command.ExecuteContext(ctx)
			if phase == store.RemediationPhaseSucceeded {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				if phase == store.RemediationPhaseQueued {
					require.Contains(t, err.Error(), "not cancelled")
				}
			}
			require.Equal(t, int32(1), calls.Load(), "waiting or interruption must not resubmit or cancel")
			require.Contains(t, output.String(), phase)
		})
	}
}

func remediationArtifactFixture(name, mediaType string, content []byte) store.RemediationArtifact {
	return store.RemediationArtifact{
		Name: name, MediaType: mediaType, Size: int64(len(content)), Digest: remediationservice.Digest(content),
	}
}

func TestRemediationRemoteDownloadPrivateVerifiedFiles(t *testing.T) {
	patch, evidence := []byte("synthetic patch bytes\n"), []byte(`{"conclusion":"synthetic"}`)
	status := remoteRemediationFixtureStatus()
	status.Phase = store.RemediationPhaseSucceeded
	status.Artifacts = []store.RemediationArtifact{
		remediationArtifactFixture("patch.diff", "text/x-diff", patch),
		remediationArtifactFixture("evidence.json", "application/json", evidence),
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "tenant-a", r.URL.Query().Get("namespace"))
		require.Equal(t, "Bearer synthetic-caller", r.Header.Get("Authorization"))
		if r.URL.Path == "/api/v1/remediations/"+status.ID {
			require.NoError(t, json.NewEncoder(w).Encode(status))
			return
		}
		var raw []byte
		switch r.URL.Path {
		case "/api/v1/remediations/" + status.ID + "/artifacts/patch.diff":
			raw = patch
		case "/api/v1/remediations/" + status.ID + "/artifacts/evidence.json":
			raw = evidence
		default:
			t.Error("unlisted artifact was requested")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		digest := sha256.Sum256(raw)
		w.Header().Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(digest[:]))
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	directory := filepath.Join(t.TempDir(), "download")
	command, output, _ := remoteRemediationCommand(t, server.URL, "download", status.ID, "--output-dir", directory)
	require.NoError(t, command.ExecuteContext(t.Context()))
	require.Equal(t, int32(3), requests.Load())
	info, err := os.Stat(directory)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	for name, want := range map[string][]byte{"patch.diff": patch, "evidence.json": evidence} {
		filename := filepath.Join(directory, name)
		raw, err := os.ReadFile(filename)
		require.NoError(t, err)
		require.Equal(t, want, raw)
		info, err := os.Stat(filename)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	require.NotContains(t, output.String(), string(patch))
	command, _, _ = remoteRemediationCommand(t, server.URL, "download", status.ID, "--output-dir", directory)
	require.ErrorContains(t, command.ExecuteContext(t.Context()), "already exists")
	raw, err := os.ReadFile(filepath.Join(directory, "patch.diff"))
	require.NoError(t, err)
	require.Equal(t, patch, raw)
}

func TestRemediationRemoteDownloadRejectsCorruptionBeforeWriting(t *testing.T) {
	for _, scenario := range []string{"tampered", "missing-bytes", "missing-digest-header", "wrong-size", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			content := []byte(`{"evidence":"synthetic"}`)
			status := remoteRemediationFixtureStatus()
			status.Phase = store.RemediationPhaseFailed
			status.Artifacts = []store.RemediationArtifact{remediationArtifactFixture("evidence.json", "application/json", content)}
			if scenario == "wrong-size" {
				status.Artifacts[0].Size++
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/remediations/"+status.ID {
					require.NoError(t, json.NewEncoder(w).Encode(status))
					return
				}
				digest := sha256.Sum256(content)
				if scenario != "missing-digest-header" {
					w.Header().Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(digest[:]))
				}
				switch scenario {
				case "tampered":
					_, _ = io.WriteString(w, "wrong bytes")
				case "missing-bytes":
					return
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat("x", store.RemediationMaxArtifactBytes+1))
				default:
					_, _ = w.Write(content)
				}
			}))
			defer server.Close()
			directory := filepath.Join(t.TempDir(), "download")
			command, output, _ := remoteRemediationCommand(t, server.URL, "download", status.ID, "--output-dir", directory)
			require.Error(t, command.ExecuteContext(t.Context()))
			_, err := os.Lstat(directory)
			require.True(t, errors.Is(err, os.ErrNotExist))
			require.Empty(t, output.String())
		})
	}
}

func TestRemediationRemoteDownloadRejectsUnsafeMetadata(t *testing.T) {
	for _, name := range []string{"../escape.json", "/escape.json", "a/b.json", `a\b.json`, "a%2fb.json", "bad\n.json", "evil.sh", ".hidden.json", strings.Repeat("a", 256) + ".json"} {
		t.Run(name, func(t *testing.T) {
			status := remoteRemediationFixtureStatus()
			status.Phase = store.RemediationPhaseFailed
			status.Artifacts = []store.RemediationArtifact{remediationArtifactFixture(name, "application/json", []byte("{}"))}
			_, err := downloadableRemediationArtifacts(status)
			require.Error(t, err)
		})
	}
	status := remoteRemediationFixtureStatus()
	status.Phase = store.RemediationPhaseFailed
	status.Artifacts = []store.RemediationArtifact{
		remediationArtifactFixture("Evidence.json", "application/json", []byte("{}")),
		remediationArtifactFixture("evidence.json", "application/json", []byte("{}")),
	}
	_, err := downloadableRemediationArtifacts(status)
	require.Error(t, err)
	status.Artifacts = []store.RemediationArtifact{remediationArtifactFixture("evidence.json", "text/html", []byte("{}"))}
	_, err = downloadableRemediationArtifacts(status)
	require.Error(t, err)
}

func TestRemediationRemoteDownloadFailureEvidenceIsNotVerifiedPatch(t *testing.T) {
	content := []byte(`{"conclusion":"failed"}`)
	status := remoteRemediationFixtureStatus()
	status.Phase = store.RemediationPhaseFailed
	status.Artifacts = []store.RemediationArtifact{
		remediationArtifactFixture("candidate.patch", "text/x-patch", []byte("unverified candidate")),
		remediationArtifactFixture("evidence.json", "application/json", content),
		remediationArtifactFixture("verification-0123456789abcd.json", "application/json", []byte(`{"conclusion":"Verified for these checks"}`)),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/remediations/"+status.ID {
			require.NoError(t, json.NewEncoder(w).Encode(status))
			return
		}
		require.Equal(t, "/api/v1/remediations/"+status.ID+"/artifacts/evidence.json", r.URL.Path)
		digest := sha256.Sum256(content)
		w.Header().Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(digest[:]))
		_, _ = w.Write(content)
	}))
	defer server.Close()
	directory := filepath.Join(t.TempDir(), "download")
	command, output, _ := remoteRemediationCommand(t, server.URL, "download", status.ID, "--output-dir", directory)
	require.NoError(t, command.ExecuteContext(t.Context()))
	_, err := os.Lstat(filepath.Join(directory, "candidate.patch"))
	require.True(t, errors.Is(err, os.ErrNotExist))
	_, err = os.Lstat(filepath.Join(directory, "verification-0123456789abcd.json"))
	require.ErrorIs(t, err, os.ErrNotExist)
	var receipt remediationservice.Status
	require.NoError(t, json.Unmarshal(output.Bytes(), &receipt))
	require.Equal(t, store.RemediationPhaseFailed, receipt.Phase)
	require.Len(t, receipt.Artifacts, 1)

	status.Phase = store.RemediationPhaseSucceeded
	status.Artifacts = status.Artifacts[1:]
	_, err = downloadableRemediationArtifacts(status)
	require.ErrorContains(t, err, "no verified patch")
	status.Mode = remediationservice.Validate
	_, err = downloadableRemediationArtifacts(status)
	require.NoError(t, err)
}

func TestRemediationRemoteStatusHidesOldServerFinalClaims(t *testing.T) {
	status := remoteRemediationFixtureStatus()
	status.Phase = store.RemediationPhaseNeedsInput
	status.Artifacts = []store.RemediationArtifact{
		remediationArtifactFixture("candidate.patch", "text/x-diff", []byte("staged patch")),
		remediationArtifactFixture("verification-0123456789abcd.json", "application/json", []byte(`{"conclusion":"Verified for these checks"}`)),
		remediationArtifactFixture("candidate-0-failure.json", "application/json", []byte(`{"code":"candidate-build-failed"}`)),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(status))
	}))
	defer server.Close()
	command, output, _ := remoteRemediationCommand(t, server.URL, "status", status.ID)
	require.NoError(t, command.ExecuteContext(t.Context()))
	var observed remediationservice.Status
	require.NoError(t, json.Unmarshal(output.Bytes(), &observed))
	require.Equal(t, status.Phase, observed.Phase)
	require.Len(t, observed.Artifacts, 1)
	require.Equal(t, "candidate-0-failure.json", observed.Artifacts[0].Name)
}

func TestRemediationRemoteDownloadRejectsSymlinkParent(t *testing.T) {
	parent := t.TempDir()
	target, linked := filepath.Join(parent, "target"), filepath.Join(parent, "linked")
	require.NoError(t, os.Mkdir(target, 0o700))
	require.NoError(t, os.Symlink(target, linked))
	content := []byte("{}")
	artifacts := []store.RemediationArtifact{remediationArtifactFixture("evidence.json", "application/json", content)}
	err := writeRemediationArtifacts(filepath.Join(linked, "download"), artifacts, [][]byte{content})
	require.ErrorContains(t, err, "symlink")
	_, err = os.Lstat(filepath.Join(target, "download"))
	require.True(t, errors.Is(err, os.ErrNotExist))
}

func TestRemediationRemoteStatusPreservesLocalStatus(t *testing.T) {
	root := t.TempDir()
	input, state := filepath.Join(root, "report.json"), filepath.Join(root, "state")
	require.NoError(t, os.WriteFile(input, []byte(`{"title":"Synthetic","problem":"synthetic failure","restricted":false}`), 0o600))
	ingest := newRemediationIngestCmd()
	ingest.SetOut(io.Discard)
	ingest.SetErr(io.Discard)
	ingest.SetArgs([]string{"--input", input, "--state-dir", state})
	require.NoError(t, ingest.ExecuteContext(t.Context()))
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	command, output, _ := remoteRemediationCommand(t, server.URL, "status", "--state-dir", state)
	require.NoError(t, command.ExecuteContext(t.Context()))
	require.True(t, json.Valid(output.Bytes()))
	require.Zero(t, calls.Load())
	command, _, _ = remoteRemediationCommand(t, server.URL, "status", "run-id", "--state-dir", state)
	require.Error(t, command.ExecuteContext(t.Context()))
	require.Zero(t, calls.Load())
}

func TestRemediationRemoteIncidentCapturePrecedesPost(t *testing.T) {
	hooks := remediationFixtureCaptureHooks(t)
	cache, err := hooks.cacheRoot()
	require.NoError(t, err)
	var printed, captured atomic.Bool
	original := hooks.capture
	hooks.capture = func(ctx context.Context, exporter icm.Exporter, incident, directory string) (icm.Receipt, error) {
		require.True(t, printed.Load(), "request ID must be printed before contacting IcM")
		require.Equal(t, "123456", incident)
		require.Equal(t, "trusted-icm-command", exporter.Binary)
		require.Equal(t, "env", exporter.Auth)
		receipt, err := original(ctx, exporter, incident, directory)
		captured.Store(true)
		return receipt, err
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.True(t, captured.Load(), "submission must follow complete local acquisition")
		var request remediationservice.Request
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.Empty(t, request.Incident)
		require.NotEmpty(t, request.Report)
		report, err := intake.Parse(request.Report)
		require.NoError(t, err)
		require.Equal(t, "123456", report.SourceID)
		status := remoteRemediationFixtureStatus()
		status.RequestID = request.RequestID
		w.WriteHeader(http.StatusAccepted)
		require.NoError(t, json.NewEncoder(w).Encode(status))
	}))
	defer server.Close()
	command, output, diagnostics := remoteRemediationCommandWithCapture(t, server.URL, hooks,
		"start", "--incident", "https://portal.microsofticm.com/imp/v5/incidents/details/123456/summary",
		"--request-id", "capture-request", "--icm-cli", "trusted-icm-command", "--icm-auth", "env")
	command.SetErr(remediationTestWriter(func(raw []byte) (int, error) {
		count, err := diagnostics.Write(raw)
		printed.Store(true)
		return count, err
	}))
	require.NoError(t, command.ExecuteContext(t.Context()))
	require.NotContains(t, output.String()+diagnostics.String(), "private-acquisition-marker")
	for _, name := range []string{"intent.json", "capture.json", "export/input.json", "export/receipt.json"} {
		info, err := os.Lstat(filepath.Join(cache, "capture-request", name))
		require.NoError(t, err)
		require.True(t, info.Mode().IsRegular())
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	for _, name := range []string{"capture-request", "capture-request/export"} {
		info, err := os.Lstat(filepath.Join(cache, name))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	}
}

func TestRemediationRemoteIncidentCaptureFailureIsRetained(t *testing.T) {
	hooks := remediationFixtureCaptureHooks(t)
	cache, err := hooks.cacheRoot()
	require.NoError(t, err)
	var captures, posts atomic.Int32
	hooks.capture = func(_ context.Context, _ icm.Exporter, incident, directory string) (icm.Receipt, error) {
		captures.Add(1)
		require.NoError(t, os.Mkdir(directory, 0o700))
		receipt := icm.Receipt{
			Version: 1, IncidentID: incident, State: "incomplete",
			StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
		}
		raw, err := json.Marshal(receipt)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(directory, "receipt.json"), raw, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(directory, "partial.json"), []byte("private-capture-failure-marker"), 0o600))
		return receipt, errors.New("private-capture-failure-marker")
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { posts.Add(1) }))
	defer server.Close()
	args := []string{"start", "--incident", "123456", "--request-id", "failed-capture"}
	for range 2 {
		command, output, diagnostics := remoteRemediationCommandWithCapture(t, server.URL, hooks, args...)
		err := command.ExecuteContext(t.Context())
		require.Error(t, err)
		require.Contains(t, diagnostics.String(), "requestID=failed-capture")
		require.NotContains(t, err.Error()+output.String()+diagnostics.String(), "private-capture-failure-marker")
	}
	require.Equal(t, int32(1), captures.Load(), "an incomplete snapshot must not be silently replaced")
	require.Zero(t, posts.Load())
	raw, err := os.ReadFile(filepath.Join(cache, "failed-capture", "export", "partial.json"))
	require.NoError(t, err)
	require.Equal(t, "private-capture-failure-marker", string(raw))
	_, err = os.Lstat(filepath.Join(cache, "failed-capture", "intent.json"))
	require.NoError(t, err)
}

func TestRemediationRemoteIncidentCaptureReplayIntegrity(t *testing.T) {
	for _, scenario := range []string{"different-incident", "input", "receipt", "input-and-receipt", "missing-artifact", "symlink", "missing-seal"} {
		t.Run(scenario, func(t *testing.T) {
			hooks := remediationFixtureCaptureHooks(t)
			cache, err := hooks.cacheRoot()
			require.NoError(t, err)
			var captures, posts atomic.Int32
			original := hooks.capture
			hooks.capture = func(ctx context.Context, exporter icm.Exporter, incident, directory string) (icm.Receipt, error) {
				captures.Add(1)
				return original(ctx, exporter, incident, directory)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				w.WriteHeader(http.StatusAccepted)
				require.NoError(t, json.NewEncoder(w).Encode(remoteRemediationFixtureStatus()))
			}))
			defer server.Close()
			args := []string{"start", "--incident", "123456", "--request-id", "request-current"}
			command, _, _ := remoteRemediationCommandWithCapture(t, server.URL, hooks, args...)
			require.NoError(t, command.ExecuteContext(t.Context()))
			export := filepath.Join(cache, "request-current", "export")
			input, err := os.ReadFile(filepath.Join(export, "input.json"))
			require.NoError(t, err)
			var receipt icm.Receipt
			receiptBytes, err := os.ReadFile(filepath.Join(export, "receipt.json"))
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(receiptBytes, &receipt))
			switch scenario {
			case "different-incident":
				args[2] = "987654"
			case "input", "input-and-receipt":
				input = bytes.ReplaceAll(input, []byte("private-acquisition-marker"), []byte("tampered-private-marker"))
				require.NoError(t, os.WriteFile(filepath.Join(export, "input.json"), input, 0o600))
				if scenario == "input-and-receipt" {
					receipt.Artifacts["input.json"] = icm.Artifact{Digest: remediationservice.Digest(input), Bytes: len(input)}
				}
			case "receipt":
				receipt.Entries++
			case "missing-artifact":
				require.NoError(t, os.Remove(filepath.Join(export, "details-after.json")))
			case "symlink":
				target := filepath.Join(cache, "replacement.json")
				require.NoError(t, os.WriteFile(target, input, 0o600))
				require.NoError(t, os.Remove(filepath.Join(export, "input.json")))
				require.NoError(t, os.Symlink(target, filepath.Join(export, "input.json")))
			case "missing-seal":
				require.NoError(t, os.Remove(filepath.Join(cache, "request-current", "capture.json")))
			}
			if scenario == "receipt" || scenario == "input-and-receipt" {
				raw, err := json.Marshal(receipt)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(export, "receipt.json"), raw, 0o600))
			}
			command, output, diagnostics := remoteRemediationCommandWithCapture(t, server.URL, hooks, args...)
			err = command.ExecuteContext(t.Context())
			if scenario == "missing-seal" {
				require.NoError(t, err, "a complete capture interrupted before sealing is recoverable without re-export")
				require.Equal(t, int32(2), posts.Load())
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "tampered-private-marker")
				require.Equal(t, int32(1), posts.Load())
			}
			require.Equal(t, int32(1), captures.Load())
			require.NotContains(t, output.String()+diagnostics.String(), "tampered-private-marker")
		})
	}
}

func TestRemediationRemoteIncidentCaptureSubmissionLimit(t *testing.T) {
	for _, scenario := range []string{"export-larger-than-eight-mib", "escaped-payload-larger-than-eight-mib"} {
		t.Run(scenario, func(t *testing.T) {
			hooks := remediationFixtureCaptureHooks(t)
			cache, err := hooks.cacheRoot()
			require.NoError(t, err)
			hooks.capture = func(_ context.Context, _ icm.Exporter, incident, directory string) (icm.Receipt, error) {
				padding := strings.Repeat("x", (8<<20)+1)
				if scenario == "escaped-payload-larger-than-eight-mib" {
					padding = strings.Repeat("<", 2<<20)
				}
				input := []byte(`{"details":{"id":` + incident + `,"title":"Synthetic","summary":"Complete synthetic input","padding":"` + padding + `"},"discussion":{"aggregatedDiagnosticResults":{"Data":[],"HasMoreData":false,"TotalCount":0}}}`)
				return writeRemediationCaptureFixture(t, incident, directory, input), nil
			}
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { posts.Add(1) }))
			defer server.Close()
			command, output, diagnostics := remoteRemediationCommandWithCapture(t, server.URL, hooks,
				"start", "--incident", "123456", "--request-id", "request-current")
			err = command.ExecuteContext(t.Context())
			require.ErrorContains(t, err, "8 MiB")
			require.Zero(t, posts.Load())
			require.Empty(t, output.String())
			require.Contains(t, diagnostics.String(), "requestID=request-current")
			_, err = os.Lstat(filepath.Join(cache, "request-current", "export", "input.json"))
			require.NoError(t, err, "oversized exports must remain private and available for inspection")
		})
	}
}

func TestRemediationRemoteInputDoesNotAcquireIncident(t *testing.T) {
	input := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(input, []byte(`{"title":"Synthetic","problem":"Complete supplied report","restricted":false}`), 0o600))
	hooks := remediationCaptureHooks{
		cacheRoot: func() (string, error) {
			t.Fatal("direct input must not need an incident cache")
			return "", errors.New("unexpected cache access")
		},
		capture: func(context.Context, icm.Exporter, string, string) (icm.Receipt, error) {
			t.Fatal("direct input must not invoke IcM")
			return icm.Receipt{}, errors.New("unexpected capture")
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		require.NoError(t, json.NewEncoder(w).Encode(remoteRemediationFixtureStatus()))
	}))
	defer server.Close()
	command, _, _ := remoteRemediationCommandWithCapture(t, server.URL, hooks,
		"start", "--input", input, "--request-id", "request-current")
	require.NoError(t, command.ExecuteContext(t.Context()))
}

func TestRemediationRemoteIncidentCacheRejectsCheckoutAndSymlinks(t *testing.T) {
	parent := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(parent, ".git"), []byte("gitdir: fixture"), 0o600))
	t.Setenv("XDG_CACHE_HOME", parent)
	t.Setenv("HOME", parent)
	t.Setenv("LocalAppData", parent)
	_, err := remediationIncidentCacheRoot()
	require.ErrorContains(t, err, "outside Git checkouts")

	cache := filepath.Join(parent, "private-cache")
	require.NoError(t, os.Mkdir(cache, 0o700))
	link := filepath.Join(parent, "cache-link")
	require.NoError(t, os.Symlink(cache, link))
	_, err = openRemediationCaptureCache(link)
	require.ErrorContains(t, err, "symlinks")
	require.NoError(t, os.Chmod(cache, 0o755))
	_, err = openRemediationCaptureCache(cache)
	require.ErrorContains(t, err, "not private")
}
