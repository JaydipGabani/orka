package validation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orka-agents/orka/internal/cli/client"
	pv "github.com/orka-agents/orka/internal/patchverification"
)

type fixture struct {
	request    pv.Request
	staged     Staged
	submission pv.KubernetesSubmission
	record     pv.Record
	blobs      map[string][]byte
}

func validationFixture(t *testing.T, action pv.Action) fixture {
	t.Helper()
	f := fixture{blobs: make(map[string][]byte)}
	f.request = pv.Request{
		Action: action, Repository: "/private/public-source", ChecksDir: "/private/frozen-checks",
		OriginalCommit: strings.Repeat("a", 40), Problem: "synthetic reported behavior", Scope: []string{"synthetic endpoint"},
		Image: "example/tool@" + pv.Digest([]byte("tool")), Platform: "linux/amd64", Profile: pv.Offline,
		Variables: map[string]string{"CASE": "fixture"}, Dependencies: map[string]string{"fixture": "v1"},
		Checks: []pv.Check{
			{ID: "reproduce", Kind: pv.Reproduction, Command: []string{"/checks/check.sh", "reproduce"}, TimeoutSeconds: 5,
				Healthy: pv.Expectation{Stdout: "new\n"}, Failure: pv.Expectation{Stdout: "old\n"}},
			{ID: "normal", Kind: pv.Normal, Command: []string{"/checks/check.sh", "normal"}, TimeoutSeconds: 5,
				Healthy: pv.Expectation{Stdout: "ok\n"}, Failure: pv.Expectation{ExitCode: 1}},
		},
	}
	if action != pv.ValidateReport {
		f.request.PatchFile = "/private/candidate.diff"
		f.request.DeclaredChanges = []pv.DeclaredChange{{Kind: "source", Paths: []string{"value.txt"}, Description: "synthetic replacement"}}
	}
	normalized, err := normalizeRequest(f.request)
	require.NoError(t, err)
	f.staged.Request = normalized
	root := "/validation/fixture/pv-" + strings.Repeat("1", 32)
	f.staged.Request.Repository, f.staged.Request.ChecksDir = root+"/repository", root+"/checks"
	f.staged.Sources = pv.Sources{Repository: f.staged.Request.Repository,
		Original: pv.SourceIdentity{Commit: f.request.OriginalCommit, Tree: strings.Repeat("b", 40), ArchiveDigest: f.addBlob("original archive")}}
	if action != pv.ValidateReport {
		f.staged.Request.PatchFile = root + "/candidate.patch"
		f.staged.Sources.Patched = pv.SourceIdentity{Tree: strings.Repeat("c", 40), ArchiveDigest: f.addBlob("patched archive")}
		f.staged.Sources.DiffDigest, f.staged.Sources.PatchDigest = f.addBlob("source diff"), f.addBlob("candidate patch")
	}
	check := []byte("#!/bin/sh\nprintf 'synthetic check\\n'\n")
	f.staged.Files = []pv.FrozenFile{{Path: "check.sh", Content: check, Digest: f.addBlob(string(check)), Executable: true}}
	for digest, content := range f.blobs {
		f.staged.Provenance = append(f.staged.Provenance, pv.BlobReference{Digest: digest, Bytes: len(content)})
	}
	sort.Slice(f.staged.Provenance, func(i, j int) bool { return f.staged.Provenance[i].Digest < f.staged.Provenance[j].Digest })
	environment := pv.Environment{Image: normalized.Image, ImageID: "containerd://" + normalized.Image,
		Platform: normalized.Platform, Profile: normalized.Profile, Variables: normalized.Variables,
		Dependencies: map[string]string{"fixture": "v1", policyKey: pv.KubernetesPolicyVersion, helperImageKey: "example/helper@" + pv.Digest([]byte("helper"))}}
	manifest, err := pv.RequestManifest(normalized, &pv.PreparedSources{Sources: f.staged.Sources, Files: f.staged.Files}, environment)
	require.NoError(t, err)
	require.NoError(t, pv.ValidateManifest(manifest))
	patchedTask := ""
	if action != pv.ValidateReport {
		patchedTask = "patched-uid"
	}
	binding, err := pv.NewRunBinding(manifest, "attempt-id", "original-uid", patchedTask)
	require.NoError(t, err)
	f.record = pv.Record{Manifest: manifest, Binding: binding, Provenance: f.staged.Provenance, State: pv.RunFinalized}
	for _, side := range pv.ActionSides(action) {
		for _, check := range manifest.Checks {
			expectation := check.Healthy
			if side == pv.Original && check.Kind == pv.Reproduction {
				expectation = check.Failure
			}
			task, tree := binding.OriginalTaskID, manifest.Sources.Original.Tree
			if side == pv.Patched {
				task, tree = binding.PatchedTaskID, manifest.Sources.Patched.Tree
			}
			observation := pv.Observation{
				RunID: binding.RunID, AttemptID: binding.AttemptID, TaskID: task, ManifestDigest: binding.ManifestDigest,
				Side: side, CheckID: check.ID, SourceTree: tree, ImageID: environment.ImageID,
				ContainerID: "containerd://synthetic-container", JobUID: "job-" + side + "-" + check.ID,
				PodUID: "pod-" + side + "-" + check.ID, Origin: "runner",
				StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), FinishedAt: time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
				Executed: true, ExitCode: new(expectation.ExitCode), StdoutDigest: f.addBlob(expectation.Stdout),
				StdoutBytes: len(expectation.Stdout), StderrDigest: f.addBlob(""),
			}
			f.record.Evidence = append(f.record.Evidence, pv.EvidenceRecord{Observation: observation})
		}
	}
	f.submission = pv.KubernetesSubmission{
		Namespace: "fixture", RequestID: "vr-fixture", SubmittedBy: "system:serviceaccount:fixture:coordinator",
		AttemptID: binding.AttemptID, OriginalTaskName: "original-task", OriginalTaskUID: binding.OriginalTaskID,
		Manifest: manifest, Binding: &binding, RunID: binding.RunID, State: pv.SubmissionTerminal,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 1, 1, 0, 0, 2, 0, time.UTC),
		RequiredChecks: len(f.record.Evidence), RecordedChecks: len(f.record.Evidence),
	}
	if action != pv.ValidateReport {
		f.submission.PatchedTaskName, f.submission.PatchedTaskUID = "patched-task", patchedTask
	}
	f.reseal(t)
	return f
}

func (f *fixture) addBlob(content string) string {
	digest := pv.Digest([]byte(content))
	f.blobs[digest] = []byte(content)
	return digest
}

func (f *fixture) reseal(t *testing.T) {
	t.Helper()
	observations := make([]pv.Observation, 0, len(f.record.Evidence))
	for index := range f.record.Evidence {
		entry := &f.record.Evidence[index]
		entry.Digest = pv.Digest(jsonBytes(t, entry.Observation))
		observations = append(observations, entry.Observation)
	}
	f.record.Assessment = pv.Evaluate(f.record.Manifest, f.record.Binding, observations)
	f.submission.Assessment = &f.record.Assessment
	creation := struct {
		Manifest   pv.Manifest        `json:"manifest"`
		Binding    pv.Binding         `json:"binding"`
		Provenance []pv.BlobReference `json:"provenance"`
	}{f.record.Manifest, f.record.Binding, f.record.Provenance}
	content := jsonBytes(t, map[string]any{
		"creationDigest": pv.Digest(jsonBytes(t, creation)),
		"evidenceDigest": pv.Digest(jsonBytes(t, f.record.Evidence)),
		"state":          f.record.State,
		"assessment":     f.record.Assessment,
	})
	f.record.Seal = &pv.Seal{Digest: pv.Digest(content), Content: content, Assessment: f.record.Assessment}
}

func jsonBytes(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err := w.Write(jsonBytes(t, value))
	require.NoError(t, err)
}

func fakeClient(f fixture, server *httptest.Server) Client {
	return Client{API: client.NewWithNamespace(server.URL, "synthetic-api-token", "fixture"),
		Kubeconfig: "/private/kubeconfig", InputPod: "input-upload", InputRoot: "/validation/fixture",
		PollInterval: time.Millisecond,
		Stage:        func(context.Context, pv.Request) (Staged, error) { return f.staged, nil }}
}

func evidenceHandler(t *testing.T, f *fixture, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	prefix := "/api/v1/validations/" + f.submission.RequestID
	if r.URL.Path == prefix+"/evidence" {
		writeJSON(t, w, http.StatusOK, f.record)
		return
	}
	if after, ok := strings.CutPrefix(r.URL.Path, prefix+"/evidence/"); ok {
		digest := after
		content, found := f.blobs[digest]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, err := w.Write(content)
		require.NoError(t, err)
		return
	}
	t.Errorf("unexpected validation endpoint %s %s", r.Method, r.URL.Path)
	w.WriteHeader(http.StatusNotFound)
}

func TestValidateOriginalAndPairedTerminalEvidence(t *testing.T) {
	for _, action := range []pv.Action{pv.ValidateReport, pv.VerifyPatch} {
		for _, immediate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/immediate=%t", action, immediate), func(t *testing.T) {
				f := validationFixture(t, action)
				var submits, polls, evidenceReads atomic.Int32
				seenBlobs := sync.Map{}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "fixture", r.URL.Query().Get("namespace"))
					require.Equal(t, "Bearer synthetic-api-token", r.Header.Get("Authorization"))
					require.Equal(t, "synthetic-txn-token", r.Header.Get("Txn-Token"))
					switch {
					case r.Method == http.MethodPost:
						require.Equal(t, "/api/v1/validations", r.URL.Path)
						submits.Add(1)
						content, err := io.ReadAll(r.Body)
						require.NoError(t, err)
						actual, err := pv.DecodeRequestJSON(content)
						require.NoError(t, err)
						require.JSONEq(t, string(jsonBytes(t, f.staged.Request)), string(jsonBytes(t, actual)))
						next := f.submission
						if !immediate {
							next.State, next.RunID, next.Binding = pv.SubmissionPreparing, "", nil
							next.OriginalTaskUID, next.PatchedTaskUID, next.RecordedChecks, next.Assessment = "", "", 0, nil
						}
						writeJSON(t, w, http.StatusAccepted, next)
					case r.URL.Path == "/api/v1/validations/vr-fixture":
						polls.Add(1)
						writeJSON(t, w, http.StatusOK, f.submission)
					case r.URL.Path == "/api/v1/validations/vr-fixture/evidence":
						evidenceReads.Add(1)
						evidenceHandler(t, &f, w, r)
					default:
						_, duplicate := seenBlobs.LoadOrStore(r.URL.Path, true)
						require.False(t, duplicate, "duplicate blob should only be fetched once")
						evidenceHandler(t, &f, w, r)
					}
				}))
				defer server.Close()
				c := fakeClient(f, server)
				c.API.TxnToken = "synthetic-txn-token"
				c.Stage = func(ctx context.Context, request pv.Request) (Staged, error) {
					deadline, bounded := ctx.Deadline()
					require.True(t, bounded)
					require.LessOrEqual(t, time.Until(deadline), validationTimeout)
					require.JSONEq(t, string(jsonBytes(t, f.request)), string(jsonBytes(t, request)))
					return f.staged, nil
				}
				record, err := c.Validate(t.Context(), f.request)
				require.NoError(t, err)
				require.Equal(t, f.record, *record)
				require.EqualValues(t, 1, submits.Load())
				require.EqualValues(t, 1, evidenceReads.Load())
				if immediate {
					require.Zero(t, polls.Load())
				} else {
					require.EqualValues(t, 1, polls.Load())
				}
				count := 0
				seenBlobs.Range(func(_, _ any) bool { count++; return true })
				require.Len(t, f.blobs, count)
			})
		}
	}
}

func TestValidateDefiniteAPIRejectionsAndUnknownAcknowledgements(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusUnprocessableEntity, http.StatusInternalServerError, http.StatusBadGateway} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := validationFixture(t, pv.VerifyPatch)
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodPost, r.Method)
				posts.Add(1)
				w.WriteHeader(status)
				_, err := io.WriteString(w, "private upstream diagnostic synthetic-api-token")
				require.NoError(t, err)
			}))
			defer server.Close()
			record, err := fakeClient(f, server).Validate(t.Context(), f.request)
			require.Error(t, err)
			require.Nil(t, record)
			require.Equal(t, status == http.StatusUnprocessableEntity || status >= 500, errors.Is(err, ErrSubmissionUnknown))
			require.NotContains(t, err.Error(), "synthetic-api-token")
			require.EqualValues(t, 1, posts.Load())
			var receipt *SubmissionError
			require.ErrorAs(t, err, &receipt)
			require.Equal(t, "/validation/fixture/pv-"+strings.Repeat("1", 32), receipt.InputDirectory)
		})
	}
	for _, mode := range []string{"lost", "truncated", "null", "empty", "duplicate", "oversize", "foreign-namespace"} {
		t.Run(mode, func(t *testing.T) {
			f := validationFixture(t, pv.VerifyPatch)
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodPost, r.Method)
				posts.Add(1)
				switch mode {
				case "lost":
					connection, _, err := w.(http.Hijacker).Hijack()
					require.NoError(t, err)
					require.NoError(t, connection.Close())
				case "truncated":
					w.Header().Set("Content-Length", "1000")
					w.WriteHeader(http.StatusAccepted)
					_, err := io.WriteString(w, `{"requestID":`)
					require.NoError(t, err)
				case "oversize":
					w.Header().Set("Content-Length", fmt.Sprint(maxSubmissionBytes+1))
					w.WriteHeader(http.StatusAccepted)
				case "foreign-namespace":
					next := f.submission
					next.Namespace = "foreign"
					writeJSON(t, w, http.StatusAccepted, next)
				default:
					w.WriteHeader(http.StatusAccepted)
					body := map[string]string{"null": "null", "empty": "{}", "duplicate": `{"requestID":"one","RequestID":"two"}`}[mode]
					_, err := io.WriteString(w, body)
					require.NoError(t, err)
				}
			}))
			defer server.Close()
			record, err := fakeClient(f, server).Validate(t.Context(), f.request)
			require.ErrorIs(t, err, ErrSubmissionUnknown)
			require.Nil(t, record)
			require.EqualValues(t, 1, posts.Load())
		})
	}
}

func TestValidatePinsSubmissionIdentity(t *testing.T) {
	for _, mutation := range []string{"namespace", "request", "attempt", "run", "task-name", "task-uid", "manifest", "image", "platform", "check-mode", "checks", "commit", "patch", "counter", "state", "missing-binding", "created-at"} {
		t.Run(mutation, func(t *testing.T) {
			f := validationFixture(t, pv.VerifyPatch)
			first := f.submission
			first.State = pv.SubmissionRunning
			first.RecordedChecks, first.Assessment = 0, nil
			var next pv.KubernetesSubmission
			require.NoError(t, json.Unmarshal(jsonBytes(t, f.submission), &next))
			switch mutation {
			case "namespace":
				next.Namespace = "other"
			case "request":
				next.RequestID = "vr-other"
			case "attempt":
				next.AttemptID = "other"
			case "run":
				next.RunID = "pv-foreign"
			case "task-name":
				next.OriginalTaskName = "other"
			case "task-uid":
				next.OriginalTaskUID = "foreign-uid"
			case "manifest":
				next.Manifest.Problem = "changed"
			case "image":
				next.Manifest.Environment.Image = "example/other@" + pv.Digest(nil)
			case "platform":
				next.Manifest.Environment.Platform = "linux/arm64"
			case "check-mode":
				next.Manifest.Files[0].Executable = false
			case "checks":
				next.Manifest.Checks[0].Command = []string{"/checks/other"}
			case "commit":
				next.Manifest.Sources.Original.Commit = strings.Repeat("d", 40)
			case "patch":
				next.Manifest.Sources.PatchDigest = pv.Digest(nil)
			case "counter":
				next.RecordedChecks = next.RequiredChecks + 1
			case "state":
				next.State = pv.SubmissionPreparing
			case "missing-binding":
				next.Binding = nil
			case "created-at":
				next.CreatedAt = next.CreatedAt.Add(time.Second)
			}
			var evidenceReads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					writeJSON(t, w, http.StatusAccepted, first)
				} else if r.URL.Path == "/api/v1/validations/vr-fixture" {
					writeJSON(t, w, http.StatusOK, next)
				} else {
					evidenceReads.Add(1)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			record, err := fakeClient(f, server).Validate(t.Context(), f.request)
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrSubmissionUnknown)
			require.NotNil(t, record)
			require.Equal(t, first.RunID, record.Binding.RunID)
			require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
			require.NotEqual(t, pv.RunFinalized, record.State)
			require.Nil(t, record.Seal)
			require.Zero(t, evidenceReads.Load())
		})
	}
}

func TestValidateCancellationUsesExactSubmission(t *testing.T) {
	for _, during := range []string{"poll", "evidence", "blob", "before-binding"} {
		t.Run(during, func(t *testing.T) {
			f := validationFixture(t, pv.VerifyPatch)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var cancellations atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "fixture", r.URL.Query().Get("namespace"))
				if r.URL.Path == "/api/v1/validations/vr-fixture/cancel" {
					require.Equal(t, http.MethodPost, r.Method)
					require.NoError(t, r.Context().Err())
					cancellations.Add(1)
					next := f.submission
					if during == "poll" || during == "before-binding" {
						next.State = pv.SubmissionCancelling
					}
					writeJSON(t, w, http.StatusAccepted, next)
					return
				}
				switch {
				case r.Method == http.MethodPost:
					first := f.submission
					if during == "poll" || during == "before-binding" {
						first.State, first.Assessment, first.RecordedChecks = pv.SubmissionRunning, nil, 0
					}
					if during == "before-binding" {
						first.State, first.Binding, first.RunID = pv.SubmissionPreparing, nil, ""
						first.OriginalTaskUID, first.PatchedTaskUID = "", ""
					}
					writeJSON(t, w, http.StatusAccepted, first)
				case r.URL.Path == "/api/v1/validations/vr-fixture" ||
					(during == "evidence" && r.URL.Path == "/api/v1/validations/vr-fixture/evidence") ||
					(during == "blob" && strings.Contains(r.URL.Path, "/evidence/")):
					cancel()
					<-r.Context().Done()
				default:
					evidenceHandler(t, &f, w, r)
				}
			}))
			defer server.Close()
			record, err := fakeClient(f, server).Validate(ctx, f.request)
			require.ErrorIs(t, err, context.Canceled)
			require.NotErrorIs(t, err, ErrSubmissionUnknown)
			require.EqualValues(t, 1, cancellations.Load())
			require.NotNil(t, record)
			require.Equal(t, f.record.Binding.RunID, record.Binding.RunID)
			require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
			var receipt *SubmissionError
			require.ErrorAs(t, err, &receipt)
			require.Equal(t, "vr-fixture", receipt.RequestID)
			require.Equal(t, f.record.Binding.RunID, receipt.RunID)
		})
	}
}

func TestValidateCancelledUnknownPostNeverGuessesCancellation(t *testing.T) {
	f := validationFixture(t, pv.ValidateReport)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, "/api/v1/validations", r.URL.Path)
		_, err := io.Copy(io.Discard, r.Body)
		require.NoError(t, err)
		cancel()
		<-r.Context().Done()
	}))
	defer server.Close()
	record, err := fakeClient(f, server).Validate(ctx, f.request)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, ErrSubmissionUnknown)
	require.Nil(t, record)
	require.EqualValues(t, 1, calls.Load())
}

func TestValidateRejectsRedirectsWithoutLeakingCredentials(t *testing.T) {
	f := validationFixture(t, pv.ValidateReport)
	var foreignCalls atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer foreign.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	c := fakeClient(f, server)
	c.API.HTTPClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	record, err := c.Validate(t.Context(), f.request)
	require.ErrorIs(t, err, ErrSubmissionUnknown)
	require.Nil(t, record)
	require.Zero(t, foreignCalls.Load())
	require.NoError(t, c.API.HTTPClient.CheckRedirect(nil, nil), "the supplied HTTP client must not be modified")
}

func TestValidateRejectsMissingConfigurationAndInputChanges(t *testing.T) {
	for _, mutation := range []string{"api", "namespace", "pod", "root", "cross-namespace-root", "kubeconfig", "interval", "linked", "image", "token-in-request", "stage-error", "stage-path", "stage-request"} {
		t.Run(mutation, func(t *testing.T) {
			f := validationFixture(t, pv.ValidateReport)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			c := fakeClient(f, server)
			switch mutation {
			case "api":
				c.API = nil
			case "namespace":
				c.API.Namespace = ""
			case "pod":
				c.InputPod = ""
			case "root":
				c.InputRoot = ""
			case "cross-namespace-root":
				c.InputRoot = "/validation/other"
			case "kubeconfig":
				c.Kubeconfig = ""
			case "interval":
				c.PollInterval = -1
			case "linked":
				f.request.EarlierValidation = "pv-earlier"
			case "image":
				f.request.Image = "example/tool:latest"
			case "token-in-request":
				f.request.Problem = "synthetic-api-token"
			case "stage-error":
				c.Stage = func(context.Context, pv.Request) (Staged, error) { return Staged{}, errors.New("staging failed") }
			case "stage-path":
				f.staged.Request.Repository = "/outside/repository"
				c.Stage = func(context.Context, pv.Request) (Staged, error) { return f.staged, nil }
			case "stage-request":
				f.staged.Request.Problem = "different input"
				c.Stage = func(context.Context, pv.Request) (Staged, error) { return f.staged, nil }
			}
			record, err := c.Validate(t.Context(), f.request)
			require.Error(t, err)
			require.Nil(t, record)
			require.Zero(t, calls.Load())
		})
	}
}

func TestNormalizeLegacyActionDoesNotMutateCaller(t *testing.T) {
	f := validationFixture(t, pv.VerifyPatch)
	f.request.Action, f.request.DeclaredChanges = "", nil
	request, err := normalizeRequest(f.request)
	require.NoError(t, err)
	require.Equal(t, pv.VerifyPatch, request.Action)
	require.Len(t, request.DeclaredChanges, 1)
	require.Empty(t, f.request.Action)
	require.Nil(t, f.request.DeclaredChanges)
	request.Checks[0].Command[0] = "/checks/changed"
	require.Equal(t, "/checks/check.sh", f.request.Checks[0].Command[0])
}

func TestMatchManifestPreservesEmptyDependencyKeys(t *testing.T) {
	f := validationFixture(t, pv.ValidateReport)
	f.staged.Request.Dependencies["declared-empty"] = ""
	require.Error(t, matchManifest(f.staged, f.record.Manifest))
}

func TestCancellationRequiresCancellingOrTerminalAcknowledgement(t *testing.T) {
	f := validationFixture(t, pv.VerifyPatch)
	first := f.submission
	first.State, first.Assessment, first.RecordedChecks = pv.SubmissionRunning, nil, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/validations/vr-fixture/cancel", r.URL.Path)
		writeJSON(t, w, http.StatusAccepted, first)
	}))
	defer server.Close()
	transport, err := newTransport(fakeClient(f, server).API)
	require.NoError(t, err)
	require.Error(t, transport.cancel(t.Context(), &first, f.staged))
	require.Equal(t, f.record.Binding, *first.Binding)
}

func TestCancellationAfterStagingDoesNotSubmit(t *testing.T) {
	f := validationFixture(t, pv.ValidateReport)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	c := fakeClient(f, server)
	c.Stage = func(context.Context, pv.Request) (Staged, error) {
		cancel()
		return f.staged, nil
	}
	record, err := c.Validate(ctx, f.request)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, ErrSubmissionUnknown)
	require.Nil(t, record)
	require.Zero(t, calls.Load())
}

func TestCancelledSubmissionKeepsReceiptWhenCancellationFails(t *testing.T) {
	for _, acknowledgement := range []string{"http-error", "foreign-run", "already-closed"} {
		t.Run(acknowledgement, func(t *testing.T) {
			f := validationFixture(t, pv.VerifyPatch)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var cancellations atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/validations":
					next := f.submission
					next.State, next.RecordedChecks, next.Assessment = pv.SubmissionRunning, 0, nil
					writeJSON(t, w, http.StatusAccepted, next)
				case "/api/v1/validations/vr-fixture":
					cancel()
					<-r.Context().Done()
				case "/api/v1/validations/vr-fixture/cancel":
					cancellations.Add(1)
					switch acknowledgement {
					case "http-error":
						w.WriteHeader(http.StatusInternalServerError)
						_, err := io.WriteString(w, "synthetic-private-diagnostic")
						require.NoError(t, err)
					case "foreign-run":
						next := f.submission
						next.RunID = "foreign-run"
						writeJSON(t, w, http.StatusAccepted, next)
					case "already-closed":
						w.WriteHeader(http.StatusConflict)
					}
				default:
					t.Errorf("unexpected cancellation endpoint: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			record, err := fakeClient(f, server).Validate(ctx, f.request)
			require.ErrorIs(t, err, context.Canceled)
			require.NotContains(t, err.Error(), "synthetic-private-diagnostic")
			require.NotNil(t, record)
			require.Equal(t, f.record.Binding, record.Binding)
			require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
			require.EqualValues(t, 1, cancellations.Load())
		})
	}
}
