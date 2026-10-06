package validation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/orka-agents/orka/internal/cli/client"
	pv "github.com/orka-agents/orka/internal/patchverification"
)

var _ interface {
	Validate(context.Context, pv.Request) (*pv.Record, error)
	Start(context.Context, pv.Request, func(Receipt) error) (*pv.Record, error)
	Resume(context.Context, pv.Request, Receipt) (*pv.Record, error)
} = Client{}

func fixtureReceipt(t *testing.T, f fixture) Receipt {
	t.Helper()
	digest, err := requestDigest(f.request)
	require.NoError(t, err)
	receipt, err := newReceipt(digest, &f.submission)
	require.NoError(t, err)
	return receipt
}

func readOnlyClient(t *testing.T, server *httptest.Server) Client {
	t.Helper()
	return Client{API: client.NewWithNamespace(server.URL, "synthetic-api-token", "fixture"),
		PollInterval: time.Millisecond,
		Stage: func(context.Context, pv.Request) (Staged, error) {
			t.Error("Resume must never stage")
			return Staged{}, errors.New("unexpected staging")
		}}
}

func TestStartDurableReceiptReopensAndResumesWithoutSubmission(t *testing.T) {
	for _, mode := range []string{"report", "patch", "legacy-action", "protected-http"} {
		t.Run(mode, func(t *testing.T) {
			f := validationFixture(t, pv.VerifyPatch)
			switch mode {
			case "report":
				f = validationFixture(t, pv.ValidateReport)
			case "legacy-action":
				f.request.Action = ""
			case "protected-http":
				f = protectedHTTPFixture(t, pv.VerifyPatch)
			}
			filename := filepath.Join(t.TempDir(), "receipt.json")
			var posts, callbacks, stages atomic.Int32
			var durable atomic.Bool
			startServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "fixture", r.URL.Query().Get("namespace"))
				if r.Method == http.MethodPost {
					posts.Add(1)
					require.Equal(t, "/api/v1/validations", r.URL.Path)
					next := f.submission
					next.State, next.RunID, next.Binding = pv.SubmissionPreparing, "", nil
					next.OriginalTaskUID, next.PatchedTaskUID, next.RecordedChecks, next.Assessment = "", "", 0, nil
					writeJSON(t, w, http.StatusAccepted, next)
					return
				}
				require.True(t, durable.Load(), "polling raced receipt persistence")
				require.Equal(t, "/api/v1/validations/vr-fixture", r.URL.Path)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			t.Cleanup(startServer.Close)
			c := fakeClient(f, startServer)
			c.Stage = func(context.Context, pv.Request) (Staged, error) {
				stages.Add(1)
				return f.staged, nil
			}
			partial, err := c.Start(t.Context(), f.request, func(receipt Receipt) error {
				callbacks.Add(1)
				require.Equal(t, ReceiptVersion, receipt.Version)
				require.Equal(t, "fixture", receipt.Namespace)
				require.Equal(t, "vr-fixture", receipt.RequestID)
				require.Equal(t, pv.Digest(jsonBytes(t, f.request)), receipt.InputDigest)
				require.Equal(t, f.record.Binding.ManifestDigest, receipt.ManifestDigest)
				require.Empty(t, receipt.RunID, "preparing acknowledgements need not have a run ID")
				content := jsonBytes(t, receipt)
				require.Less(t, len(content), 4096)
				for _, private := range []string{f.request.Repository, f.request.ChecksDir,
					f.request.Problem, "synthetic-api-token", string(f.staged.Files[0].Content)} {
					require.NotContains(t, string(content), private)
				}
				file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				require.NoError(t, err)
				_, err = file.Write(content)
				require.NoError(t, err)
				require.NoError(t, file.Sync())
				require.NoError(t, file.Close())
				directory, err := os.Open(filepath.Dir(filename))
				require.NoError(t, err)
				require.NoError(t, directory.Sync())
				require.NoError(t, directory.Close())
				durable.Store(true)
				return nil
			})
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrSubmissionUnknown)
			require.NotNil(t, partial)
			require.Equal(t, pv.UnavailableAction(f.staged.Request.Action), partial.Assessment.Conclusion)
			require.EqualValues(t, 1, posts.Load())
			require.EqualValues(t, 1, callbacks.Load())
			require.EqualValues(t, 1, stages.Load())
			startServer.Close()

			content, err := os.ReadFile(filename)
			require.NoError(t, err)
			var reopened Receipt
			require.NoError(t, json.Unmarshal(content, &reopened))
			var gets atomic.Int32
			resumeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method, "resuming cannot create or cancel execution")
				require.Equal(t, "fixture", r.URL.Query().Get("namespace"))
				if r.URL.Path == "/api/v1/validations/vr-fixture" {
					next := f.submission
					if gets.Add(1) == 1 {
						next.State, next.RecordedChecks, next.Assessment = pv.SubmissionRunning, 0, nil
					}
					writeJSON(t, w, http.StatusOK, next)
					return
				}
				evidenceHandler(t, &f, w, r)
			}))
			defer resumeServer.Close()
			record, err := readOnlyClient(t, resumeServer).Resume(t.Context(), f.request, reopened)
			require.NoError(t, err)
			require.Equal(t, f.record, *record)
			require.EqualValues(t, 2, gets.Load())
			require.EqualValues(t, 1, posts.Load())
			require.EqualValues(t, 1, stages.Load())
		})
	}
}

func TestStartReceiptCallbackPrecedesTerminalEvidence(t *testing.T) {
	f := validationFixture(t, pv.VerifyPatch)
	var saved atomic.Bool
	var callbacks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writeJSON(t, w, http.StatusAccepted, f.submission)
			return
		}
		require.True(t, saved.Load(), "terminal evidence was read before the callback returned")
		evidenceHandler(t, &f, w, r)
	}))
	defer server.Close()
	record, err := fakeClient(f, server).Start(t.Context(), f.request, func(receipt Receipt) error {
		callbacks.Add(1)
		require.Equal(t, f.record.Binding.RunID, receipt.RunID)
		require.Equal(t, f.record.Binding.OriginalTaskID, receipt.OriginalTaskUID)
		require.Equal(t, f.record.Binding.PatchedTaskID, receipt.PatchedTaskUID)
		saved.Store(true)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, f.record, *record)
	require.EqualValues(t, 1, callbacks.Load())
}

func TestStartReceiptPersistenceFailureStopsAndCancelsOnlyKnownSubmission(t *testing.T) {
	f := validationFixture(t, pv.VerifyPatch)
	persistenceErr := errors.New("synthetic-private-journal-diagnostic")
	var creates, cancellations, reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := f.submission
		next.RecordedChecks, next.Assessment = 0, nil
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/validations":
			creates.Add(1)
			next.State = pv.SubmissionRunning
			writeJSON(t, w, http.StatusAccepted, next)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/validations/vr-fixture/cancel":
			cancellations.Add(1)
			next.State = pv.SubmissionCancelling
			writeJSON(t, w, http.StatusAccepted, next)
		default:
			reads.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	var captured Receipt
	record, err := fakeClient(f, server).Start(t.Context(), f.request, func(receipt Receipt) error {
		captured = receipt
		return persistenceErr
	})
	require.ErrorIs(t, err, persistenceErr)
	require.ErrorIs(t, err, ErrSubmissionUnknown)
	require.NotContains(t, err.Error(), persistenceErr.Error())
	require.Equal(t, "vr-fixture", captured.RequestID)
	require.Equal(t, f.record.Binding, record.Binding)
	require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
	require.NotEqual(t, pv.RunFinalized, record.State)
	require.Less(t, len(jsonBytes(t, record)), maxRecordBytes)
	require.EqualValues(t, 1, creates.Load())
	require.EqualValues(t, 1, cancellations.Load())
	require.Zero(t, reads.Load())
}

func TestStartDoesNotSaveReceiptForUnknownAcknowledgement(t *testing.T) {
	for _, status := range []int{http.StatusAccepted, http.StatusUnprocessableEntity, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := validationFixture(t, pv.ValidateReport)
			var calls, callbacks atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.Equal(t, http.MethodPost, r.Method)
				w.WriteHeader(status)
				_, err := io.WriteString(w, `{"requestID":"vr-fixture"}`)
				require.NoError(t, err)
			}))
			defer server.Close()
			record, err := fakeClient(f, server).Start(t.Context(), f.request, func(Receipt) error {
				callbacks.Add(1)
				return nil
			})
			require.ErrorIs(t, err, ErrSubmissionUnknown)
			require.Nil(t, record)
			require.EqualValues(t, 1, calls.Load())
			require.Zero(t, callbacks.Load())
		})
	}
}

func TestResumeRejectsMissingForeignOrChangedReceiptBeforeIO(t *testing.T) {
	for _, mutation := range []string{"missing", "version", "request-id", "input-digest", "manifest-digest", "identity-digest",
		"namespace", "api-namespace", "request", "task-uid", "run-without-task", "report-patched-task"} {
		t.Run(mutation, func(t *testing.T) {
			f := validationFixture(t, pv.ValidateReport)
			receipt := fixtureReceipt(t, f)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			c := readOnlyClient(t, server)
			switch mutation {
			case "missing":
				receipt = Receipt{}
			case "version":
				receipt.Version++
			case "request-id":
				receipt.RequestID = "../foreign"
			case "input-digest":
				receipt.InputDigest = ""
			case "manifest-digest":
				receipt.ManifestDigest = ""
			case "identity-digest":
				receipt.IdentityDigest = ""
			case "namespace":
				receipt.Namespace = "other"
			case "api-namespace":
				c.API.Namespace = "other"
			case "request":
				f.request.Checks[0].TimeoutSeconds++
			case "task-uid":
				receipt.OriginalTaskUID = "unsafe/task"
			case "run-without-task":
				receipt.OriginalTaskUID = ""
			case "report-patched-task":
				receipt.PatchedTaskUID = "foreign-patched"
			}
			record, err := c.Resume(t.Context(), f.request, receipt)
			require.Error(t, err)
			if mutation == "missing" || mutation == "version" {
				require.ErrorIs(t, err, ErrSubmissionUnknown)
			}
			require.Nil(t, record)
			require.Zero(t, calls.Load())
		})
	}
}

func TestResumePinsReceiptToAuthoritativeSubmission(t *testing.T) {
	for _, mutation := range []string{"namespace", "request-id", "manifest", "attempt", "original-task", "patched-task",
		"submitter", "created-at", "original-uid", "patched-uid", "run", "missing", "malformed"} {
		t.Run(mutation, func(t *testing.T) {
			f := validationFixture(t, pv.VerifyPatch)
			receipt := fixtureReceipt(t, f)
			var next pv.KubernetesSubmission
			require.NoError(t, json.Unmarshal(jsonBytes(t, f.submission), &next))
			switch mutation {
			case "namespace":
				next.Namespace = "other"
			case "request-id":
				next.RequestID = "vr-other"
			case "manifest":
				next.Manifest.Sources.PatchDigest = pv.Digest([]byte("different patch"))
			case "attempt":
				next.AttemptID = "other-attempt"
			case "original-task":
				next.OriginalTaskName = "other-original"
			case "patched-task":
				next.PatchedTaskName = "other-patched"
			case "submitter":
				next.SubmittedBy = "other-identity"
			case "created-at":
				next.CreatedAt = next.CreatedAt.Add(time.Second)
			case "original-uid":
				next.OriginalTaskUID = "other-original-uid"
			case "patched-uid":
				next.PatchedTaskUID = "other-patched-uid"
			case "run":
				next.RunID = "pv-foreign"
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/api/v1/validations/vr-fixture", r.URL.Path)
				require.Equal(t, "fixture", r.URL.Query().Get("namespace"))
				switch mutation {
				case "missing":
					w.WriteHeader(http.StatusNotFound)
				case "malformed":
					_, err := io.WriteString(w, `{"state":"terminal","State":"running"}`)
					require.NoError(t, err)
				default:
					writeJSON(t, w, http.StatusOK, next)
				}
			}))
			defer server.Close()
			record, err := readOnlyClient(t, server).Resume(t.Context(), f.request, receipt)
			require.Error(t, err)
			require.NotNil(t, record)
			require.Equal(t, receipt.RunID, record.Binding.RunID)
			require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
			require.NotEqual(t, pv.RunFinalized, record.State)
			require.EqualValues(t, 1, calls.Load())
			var failure *SubmissionError
			require.ErrorAs(t, err, &failure)
			require.Equal(t, receipt.RequestID, failure.RequestID)
		})
	}
}

func TestResumeDoesNotTrustAdvertisedEvidenceSizesOrContent(t *testing.T) {
	for _, mutation := range []string{"size", "hash", "missing-reference", "extra-reference", "seal"} {
		t.Run(mutation, func(t *testing.T) {
			f := validationFixture(t, pv.VerifyPatch)
			receipt := fixtureReceipt(t, f)
			digest := f.record.Manifest.Sources.Original.ArchiveDigest
			switch mutation {
			case "size":
				for index := range f.record.Provenance {
					if f.record.Provenance[index].Digest == digest {
						f.record.Provenance[index].Bytes++
					}
				}
				f.reseal(t)
			case "hash":
				f.blobs[digest] = []byte(strings.Repeat("x", len(f.blobs[digest])))
			case "missing-reference":
				f.record.Provenance = f.record.Provenance[1:]
				f.reseal(t)
			case "extra-reference":
				f.record.Provenance = append(f.record.Provenance, pv.BlobReference{Digest: f.addBlob("foreign provenance"), Bytes: 18})
				f.reseal(t)
			case "seal":
				f.record.Seal.Digest = pv.Digest(nil)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method)
				if r.URL.Path == "/api/v1/validations/vr-fixture" {
					writeJSON(t, w, http.StatusOK, f.submission)
					return
				}
				evidenceHandler(t, &f, w, r)
			}))
			defer server.Close()
			record, err := readOnlyClient(t, server).Resume(t.Context(), f.request, receipt)
			require.Error(t, err)
			require.Equal(t, receipt.RunID, record.Binding.RunID)
			require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
		})
	}
}

func TestResumeCancellationIsReadOnlyAndKeepsRunReceipt(t *testing.T) {
	f := validationFixture(t, pv.VerifyPatch)
	receipt := fixtureReceipt(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method, "Resume must not POST cancellation")
		require.Equal(t, "/api/v1/validations/vr-fixture", r.URL.Path)
		if calls.Add(1) == 1 {
			next := f.submission
			next.State, next.RecordedChecks, next.Assessment = pv.SubmissionRunning, 0, nil
			writeJSON(t, w, http.StatusOK, next)
			return
		}
		cancel()
		<-r.Context().Done()
	}))
	defer server.Close()
	record, err := readOnlyClient(t, server).Resume(ctx, f.request, receipt)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, receipt.RunID, record.Binding.RunID)
	require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
	require.EqualValues(t, 2, calls.Load())
}

func TestResumeAlreadyCancelledPreservesReceiptWithoutIO(t *testing.T) {
	f := validationFixture(t, pv.VerifyPatch)
	receipt := fixtureReceipt(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	record, err := readOnlyClient(t, server).Resume(ctx, f.request, receipt)
	require.ErrorIs(t, err, context.Canceled)
	require.NotNil(t, record)
	require.Equal(t, receipt.RunID, record.Binding.RunID)
	require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
	require.Zero(t, calls.Load())
}

func TestStartCallbackFailureAndContextCancellationCancelOnce(t *testing.T) {
	f := validationFixture(t, pv.VerifyPatch)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var cancellations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		next := f.submission
		next.RecordedChecks, next.Assessment = 0, nil
		if r.URL.Path == "/api/v1/validations" {
			next.State = pv.SubmissionRunning
		} else {
			require.Equal(t, "/api/v1/validations/vr-fixture/cancel", r.URL.Path)
			cancellations.Add(1)
			next.State = pv.SubmissionCancelling
		}
		writeJSON(t, w, http.StatusAccepted, next)
	}))
	defer server.Close()
	persistenceErr := errors.New("synthetic receipt persistence failure")
	record, err := fakeClient(f, server).Start(ctx, f.request, func(Receipt) error {
		cancel()
		return persistenceErr
	})
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, persistenceErr)
	require.ErrorIs(t, err, ErrSubmissionUnknown)
	require.Equal(t, f.record.Binding.RunID, record.Binding.RunID)
	require.EqualValues(t, 1, cancellations.Load())
}

func TestResumePinsUIDObservedBeforeRunBinding(t *testing.T) {
	f := validationFixture(t, pv.VerifyPatch)
	preparing := f.submission
	preparing.State, preparing.RunID, preparing.Binding = pv.SubmissionPreparing, "", nil
	preparing.PatchedTaskUID, preparing.RecordedChecks, preparing.Assessment = "", 0, nil
	digest, err := requestDigest(f.request)
	require.NoError(t, err)
	receipt, err := newReceipt(digest, &preparing)
	require.NoError(t, err)
	require.NotEmpty(t, receipt.OriginalTaskUID)
	require.Empty(t, receipt.RunID)

	foreign := f.submission
	foreign.OriginalTaskUID = "replacement-original-uid"
	binding, err := pv.NewRunBinding(foreign.Manifest, foreign.AttemptID, foreign.OriginalTaskUID, foreign.PatchedTaskUID)
	require.NoError(t, err)
	foreign.Binding, foreign.RunID = &binding, binding.RunID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/validations/vr-fixture", r.URL.Path)
		writeJSON(t, w, http.StatusOK, foreign)
	}))
	defer server.Close()
	record, err := readOnlyClient(t, server).Resume(t.Context(), f.request, receipt)
	require.ErrorIs(t, err, pv.ErrBinding)
	require.Empty(t, record.Binding.RunID, "the foreign replacement must not become a trusted receipt")
	require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
}
