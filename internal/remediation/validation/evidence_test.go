package validation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

func TestValidateRejectsMissingForeignAndContradictoryEvidence(t *testing.T) {
	for _, mutation := range []string{
		"missing-endpoint", "empty-record", "record-overflow", "foreign-run", "foreign-task", "foreign-image", "missing-observation",
		"duplicate-observation", "observation-hash", "missing-stdout-hash", "negative-size", "output-overflow",
		"missing-provenance", "extra-provenance", "duplicate-provenance", "provenance-size", "missing-blob",
		"blob-hash", "blob-size", "blob-overflow", "seal-hash", "seal-creation", "seal-evidence", "missing-seal",
		"summary", "assessment", "cancelled", "running", "incident", "rejected", "recorded-count", "platform", "check-mode",
	} {
		t.Run(mutation, func(t *testing.T) {
			f := validationFixture(t, pv.VerifyPatch)
			var submit pv.KubernetesSubmission
			require.NoError(t, json.Unmarshal(jsonBytes(t, f.submission), &submit))
			badBlob := corruptEvidenceFixture(t, &f, &submit, mutation)
			var creates, evidenceCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					creates.Add(1)
					writeJSON(t, w, http.StatusAccepted, submit)
					return
				}
				if r.URL.Path == "/api/v1/validations/vr-fixture/evidence" {
					evidenceCalls.Add(1)
					switch mutation {
					case "missing-endpoint":
						w.WriteHeader(http.StatusNotFound)
						return
					case "empty-record":
						writeJSON(t, w, http.StatusOK, pv.Record{})
						return
					case "record-overflow":
						w.Header().Set("Content-Length", fmt.Sprint(maxRecordBytes+1))
						w.WriteHeader(http.StatusOK)
						return
					}
				}
				if badBlob != "" && strings.HasSuffix(r.URL.Path, "/"+badBlob) {
					switch mutation {
					case "missing-blob":
						w.WriteHeader(http.StatusNotFound)
					case "blob-hash":
						_, err := w.Write([]byte(strings.Repeat("x", len(f.blobs[badBlob]))))
						require.NoError(t, err)
					case "blob-size":
						_, err := w.Write(append(append([]byte(nil), f.blobs[badBlob]...), 'x'))
						require.NoError(t, err)
					case "blob-overflow":
						w.Header().Set("Content-Length", fmt.Sprint(pv.MaxProvenanceBytes+1))
						w.WriteHeader(http.StatusOK)
					}
					return
				}
				evidenceHandler(t, &f, w, r)
			}))
			defer server.Close()
			c := fakeClient(f, server)
			record, err := c.Validate(t.Context(), f.request)
			require.Error(t, err)
			require.NotNil(t, record)
			require.Equal(t, submit.RunID, record.Binding.RunID)
			require.Equal(t, pv.UnableToVerify, record.Assessment.Conclusion)
			require.NotEqual(t, pv.RunFinalized, record.State)
			require.Nil(t, record.Seal)
			require.EqualValues(t, 1, creates.Load())
			require.EqualValues(t, 1, evidenceCalls.Load())
		})
	}
}

func corruptEvidenceFixture(t *testing.T, f *fixture, submit *pv.KubernetesSubmission, mutation string) string {
	t.Helper()
	badBlob := ""
	switch mutation {
	case "foreign-run":
		f.record.Binding.RunID = "pv-foreign"
	case "foreign-task":
		f.record.Evidence[0].Observation.TaskID = "foreign-task"
		f.reseal(t)
	case "foreign-image":
		f.record.Evidence[0].Observation.ImageID = "example/other@" + pv.Digest(nil)
		f.reseal(t)
	case "missing-observation":
		f.record.Evidence = f.record.Evidence[1:]
		f.reseal(t)
	case "duplicate-observation":
		f.record.Evidence[1] = f.record.Evidence[0]
		f.reseal(t)
	case "observation-hash":
		f.record.Evidence[0].Digest = pv.Digest([]byte("different observation"))
	case "missing-stdout-hash":
		f.record.Evidence[0].Observation.StdoutDigest = ""
		f.reseal(t)
	case "negative-size":
		f.record.Evidence[0].Observation.StdoutBytes = -1
		f.reseal(t)
	case "output-overflow":
		f.record.Evidence[0].Observation.StdoutBytes = pv.MaxOutputBytes + 1
		f.reseal(t)
	case "missing-provenance":
		f.record.Provenance = f.record.Provenance[1:]
		f.reseal(t)
	case "extra-provenance":
		f.record.Provenance = append(f.record.Provenance, pv.BlobReference{Digest: pv.Digest([]byte("foreign")), Bytes: 7})
		f.reseal(t)
	case "duplicate-provenance":
		f.record.Provenance = append(f.record.Provenance, f.record.Provenance[0])
		f.reseal(t)
	case "provenance-size":
		f.record.Provenance = append([]pv.BlobReference(nil), f.record.Provenance...)
		f.record.Provenance[0].Bytes++
		f.reseal(t)
	case "missing-blob", "blob-hash", "blob-size", "blob-overflow":
		badBlob = f.record.Evidence[0].Observation.StdoutDigest
	case "seal-hash":
		f.record.Seal.Digest = pv.Digest(nil)
	case "seal-creation", "seal-evidence":
		var envelope map[string]any
		require.NoError(t, json.Unmarshal(f.record.Seal.Content, &envelope))
		key := "creationDigest"
		if mutation == "seal-evidence" {
			key = "evidenceDigest"
		}
		envelope[key] = pv.Digest(nil)
		f.record.Seal.Content = jsonBytes(t, envelope)
		f.record.Seal.Digest = pv.Digest(f.record.Seal.Content)
	case "missing-seal":
		f.record.Seal = nil
	case "summary":
		submit.Assessment.Conclusion = pv.NotFixed
	case "assessment":
		f.record.Assessment.Conclusion = pv.NotFixed
		submit.Assessment = &f.record.Assessment
	case "cancelled":
		f.record.State = pv.RunCancelled
	case "running":
		f.record.State = pv.RunRunning
	case "incident":
		f.record.Incidents = []pv.Incident{{Kind: "conflict", Reason: "synthetic conflict"}}
	case "rejected":
		f.record.Evidence[0].Rejection = "invalid execution evidence"
	case "recorded-count":
		submit.RecordedChecks--
	case "platform":
		f.record.Manifest.Environment.Platform = "linux/arm64"
	case "check-mode":
		f.record.Manifest.Files = append([]pv.FrozenFile(nil), f.record.Manifest.Files...)
		f.record.Manifest.Files[0].Executable = false
	}
	return badBlob
}

func TestVerifyRecordAggregateBlobBudget(t *testing.T) {
	f := validationFixture(t, pv.VerifyPatch)
	f.staged.Provenance = append([]pv.BlobReference(nil), f.staged.Provenance...)
	f.record.Provenance = append([]pv.BlobReference(nil), f.record.Provenance...)
	for index := range f.record.Provenance {
		f.staged.Provenance[index].Bytes = pv.MaxProvenanceBytes
		f.record.Provenance[index].Bytes = pv.MaxProvenanceBytes
	}
	_, err := verifyRecord(f.staged, &f.submission, &f.record)
	require.ErrorIs(t, err, pv.ErrLimit)
}

func TestValidateReadsCompleteEvidenceForUnboundTerminalFailure(t *testing.T) {
	f := validationFixture(t, pv.ValidateReport)
	var evidenceReads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			submission := f.submission
			submission.RunID, submission.Binding = "", nil
			submission.OriginalTaskUID, submission.RecordedChecks = "", 0
			submission.Failure = "synthetic admission failure"
			submission.Assessment = &pv.Assessment{Conclusion: pv.UnableToValidate}
			writeJSON(t, w, http.StatusAccepted, submission)
			return
		}
		require.Equal(t, "/api/v1/validations/vr-fixture/evidence", r.URL.Path)
		evidenceReads.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	record, err := fakeClient(f, server).Validate(t.Context(), f.request)
	require.Error(t, err)
	require.NotNil(t, record)
	require.Empty(t, record.Binding.RunID)
	require.Equal(t, pv.UnableToValidate, record.Assessment.Conclusion)
	require.EqualValues(t, 1, evidenceReads.Load())
}

func TestVerifyRecordBindsServicesAndFetchesTheirBlobs(t *testing.T) {
	f := validationFixture(t, pv.VerifyPatch)
	service := pv.Service{ID: "server", Command: []string{"/checks/check.sh", "serve"}, Port: 8080, ReadyOutput: "ready"}
	f.request.Profile, f.staged.Request.Profile = pv.LocalServices, pv.LocalServices
	f.request.Services, f.staged.Request.Services = []pv.Service{service}, []pv.Service{service}
	f.record.Manifest.Environment.Profile, f.record.Manifest.Environment.Services = pv.LocalServices, []pv.Service{service}
	f.request.Checks = append([]pv.Check(nil), f.request.Checks...)
	for index := range f.request.Checks {
		f.request.Checks[index].Healthy.Services = map[string]string{"server": "ready\n"}
		f.request.Checks[index].Failure.Services = map[string]string{"server": "ready\n"}
	}
	f.staged.Request.Checks, f.record.Manifest.Checks = f.request.Checks, f.request.Checks
	f.submission.Manifest = f.record.Manifest
	binding, err := pv.NewRunBinding(f.record.Manifest, f.submission.AttemptID, f.submission.OriginalTaskUID, f.submission.PatchedTaskUID)
	require.NoError(t, err)
	f.record.Binding, f.submission.Binding, f.submission.RunID = binding, &binding, binding.RunID
	digest := f.addBlob("ready\n")
	for index := range f.record.Evidence {
		observation := &f.record.Evidence[index].Observation
		observation.RunID, observation.ManifestDigest = binding.RunID, binding.ManifestDigest
		observation.ServiceOutputs = map[string]pv.CapturedOutput{"server": {Digest: digest, Bytes: len("ready\n")}}
	}
	f.reseal(t)
	var serviceReads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writeJSON(t, w, http.StatusAccepted, f.submission)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/"+digest) {
			serviceReads.Add(1)
		}
		evidenceHandler(t, &f, w, r)
	}))
	defer server.Close()
	record, err := fakeClient(f, server).Validate(t.Context(), f.request)
	require.NoError(t, err)
	require.Equal(t, pv.Verified, record.Assessment.Conclusion)
	require.EqualValues(t, 1, serviceReads.Load())
}

func TestBoundedChunkedResponseAndBlob(t *testing.T) {
	for _, operation := range []string{"json", "blob"} {
		t.Run(operation, func(t *testing.T) {
			f := validationFixture(t, pv.ValidateReport)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				_, _ = io.WriteString(w, strings.Repeat("x", 1025))
			}))
			defer server.Close()
			transport, err := newTransport(fakeClient(f, server).API)
			require.NoError(t, err)
			if operation == "json" {
				_, err = transport.request(t.Context(), http.MethodGet, "/fixture", nil, http.StatusOK, 1024)
			} else {
				err = transport.blob(t.Context(), "/fixture", pv.BlobReference{Digest: pv.Digest([]byte(strings.Repeat("x", 1024))), Bytes: 1024})
			}
			require.Error(t, err)
		})
	}
}

func TestResponseJSONRejectsAmbiguityAndTrailingData(t *testing.T) {
	for _, content := range []string{
		`{"state":"finalized","state":"cancelled"}`, `{"state":"finalized","STATE":"cancelled"}`,
		`{"state":"finalized","unknown":1}`, `{"state":"finalized"} {}`, `[]`, `null`,
		"{\"state\":\"\xff\"}", `{"state":` + strings.Repeat("[", 33) + strings.Repeat("]", 33) + `}`,
	} {
		var record pv.Record
		require.Error(t, decodeJSON([]byte(content), &record))
	}
}

func TestValidatePreservesEvidenceBackedNegativeConclusions(t *testing.T) {
	for _, action := range []pv.Action{pv.ValidateReport, pv.VerifyPatch} {
		t.Run(string(action), func(t *testing.T) {
			f := validationFixture(t, action)
			side, output, conclusion := pv.Original, "new\n", pv.NotReproduced
			if action == pv.VerifyPatch {
				side, output, conclusion = pv.Patched, "old\n", pv.NotFixed
			}
			for index := range f.record.Evidence {
				observation := &f.record.Evidence[index].Observation
				if observation.Side == side && observation.CheckID == "reproduce" {
					observation.StdoutDigest, observation.StdoutBytes = f.addBlob(output), len(output)
				}
			}
			f.reseal(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					writeJSON(t, w, http.StatusAccepted, f.submission)
					return
				}
				evidenceHandler(t, &f, w, r)
			}))
			defer server.Close()
			record, err := fakeClient(f, server).Validate(t.Context(), f.request)
			require.NoError(t, err)
			require.Equal(t, pv.RunFinalized, record.State)
			require.Equal(t, conclusion, record.Assessment.Conclusion)
			require.NotNil(t, record.Seal)
		})
	}
}
