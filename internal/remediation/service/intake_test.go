package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestServiceRetainsRawIntakeOnlyInEncryptedSnapshot(t *testing.T) {
	service, storage := testService(t, processorFunc{})
	request := requestFixture()
	request.Report = json.RawMessage(`{"title":"Synthetic report","problem":"A value is accepted","restricted":false,"administrative":"omitted-private-snapshot-marker"}`)
	status, _, err := service.Submit(t.Context(), "testing", "caller", request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := storage.ReadRemediationIntake(t.Context(), "testing", status.ID)
	if err != nil || string(raw) != string(request.Report) {
		t.Fatal("raw input was not preserved exactly", err)
	}
	run, err := storage.GetRemediationRun(t.Context(), "testing", status.ID)
	if err != nil {
		t.Fatal(err)
	}
	var normalized StoredRequest
	if err := json.Unmarshal(run.RequestJSON, &normalized); err != nil {
		t.Fatal(err)
	}
	if normalized.Report == nil || run.InputDigest != Digest(raw) || normalized.Report.SourceDigest != Digest(raw) {
		t.Fatal("normalized record is not bound to the private capture")
	}
	if bytes.Contains(run.RequestJSON, []byte("omitted-private-snapshot-marker")) {
		t.Fatal("administrative input escaped into normalized execution state")
	}
	artifacts, err := storage.ListRemediationArtifacts(t.Context(), "testing", status.ID)
	if err != nil || len(artifacts) != 0 || len(run.Intake) != 0 {
		t.Fatal("raw intake escaped through a regular run or artifact", err)
	}
}

func TestServiceRejectsIncidentWithoutIntakeConnector(t *testing.T) {
	service, storage := testService(t, processorFunc{})
	_, created, err := service.Submit(t.Context(), "testing", "caller", Request{
		RequestID: "incident-only", Incident: "123456", Mode: Generate,
	})
	if created || !errors.Is(err, ErrIntakeConnectorUnavailable) {
		t.Fatal("incident-only input was accepted without an acquisition connector", err)
	}
	runs, err := storage.ListRemediationRuns(t.Context(), "testing", 1)
	if err != nil || len(runs) != 0 {
		t.Fatal("unsupported acquisition left runnable work", err)
	}
}

func TestServiceArtifactDisclosureFailsClosed(t *testing.T) {
	for _, content := range [][]byte{
		{'f', 'i', 'x', 't', 'u', 'r', 'e', 0xff},
		[]byte("--- a/example\n+++ b/example\n@@ -1 +1 @@\n-http://user:synthetic-value@example.invalid\n+redacted\n"),
	} {
		service, storage := testService(t, processorFunc{})
		status, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		run, err := storage.ClaimNextRemediationRun(t.Context(), "testing", "worker", now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		_, err = storage.PutRemediationArtifact(t.Context(), "testing", status.ID, run.ClaimOwner, run.ClaimEpoch,
			"private.txt", "text/plain", content, now)
		if err != nil {
			t.Fatal(err)
		}
		ref, raw, err := service.Artifact(t.Context(), "testing", status.ID, "private.txt")
		if !errors.Is(err, ErrPolicy) || ref != nil || raw != nil {
			t.Fatal("unapproved artifact bytes were disclosed", err)
		}
	}
}
