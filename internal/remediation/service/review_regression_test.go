package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
)

func TestAuthorizationOutageDoesNotCancelAcceptedRun(t *testing.T) {
	service, _ := testService(t, processorFunc{})
	unavailable := false
	service.config.Authorize = func(context.Context, string, string, ActorIdentity) error {
		if unavailable {
			return ErrAuthorizationUnavailable
		}
		return nil
	}
	run, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
	if err != nil {
		t.Fatal(err)
	}
	unavailable = true
	if err := service.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	waiting, err := service.Get(t.Context(), "testing", run.ID)
	if err != nil || waiting.CancelRequested || waiting.Phase != store.RemediationPhaseRunning {
		t.Fatal("authorization outage was treated as revocation", waiting, err)
	}
	time.Sleep(service.config.Lease + 20*time.Millisecond)
	unavailable = false
	if err := service.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	done, err := service.Get(t.Context(), "testing", run.ID)
	if err != nil || done.Phase != store.RemediationPhaseSucceeded {
		t.Fatal("authorization recovery did not resume", done, err)
	}
}

func TestDiffHeaderLikeContentIsNotAFileHeader(t *testing.T) {
	packet := source.Packet{Files: []source.PacketFile{{Path: "db/query.sql"}}}
	patch := "diff --git a/db/query.sql b/db/query.sql\n--- a/db/query.sql\n+++ b/db/query.sql\n@@ -1 +1 @@\n--- stale comment\n+-- corrected comment\n"
	if err := validateCandidatePaths(patch, packet); err != nil {
		t.Fatal("valid removed SQL comment was treated as a new file header", err)
	}
	if err := validateCandidatePaths(patch+"\n--- a/../../outside\n", packet); err == nil {
		t.Fatal("header after the completed hunk escaped path validation")
	}
}

func TestConsistentOtherCandidateOutcomeRequestsRepair(t *testing.T) {
	check := environment.Check{ID: "normal", Class: environment.Normal, HTTP: &environment.HTTPProbe{
		Resource: "app", Healthy: environment.HTTPExpectation{Status: 200, Body: "ok"},
	}}
	plan := environment.Plan{Version: 1, Checks: []environment.Check{check}}
	plan.Bind.ChecksDigest = environment.ChecksDigest(plan)
	receipt := environment.Receipt{Request: environment.Request{Plan: plan,
		Subject: environment.Subject{Role: environment.Candidate, Image: "candidate"}}}
	result := environment.HTTPResult{CheckID: "normal", Class: environment.Normal, Image: "candidate",
		PodUID: "pod", RuntimeImageID: "image", Status: 500, BodyDigest: Digest([]byte("broken")),
		HealthyStatus: 200, HealthyBodyDigest: Digest([]byte("ok")), Outcome: environment.OutcomeOther}
	observation := environment.Observation{Receipt: receipt, Phase: environment.Completed, CleanupComplete: true,
		Checks: []environment.HTTPResult{result}}
	var rejection *candidateRejected
	if err := validateArm(plan, observation, true); !errors.As(err, &rejection) {
		t.Fatal("observed candidate regression did not reach repair", err)
	}
	if err := validateArm(plan, observation, false); err == nil {
		t.Fatal("unrelated baseline 500 was accepted as reproduction")
	}
}
