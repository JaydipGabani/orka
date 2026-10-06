package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/environment"
)

func TestBaselineRequiresSpecificFailureNotAnyMismatch(t *testing.T) {
	plan := environment.Plan{Version: 1, Checks: []environment.Check{
		{ID: "repro", Class: environment.Reproduction, HTTP: &environment.HTTPProbe{
			Resource: "subject", Healthy: environment.HTTPExpectation{Status: 400, Body: "rejected"},
			Failure: &environment.HTTPExpectation{Status: 200, Body: "accepted"}}},
		{ID: "normal", Class: environment.Normal, HTTP: &environment.HTTPProbe{
			Resource: "subject", Healthy: environment.HTTPExpectation{Status: 200, Body: "ok"}}},
	}}
	plan.Bind.ChecksDigest = environment.ChecksDigest(plan)
	receipt := environment.Receipt{Request: environment.Request{Plan: plan,
		Subject: environment.Subject{Role: environment.PublishedOriginal, Image: "example.invalid/subject@sha256:" + strings.Repeat("1", 64)}}}
	executor := pipelineEnvironment{}
	original, err := executor.Observe(t.Context(), receipt)
	if err != nil || validateArm(plan, original, false) != nil {
		t.Fatal("synthetic original was not valid")
	}
	for name, mutate := range map[string]func(*environment.Observation){
		"wrong route 404": func(o *environment.Observation) {
			o.Checks[0].Status = 404
			o.Checks[0].Outcome = environment.OutcomeOther
		},
		"fake classification": func(o *environment.Observation) {
			o.Checks[0].Status = 500
			o.Checks[0].BodyDigest = Digest([]byte("crashed"))
			o.Checks[0].Outcome = environment.OutcomeFailure
		},
		"missing normal": func(o *environment.Observation) { o.Checks = o.Checks[:1] },
		"changed frozen check": func(o *environment.Observation) {
			o.Receipt.Request.Plan.Checks[0].HTTP.Failure.Body = "unrelated"
		},
		"cleanup absent":     func(o *environment.Observation) { o.CleanupComplete = false },
		"subject UID absent": func(o *environment.Observation) { o.Checks[0].PodUID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var candidate environment.Observation
			if err := json.Unmarshal(raw, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			if err := validateArm(plan, candidate, false); err == nil {
				t.Fatal("unrelated or incomplete evidence established reproduction")
			}
		})
	}
}
