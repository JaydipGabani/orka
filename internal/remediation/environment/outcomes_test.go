package environment

import (
	"bytes"
	"encoding/json"
	"testing"
)

func clonedPlan(t *testing.T, plan Plan) Plan {
	t.Helper()
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := DecodePlan(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	cloned.Bind.ChecksDigest = ""
	return cloned
}

func TestReproductionRequiresExplicitDistinctFailureAndPairedNormal(t *testing.T) {
	f := testFixture(t)
	a, client := testAdapter(t, f)
	for _, test := range []struct {
		name   string
		mutate func(*Plan)
	}{
		{"missing-failure", func(p *Plan) { p.Checks[0].HTTP.Failure = nil }},
		{"same-outcome", func(p *Plan) { p.Checks[0].HTTP.Failure = &p.Checks[0].HTTP.Healthy }},
		{"normal-failure", func(p *Plan) { p.Checks[1].HTTP.Failure = &HTTPExpectation{Status: 500, Body: "bad"} }},
		{"legacy-single-expectation", func(p *Plan) {
			p.Checks[0].HTTP.ExpectedStatus, p.Checks[0].HTTP.ExpectedBody = 200, "fixed"
			p.Checks[0].HTTP.Healthy, p.Checks[0].HTTP.Failure = HTTPExpectation{}, nil
		}},
		{"unpaired-normal", func(p *Plan) {
			second := p.Resources[0]
			second.ID = "other-service"
			p.Resources = append(p.Resources, second)
			p.Checks[1].HTTP.Resource = second.ID
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := clonedPlan(t, f.plans[0])
			test.mutate(&plan)
			_, err := a.FreezePlan(plan)
			assertKind(t, err, NeedsAdapter)
		})
	}
	if len(client.Actions()) != 0 {
		t.Fatal("invalid reproduction contract reached the executor")
	}
}

func TestPublishedImageNeedsNoCaseSpecificOperatorBinding(t *testing.T) {
	f := testFixture(t)
	f.config.ImageBindings = nil
	a, client := testAdapter(t, f)
	for _, name := range []string{"first-case", "different-case"} {
		plan := clonedPlan(t, f.plans[0])
		plan.Checks[0].HTTP.Healthy.Body = name
		plan, err := a.FreezePlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		request := Request{
			RunID: name, OperationID: "published", Plan: plan,
			Subject: Subject{Role: PublishedOriginal, Image: f.config.Repositories[0].Recipes[0].OriginalImage},
		}
		receipt, err := a.Start(t.Context(), request)
		if err != nil {
			t.Fatal("approved published image required per-case config")
		}
		if err := a.Cancel(t.Context(), receipt); err != nil {
			t.Fatal(err)
		}
	}
	before := createCount(client)
	request := Request{
		RunID: "forged-image", OperationID: "published", Plan: f.plans[0],
		Subject: Subject{Role: PublishedOriginal, Image: "registry.example.invalid/other@sha256:" + f.plans[0].Bind.Recipe.ContentDigest[7:]},
	}
	_, err := a.Start(t.Context(), request)
	assertKind(t, err, NeedsAdapter)
	if createCount(client) != before {
		t.Fatal("unapproved original image created resources")
	}
}

func TestExternalImageIdentityDoesNotDependOnChecks(t *testing.T) {
	f := testFixture(t)
	a, _ := testAdapter(t, f)
	request := fixtureRequest(f, 0, RebuiltControl, "different-checks")
	request.Plan = clonedPlan(t, request.Plan)
	request.Plan.Checks[0].HTTP.Healthy.Body = "another-fixed-response"
	var err error
	request.Plan, err = a.FreezePlan(request.Plan)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := a.Start(t.Context(), request)
	if err != nil {
		t.Fatal("immutable control image binding was coupled to the case's checks")
	}
	if err := a.Cancel(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
}
