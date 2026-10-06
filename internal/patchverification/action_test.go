package patchverification

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActionReportOriginalOnly(test *testing.T) {
	manifest := testManifest()
	manifest.Action = ValidateReport
	manifest.ReportDigest, _ = StableReportDigest(manifest.Problem, manifest.Scope)
	manifest.Sources.Patched = SourceIdentity{}
	manifest.Sources.DiffDigest = ""
	manifest.Checks = manifest.Checks[:1]
	binding, observations := testEvidence(manifest)
	binding.PatchedTaskID = ""
	if err := ValidateManifest(manifest); err != nil {
		test.Fatal(err)
	}
	assessment := Evaluate(manifest, binding, observations[:1])
	if assessment.Conclusion != Reproduced || len(assessment.Checks) != 1 {
		test.Fatalf("original-only report result: %+v", assessment)
	}
	if err := ValidateObservation(manifest, binding, observations[1]); err == nil {
		test.Fatal("report accepted patched evidence")
	}
	manifest.ReportDigest = Digest([]byte("claimed identity"))
	if err := ValidateManifest(manifest); err == nil {
		test.Fatal("accepted an arbitrary report digest")
	}
}

func TestActionReportDigestAndLegacyJSON(test *testing.T) {
	digest, err := StableReportDigest("reported problem", []string{"first", "second"})
	if err != nil || digest != Digest([]byte(`{"problem":"reported problem","scope":["first","second"]}`)) {
		test.Fatalf("report digest contract: %s, %v", digest, err)
	}
	changed, err := StableReportDigest("reported problem", []string{"second", "first"})
	if err != nil || changed == digest {
		test.Fatal("report identity did not bind the ordered scope")
	}
	manifest := testManifest()
	content, err := json.Marshal(manifest)
	if err != nil || strings.Contains(string(content), `"action"`) || strings.Contains(string(content), `"reportDigest"`) {
		test.Fatalf("new fields changed legacy JSON: %s, %v", content, err)
	}
	binding, observations := testEvidence(manifest)
	if result := Evaluate(manifest, binding, observations); result.Conclusion != Verified {
		test.Fatalf("legacy adjudication changed: %+v", result)
	}
}

func TestSourceReportNoPatchedTree(test *testing.T) {
	request := sourceRequestFixture(test)
	request.Action, request.PatchedCommit = ValidateReport, ""
	request.Checks = request.Checks[:1]
	prepared := sourceMustPrepare(test, request)
	if prepared.PatchedDir != "" || prepared.Sources.Patched != (SourceIdentity{}) ||
		prepared.Sources.PatchDigest != "" || prepared.Sources.DiffDigest != "" {
		test.Fatal("report preparation produced patched provenance")
	}
	if _, err := os.Lstat(filepath.Join(prepared.Root, "patched")); !os.IsNotExist(err) {
		test.Fatalf("report preparation created a patched directory: %v", err)
	}
	if len(prepared.Provenance) != len(prepared.Files)+1 {
		test.Fatal("report retained provenance other than original source and checks")
	}
	manifest, err := RequestManifest(request, prepared, Environment{
		Image: request.Image, ImageID: Digest(nil), Platform: request.Platform, Profile: request.Profile,
	})
	if err != nil {
		test.Fatal(err)
	}
	if _, err := NewRunBinding(manifest, "attempt", "original-task", ""); err != nil {
		test.Fatal(err)
	}
	if err := os.RemoveAll(request.ChecksDir); err != nil {
		test.Fatal(err)
	}
	restored, err := RestoreFrozenChecks(context.Background(), manifest)
	if err != nil {
		test.Fatal(err)
	}
	defer func() { _ = restored.Close() }()
	if err := ValidateFrozenChecks(context.Background(), restored.ChecksDir, manifest); err != nil {
		test.Fatalf("frozen check content or executable mode changed on restoration: %v", err)
	}
}

func TestRequirementsAndLifecycleFrozen(test *testing.T) {
	manifest := testManifest()
	before, _ := ManifestDigest(manifest)
	manifest.Environment.Requirements = []EnvironmentRequirement{
		{Kind: "process", Name: "modeled-manager"},
		{Kind: "cluster", Name: "test-cluster"},
		{Kind: "controller", Name: "real-manager"},
		{Kind: "test-identity", Name: "separate-user"},
	}
	manifest.Checks[0].Lifecycle = []string{"install", "reconcile", "restart", "upgrade"}
	manifest.DeclaredChanges = []DeclaredChange{{Kind: "configuration", Paths: []string{"config/settings.json"},
		Description: "persist the managed setting"}}
	if err := ValidateManifest(manifest); err != nil {
		test.Fatal(err)
	}
	after, _ := ManifestDigest(manifest)
	if before == after || len(MissingRequirements(manifest.Environment)) != 3 {
		test.Fatal("frozen metadata or missing environment requirements were lost")
	}
	manifest.DeclaredChanges[0].Paths = []string{"../outside"}
	if err := ValidateManifest(manifest); err == nil {
		test.Fatal("unsafe declaration path accepted")
	}
}

func TestRequirementsRunnerRejectsBeforeExecution(test *testing.T) {
	manifest := testManifest()
	manifest.Environment.Requirements = []EnvironmentRequirement{{Kind: "cluster", Name: "required-cluster"}}
	binding, _ := testEvidence(manifest)
	evidence, err := (DockerRunner{}).RunCheck(test.Context(), manifest, binding, Original,
		manifest.Checks[0], "/unavailable-source", "/unavailable-checks")
	if err == nil || evidence.Observation.Executed || !strings.Contains(err.Error(), "required-cluster") {
		test.Fatalf("unsupported setup reached execution: %+v, %v", evidence, err)
	}
}

func TestRequirementsNamedLocalServices(test *testing.T) {
	for _, fixtureID := range []string{"", "other-service", "inventory"} {
		test.Run("fixture="+fixtureID, func(test *testing.T) {
			environment := Environment{Profile: LocalServices, Requirements: []EnvironmentRequirement{
				{Kind: LocalServices, Name: "inventory"},
			}}
			if fixtureID != "" {
				environment.Services = []Service{{ID: fixtureID}}
			}
			missing := MissingRequirements(environment)
			if (len(missing) == 0) != (fixtureID == "inventory") {
				test.Fatalf("required inventory fixture matched %q: %v", fixtureID, missing)
			}
			if len(missing) != 0 && !strings.Contains(missing[0], "inventory") {
				test.Fatal("missing fixture identity was not named")
			}
		})
	}
}
