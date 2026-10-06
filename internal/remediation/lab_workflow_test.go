package remediation

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pv "github.com/orka-agents/orka/internal/patchverification"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/lab"
	"github.com/orka-agents/orka/internal/remediation/source"
)

const labWorkflowFixture = `#!/usr/bin/python3
import hashlib,json,pathlib,sys
raw=pathlib.Path(sys.argv[2]).read_bytes()
r=json.loads(raw)
cfg=json.loads(pathlib.Path(r["configuration"]["path"]).read_text())
counter=pathlib.Path(cfg["counter"])
count=json.loads(counter.read_text()) if counter.exists() else {}
count[r["operation"]]=count.get(r["operation"],0)+1
counter.write_text(json.dumps(count))
out={"version":1,"operation":r["operation"],"requestDigest":"sha256:"+hashlib.sha256(raw).hexdigest(),
"checksDigest":r["profile"]["checksDigest"],
"original":{"image":r["profile"]["originalImage"],"uid":"fixture-original"},
"control":{"image":r["profile"]["controlImage"],"uid":"fixture-control"},
"checks":[{"id":"normal","class":"normal","original":"pass","control":"pass"},
{"id":"repro","class":"reproduction","original":"fail","control":"fail"}],
"cleanup":{"state":"complete","receiptDigest":""}}
out["cleanup"]["receiptDigest"]="sha256:"+hashlib.sha256(b"fixture created no external resources").hexdigest()
if r["operation"]=="verify":
    patch=pathlib.Path(r["candidate"]["patch"]["path"]).read_text()
    good="+good" in patch and "-bad" in patch
    out["patched"]={"image":"sha256:"+"3"*64,"uid":"fixture-candidate"}
    for check in out["checks"]: check["patched"]="pass" if good else "fail"
print(json.dumps(out,separators=(",",":")))
`

func labWorkflowTest(t *testing.T) (*Engine, []byte, string, *int) {
	t.Helper()
	engine, _, _ := newWorkflowTest(t, false)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	counter := filepath.Join(root, "operations.json")
	driver := labWorkflowFixture
	driverPath, configPath := filepath.Join(root, "driver.py"), filepath.Join(root, "configuration.json")
	config, err := json.Marshal(map[string]string{"counter": counter, "privateDriverOnly": "not-for-model"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(driverPath, []byte(driver), 0500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	checksDigest, err := lab.DigestChecks([]lab.Check{{ID: "repro", Class: lab.Reproduction}, {ID: "normal", Class: lab.Normal}})
	if err != nil {
		t.Fatal(err)
	}
	profile := lab.Profile{
		Version: 1, Repository: "https://github.com/example/project", Commit: strings.Repeat("a", 40),
		OriginalImage: "sha256:" + strings.Repeat("1", 64), ControlImage: "sha256:" + strings.Repeat("2", 64),
		Platform: "linux/amd64", Driver: lab.FileIdentity{Path: driverPath, Digest: pv.Digest([]byte(driver))},
		Configuration: lab.FileIdentity{Path: configPath, Digest: pv.Digest(config)}, ChecksDigest: checksDigest,
		Scope: []string{"synthetic driver only"}, Gaps: []string{},
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	target := source.Target{Repository: source.Repository{
		URL: profile.Repository, Owner: "example", Name: "project", DefaultBranch: "main",
	}, Ref: profile.Commit, Commit: profile.Commit, Tree: strings.Repeat("b", 40)}
	engine.Resolver = resolverFunc(func(_ context.Context, repo, ref string) (source.Target, error) {
		if repo != target.Repository.URL || ref != target.Commit {
			t.Fatalf("unexpected source resolution: %s %s", repo, ref)
		}
		return target, nil
	})
	engine.SourcePacket = func(_ context.Context, requested source.Target, paths []string) (source.Packet, error) {
		if requested != target || len(paths) != 1 || paths[0] != "source.txt" {
			t.Fatal("source packet request escaped selected files")
		}
		content := []byte("bad\n")
		digest := sha256.Sum256(content)
		blob := sha1.Sum(append([]byte(fmt.Sprintf("blob %d\x00", len(content))), content...))
		return source.Packet{Version: 1, Target: target, Files: []source.PacketFile{
			{Path: "source.txt", Content: string(content), SHA256: hex.EncodeToString(digest[:]), BlobSHA: hex.EncodeToString(blob[:])},
		}}, nil
	}
	calls := new(int)
	engine.Generator = generatorFunc(func(_ context.Context, request modelagent.Request) (modelagent.Result, error) {
		*calls++
		if strings.Contains(request.Prompt, "not-for-model") || strings.Contains(request.Prompt, configPath) ||
			strings.Contains(request.Prompt, driverPath) || request.Repository != "" || request.Commit != "" {
			t.Fatal("model received driver configuration, paths, or repository tool authority")
		}
		var result any = TargetProposal{
			Problem: "synthetic report", Targets: []TargetSuggestion{{Repository: target.Repository.URL, Ref: target.Commit, Reason: "fixture"}},
		}
		if strings.Contains(request.Prompt, "PINNED_SOURCE_PACKET:") {
			result = PatchProposal{
				Summary: "replace synthetic bad value", Edits: []SourceEdit{{Path: "source.txt", Old: "bad\n", New: "good\n"}},
				DeclaredChanges: []pv.DeclaredChange{{Kind: "source", Paths: []string{"source.txt"}, Description: "fixture correction"}},
			}
		}
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		return modelagent.Result{TaskName: request.TaskName, TaskUID: "uid-" + request.TaskName, Output: string(data)}, nil
	})
	return engine, raw, counter, calls
}

func TestLabWorkflowValidateThenGenerateAndVerify(t *testing.T) {
	engine, profile, counter, calls := labWorkflowTest(t)
	plan, err := engine.ProposeLab(t.Context(), profile, []string{"source.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ValidateLab(t.Context()); err != ErrApprovalRequired {
		t.Fatal("unapproved lab work was admitted", err)
	}
	if _, err := os.Stat(counter); !os.IsNotExist(err) {
		t.Fatal("driver ran before exact plan approval")
	}
	engine.ApprovePlanDigest = plan.PlanDigest
	validated, err := engine.ValidateLab(t.Context())
	if err != nil || validated.Phase != "report-validated" || *calls != 0 || validated.Targets[0].Patch != nil {
		t.Fatalf("report validation generated a patch or failed: %+v %v", validated, err)
	}
	result, err := engine.ExecuteLab(t.Context())
	if err != nil || result.Phase != "completed" || !result.Lab.Verified || result.Targets[0].Conclusion != pv.Verified {
		t.Fatalf("lab workflow failed: %+v %v", result, err)
	}
	if _, err := engine.ExecuteLab(t.Context()); err != nil {
		t.Fatal(err)
	}
	countsRaw, err := os.ReadFile(counter)
	if err != nil {
		t.Fatal(err)
	}
	var counts map[string]int
	if err := json.Unmarshal(countsRaw, &counts); err != nil {
		t.Fatal(err)
	}
	if counts["baseline"] != 1 || counts["verify"] != 1 || *calls != 1 {
		t.Fatalf("completed workflow replayed work: counts=%v model calls=%d", counts, *calls)
	}
}

func TestLabWorkflowBoundsMalformedProposalRepair(t *testing.T) {
	engine, profile, _, calls := labWorkflowTest(t)
	plan, err := engine.ProposeLab(t.Context(), profile, []string{"source.txt"})
	if err != nil {
		t.Fatal(err)
	}
	engine.ApprovePlanDigest = plan.PlanDigest
	engine.Generator = generatorFunc(func(_ context.Context, request modelagent.Request) (modelagent.Result, error) {
		*calls++
		return modelagent.Result{TaskName: request.TaskName, TaskUID: "uid-" + request.TaskName, Output: `{}`}, nil
	})
	result, err := engine.ExecuteLab(t.Context())
	if err == nil || result.Phase != "blocked" || len(result.Lab.Attempts) != maxLabProposals || result.Lab.Verified {
		t.Fatalf("malformed proposal did not stop within the bound: %+v %v", result, err)
	}
	before := *calls
	if _, err := engine.ExecuteLab(t.Context()); err == nil || *calls != before {
		t.Fatal("exhausted proposal repair resumed new model work")
	}
}

func TestLabWorkflowSuppliedPatchDoesNotCallModel(t *testing.T) {
	engine, profile, _, calls := labWorkflowTest(t)
	plan, err := engine.ProposeLab(t.Context(), profile, []string{"source.txt"})
	if err != nil {
		t.Fatal(err)
	}
	engine.ApprovePlanDigest = plan.PlanDigest
	proposal := PatchProposal{
		Summary:         "reviewed synthetic correction",
		Patch:           "diff --git a/source.txt b/source.txt\n--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-bad\n+good\n",
		DeclaredChanges: []pv.DeclaredChange{{Kind: "source", Description: "replace the synthetic bad value"}},
	}
	result, err := engine.VerifyLab(t.Context(), proposal)
	if err != nil || result.Phase != "completed" || !result.Lab.Supplied || !result.Lab.Verified || *calls != 0 {
		t.Fatalf("supplied patch path failed or disclosed data to model: %+v %v calls=%d", result, err, *calls)
	}
	if _, err := engine.VerifyLab(t.Context(), proposal); err != nil {
		t.Fatal(err)
	}
	proposal.Patch += "\n"
	if _, err := engine.VerifyLab(t.Context(), proposal); err == nil {
		t.Fatal("different supplied patch reused an existing verified decision")
	}
}
