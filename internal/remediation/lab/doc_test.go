package lab

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

func ExampleDigestChecks() {
	manifest, err := DigestChecks([]Check{
		{ID: "repro-boundary", Class: Reproduction},
		{ID: "normal-flow", Class: Normal},
	})
	if err != nil {
		fmt.Println("invalid check manifest")
		return
	}
	fmt.Println(manifest)
	// Output:
	// sha256:09b45bfe61b040718084ebe77b2a11ac134723a45850766b4b86bb31cbc06e24
}

func TestDocumentedDriverResult(t *testing.T) {
	t.Parallel()
	source, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatal(err)
	}
	var example strings.Builder
	inExample := false
	for line := range strings.SplitSeq(string(source), "\n") {
		if line == "//\t{" {
			inExample = true
		}
		if !inExample {
			continue
		}
		content, found := strings.CutPrefix(line, "//\t")
		if !found {
			t.Fatal("documented result is not one JSON code block")
		}
		example.WriteString(content + "\n")
		if content == "}" {
			break
		}
	}
	var result Result
	if err := decodeStrict([]byte(example.String()), MaxResultBytes, &result); err != nil {
		t.Fatal("documented driver result is not valid strict result JSON")
	}
	if err := validateResultShape(result); err != nil {
		t.Fatal("documented driver result has invalid identities or fields")
	}
	manifest, err := DigestChecks([]Check{{ID: "repro-boundary", Class: Reproduction}, {ID: "normal-flow", Class: Normal}})
	if err != nil || result.ChecksDigest != manifest || result.Patched == nil {
		t.Fatal("documented result does not bind the illustrated check manifest")
	}
	baseline := result
	baseline.Operation, baseline.Patched = OperationBaseline, nil
	baseline.Checks = slices.Clone(result.Checks)
	for index := range baseline.Checks {
		baseline.Checks[index].Patched = ""
	}
	request := Request{
		Operation: OperationVerify, Baseline: &baseline,
		Profile: Profile{
			OriginalImage: result.Original.Image, ControlImage: result.Control.Image, ChecksDigest: manifest,
		},
		Candidate: &Candidate{Image: result.Patched.Image},
	}
	if err := validateResult(request, result.RequestDigest, result); !errors.Is(err, ErrBlocked) {
		t.Fatal("documented candidate failure is not a complete, bound assertion failure")
	}
	for index := range result.Checks {
		result.Checks[index].Patched = Pass
	}
	if err := validateResult(request, result.RequestDigest, result); err != nil {
		t.Fatal("documented result cannot verify after all measured patched checks pass")
	}
	request.Candidate.Image = ""
	if err := validateResult(request, result.RequestDigest, result); err != nil {
		t.Fatal("documented actual image cannot verify without a predeclared expected image")
	}
}
