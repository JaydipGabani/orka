//go:build linux

package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestVerifyBuildsWithoutExpectedCandidateImage(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "ok")
	bridge := input.bridge(t)
	baseline := baselineFixture(t, bridge)
	candidate := Candidate{Patch: input.patch}
	receipt, err := bridge.Verify(context.Background(), "build-and-verify", baseline, candidate)
	if err != nil || receipt.State != Verified || receipt.Result == nil || receipt.Result.Patched == nil {
		t.Fatalf("approved driver could not build and verify a patch without a prebuilt image: %v", err)
	}
	requestBytes := readFixture(t, filepath.Join(input.root, "build-and-verify", "request.json"))
	var request Request
	if err := decodeStrict(requestBytes, MaxRequestBytes, &request); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Candidate map[string]json.RawMessage `json:"candidate"`
	}
	if err := json.Unmarshal(requestBytes, &envelope); err != nil {
		t.Fatal(err)
	}
	if _, supplied := envelope.Candidate["image"]; supplied {
		t.Fatal("absent expected image was not omitted from the request")
	}
	if request.Candidate == nil || request.Candidate.Image != "" || request.Candidate.Patch.Path == input.patch.Path ||
		request.Candidate.Patch.Digest != input.patch.Digest || request.Configuration.Digest != input.profile.Configuration.Digest ||
		!bytes.Equal(readFixture(t, request.Candidate.Patch.Path), readFixture(t, input.patch.Path)) {
		t.Fatal("build request did not preserve the exact frozen patch and configuration")
	}
	wantImage := testDigest([]byte(input.patch.Digest + "\n" + input.profile.Configuration.Digest))
	if receipt.Result.Patched.Image != wantImage || receipt.Result.Patched.UID == "" ||
		receipt.Result.Patched.Image == baseline.Result.Original.Image ||
		receipt.Result.Patched.Image == baseline.Result.Control.Image ||
		receipt.RequestDigest != testDigest(requestBytes) || receipt.Result.RequestDigest != receipt.RequestDigest ||
		receipt.TrustStatement != TrustStatement {
		t.Fatal("driver-built image identity was not retained as request-bound driver evidence")
	}
	saved, err := input.bridge(t).ReadReceipt("build-and-verify")
	if err != nil || !reflect.DeepEqual(saved, receipt) {
		t.Fatalf("saved build-and-verify result could not be recovered: %v", err)
	}
	if _, err := bridge.Verify(context.Background(), "build-and-verify", baseline, candidate); !errors.Is(err, ErrRunExists) {
		t.Fatal("recovery allowed a repeated build")
	}
}

func TestDriverBuiltCandidateRequiresImmutableDistinctIdentity(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{
		"patched-missing-image", "patched-tag", "patched-original", "patched-control", "patched-missing-uid",
	} {
		t.Run(mode, func(t *testing.T) {
			input := newFixture(t, mode)
			bridge := input.bridge(t)
			baseline := baselineFixture(t, bridge)
			candidate := Candidate{Patch: input.patch}
			receipt, err := bridge.Verify(context.Background(), "invalid-build", baseline, candidate)
			if !errors.Is(err, ErrInvalidResult) || receipt.State != Unknown || receipt.Result != nil {
				t.Fatalf("invalid driver-built image became accepted evidence: %v", err)
			}
			if stored, err := bridge.ReadReceipt("invalid-build"); !errors.Is(err, ErrUnknown) || stored.Result != nil {
				t.Fatal("invalid image identity was exposed as a saved assertion result")
			}
			if _, err := bridge.Verify(context.Background(), "invalid-build", baseline, candidate); !errors.Is(err, ErrRunExists) {
				t.Fatal("unknown build outcome allowed a retry")
			}
		})
	}
}

func TestDriverBuiltCandidateFailureReceipts(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"patched-fail", "patched-normal-fail", "valid-result-nonzero", "patched-fail-receipt-collision"} {
		t.Run(mode, func(t *testing.T) {
			input := newFixture(t, mode)
			bridge := input.bridge(t)
			baseline := baselineFixture(t, bridge)
			candidate := Candidate{Patch: input.patch}
			receipt, err := bridge.Verify(context.Background(), "build-result", baseline, candidate)
			if mode == "patched-fail" || mode == "patched-normal-fail" {
				if !errors.Is(err, ErrBlocked) || receipt.State != Blocked || receipt.Result == nil ||
					receipt.Result.Patched == nil || !digestPattern.MatchString(receipt.Result.Patched.Image) {
					t.Fatal("measured assertion failure lost its driver-built image and result")
				}
				saved, readErr := bridge.ReadReceipt("build-result")
				if !errors.Is(readErr, ErrBlocked) || !reflect.DeepEqual(saved, receipt) {
					t.Fatal("driver-built assertion result could not be recovered")
				}
			} else {
				if err == nil || errors.Is(err, ErrBlocked) || receipt.State != Unknown || receipt.Result != nil {
					t.Fatal("execution or receipt failure was accepted as a build/assertion result")
				}
				if mode == "valid-result-nonzero" && !errors.Is(err, ErrDriver) {
					t.Fatal("valid stdout overrode nonzero driver exit")
				}
				if mode == "patched-fail-receipt-collision" && !errors.Is(err, ErrIO) {
					t.Fatal("receipt persistence failure was not surfaced")
				}
			}
			if _, err := bridge.Verify(context.Background(), "build-result", baseline, candidate); !errors.Is(err, ErrRunExists) {
				t.Fatal("failed build verification was re-executed")
			}
		})
	}
}

func TestExpectedImageStillBindsDriverResult(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "changed-candidate")
	bridge := input.bridge(t)
	baseline := baselineFixture(t, bridge)
	receipt, err := bridge.Verify(context.Background(), "expected-image", baseline, input.candidate())
	if !errors.Is(err, ErrInvalidResult) || receipt.State != Unknown || receipt.Result != nil {
		t.Fatal("a supplied expected image did not bind the driver's actual image")
	}
}
