//go:build linux

package lab

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIncompleteResultsAreNotAssertionFailures(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*Result){
		"missing-control-image": func(result *Result) { result.Control.Image = "" },
		"missing-runtime-uid":   func(result *Result) { result.Original.UID = "" },
		"wrong-original-image": func(result *Result) {
			result.Original.Image = imageDigest("9")
		},
		"missing-normal-check": func(result *Result) { result.Checks = result.Checks[:1] },
		"missing-observation":  func(result *Result) { result.Checks[1].Control = "" },
		"unavailable-observation": func(result *Result) {
			result.Checks[1].Patched = Unavailable
		},
		"baseline-outcome-drift": func(result *Result) { result.Checks[1].Original = Fail },
		"missing-cleanup":        func(result *Result) { result.Cleanup = CleanupReceipt{} },
		"incomplete-cleanup": func(result *Result) {
			result.Cleanup.State = CleanupIncomplete
		},
		"failure-before-missing": func(result *Result) {
			result.Checks[0].Patched = Fail
			result.Checks[1].Patched = ""
		},
		"failure-before-observer-drift": func(result *Result) {
			result.Checks[0].Patched = Fail
			result.Checks[1].Control = Fail
		},
		"failure-after-missing": func(result *Result) {
			result.Checks[0].Original = ""
			result.Checks[1].Patched = Fail
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := newFixture(t, "ok")
			baseline := helperResult(Request{Operation: OperationBaseline, Profile: input.profile}, imageDigest("b"))
			candidate := input.candidate()
			request := Request{Operation: OperationVerify, Profile: input.profile, Baseline: &baseline, Candidate: &candidate}
			result := helperResult(request, imageDigest("d"))
			mutate(&result)
			if err := validateResult(request, imageDigest("d"), result); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("missing, unavailable or unbound observations became an ordinary assertion failure: %v", err)
			}
		})
	}
}

func TestFailedCandidateReceiptRemainsAvailable(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"patched-fail", "patched-normal-fail"} {
		t.Run(mode, func(t *testing.T) {
			input := newFixture(t, mode)
			bridge := input.bridge(t)
			baseline := baselineFixture(t, bridge)
			receipt, err := bridge.Verify(context.Background(), "failed-candidate", baseline, input.candidate())
			if !errors.Is(err, ErrBlocked) || receipt.State != Blocked || receipt.Result == nil {
				t.Fatalf("measured candidate assertion failure lost its receipt: %v", err)
			}

			if receipt.ResultDigest != testDigest(readFixture(t, filepath.Join(input.root, "failed-candidate", "result.json"))) {
				t.Fatal("failed candidate result bytes were not persisted")
			}
			index := 0
			if mode == "patched-normal-fail" {
				index = 1
			}
			if receipt.Result.Checks[index].Patched != Fail {
				t.Fatal("failed assertion was hidden from the caller")
			}
			saved, readErr := bridge.ReadReceipt("failed-candidate")
			if !errors.Is(readErr, ErrBlocked) || !reflect.DeepEqual(saved, receipt) {
				t.Fatal("failed candidate observations could not be recovered without execution")
			}
			prior, priorErr := bridge.ReadReceipt("baseline")
			if priorErr != nil || !reflect.DeepEqual(prior, baseline) {
				t.Fatal("candidate assertion failure changed the baseline")
			}
			if _, err := bridge.Verify(context.Background(), "failed-candidate", baseline, input.candidate()); !errors.Is(err, ErrRunExists) {
				t.Fatal("a completed failed assertion was automatically re-executed")
			}
		})
	}
}

func TestReceiptWriteFailureIsNotAnAssertionFailure(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "patched-fail-receipt-collision")
	bridge := input.bridge(t)
	baseline := baselineFixture(t, bridge)
	receipt, err := bridge.Verify(context.Background(), "failed-save", baseline, input.candidate())
	if !errors.Is(err, ErrUnknown) || !errors.Is(err, ErrIO) || errors.Is(err, ErrBlocked) ||
		receipt.State != Unknown || receipt.Result != nil {
		t.Fatal("failure to persist an assertion-failure receipt was exposed as an ordinary candidate failure")
	}
	if _, err := bridge.Verify(context.Background(), "failed-save", baseline, input.candidate()); !errors.Is(err, ErrRunExists) {
		t.Fatal("failure to persist a receipt allowed replay")
	}
}
