//go:build linux

package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fixture struct {
	profile Profile
	root    string
	patch   FileIdentity
}

func testDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func imageDigest(char string) string {
	return "sha256:" + strings.Repeat(char, 64)
}

func newFixture(t *testing.T, mode string) fixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nexport GOCOVERDIR=\"$HOME\"\nexec " + shellQuote(executable) + " -test.run=^TestDriverHelper$ -- lab-driver-fixture " +
		shellQuote(mode) + " \"$@\"\n"
	driver := writeFixture(t, filepath.Join(dir, "driver"), []byte(script), 0700)
	configuration := writeFixture(t, filepath.Join(dir, "private-config"),
		[]byte(`{"fixture":"synthetic","privateMarker":"SYNTHETIC_PRIVATE_MARKER"}`), 0600)
	patch := writeFixture(t, filepath.Join(dir, "patch"), []byte("--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-old\n+fixed\n"), 0600)
	manifest, err := DigestChecks([]Check{{ID: "repro-boundary", Class: Reproduction}, {ID: "normal-flow", Class: Normal}})
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "runs")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	return fixture{
		profile: Profile{
			Version: Version, Repository: "https://example.invalid/public/controller", Commit: strings.Repeat("a", 40),
			OriginalImage: imageDigest("1"), ControlImage: imageDigest("2"), Platform: "linux/amd64",
			Driver: driver, Configuration: configuration, ChecksDigest: manifest,
			Scope: []string{"synthetic controller image reproduction"}, Gaps: []string{},
		},
		root: root, patch: patch,
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func writeFixture(t *testing.T, path string, data []byte, mode os.FileMode) FileIdentity {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return FileIdentity{Path: path, Digest: testDigest(data)}
}

func (input fixture) bridge(t *testing.T) *Bridge {
	t.Helper()
	approved, err := DigestProfile(input.profile)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := New(input.profile, input.root, approved)
	if err != nil {
		t.Fatalf("construct synthetic bridge: %v", err)
	}
	return bridge
}

func (input fixture) candidate() Candidate {
	return Candidate{Patch: input.patch, Image: imageDigest("3")}
}

func baselineFixture(t *testing.T, bridge *Bridge) Receipt {
	t.Helper()
	receipt, err := bridge.Baseline(context.Background(), "baseline")
	if err != nil {
		t.Fatalf("synthetic baseline: %v", err)
	}
	return receipt
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The bridge executes a synthetic approved shell script that execs this helper.
// No extra runtime, installed tools, network or real credentials are needed.
func TestDriverHelper(t *testing.T) {
	index := -1
	for i, argument := range os.Args {
		if argument == "lab-driver-fixture" {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	if len(os.Args) != index+4 {
		os.Exit(20)
	}
	mode, operation, requestPath := os.Args[index+1], os.Args[index+2], os.Args[index+3]
	if mode == "child" {
		for {
			time.Sleep(time.Hour)
		}
	}
	if os.Getenv("LAB_SYNTHETIC_SECRET") != "" || os.Getenv("KUBECONFIG") != "" ||
		os.Getenv("AZURE_CLIENT_SECRET") != "" || os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
		os.Exit(21)
	}
	raw, err := os.ReadFile(requestPath)
	if err != nil {
		os.Exit(22)
	}
	var request Request
	if json.Unmarshal(raw, &request) != nil || operation != string(request.Operation) {
		os.Exit(23)
	}
	config, err := os.ReadFile(request.Configuration.Path)
	if err != nil || testDigest(config) != request.Configuration.Digest || bytes.Contains(raw, []byte("SYNTHETIC_PRIVATE_MARKER")) {
		os.Exit(24)
	}
	if request.Candidate != nil {
		patch, err := os.ReadFile(request.Candidate.Patch.Path)
		if err != nil || testDigest(patch) != request.Candidate.Patch.Digest || request.Operation != OperationVerify {
			os.Exit(25)
		}
	}
	if mode == "sleep" || mode == "descendant" {
		executable, err := os.Executable()
		if err != nil {
			os.Exit(26)
		}
		child := exec.Command(executable, "-test.run=^TestDriverHelper$", "--", "lab-driver-fixture", "child", "unused", "unused")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(27)
		}
		pids := fmt.Sprintf("%d %d", os.Getpid(), child.Process.Pid)
		if os.WriteFile(filepath.Join(filepath.Dir(requestPath), "fixture-pids"), []byte(pids), 0600) != nil {
			os.Exit(28)
		}
		if mode == "sleep" {
			for {
				time.Sleep(time.Hour)
			}
		}
	}
	emitHelperResult(mode, request, raw)
}

func emitHelperResult(mode string, request Request, raw []byte) {
	_, _ = fmt.Fprint(os.Stderr, "SYNTHETIC_PRIVATE_MARKER\n")
	if mode == "failure" {
		os.Exit(31)
	}
	if mode == "stdout-limit" {
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", MaxResultBytes+1))
		os.Exit(0)
	}
	if mode == "stderr-limit" {
		_, _ = fmt.Fprint(os.Stderr, strings.Repeat("x", MaxStderrBytes+1))
		os.Exit(0)
	}
	if mode == "stderr-at-limit" {
		_, _ = fmt.Fprint(os.Stderr, strings.Repeat("x", MaxStderrBytes-len("SYNTHETIC_PRIVATE_MARKER\n")))
	}
	if mode == "malformed" {
		_, _ = fmt.Fprint(os.Stdout, `{"SYNTHETIC_PRIVATE_MARKER":`)
		os.Exit(0)
	}
	result := helperResult(request, testDigest(raw))
	mutateHelperResult(mode, request, &result)
	if mode == "mutate-config" {
		if os.Chmod(request.Configuration.Path, 0600) != nil ||
			os.WriteFile(request.Configuration.Path, []byte("changed"), 0600) != nil {
			os.Exit(32)
		}
	}
	if mode == "receipt-collision" || (mode == "patched-fail-receipt-collision" && request.Operation == OperationVerify) {
		if os.WriteFile(filepath.Join(filepath.Dir(request.Configuration.Path), "receipt.json"), []byte("{}"), 0600) != nil {
			os.Exit(32)
		}
	}
	data, err := json.Marshal(result)
	if err != nil {
		os.Exit(33)
	}
	if mode == "duplicate" {
		data = bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	}
	if mode == "unknown-field" {
		data = append([]byte(`{"unexpected":"SYNTHETIC_PRIVATE_MARKER",`), data[1:]...)
	}
	if mode == "trailing" {
		data = append(data, []byte("{}")...)
	}
	if mode == "stdout-at-limit" {
		data = append(data, bytes.Repeat([]byte(" "), MaxResultBytes-len(data))...)
	}
	_, _ = os.Stdout.Write(data)
	if mode == "valid-result-nonzero" && request.Operation == OperationVerify {
		os.Exit(34)
	}
	os.Exit(0)
}

func helperResult(request Request, requestDigest string) Result {
	control := request.Profile.ControlImage
	if control == "" {
		control = imageDigest("2")
	}
	result := Result{
		Version: Version, Operation: request.Operation, RequestDigest: requestDigest,
		ChecksDigest: request.Profile.ChecksDigest,
		Original:     Runtime{Image: request.Profile.OriginalImage, UID: "synthetic-original-" + request.Name},
		Control:      Runtime{Image: control, UID: "synthetic-control-" + request.Name},
		Checks: []CheckResult{
			{ID: "repro-boundary", Class: Reproduction, Original: Fail, Control: Fail},
			{ID: "normal-flow", Class: Normal, Original: Pass, Control: Pass},
		},
		Cleanup: CleanupReceipt{State: CleanupComplete, ReceiptDigest: imageDigest("c")},
	}
	if request.Operation == OperationVerify {
		image := request.Candidate.Image
		if image == "" {
			image = testDigest([]byte(request.Candidate.Patch.Digest + "\n" + request.Configuration.Digest))
		}
		result.Patched = &Runtime{Image: image, UID: "synthetic-patched-" + request.Name}
		for index := range result.Checks {
			result.Checks[index].Patched = Pass
		}
	}
	return result
}

func mutateHelperResult(mode string, request Request, result *Result) {
	switch mode {
	case "wrong-request":
		result.RequestDigest = imageDigest("9")
	case "wrong-checks":
		result.ChecksDigest = imageDigest("9")
	case "wrong-original":
		result.Original.Image = imageDigest("9")
	case "missing-control":
		result.Control = Runtime{}
	case "missing-check":
		result.Checks = result.Checks[:1]
	case "missing-reproduction":
		result.Checks = result.Checks[1:]
	case "unavailable":
		result.Checks[0].Original = Unavailable
	case "repro-pass":
		result.Checks[0].Control = Pass
	case "normal-fail":
		result.Checks[1].Original = Fail
	case "missing-uid":
		result.Original.UID = ""
	case "cleanup-missing":
		result.Cleanup = CleanupReceipt{}
	case "cleanup-incomplete":
		result.Cleanup.State = CleanupIncomplete
	}
	if request.Operation != OperationVerify {
		return
	}
	switch mode {
	case "patched-fail", "patched-fail-receipt-collision":
		result.Checks[0].Patched = Fail
	case "patched-normal-fail":
		result.Checks[1].Patched = Fail
	case "patched-unavailable":
		result.Checks[1].Patched = Unavailable
	case "changed-check-id":
		result.Checks[1].ID = "different-normal"
	case "changed-check-class":
		result.Checks[1].Class = Reproduction
	case "changed-control":
		result.Control.Image = imageDigest("8")
	case "changed-candidate":
		result.Patched.Image = imageDigest("8")
	case "patched-missing-image":
		result.Patched.Image = ""
	case "patched-tag":
		result.Patched.Image = "example.invalid/controller:latest"
	case "patched-original":
		result.Patched.Image = result.Original.Image
	case "patched-control":
		result.Patched.Image = result.Control.Image
	case "patched-missing-uid":
		result.Patched.UID = ""
	case "changed-original-outcome":
		result.Checks[0].Original = Pass
	}
}

func TestBaselineAndVerifyBindings(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "ok")
	bridge := input.bridge(t)
	baseline := baselineFixture(t, bridge)
	if baseline.State != BaselineReady || baseline.Result == nil || baseline.TrustStatement != TrustStatement {
		t.Fatal("baseline receipt did not explicitly preserve its observation trust")
	}
	verified, err := bridge.Verify(context.Background(), "verify", baseline, input.candidate())
	if err != nil || verified.State != Verified {
		t.Fatalf("synthetic verification failed: %v", err)
	}
	if verified.Result.Original.Image != baseline.Result.Original.Image ||
		verified.Result.Control.Image != baseline.Result.Control.Image ||
		verified.Result.Patched.Image != input.candidate().Image ||
		verified.Result.Original.UID == baseline.Result.Original.UID {
		t.Fatal("image identity bindings or independently observed UIDs were lost")
	}
	for _, name := range []string{"baseline", "verify"} {
		saved, err := bridge.ReadReceipt(name)
		if err != nil {
			t.Fatal(err)
		}
		expected := baseline
		if name == "verify" {
			expected = verified
		}
		if !reflect.DeepEqual(saved, expected) {
			t.Fatal("saved receipt differs from the accepted result")
		}
		raw := readFixture(t, filepath.Join(input.root, name, "request.json"))
		if testDigest(raw) != saved.RequestDigest ||
			testDigest(readFixture(t, filepath.Join(input.root, name, "result.json"))) != saved.ResultDigest {
			t.Fatal("receipt digests do not bind exact private artifact bytes")
		}
		if bytes.Contains(raw, []byte("SYNTHETIC_PRIVATE_MARKER")) ||
			bytes.Contains(readFixture(t, filepath.Join(input.root, name, "receipt.json")), []byte("SYNTHETIC_PRIVATE_MARKER")) {
			t.Fatal("private configuration or diagnostics escaped into request/receipt")
		}
		if !bytes.Contains(readFixture(t, filepath.Join(input.root, name, "stderr.log")), []byte("SYNTHETIC_PRIVATE_MARKER")) {
			t.Fatal("private driver diagnostics were not retained")
		}
		for _, file := range []string{"request.json", "intent.json", "receipt.json", "stderr.log", "configuration"} {
			stat, err := os.Lstat(filepath.Join(input.root, name, file))
			if err != nil || stat.Mode().Perm()&0077 != 0 {
				t.Fatal("an artifact is not private")
			}
		}
	}
}

func TestOmittedControlIsFrozenByBaseline(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "ok")
	input.profile.ControlImage = ""
	bridge := input.bridge(t)
	baseline := baselineFixture(t, bridge)
	if baseline.Result.Control.Image != imageDigest("2") {
		t.Fatal("baseline did not require an explicit control digest")
	}
	receipt, err := bridge.Verify(context.Background(), "verify", baseline, input.candidate())
	if err != nil || receipt.Result.Control.Image != baseline.Result.Control.Image {
		t.Fatal("verification lost the baseline's discovered control identity")
	}
}

func TestNoInheritedCredentials(t *testing.T) {
	t.Setenv("LAB_SYNTHETIC_SECRET", "SYNTHETIC_PRIVATE_MARKER")
	t.Setenv("KUBECONFIG", "/synthetic/not-a-real-kubeconfig")
	t.Setenv("AZURE_CLIENT_SECRET", "SYNTHETIC_PRIVATE_MARKER")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SYNTHETIC_PRIVATE_MARKER")
	input := newFixture(t, "ok")
	baselineFixture(t, input.bridge(t))
}

func TestNamedExecutionIsNeverRepeated(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"ok", "failure", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			input := newFixture(t, mode)
			bridge := input.bridge(t)
			first, _ := bridge.Baseline(context.Background(), "once")
			before := readFixture(t, filepath.Join(input.root, "once", "intent.json"))
			for _, current := range []*Bridge{bridge, input.bridge(t)} {
				if _, err := current.Baseline(context.Background(), "once"); !errors.Is(err, ErrRunExists) {
					t.Fatal("a consumed run name could be executed again")
				}
			}
			if !bytes.Equal(before, readFixture(t, filepath.Join(input.root, "once", "intent.json"))) {
				t.Fatal("existing run intent was changed")
			}
			saved, err := bridge.ReadReceipt("once")
			if mode == "ok" {
				if err != nil || !reflect.DeepEqual(saved, first) {
					t.Fatal("completed receipt could not be read without execution")
				}
			} else if !errors.Is(err, ErrUnknown) || saved.State != Unknown {
				t.Fatal("unknown execution was not explicit")
			}
		})
	}
	input := newFixture(t, "ok")
	bridge := input.bridge(t)
	if err := os.Mkdir(filepath.Join(input.root, "crashed-before-intent"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.Baseline(context.Background(), "crashed-before-intent"); !errors.Is(err, ErrRunExists) {
		t.Fatal("an incomplete reservation was retried")
	}
	if receipt, err := bridge.ReadReceipt("crashed-before-intent"); !errors.Is(err, ErrUnknown) || receipt.State != Unknown {
		t.Fatal("incomplete reservation did not require operator reconciliation")
	}
}

func TestConcurrentSameNameExecutesOnce(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "ok")
	bridge := input.bridge(t)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := bridge.Baseline(context.Background(), "contended")
			results <- err
		}()
	}
	first, second := <-results, <-results
	switch {
	case first == nil && errors.Is(second, ErrRunExists):
	case second == nil && errors.Is(first, ErrRunExists):
	default:
		t.Fatal("exclusive run intent did not admit exactly one execution")
	}
}

func TestBlockedResultsNeverVerify(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{
		"repro-pass", "normal-fail",
	} {
		t.Run(mode, func(t *testing.T) {
			input := newFixture(t, mode)
			bridge := input.bridge(t)
			receipt, err := bridge.Baseline(context.Background(), "blocked")
			if !errors.Is(err, ErrBlocked) || receipt.State != Blocked {
				t.Fatalf("measured baseline assertion failure did not block: %v", err)
			}
			if _, err := bridge.Verify(context.Background(), "verify", receipt, input.candidate()); !errors.Is(err, ErrBaseline) {
				t.Fatal("blocked baseline was accepted")
			}
			if _, err := bridge.ReadReceipt("blocked"); !errors.Is(err, ErrBlocked) {
				t.Fatal("blocked receipt was not persistent")
			}
		})
	}
	input := newFixture(t, "ok")
	input.profile.Gaps = []string{"Kind does not establish managed AKS policy"}
	receipt, err := input.bridge(t).Baseline(context.Background(), "gap")
	if !errors.Is(err, ErrBlocked) || receipt.State != Blocked {
		t.Fatal("an explicit policy gap was treated as verified evidence")
	}
}

func TestCandidateChecksAndImagesCannotDrift(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{
		"patched-unavailable", "changed-check-id", "changed-check-class",
		"changed-control", "changed-candidate", "changed-original-outcome",
	} {
		t.Run(mode, func(t *testing.T) {
			input := newFixture(t, mode)
			bridge := input.bridge(t)
			baseline := baselineFixture(t, bridge)
			receipt, err := bridge.Verify(context.Background(), "verify", baseline, input.candidate())
			if !errors.Is(err, ErrInvalidResult) || receipt.State != Unknown || receipt.Result != nil {
				t.Fatalf("incomplete observations or observer drift were not rejected: %v", err)
			}
			if saved, readErr := bridge.ReadReceipt("verify"); !errors.Is(readErr, ErrUnknown) || saved.Result != nil {
				t.Fatal("incomplete or mismatched observations could be loaded as an assertion failure")
			}
			if _, err := bridge.Verify(context.Background(), "verify", baseline, input.candidate()); !errors.Is(err, ErrRunExists) {
				t.Fatal("an invalid result authorized replay")
			}
		})
	}
}

func TestUnknownResultsArePrivateAndNeverRetried(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{
		"failure", "malformed", "duplicate", "unknown-field", "trailing", "wrong-request", "wrong-checks",
		"stdout-limit", "stderr-limit", "mutate-config", "receipt-collision",
		"wrong-original", "missing-control", "missing-check", "missing-reproduction", "unavailable",
		"missing-uid", "cleanup-missing", "cleanup-incomplete",
	} {
		t.Run(mode, func(t *testing.T) {
			input := newFixture(t, mode)
			bridge := input.bridge(t)
			receipt, err := bridge.Baseline(context.Background(), "unknown")
			if err == nil || receipt.State != Unknown || receipt.Result != nil ||
				strings.Contains(err.Error(), "SYNTHETIC_PRIVATE_MARKER") ||
				strings.Contains(err.Error(), input.profile.Configuration.Path) {
				t.Fatal("driver failure produced a success or exposed private information")
			}
			if _, err := bridge.Baseline(context.Background(), "unknown"); !errors.Is(err, ErrRunExists) {
				t.Fatal("unknown execution could be retried")
			}
			if mode == "stderr-limit" {
				stat, err := os.Stat(filepath.Join(input.root, "unknown", "stderr.log"))
				if err != nil || stat.Size() != MaxStderrBytes {
					t.Fatal("stderr exceeded its exact byte limit")
				}
			}
		})
	}
	input := newFixture(t, "stdout-at-limit")
	baselineFixture(t, input.bridge(t))
	input = newFixture(t, "stderr-at-limit")
	baselineFixture(t, input.bridge(t))
	stat, err := os.Stat(filepath.Join(input.root, "baseline", "stderr.log"))
	if err != nil || stat.Size() != MaxStderrBytes {
		t.Fatal("stderr's inclusive byte limit was not preserved")
	}
}

func TestDriverStartFailureConsumesName(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "ok")
	input.profile.Driver = writeFixture(t, input.profile.Driver.Path, []byte("not an executable format\n"), 0700)
	bridge := input.bridge(t)
	receipt, err := bridge.Baseline(context.Background(), "start-failure")
	if !errors.Is(err, ErrDriver) || receipt.State != Unknown {
		t.Fatal("exec failure was not recorded as unknown")
	}
	if _, err := bridge.Baseline(context.Background(), "start-failure"); !errors.Is(err, ErrRunExists) {
		t.Fatal("exec failure authorized an automatic retry")
	}
}

func TestLiteralInputPathsAndCandidateIntegrity(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "ok")
	for _, identity := range []*FileIdentity{&input.profile.Driver, &input.profile.Configuration, &input.patch} {
		renamed := identity.Path + " with spaces;literal"
		if err := os.Rename(identity.Path, renamed); err != nil {
			t.Fatal(err)
		}
		identity.Path = renamed
	}
	bridge := input.bridge(t)
	baseline := baselineFixture(t, bridge)
	if _, err := bridge.Verify(context.Background(), "literal-path", baseline, input.candidate()); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, input.patch.Path, []byte("changed patch"), 0600)
	if _, err := bridge.Verify(context.Background(), "changed-patch", baseline, input.candidate()); !errors.Is(err, ErrDigestMismatch) {
		t.Fatal("a changed candidate patch was executed")
	}
	if _, err := os.Stat(filepath.Join(input.root, "changed-patch")); !os.IsNotExist(err) {
		t.Fatal("a changed patch began an execution")
	}
	for _, image := range []string{"tag:latest", baseline.Result.Original.Image, baseline.Result.Control.Image} {
		candidate := input.candidate()
		candidate.Image = image
		if _, err := bridge.Verify(context.Background(), "bad-image", baseline, candidate); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("an unpinned or unchanged candidate image was accepted")
		}
	}
}

func TestVerifyRequiresSavedUnmodifiedBaseline(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "ok")
	bridge := input.bridge(t)
	baseline := baselineFixture(t, bridge)
	for _, mutate := range []func(*Receipt){
		func(receipt *Receipt) { receipt.Name = "unrecorded" },
		func(receipt *Receipt) { receipt.RequestDigest = imageDigest("9") },
		func(receipt *Receipt) { receipt.State = Verified },
		func(receipt *Receipt) { receipt.ProfileDigest = imageDigest("9") },
		func(receipt *Receipt) { receipt.Result = nil },
	} {
		changed := baseline
		mutate(&changed)
		if _, err := bridge.Verify(context.Background(), "verify", changed, input.candidate()); !errors.Is(err, ErrBaseline) {
			t.Fatal("a fabricated or changed baseline was accepted")
		}
	}
	path := filepath.Join(input.root, "baseline", "result.json")
	writeFixture(t, path, []byte("{}"), 0600)
	if _, err := bridge.Verify(context.Background(), "verify", baseline, input.candidate()); !errors.Is(err, ErrBaseline) {
		t.Fatal("a modified persisted baseline was accepted")
	}
	if _, err := os.Stat(filepath.Join(input.root, "verify")); !os.IsNotExist(err) {
		t.Fatal("invalid baseline began an execution")
	}
}

func TestCancellationKillsOnlyOwnedProcessGroup(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "sleep")
	bridge := input.bridge(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	unrelated := exec.Command(executable, "-test.run=^TestDriverHelper$", "--",
		"lab-driver-fixture", "child", "unused", "unused")
	unrelated.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unrelated.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Error("could not stop the unrelated synthetic process")
		}
		_ = unrelated.Wait()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := bridge.Baseline(ctx, "cancel")
		done <- err
	}()
	pids := waitForPIDs(t, filepath.Join(input.root, "cancel", "fixture-pids"))
	if syscall.Kill(os.Getpid(), 0) != nil {
		t.Fatal("test parent is not alive")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation was not propagated")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not terminate and wait for the driver")
	}
	for _, pid := range pids {
		requireProcessStopped(t, pid)
	}
	if syscall.Kill(unrelated.Process.Pid, 0) != nil {
		t.Fatal("cancellation affected a separate process group")
	}
	unrelatedState := string(readFixture(t, fmt.Sprintf("/proc/%d/stat", unrelated.Process.Pid)))
	_, state, found := strings.Cut(unrelatedState, ") ")
	if !found || strings.HasPrefix(state, "Z ") || strings.HasPrefix(state, "X ") {
		t.Fatal("the separate synthetic process group did not remain running")
	}
	if _, err := bridge.Baseline(context.Background(), "cancel"); !errors.Is(err, ErrRunExists) {
		t.Fatal("a cancelled unknown run was retried")
	}
	receipt, err := bridge.ReadReceipt("cancel")
	if !errors.Is(err, ErrUnknown) || receipt.State != Unknown {
		t.Fatal("cancelled execution did not retain an unknown receipt")
	}
}

func TestDeadlineLeavesAnUnknownNonReplayableReceipt(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "sleep")
	bridge := input.bridge(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	receipt, err := bridge.Baseline(ctx, "deadline")
	if !errors.Is(err, context.DeadlineExceeded) || receipt.State != Unknown {
		t.Fatal("deadline did not settle as an unknown execution")
	}
	if _, err := bridge.Baseline(context.Background(), "deadline"); !errors.Is(err, ErrRunExists) {
		t.Fatal("deadline authorized a repeated execution")
	}
}

func TestCancelledContextDoesNotStartADriver(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "ok")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := input.bridge(t).Baseline(ctx, "not-started"); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancelled context was not respected")
	}
	if _, err := os.Stat(filepath.Join(input.root, "not-started")); !os.IsNotExist(err) {
		t.Fatal("pre-cancelled call consumed a run or started a driver")
	}
}

func TestNormalExitStopsInheritedPipeDescendant(t *testing.T) {
	t.Parallel()
	input := newFixture(t, "descendant")
	bridge := input.bridge(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	receipt, err := bridge.Baseline(ctx, "descendant")
	if err != nil || receipt.State != BaselineReady {
		t.Fatalf("descendant held result pipes open: %v", err)
	}
	pids := waitForPIDs(t, filepath.Join(input.root, "descendant", "fixture-pids"))
	for _, pid := range pids {
		requireProcessStopped(t, pid)
	}
}

func waitForPIDs(t *testing.T, path string) []int {
	t.Helper()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) == 2 {
				pids := make([]int, 2)
				for index, field := range fields {
					pid, err := strconv.Atoi(field)
					if err != nil || pid <= 1 {
						t.Fatal("invalid synthetic process identity")
					}
					pids[index] = pid
				}
				return pids
			}
		}
		select {
		case <-deadline:
			t.Fatal("synthetic driver did not start")
		case <-ticker.C:
		}
	}
}

func requireProcessStopped(t *testing.T, pid int) {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal("cannot observe synthetic process exit")
	}
	_, state, found := strings.Cut(string(data), ") ")
	if !found || (!strings.HasPrefix(state, "Z ") && !strings.HasPrefix(state, "X ")) {
		t.Fatal("synthetic child remains running")
	}
}
