//go:build linux

package buildjob

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func historyHelper(mode string) int {
	if !slices.Contains(os.Args, "--format") || !slices.Contains(os.Args, "debug") {
		return 90
	}
	index := slices.Index(os.Args, "--format")
	if index+1 >= len(os.Args) || !strings.Contains(os.Args[index+1], `.Record.Ref "fixture-build-ref"`) ||
		strings.Contains(os.Args[index+1], "{{json .}}") || !helperTLSArguments(os.Args[1:]) {
		return 91
	}
	completed, ref := true, "fixture-build-ref"
	if mode == "history-pending" || mode == "go-test-unsettled" {
		completed = false
	}
	if mode == "go-test-slow-settlement" {
		time.Sleep(1100 * time.Millisecond)
	}
	if mode == "history-mismatch" {
		ref = "other-build-ref"
	}
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		Ref       string `json:"ref"`
		Completed bool   `json:"completed"`
	}{ref, completed})
	return 0
}

func helperBuildPaths(arguments []string) (metadata, contextDirectory, refFile string) {
	for index, argument := range arguments {
		if argument == "--metadata-file" && index+1 < len(arguments) {
			metadata = arguments[index+1]
		}
		if argument == "--ref-file" && index+1 < len(arguments) {
			refFile = arguments[index+1]
		}
		if after, ok := strings.CutPrefix(argument, "context="); ok {
			contextDirectory = after
		}
	}
	return metadata, contextDirectory, refFile
}

func TestWorkerReportsOnlyMatchingCompletedDaemonHistory(t *testing.T) {
	for _, mode := range []string{"success", "history-pending", "history-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			if mode != "success" {
				f.config.Limits.SettlementTimeout = 200 * time.Millisecond
				var err error
				f.backend, err = New(f.config)
				require.NoError(t, err)
			}
			options, output := workerFixture(t, f)
			exit := runWorker(t.Context(), options, helperProcess(t, mode))
			result := readTermination(t, options)
			require.Equal(t, "fixture-build-ref", result.BuildRef)
			require.Equal(t, mode == "success", result.DaemonSettled)
			if mode == "success" {
				require.Zero(t, exit)
			} else {
				require.Equal(t, 1, exit)
				require.Empty(t, result.ImmutableImageDigest)
				require.Equal(t, Infrastructure, result.BuildOutcome)
			}
			require.NotContains(t, output.String(), "fixture-build-ref")
			require.NotContains(t, output.String(), `"completed"`)
		})
	}
}

func TestHistoryEvidenceIsBoundedAndRejectsForeignOrExtraFields(t *testing.T) {
	for _, raw := range []string{
		`{"ref":"another-ref","completed":true}` + "\n",
		`{"ref":"fixture-build-ref","completed":true,"private":"must-not-retain"}` + "\n",
		`{"ref":"fixture-build-ref","completed":true,"completed":false}` + "\n",
		strings.Repeat("x", 2048) + "\n",
	} {
		evidence := &historyEvidence{ref: "fixture-build-ref"}
		n, err := evidence.Write([]byte(raw))
		require.NoError(t, err)
		require.Equal(t, len(raw), n)
		require.True(t, evidence.invalid)
		require.LessOrEqual(t, cap(evidence.line), 2048)
	}
	evidence := &historyEvidence{ref: "fixture-build-ref"}
	_, err := evidence.Write(bytes.Repeat([]byte("\n"), 1<<20))
	require.NoError(t, err)
	require.Empty(t, evidence.line)
	_, err = evidence.Write([]byte(`{"ref":"fixture-build-ref","completed":true}` + "\n"))
	require.NoError(t, err)
	require.True(t, evidence.completed)
	require.False(t, evidence.invalid)
}
