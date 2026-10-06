package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	remediationservice "github.com/orka-agents/orka/internal/remediation/service"
	"github.com/orka-agents/orka/internal/store"
)

func remediationOperatorCommand(t *testing.T, server string, arguments ...string) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	root := newRootCmd()
	existing, _, err := root.Find([]string{"remediate"})
	require.NoError(t, err)
	root.RemoveCommand(existing)
	operators := &cobra.Command{Use: "remediate"}
	operators.AddCommand(newRemediationOperatorCommands()...)
	root.AddCommand(operators)
	output, diagnostics := &bytes.Buffer{}, &bytes.Buffer{}
	root.SetOut(output)
	root.SetErr(diagnostics)
	root.SetArgs(append([]string{"--server", server, "--namespace", "tenant-a", "remediate"}, arguments...))
	return root, output, diagnostics
}

func TestRemediationOperatorCommandsRegistered(t *testing.T) {
	root := newRootCmd()
	for _, operation := range []string{remediationListOperation, "drain", "reconcile"} {
		command, _, err := root.Find([]string{"remediate", operation})
		require.NoError(t, err)
		require.Equal(t, operation, command.Name(), "the normal CLI must register the operator constructor")
	}
}

func TestRemediationOperatorListAndDrainMetadata(t *testing.T) {
	for _, operation := range []string{"list", "drain"} {
		t.Run(operation, func(t *testing.T) {
			status := remoteRemediationFixtureStatus()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "tenant-a", r.URL.Query().Get("namespace"))
				if operation == "list" {
					require.Equal(t, remediationRemotePath, r.URL.Path)
					require.Equal(t, "1", r.URL.Query().Get("limit"))
					require.Equal(t, "prior-run", r.URL.Query().Get("continue"))
					require.NoError(t, json.NewEncoder(w).Encode(remediationservice.RunList{
						Items: []remediationservice.RunSummary{{
							ID: status.ID, Namespace: status.Namespace, Mode: string(status.Mode), Phase: status.Phase, Revision: status.Revision,
						}}, Continue: status.ID,
					}))
					return
				}
				require.Equal(t, remediationRemotePath+"/drain", r.URL.Path)
				require.NoError(t, json.NewEncoder(w).Encode(remediationservice.DrainStatus{
					Namespace: "tenant-a", Active: 2, Quarantined: 1, RetainedIntakes: 4,
				}))
			}))
			defer server.Close()
			args := []string{operation}
			if operation == "list" {
				args = append(args, "--limit", "1", "--continue", "prior-run")
			}
			command, output, diagnostics := remediationOperatorCommand(t, server.URL, args...)
			require.NoError(t, command.ExecuteContext(t.Context()))
			require.Empty(t, diagnostics.String())
			require.Contains(t, output.String(), `"namespace":"tenant-a"`)
			require.NotContains(t, output.String(), "report")
			require.NotContains(t, output.String(), "requestJson")
			require.NotContains(t, output.String(), "stateJson")
		})
	}
}

func TestRemediationOperatorCleanupReconcileExactRequest(t *testing.T) {
	status := remoteRemediationFixtureStatus()
	status.Phase, status.Reason, status.Revision = store.RemediationPhaseCancelling, "cleanup-requires-reconciliation", 9
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, remediationRemotePath+"/"+status.ID+"/reconcile", r.URL.Path)
		require.Equal(t, "tenant-a", r.URL.Query().Get("namespace"))
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.JSONEq(t, `{"expectedRevision":8}`, string(raw))
		w.WriteHeader(http.StatusAccepted)
		require.NoError(t, json.NewEncoder(w).Encode(status))
	}))
	defer server.Close()
	command, output, _ := remediationOperatorCommand(t, server.URL, "reconcile", status.ID, "--revision", "8")
	require.NoError(t, command.ExecuteContext(t.Context()))
	require.EqualValues(t, 1, calls.Load())
	require.Contains(t, output.String(), `"phase":"Cancelling"`)
	require.Contains(t, output.String(), `"revision":9`)
}

func TestRemediationOperatorRejectsUnsafeArgumentsAndResponses(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.HasSuffix(r.URL.Path, "/reconcile") {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte("private-sentinel"))
			return
		}
		_, _ = w.Write([]byte(`{"namespace":"foreign","private-sentinel":"unexpected payload"}`))
	}))
	defer server.Close()
	for _, args := range [][]string{
		{"list", "--limit", "0"}, {"list", "--limit", "101"}, {"list", "--continue", "../unsafe"},
		{"reconcile", "run-current"}, {"reconcile", "run-current", "--revision", "9223372036854775807"},
		{"reconcile", "../unsafe", "--revision", "1"},
	} {
		command, output, _ := remediationOperatorCommand(t, server.URL, args...)
		require.Error(t, command.ExecuteContext(t.Context()))
		require.Empty(t, output.String())
	}
	require.Zero(t, calls.Load())
	for _, args := range [][]string{{"list"}, {"drain"}, {"reconcile", "run-current", "--revision", "8"}} {
		command, output, diagnostics := remediationOperatorCommand(t, server.URL, args...)
		err := command.ExecuteContext(t.Context())
		require.Error(t, err)
		require.Empty(t, output.String())
		require.NotContains(t, err.Error()+diagnostics.String(), "private-sentinel")
	}
	require.EqualValues(t, 3, calls.Load(), "reconcile failures must not automatically retry a write")
}

func TestRemediationOperatorRejectsInconsistentDrainAndList(t *testing.T) {
	for _, test := range []struct{ operation, body string }{
		{"drain", `{"namespace":"tenant-a","complete":true,"active":1,"quarantined":0,"retainedIntakes":0,"intakeDrained":true}`},
		{"drain", `{"namespace":"tenant-a","complete":true,"active":0,"quarantined":0,"retainedIntakes":1,"intakeDrained":true}`},
		{"list", `{"items":[],"continue":"nonexistent"}`},
		{"list", `{"items":[{"id":"run-current","namespace":"foreign","phase":"Running","mode":"generate","revision":1}]}`},
	} {
		t.Run(test.operation+test.body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			command, output, _ := remediationOperatorCommand(t, server.URL, test.operation)
			require.Error(t, command.ExecuteContext(t.Context()))
			require.Empty(t, output.String())
		})
	}
}
