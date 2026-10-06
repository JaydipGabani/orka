package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/disclosure"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/provenance"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

type disclosureModelClient struct {
	accepted func(context.Context, modelagent.Result) error
	output   string
	calls    *int
}

func (c disclosureModelClient) Snapshot(context.Context) (modelagent.PlanIdentity, error) {
	return modelagent.PlanIdentity{Digest: Digest([]byte("synthetic-model-identity"))}, nil
}

func (c disclosureModelClient) Generate(ctx context.Context, request modelagent.Request) (modelagent.Result, error) {
	*c.calls++
	result := modelagent.Result{TaskName: request.TaskName, TaskUID: "synthetic-task-uid", Output: c.output}
	return result, c.accepted(ctx, result)
}

func (disclosureModelClient) Cancel(context.Context, string, string) error { return nil }
func (disclosureModelClient) Retire(context.Context, string, string) error { return nil }

func disclosurePipelineFixture(t *testing.T, output string) (*Pipeline, *Session, *pipelineState, Policy, *int, *int) {
	t.Helper()
	fixture, session, state := controllerSessionFixture(t)
	var policy Policy
	require.NoError(t, json.Unmarshal(session.run.PolicyJSON, &policy))
	clients, calls := new(int), new(int)
	fixture.pipeline.Agents = func(_, _ string, accepted func(context.Context, modelagent.Result) error) ProposalClient {
		*clients++
		return disclosureModelClient{accepted: accepted, output: output, calls: calls}
	}
	state.ModelIdentity = &modelagent.PlanIdentity{Digest: Digest([]byte("synthetic-model-identity"))}
	return fixture.pipeline, session, state, policy, clients, calls
}

func TestControllerPipelineDisclosureBlocksPromptBeforeSubmission(t *testing.T) {
	t.Parallel()
	for _, prompt := range []string{
		`{"password":"example-value"}`,
		"inspect https://user:example-value@example.invalid/source",
		"inspect https://example.invalid/source?token=example-value",
		string([]byte{0xff}),
	} {
		pipeline, session, state, policy, clients, calls := disclosurePipelineFixture(t, `{}`)
		_, err := pipeline.generate(t.Context(), session, session.run, policy, state, modelagent.Request{
			TaskName: "blocked-prompt", Prompt: prompt,
		})
		require.ErrorIs(t, err, ErrNeedsInput)
		require.Equal(t, ErrNeedsInput.Error(), err.Error())
		require.Zero(t, *clients)
		require.Zero(t, *calls)
		require.Zero(t, state.ModelCalls)
		artifacts, err := session.store.ListRemediationArtifacts(t.Context(), session.run.Namespace, session.run.ID)
		require.NoError(t, err)
		require.Empty(t, artifacts)
	}
}

func TestControllerPipelineDisclosureBlocksModelOutputBeforeArtifact(t *testing.T) {
	t.Parallel()
	pipeline, session, state, policy, _, calls := disclosurePipelineFixture(t, `{"password":"example-value"}`)
	request := modelagent.Request{TaskName: "blocked-output", Prompt: "Return one declarative check plan."}
	result, err := pipeline.generate(t.Context(), session, session.run, policy, state, request)
	require.ErrorIs(t, err, ErrNeedsInput)
	require.Empty(t, result.Output)
	require.Equal(t, 1, *calls)
	key := Digest([]byte(request.TaskName + "\x00" + request.Prompt))
	require.Nil(t, state.Models[key].Output)
	require.NotEmpty(t, state.Models[key].UID, "retain only the accepted task identity for cleanup")
	artifacts, err := session.store.ListRemediationArtifacts(t.Context(), session.run.Namespace, session.run.ID)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)
	require.Equal(t, modelReceiptName(request.TaskName), artifacts[0].Name)
}

func TestControllerPipelineDisclosureRechecksCachedModelAndPatch(t *testing.T) {
	t.Parallel()
	pipeline, session, state, policy, clients, calls := disclosurePipelineFixture(t, `{}`)
	raw := []byte(`{"password":"example-value"}`)
	legacy, err := session.store.PutRemediationArtifact(t.Context(), session.run.Namespace, session.run.ID, session.owner, session.epoch,
		"legacy-content.json", "application/json", raw, time.Now())
	require.NoError(t, err)
	request := modelagent.Request{TaskName: "cached-model", Prompt: "Return one declarative check plan."}
	key := Digest([]byte(request.TaskName + "\x00" + request.Prompt))
	state.Models[key] = modelOperation{Name: request.TaskName, UID: "saved-task", Output: legacy, Retired: true}
	_, err = pipeline.generate(t.Context(), session, session.run, policy, state, request)
	require.ErrorIs(t, err, ErrNeedsInput)
	require.Zero(t, *clients)
	require.Zero(t, *calls)
	state.Attempts = []pipelineAttempt{{Patch: legacy}}
	err = pipeline.proposePatch(t.Context(), session, session.run, StoredRequest{Mode: Verify}, policy,
		investigate.Plan{}, ExecutionPlan{}, state, 0)
	require.ErrorIs(t, err, ErrNeedsInput)
}

func TestControllerPipelineDisclosureChecksWholeCandidate(t *testing.T) {
	t.Parallel()
	for _, mode := range []Mode{Verify, Generate} {
		t.Run(string(mode), func(t *testing.T) {
			pipeline, session, state, policy, clients, calls := disclosurePipelineFixture(t, `{}`)
			sourcePlan := investigate.Plan{Packet: source.Packet{Files: []source.PacketFile{{
				Path: "server.go", Content: "package server\n// https://user:example-value@example.invalid/source\nconst healthy = false\n",
			}}}}
			proposal := remediation.PatchProposal{
				Summary: "fix handler", Edits: []remediation.SourceEdit{{Path: "server.go", Old: "false", New: "true"}},
				DeclaredChanges: []pv.DeclaredChange{{Kind: "source", Paths: []string{"server.go"}, Description: "preserve normal behavior"}},
			}
			patch, err := remediation.CompilePatch(proposal, map[string][]byte{"server.go": []byte(sourcePlan.Packet.Files[0].Content)})
			require.NoError(t, err)
			require.ErrorIs(t, disclosure.Check(disclosure.Candidate, []byte(patch)), disclosure.ErrBlocked)
			state.Attempts = []pipelineAttempt{{Operation: executionOperation{ID: "candidate-0", Role: environment.Candidate}}}
			expectedArtifacts := 0
			if mode == Generate {
				raw, err := json.Marshal(proposal)
				require.NoError(t, err)
				_, err = remediation.DecodePatchProposal(string(raw))
				require.NoError(t, err)
				ref, err := session.Put(t.Context(), "safe-proposal.json", "application/json", raw)
				require.NoError(t, err)
				state.Attempts[0].Proposal = ref
				expectedArtifacts = 1
			}
			err = pipeline.proposePatch(t.Context(), session, session.run, StoredRequest{Mode: mode, Patch: patch},
				policy, sourcePlan, ExecutionPlan{}, state, 0)
			require.ErrorIs(t, err, ErrNeedsInput)
			require.Equal(t, ErrNeedsInput.Error(), err.Error())
			require.Nil(t, state.Attempts[0].Patch)
			require.Zero(t, *clients)
			require.Zero(t, *calls)
			artifacts, err := session.store.ListRemediationArtifacts(t.Context(), session.run.Namespace, session.run.ID)
			require.NoError(t, err)
			require.Len(t, artifacts, expectedArtifacts)
		})
	}
}

func TestControllerPipelineDisclosureAllowsSchemaAndCodeReferences(t *testing.T) {
	t.Parallel()
	for _, content := range []string{
		`{"password":{"type":"string"}}`,
		"package demo\nfunc options(info Config){ _ = Options{Password: info.Password} }\n",
	} {
		pipeline, session, state, policy, _, calls := disclosurePipelineFixture(t, content)
		result, err := pipeline.generate(t.Context(), session, session.run, policy, state,
			modelagent.Request{TaskName: "safe-model", Prompt: content})
		require.NoError(t, err)
		require.Equal(t, content, result.Output)
		require.Equal(t, 1, *calls)
	}
}

func TestControllerPipelineDisclosureKeepsPrivateBuildMetadataOutOfArtifacts(t *testing.T) {
	t.Parallel()
	pipeline, session, _, _, _, _ := disclosurePipelineFixture(t, `{}`)
	_, err := pipeline.putJSON(t.Context(), session, "build", environment.BuildResult{
		Baseline: provenance.Recipe{BuildEnvironment: map[string]string{"password": "example-value"}},
	})
	require.ErrorIs(t, err, ErrNeedsInput)
	artifacts, err := session.store.ListRemediationArtifacts(t.Context(), session.run.Namespace, session.run.ID)
	require.NoError(t, err)
	require.Empty(t, artifacts)
}
