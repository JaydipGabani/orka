package investigate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExactContractAllowsReadingSourceWhilePreservingOpenQuestions(t *testing.T) {
	config := fixtureConfig()
	config.AllowDownstreamSourceInvestigation = true
	repository := config.AllowedRepositoryRoots[0]
	client := fixtureSource(repository, "src/file.go")
	client.target.Ref = client.target.Commit
	config.SourceCatalog = []SourceCatalogEntry{{
		Repository: repository, Commit: client.target.Commit, Version: "1.2.3", VerificationContract: "Preserve the declared namespace boundary.",
	}}
	proposal := fixtureProposal(repository)
	proposal.Scope, proposal.Targets[0].Ref = ScopeDownstream, client.target.Commit
	proposal.Missing = []string{"Confirm the reported source behavior and minimum triggering permissions."}
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, proposal), fixtureJSON(t, fixtureSelection("src/file.go")),
	}}
	engine := Engine{Source: client, Generator: generator}
	report := fixtureReport(t)
	state := State{}
	for range 5 {
		state = stepFixture(t, engine, state, report, config)
	}
	require.Equal(t, Ready, state.Stage, "the source must be readable before source-dependent questions can be answered")
	require.Equal(t, proposal.Missing, state.Plan.Missing, "open questions must not be erased or labeled proven")
	require.NotEmpty(t, state.Plan.EvidenceRequired, "source inspection does not authorize a downstream execution")
	require.Equal(t, client.target, state.Plan.Target)
	require.Equal(t, []Stage{Resolving, Inventory, Packet}, client.operations)
	require.Contains(t, generator.requests[1].Prompt, "unverifiedClaims.missing lists open questions that reading source should answer")
	require.Contains(t, generator.requests[1].Prompt, "Use missing only when the needed source is absent from the inventory")
}

func TestOpenQuestionsRemainBlockingWithoutAnExactOperatorContract(t *testing.T) {
	for _, mismatch := range []string{"missing-contract", "different-commit", "tag-only", "unknown-version", "ambiguous-target"} {
		config := fixtureConfig()
		config.AllowDownstreamSourceInvestigation = true
		repository := config.AllowedRepositoryRoots[0]
		proposal := fixtureProposal(repository)
		proposal.Scope, proposal.Targets[0].Ref = ScopeDownstream, strings.Repeat("c", 40)
		proposal.Missing = []string{"Source inspection is still required."}
		config.SourceCatalog = []SourceCatalogEntry{{
			Repository: repository, Commit: strings.Repeat("c", 40), Version: "1.2.3", VerificationContract: "Synthetic expected boundary.",
		}}
		switch mismatch {
		case "missing-contract":
			config.SourceCatalog[0].VerificationContract = ""
		case "different-commit":
			config.SourceCatalog[0].Commit = strings.Repeat("d", 40)
		case "tag-only":
			proposal.Targets[0].Ref = "v1.2.3"
		case "unknown-version":
			proposal.VersionStatus = "unknown"
		case "ambiguous-target":
			proposal.Targets = append(proposal.Targets, proposal.Targets[0])
		}
		generator := &syntheticGenerator{outputs: []string{fixtureJSON(t, proposal)}}
		state := stepFixture(t, Engine{Generator: generator}, State{}, fixtureReport(t), config)
		require.NotEqual(t, Resolving, state.Stage, mismatch)
	}
}
