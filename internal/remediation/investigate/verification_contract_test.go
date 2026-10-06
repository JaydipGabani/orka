package investigate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceSelectionReceivesBoundedOperatorExpectationNotExecutionEvidence(t *testing.T) {
	config := fixtureConfig()
	repository := config.AllowedRepositoryRoots[0]
	config.SourceCatalog = []SourceCatalogEntry{{
		Repository: repository, Commit: strings.Repeat("c", 40), Version: "1.2.3",
		VerificationContract: "The namespace boundary must hold; real execution still needs independent verification.",
	}}
	normalized, _, err := normalizeConfig(config)
	require.NoError(t, err)
	report, err := reportData(fixtureReport(t))
	require.NoError(t, err)
	prompt, err := identifyPrompt(report, State{}, normalized)
	require.NoError(t, err)
	require.Contains(t, prompt, config.SourceCatalog[0].VerificationContract)
	require.Contains(t, prompt, "not proof of a vulnerability")
	require.Contains(t, prompt, "minimum triggering RBAC")
	config.SourceCatalog[0].VerificationContract = strings.Repeat("x", 4097)
	_, _, err = normalizeConfig(config)
	require.ErrorIs(t, err, ErrConfig)
}
