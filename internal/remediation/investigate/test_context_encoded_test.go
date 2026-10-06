package investigate

import (
	"crypto/sha1" // Synthetic Git object identity, matching the source contract.
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodedPlanBudgetDropsOnlyVerifiedOptionalTests(t *testing.T) {
	config := fixtureConfig()
	config.IncludeAdjacentGoTests, config.MaxPlanJSONBytes = true, 8000
	repository := config.AllowedRepositoryRoots[0]
	client := fixtureSource(repository, "src/file.go")
	companion := fixtureSource(repository, "src/file_test.go")
	content := strings.Repeat("<>&\n", 1024)
	blob := sha1.Sum(fmt.Appendf(nil, "blob %d\x00%s", len(content), content))
	sum := sha256.Sum256([]byte(content))
	companion.files[0].Content = content
	companion.files[0].BlobSHA = hex.EncodeToString(blob[:])
	companion.files[0].SHA256 = hex.EncodeToString(sum[:])
	companion.entries[0].BlobSHA = companion.files[0].BlobSHA
	companion.entries[0].Size = int64(len(content))
	client.files = append(client.files, companion.files...)
	client.entries = append(client.entries, companion.entries...)
	require.Less(t, len(content)+len(client.files[0].Content), config.MaxPlanJSONBytes)
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, fixtureSelection("src/file.go")),
	}}
	engine := Engine{Source: client, Generator: generator}
	report := fixtureReport(t)
	state := State{}
	for range 5 {
		state = stepFixture(t, engine, state, report, config)
	}
	require.Equal(t, Ready, state.Stage)
	require.Equal(t, testContextEncodedBudget, state.TestContextOmission)
	require.Equal(t, []string{"src/file.go"}, state.SelectedPaths)
	require.Equal(t, []string{"src/file_test.go"}, state.OmittedTestPaths)
	require.Empty(t, state.AddedTestPaths)
	require.Equal(t, client.files[:1], state.Plan.Packet.Files)
	raw, err := json.Marshal(state.Plan)
	require.NoError(t, err)
	require.LessOrEqual(t, len(raw), config.MaxPlanJSONBytes)
	full := *state.Plan
	full.Packet.Files = client.files
	raw, err = json.Marshal(full)
	require.NoError(t, err)
	require.Greater(t, len(raw), config.MaxPlanJSONBytes)
	require.Equal(t, []Stage{Resolving, Inventory, Packet}, client.operations,
		"an already verified packet subset must not spend another API request")
	require.Len(t, generator.requests, 2)
	require.Equal(t, state, stepFixture(t, engine, state, report, config))
}
