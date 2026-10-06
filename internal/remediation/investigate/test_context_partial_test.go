package investigate

import (
	"crypto/sha1" // Synthetic Git blob identity.
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

func TestLargeOptionalTestDoesNotDiscardSmallUsefulTests(t *testing.T) {
	entries := []source.Entry{
		{Path: "small.go", Mode: "100644", Size: 100},
		{Path: "large.go", Mode: "100644", Size: 100},
		{Path: "small_test.go", Mode: "100644", Size: 100},
		{Path: "large_test.go", Mode: "100644", Size: 2000},
	}
	config := Config{IncludeAdjacentGoTests: true, MaxFiles: 4, MaxPlanJSONBytes: 1000}
	paths, added, omitted := boundedTestContext(entries, []string{"large.go", "small.go"}, config)
	require.Equal(t, []string{"large.go", "small.go", "small_test.go"}, paths)
	require.Equal(t, []string{"small_test.go"}, added)
	require.Equal(t, []string{"large_test.go"}, omitted)
	require.True(t, testContextFits(entries, paths, config))
}

func TestEncodedOverflowRetainsOtherVerifiedTestFiles(t *testing.T) {
	config := fixtureConfig()
	config.IncludeAdjacentGoTests, config.MaxPlanJSONBytes = true, 8000
	repository := config.AllowedRepositoryRoots[0]
	client := fixtureSource(repository, "src/small.go")
	large := fixtureSource(repository, "src/large.go")
	smallTest := fixtureSource(repository, "src/small_test.go")
	largeTest := fixtureSource(repository, "src/large_test.go")
	content := strings.Repeat("<>&\n", 1024)
	blob := sha1.Sum(fmt.Appendf(nil, "blob %d\x00%s", len(content), content))
	sum := sha256.Sum256([]byte(content))
	largeTest.files[0].Content = content
	largeTest.files[0].BlobSHA, largeTest.files[0].SHA256 = hex.EncodeToString(blob[:]), hex.EncodeToString(sum[:])
	largeTest.entries[0].BlobSHA, largeTest.entries[0].Size = largeTest.files[0].BlobSHA, int64(len(content))
	for _, extra := range []*syntheticSource{large, smallTest, largeTest} {
		client.files = append(client.files, extra.files...)
		client.entries = append(client.entries, extra.entries...)
	}
	generator := &syntheticGenerator{outputs: []string{
		fixtureJSON(t, fixtureProposal(repository)), fixtureJSON(t, fixtureSelection("src/small.go", "src/large.go")),
	}}
	engine := Engine{Source: client, Generator: generator}
	report := fixtureReport(t)
	state := State{}
	for range 5 {
		state = stepFixture(t, engine, state, report, config)
	}
	require.Equal(t, Ready, state.Stage)
	require.Equal(t, []string{"src/small.go", "src/large.go", "src/small_test.go"}, state.SelectedPaths)
	require.Equal(t, []string{"src/small_test.go"}, state.AddedTestPaths)
	require.Equal(t, []string{"src/large_test.go"}, state.OmittedTestPaths)
	require.Equal(t, testContextEncodedBudget, state.TestContextOmission)
	require.Equal(t, []Stage{Resolving, Inventory, Packet}, client.operations)
	require.Len(t, generator.requests, 2)
	body, err := json.Marshal(state.Plan)
	require.NoError(t, err)
	require.LessOrEqual(t, len(body), config.MaxPlanJSONBytes)
	require.Equal(t, state, stepFixture(t, engine, state, report, config))
	state.OmittedTestPaths = []string{"src/small.go"}
	_, err = engine.Step(t.Context(), state, report, taskConfig(state, config))
	require.ErrorIs(t, err, ErrState, "required model paths cannot become omitted optional context")
}
