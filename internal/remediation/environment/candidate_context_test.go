package environment

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestGeneratedCandidateUsesDalecDirectoryPatchSubpath(t *testing.T) {
	f := testFixture(t)
	adapter, err := newAdapter(f.config)
	require.NoError(t, err)
	snapshot, err := adapter.recipeSnapshot(BuildRequest{
		Plan: f.plans[0], Role: Candidate, Patch: candidatePatch(), PatchDigest: digest(candidatePatch()),
	})
	require.NoError(t, err)
	var tree yaml.Node
	require.NoError(t, yaml.Unmarshal(snapshot.files[f.plans[0].Bind.Recipe.Path], &tree))
	source := snapshot.built.UpstreamSource
	series := yamlValue(yamlValue(tree.Content[0], "patches"), source)
	added := series.Content[len(series.Content)-1]
	name := yamlValue(added, "source").Value
	patchPath := yamlValue(added, "path")
	require.NotNil(t, patchPath, "Dalec context sources are directories and require a patch subpath")
	require.Equal(t, candidatePatch(), snapshot.files[patchPath.Value])
	context := yamlValue(yamlValue(tree.Content[0], "sources"), name)
	require.NotNil(t, yamlValue(context, "context"))
	require.Nil(t, yamlValue(context, "path"))
	include := yamlValue(context, "includes")
	require.NotNil(t, include)
	require.Len(t, include.Content, 1)
	require.Equal(t, patchPath.Value, include.Content[0].Value)
}
