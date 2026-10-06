package buildjob

import (
	"bytes"
	"encoding/json"
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrivateBaselineInputsRequireExactOperatorBinding(t *testing.T) {
	raw := []byte("--- a/test.conf\n+++ b/test.conf\n@@ -1 +1 @@\n-old\n+endpoint=https://fixture:nonsecret@example.invalid\n")
	f := newFixture(t)
	f.input.Files["vendor/baseline.patch"] = bytes.Clone(raw)
	require.Error(t, f.backend.ValidateInput(f.input), "ordinary build input screening remains strict")
	f.input.BuildOnlyInputs = map[string]string{"vendor/baseline.patch": digest(raw)}
	require.Error(t, f.backend.ValidateInput(f.input), "a caller cannot grant itself private-input authority")
	f.config.Policies[0].BuildOnlyInputs = maps.Clone(f.input.BuildOnlyInputs)
	_, err := New(f.config)
	require.Error(t, err, "private baseline input requires a separately authenticated registry")
	f.config.RegistrySecretName = "private-registry"
	f.backend, err = New(f.config)
	require.NoError(t, err)
	require.NoError(t, f.backend.ValidateInput(f.input))

	admitted, policy, err := f.backend.admit(f.input)
	require.NoError(t, err)
	bundle, err := f.backend.bundle(admitted, policy)
	require.NoError(t, err)
	manifest, restored, err := unpackBundle(bundle)
	require.NoError(t, err)
	require.Equal(t, raw, restored.Files["vendor/baseline.patch"])
	require.NotContains(t, string(bundle[manifestKey]), "fixture:nonsecret")
	require.Equal(t, admitted.InputDigest, restored.InputDigest)
	manifest.RegistrySecretName = ""
	bundle[manifestKey], err = json.Marshal(manifest)
	require.NoError(t, err)
	_, _, err = unpackBundle(bundle)
	require.Error(t, err, "worker-side validation must preserve the private boundary")

	for _, mutate := range []func(*Input){
		func(i *Input) { i.Files["vendor/baseline.patch"] = append(bytes.Clone(raw), '\n') },
		func(i *Input) { i.BuildOnlyInputs["vendor/baseline.patch"] = digest([]byte("replacement")) },
		func(i *Input) { i.Files["candidate.patch"] = bytes.Clone(raw) },
		func(i *Input) {
			i.Files["candidate.patch"] = bytes.Clone(raw)
			i.BuildOnlyInputs["candidate.patch"] = digest(raw)
		},
		func(i *Input) { i.BuildOnlyInputs[i.RecipePath] = digest(i.Files[i.RecipePath]) },
	} {
		input := f.input
		input.Files, input.BuildOnlyInputs = maps.Clone(f.input.Files), maps.Clone(f.input.BuildOnlyInputs)
		mutate(&input)
		require.Error(t, f.backend.ValidateInput(input), "changed or newly introduced bytes must never inherit baseline authority")
	}
}
