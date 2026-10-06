package provenance

import "errors"

// InputDisposition is a disclosure restriction, never a declaration that a
// credential-looking value is synthetic or safe. Matched content is not returned.
type InputDisposition struct {
	Path           string `json:"path"`
	Digest         string `json:"digest"`
	Classification string `json:"classification"`
}

// PrivateBuildInputs preserves exact opaque patch inputs without conflating
// identity parsing with disclosure. BuildOnly entries must not reach models,
// logs or outgoing artifacts. Callers must independently enforce private build
// storage, credential separation, and network-isolated candidate execution.
type PrivateBuildInputs struct {
	Recipe    Recipe             `json:"recipe"`
	BuildOnly []InputDisposition `json:"buildOnly,omitempty"`
}

// InspectPrivateBuildInputs never authorizes code execution or disclosure.
// Recipe fields/URLs/environment remain strictly screened; only referenced,
// digest-bound opaque patch bytes can be retained under BuildOnly restrictions.
// ParseDalec remains the strict, disclosure-safe compatibility entrypoint.
func InspectPrivateBuildInputs(spec []byte, files map[string][]byte, metadata Metadata) (PrivateBuildInputs, error) {
	if err := validateInputStructure(spec, files, metadata); err != nil {
		return PrivateBuildInputs{}, err
	}
	recipe, err := parseDalec(spec, files, metadata)
	if err != nil {
		return PrivateBuildInputs{}, err
	}
	result := PrivateBuildInputs{Recipe: recipe}
	for _, patch := range recipe.OrderedPatches {
		expected, exists := metadata.ExpectedDigests[patch.Path]
		if !exists || expected != patch.Digest {
			return PrivateBuildInputs{}, errors.New("private patch inputs require an independently supplied exact digest")
		}
		if credentialText(string(files[patch.Path])) {
			result.BuildOnly = append(result.BuildOnly, InputDisposition{
				Path: patch.Path, Digest: patch.Digest, Classification: "credential-shaped-content-not-approved-for-disclosure",
			})
		}
	}
	return result, nil
}
