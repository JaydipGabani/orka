package buildjob

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	manifestKey = "manifest.json"
	archiveKey  = "files.tar.gz"
)

type manifest struct {
	Version             int      `json:"version"`
	Namespace           string   `json:"namespace"`
	ConfigurationDigest string   `json:"configurationDigest"`
	Input               Input    `json:"input"`
	SourcePaths         []string `json:"sourcePaths,omitempty"`
	BuildKitAddress     string   `json:"buildKitAddress"`
	TLS                 *TLS     `json:"tls,omitempty"`
	RegistrySecretName  string   `json:"registrySecretName,omitempty"`
	Limits              Limits   `json:"limits"`
}

func (b *Backend) bundle(input Input, policy Policy) (map[string][]byte, error) {
	m := manifest{
		Version: Version, Namespace: b.config.Namespace, ConfigurationDigest: b.digest,
		Input: input, SourcePaths: policy.SourcePaths, BuildKitAddress: b.config.BuildKitAddress,
		TLS: b.config.TLS, RegistrySecretName: b.config.RegistrySecretName, Limits: b.config.Limits,
	}
	m.Input.Files = nil
	m.Input.ExpectedJobUID, m.Input.RequireExisting = "", false
	body, err := json.Marshal(m)
	if err != nil || len(body) > 64<<10 {
		return nil, failure(ErrLimit, "build-manifest-size-limit")
	}
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	archive := tar.NewWriter(zip)
	names := make([]string, 0, len(input.Files))
	for name := range input.Files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		raw := input.Files[name]
		header := &tar.Header{
			Name: name, Size: int64(len(raw)), Mode: 0600, Typeflag: tar.TypeReg,
			ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR,
		}
		if archive.WriteHeader(header) != nil {
			return nil, failure(ErrInvalid, "unsupported-archive-path")
		}
		if _, err := archive.Write(raw); err != nil {
			return nil, failure(ErrInvalid, "build-archive-write-failed")
		}
	}
	if archive.Close() != nil || zip.Close() != nil {
		return nil, failure(ErrInvalid, "build-archive-close-failed")
	}
	if len(body)+compressed.Len() > b.config.Limits.MaxInputBytes {
		return nil, failure(ErrLimit, "build-secret-size-limit")
	}
	return map[string][]byte{manifestKey: body, archiveKey: compressed.Bytes()}, nil
}

func unpackBundle(data map[string][]byte) (manifest, Input, error) {
	var m manifest
	if len(data) != 2 || len(data[manifestKey]) == 0 || len(data[manifestKey]) > 64<<10 ||
		len(data[manifestKey])+len(data[archiveKey]) > MaxInputBytes ||
		decodeStrict(data[manifestKey], &m) != nil || m.Version != Version ||
		!digestPattern.MatchString(m.ConfigurationDigest) || !digestPattern.MatchString(m.Input.InputDigest) ||
		m.Input.Files != nil || m.Input.RequireExisting || m.Input.ExpectedJobUID != "" {
		return m, Input{}, failure(ErrIdentity, "invalid-build-bundle")
	}
	if validateLimits(m.Limits) != nil || validateEndpoint(m.Namespace, m.BuildKitAddress, m.TLS) != nil ||
		(len(m.Input.BuildOnlyInputs) != 0 && m.RegistrySecretName == "") ||
		len(data[manifestKey])+len(data[archiveKey]) > m.Limits.MaxInputBytes || len(m.SourcePaths) > 512 {
		return m, Input{}, failure(ErrIdentity, "invalid-build-bundle-policy")
	}
	for _, name := range m.SourcePaths {
		if SourcePath(name) != nil {
			return m, Input{}, failure(ErrIdentity, "invalid-diagnostic-source-path")
		}
	}
	files, err := unpackArchive(data[archiveKey], m.Limits)
	if err != nil {
		return m, Input{}, err
	}
	input := m.Input
	input.Files = files
	if validateInput(input, m.Limits) != nil {
		return m, Input{}, failure(ErrIdentity, "build-bundle-digest-or-input-mismatch")
	}
	return m, input, nil
}

func unpackArchive(body []byte, limits Limits) (map[string][]byte, error) {
	source := bytes.NewReader(body)
	zip, err := gzip.NewReader(source)
	if err != nil {
		return nil, failure(ErrIdentity, "invalid-build-archive")
	}
	defer func() { _ = zip.Close() }()
	zip.Multistream(false)
	// Bound decompressed tar headers and payloads too, not just file contents.
	bounded := &io.LimitedReader{R: zip, N: int64(limits.MaxInputBytes + limits.MaxFiles*1024 + 2048)}
	archive := tar.NewReader(bounded)
	files := make(map[string][]byte)
	total := 0
	for {
		entry, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || entry.Typeflag != tar.TypeReg || entry.Linkname != "" ||
			entry.Mode != 0600 || entry.Uid != 0 || entry.Gid != 0 || len(entry.PAXRecords) != 0 ||
			SourcePath(entry.Name) != nil || entry.Size < 0 || entry.Size > int64(limits.MaxFileBytes) ||
			len(files) >= limits.MaxFiles {
			return nil, failure(ErrIdentity, "unsafe-build-archive-entry")
		}
		if _, exists := files[entry.Name]; exists {
			return nil, failure(ErrIdentity, "duplicate-build-archive-entry")
		}
		total += len(entry.Name) + int(entry.Size)
		if total > limits.MaxInputBytes {
			return nil, failure(ErrLimit, "decompressed-build-input-size-limit")
		}
		content, err := io.ReadAll(io.LimitReader(archive, entry.Size+1))
		if err != nil || len(content) != int(entry.Size) {
			return nil, failure(ErrIdentity, "truncated-build-archive-entry")
		}
		files[entry.Name] = content
	}
	// Consume the gzip trailer, rejecting concatenated streams and trailing
	// payloads that were not part of the authenticated file map.
	trailer, err := io.ReadAll(bounded)
	if err != nil || bounded.N == 0 || len(trailer) != 0 || source.Len() != 0 {
		return nil, failure(ErrIdentity, "trailing-or-oversized-build-archive")
	}
	return files, nil
}

func offlineRecipe(raw []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if decoder.Decode(&document) != nil || len(document.Content) != 1 ||
		document.Content[0].Kind != yaml.MappingNode || validateYAML(document.Content[0]) != nil {
		return failure(ErrInvalid, "unambiguous-dalec-recipe-required")
	}
	var extra yaml.Node
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return failure(ErrInvalid, "single-dalec-recipe-required")
	}
	build := yamlField(document.Content[0], "build")
	network := yamlField(build, "network_mode")
	// The operator-approved, pinned Dalec frontend defaults build networking to
	// none. Preserve those exact recipe bytes instead of inserting a field that
	// changes provenance; any explicit override must still be none.
	if build == nil || build.Kind != yaml.MappingNode || (network != nil &&
		(network.Kind != yaml.ScalarNode || network.Tag != "!!str" || network.Value != "none")) {
		return failure(ErrInvalid, "dalec-build-network-none-required")
	}
	return nil
}

func validateYAML(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return failure(ErrInvalid, "dalec-aliases-unsupported")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]bool)
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] {
				return failure(ErrInvalid, "ambiguous-dalec-mapping")
			}
			seen[key.Value] = true
			if key.Value == "network_mode" && (value.Kind != yaml.ScalarNode || value.Value != "none") {
				return failure(ErrInvalid, "dalec-build-network-must-be-none")
			}
			if key.Value == "caches" && (len(value.Content) != 0 || value.Kind == yaml.ScalarNode) {
				return failure(ErrInvalid, "shared-build-cache-mounts-unsupported")
			}
		}
	}
	for _, child := range node.Content {
		if err := validateYAML(child); err != nil {
			return err
		}
	}
	return nil
}

func yamlField(node *yaml.Node, name string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == name {
			return node.Content[i+1]
		}
	}
	return nil
}

func decodeStrict(body []byte, value any) error {
	duplicateCheck := json.NewDecoder(bytes.NewReader(body))
	if err := jsonValue(duplicateCheck); err != nil {
		return err
	}
	if _, err := duplicateCheck.Token(); !errors.Is(err, io.EOF) {
		return failure(ErrInvalid, "trailing-json-value")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func jsonValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	keys := make(map[string]bool)
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return failure(ErrInvalid, "duplicate-json-key")
			}
			keys[name] = true
		}
		if err := jsonValue(decoder); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
