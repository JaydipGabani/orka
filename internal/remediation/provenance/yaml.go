package provenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const (
	yamlStringTag = "!!str"
	yamlNullTag   = "!!null"
)

func readSpec(spec []byte, platform string) (*yaml.Node, map[string]string, error) {
	root, err := readDocument(spec)
	if err != nil {
		return nil, nil, err
	}
	args, err := readArguments(mappingValue(root, "args"), platform)
	if err != nil {
		return nil, nil, err
	}
	remaining := MaxSpecBytes
	if err := resolveNode(root, args, nil, &remaining); err != nil {
		return nil, nil, err
	}
	return root, args, nil
}

// ValidateDalecBuildArguments checks the bounded YAML structure and effective
// declared arguments without expanding commands or authorizing build execution.
// It does not inspect patch bytes or replace complete recipe provenance checks.
func ValidateDalecBuildArguments(spec []byte, platform string) error {
	root, err := readDocument(spec)
	if err != nil {
		return err
	}
	_, err = readArguments(mappingValue(root, "args"), platform)
	return err
}

func readDocument(spec []byte) (*yaml.Node, error) {
	if len(spec) == 0 || len(spec) > MaxSpecBytes || !utf8.Valid(spec) {
		return nil, errors.New("provenance recipe is empty, oversized, or not UTF-8")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(spec))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("provenance contains invalid YAML")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("provenance requires exactly one YAML document")
	}
	count := 0
	if err := validateNode(&document, 0, &count, nil); err != nil {
		return nil, err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("provenance recipe must be a YAML mapping")
	}
	return document.Content[0], nil
}

func validateNode(node *yaml.Node, depth int, count *int, location []string) error {
	*count++
	if depth > maxYAMLDepth || *count > maxYAMLNodes {
		return errors.New("provenance YAML exceeds the structural limit")
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode || node.Tag == "!!merge" {
		return errors.New("provenance does not support YAML aliases, anchors, or merges")
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.MappingNode, yaml.SequenceNode:
		if node.Kind != yaml.DocumentNode && node.Tag != "!!map" && node.Tag != "!!seq" {
			return errors.New("provenance contains an unsupported YAML tag")
		}
	case yaml.ScalarNode:
		if err := validateScalar(node, location); err != nil {
			return err
		}
	default:
		return errors.New("provenance contains an unsupported YAML node")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]bool, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			value := node.Content[index+1]
			canonical := strings.ToLower(key.Value)
			if key.Kind != yaml.ScalarNode || key.Tag != yamlStringTag || len(key.Value) > maxPathSize ||
				strings.ContainsAny(key.Value, "$`") || seen[canonical] {
				return errors.New("provenance contains duplicate or unsupported YAML keys")
			}
			if value.Kind == yaml.ScalarNode && value.Tag != yamlNullTag && value.Value != "" && sensitiveName(key.Value) {
				return errors.New("provenance contains a credential-bearing YAML field")
			}
			seen[canonical] = true
		}
	}
	for index, child := range node.Content {
		childLocation := location
		if node.Kind == yaml.MappingNode && index%2 == 1 {
			childLocation = append(location, node.Content[index-1].Value)
		} else if node.Kind == yaml.SequenceNode {
			childLocation = append(location, "[]")
		}
		if err := validateNode(child, depth+1, count, childLocation); err != nil {
			return err
		}
	}
	return nil
}

func validateScalar(node *yaml.Node, location []string) error {
	if !safeText(node.Value, maxScalarSize) {
		return errors.New("provenance contains an unsafe or oversized YAML scalar")
	}
	if buildCommandLocation(location) {
		if node.Tag != yamlStringTag {
			return errors.New("provenance build commands must be literal strings")
		}
		return validateBuildCommand(node.Value)
	}
	switch node.Tag {
	case yamlStringTag, "!!int", "!!bool":
		return nil
	case yamlNullTag:
		if !allowedNull(location) {
			return errors.New("provenance null is not an argument declaration or package constraint")
		}
		switch node.Value {
		case "", "~", "null", "Null", "NULL":
			return nil
		}
	}
	return errors.New("provenance contains an unsupported YAML scalar type")
}

func allowedNull(location []string) bool {
	if len(location) == 2 && location[0] == "args" {
		return targetPlatformArgument(location[1])
	}
	if len(location) == 5 && location[0] == "targets" {
		location = location[2:]
	}
	if len(location) != 3 || location[0] != "dependencies" {
		return false
	}
	switch location[1] {
	case "build", "runtime", "test":
		return location[2] != ""
	default:
		return false
	}
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

func readArguments(node *yaml.Node, platform string) (map[string]string, error) {
	args := make(map[string]string)
	if node == nil {
		return args, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, errors.New("provenance arguments must be a mapping")
	}
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index].Value
		value := node.Content[index+1]
		literal := value.Tag == yamlStringTag || value.Tag == "!!int"
		declaration := value.Tag == yamlNullTag && targetPlatformArgument(key)
		if value.Kind != yaml.ScalarNode ||
			(!literal && !declaration) ||
			strings.ContainsAny(value.Value, "$`") {
			return nil, errors.New("provenance arguments must be literal strings or integers")
		}
		resolved, err := argumentValue(key, value, platform)
		if err != nil {
			return nil, err
		}
		args[key] = resolved
	}
	if err := safeVariables(args); err != nil {
		return nil, err
	}
	return args, nil
}

func targetPlatformArgument(key string) bool {
	return key == "TARGETARCH" || key == "TARGETOS" || key == "TARGETPLATFORM"
}

func argumentValue(key string, value *yaml.Node, platform string) (string, error) {
	switch key {
	case "BUILDOS", "BUILDARCH", "BUILDPLATFORM", "BUILDVARIANT", "TARGETVARIANT":
		return "", errors.New("provenance cannot infer build platform or variant arguments")
	}
	if !targetPlatformArgument(key) {
		return value.Value, nil
	}
	// These are the two canonical platforms admitted by the build backend.
	// Do not guess normalization, variants, or the builder's own architecture.
	if platform != "linux/amd64" && platform != "linux/arm64" {
		return "", errors.New("provenance platform arguments require a supported explicit target platform")
	}
	os, arch, _ := strings.Cut(platform, "/")
	expected := platform
	switch key {
	case "TARGETOS":
		expected = os
	case "TARGETARCH":
		expected = arch
	}
	if value.Tag != yamlNullTag && value.Value != "" && value.Value != expected {
		return "", errors.New("provenance platform argument default conflicts with the selected platform")
	}
	return expected, nil
}

func resolveNode(node *yaml.Node, args map[string]string, location []string, remaining *int) error {
	if len(location) == 1 && location[0] == "args" {
		return nil
	}
	// Dalec substitutes step environments, not shell command text. Keep the
	// approved command verbatim in the base digest, including shell variables.
	if buildCommandLocation(location) {
		*remaining -= len(node.Value)
		if *remaining < 0 {
			return errors.New("provenance commands exceed the aggregate limit")
		}
		return nil
	}
	// Patch bytes are never expanded or repaired.
	if len(location) == 5 && location[0] == "sources" && location[2] == "inline" &&
		location[3] == "file" && location[4] == "contents" {
		return nil
	}
	switch node.Kind {
	case yaml.MappingNode:
		for index := 0; index < len(node.Content); index += 2 {
			if err := resolveNode(node.Content[index+1], args, append(location, node.Content[index].Value), remaining); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := resolveNode(child, args, append(location, "[]"), remaining); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if node.Tag == yamlStringTag {
			resolved, err := resolve(node.Value, args)
			if err != nil {
				return err
			}
			if !safeText(resolved, maxScalarSize) {
				return errors.New("provenance substitution produced unsafe content")
			}
			*remaining -= len(resolved)
			if *remaining < 0 {
				return errors.New("provenance substitution exceeds the aggregate limit")
			}
			node.Value = resolved
		}
	}
	return nil
}

func decodeStrict(root *yaml.Node, destination any) error {
	data, err := yaml.Marshal(root)
	if err != nil {
		return errors.New("provenance YAML could not be normalized")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return errors.New("provenance contains unexpected YAML fields or unsupported field types")
	}
	return nil
}

// The v2 base digest is sha256 of domain-separated, canonical JSON of the
// resolved YAML tree, excluding only patch declarations and local patch sources.
// Scalar tags are retained, mapping keys are JSON-sorted and sequences retain
// order. Unlike v1, build commands are verbatim, not argument-expanded.
func baseDigest(root *yaml.Node, patchSources map[string]bool) (string, error) {
	value := make(map[string]any, len(root.Content)/2)
	for index := 0; index < len(root.Content); index += 2 {
		key, child := root.Content[index].Value, root.Content[index+1]
		switch key {
		case "patches":
			continue
		case "sources":
			sources := make(map[string]any)
			for sourceIndex := 0; sourceIndex < len(child.Content); sourceIndex += 2 {
				name := child.Content[sourceIndex].Value
				if !patchSources[name] {
					sources[name] = canonicalYAML(child.Content[sourceIndex+1])
				}
			}
			value[key] = sources
		default:
			value[key] = canonicalYAML(child)
		}
	}
	data, err := json.Marshal(struct {
		Domain string         `json:"domain"`
		Spec   map[string]any `json:"spec"`
	}{Domain: "orka.build-provenance.base.v2", Spec: value})
	if err != nil {
		return "", errors.New("provenance base inputs could not be digested")
	}
	return digestBytes(data), nil
}

func canonicalYAML(node *yaml.Node) any {
	switch node.Kind {
	case yaml.MappingNode:
		values := make(map[string]any, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			values[node.Content[index].Value] = canonicalYAML(node.Content[index+1])
		}
		return values
	case yaml.SequenceNode:
		values := make([]any, len(node.Content))
		for index, child := range node.Content {
			values[index] = canonicalYAML(child)
		}
		return values
	default:
		return []string{node.Tag, node.Value}
	}
}
