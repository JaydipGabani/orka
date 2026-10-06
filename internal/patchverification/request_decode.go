package patchverification

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

func DecodeRequestJSON(content []byte) (Request, error) {
	var request Request
	if len(content) > MaxManifestBytes || !utf8.Valid(content) {
		return request, errors.New("request must be valid UTF-8 JSON of at most 1 MiB")
	}
	if err := uniqueRequestJSON(json.NewDecoder(bytes.NewReader(content)), 0); err != nil {
		return request, errors.New("request must contain one JSON object without duplicate fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, errors.New("invalid request JSON or unknown field")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return request, errors.New("trailing request JSON is forbidden")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		return request, errors.New("invalid request fields")
	}
	request.ProvidedFields = make(map[string]bool, len(fields))
	validFields := make(map[string]bool)
	for field := range reflect.TypeFor[Request]().Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			validFields[name] = true
		}
	}
	for field := range fields {
		if !validFields[field] {
			return request, errors.New("request fields must use their canonical JSON names")
		}
		request.ProvidedFields[field] = true
	}
	if err := ValidateRequestAction(request); err != nil {
		return request, err
	}
	if request.EarlierValidation == "" && (strings.TrimSpace(request.Problem) == "" || len(request.Scope) == 0 ||
		request.Repository == "" || request.ChecksDir == "" || len(request.Checks) == 0 ||
		!gitIdentityPattern.MatchString(request.OriginalCommit)) {
		return request, errors.New("problem, scope, repository, exact original commit, checksDir, and checks are required")
	}
	for _, commit := range []string{request.OriginalCommit, request.PatchedCommit} {
		if commit != "" && !gitIdentityPattern.MatchString(commit) {
			return request, errors.New("commit must be an exact commit identity")
		}
	}
	return request, nil
}

func MatchLinkedRequest(request Request, manifest Manifest) error {
	fields := []struct {
		name     string
		supplied any
		frozen   any
	}{
		{"problem", request.Problem, manifest.Problem},
		{"scope", request.Scope, manifest.Scope},
		{"gaps", request.Gaps, manifest.Gaps},
		{"repository", request.Repository, manifest.Sources.Repository},
		{"originalCommit", request.OriginalCommit, manifest.Sources.Original.Commit},
		{"image", request.Image, manifest.Environment.Image},
		{"platform", request.Platform, manifest.Environment.Platform},
		{"profile", request.Profile, manifest.Environment.Profile},
		{"variables", request.Variables, manifest.Environment.Variables},
		{"dependencies", request.Dependencies, manifest.Environment.Dependencies},
		{"services", request.Services, manifest.Environment.Services},
		{"requiredEnvironment", request.RequiredEnvironment, manifest.Environment.Requirements},
		{"checks", request.Checks, manifest.Checks},
	}
	for _, field := range fields {
		provided := request.ProvidedFields[field.name] || !reflect.ValueOf(field.supplied).IsZero()
		if provided && !reflect.DeepEqual(field.supplied, field.frozen) {
			return errors.New("supplied " + field.name + " differs from the earlier frozen validation")
		}
	}
	return nil
}

func HydrateLinkedRequest(request Request, manifest Manifest) Request {
	request.Problem, request.Scope, request.Gaps = manifest.Problem, manifest.Scope, manifest.Gaps
	request.Repository, request.OriginalCommit = manifest.Sources.Repository, manifest.Sources.Original.Commit
	environment := manifest.Environment
	request.Image, request.Platform, request.Profile = environment.Image, environment.Platform, environment.Profile
	request.Variables, request.Dependencies, request.Services = environment.Variables, environment.Dependencies, environment.Services
	request.RequiredEnvironment, request.Checks = environment.Requirements, manifest.Checks
	return request
}

func uniqueRequestJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		if depth == 0 {
			return errors.New("expected object")
		}
		return nil
	}
	if depth == 0 && delimiter != '{' {
		return errors.New("expected object")
	}
	keys := make(map[string]bool)
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			// encoding/json matches struct fields case-insensitively.
			canonical := strings.ToLower(name)
			if !ok || keys[canonical] {
				return errors.New("duplicate or invalid field")
			}
			keys[canonical] = true
		}
		if err := uniqueRequestJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
