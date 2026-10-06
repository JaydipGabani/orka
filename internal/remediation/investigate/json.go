package investigate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

const maxProposalBytes = 128 << 10

var errProposal = errors.New("investigation model output is invalid, incomplete, or exceeds its bounds")

// DecodeProposal accepts only the exact, bounded JSON schema. Decoding is not
// evidence that a repository, version, build mapping, or model claim is correct.
func DecodeProposal(raw string) (Proposal, error) {
	var proposal Proposal
	if err := decodeStrict(raw, &proposal); err != nil {
		return Proposal{}, err
	}
	if !text(proposal.Problem, 32768, true) || !text(proposal.Trigger, 16384, false) ||
		!text(proposal.ExpectedBehavior, 16384, false) || len(proposal.Targets) > 4 ||
		!stringList(proposal.Missing, 32, 4096) || !stringList(proposal.Limitations, 32, 4096) ||
		!stringList(proposal.LanguageHints, 16, 256) || !stringList(proposal.BuildHints, 16, 1024) ||
		!stringList(proposal.DownstreamEvidenceRequired, 8, 1024) ||
		!validRequirements(proposal.Requirements) {
		return Proposal{}, errProposal
	}
	if proposal.Scope != upstreamSource && proposal.Scope != ScopeDownstream && proposal.Scope != ScopeUnknown {
		return Proposal{}, errProposal
	}
	if proposal.VersionStatus != versionSingle && proposal.VersionStatus != "ambiguous" && proposal.VersionStatus != "unknown" {
		return Proposal{}, errProposal
	}
	for _, target := range proposal.Targets {
		if canonicalRepository(target.Repository) == "" || !validRef(target.Ref) || !text(target.Reason, 8192, true) {
			return Proposal{}, errProposal
		}
	}
	if len(proposal.Targets) == 0 && len(proposal.Missing) == 0 {
		return Proposal{}, errProposal
	}
	return proposal, nil
}

func DecodeSelection(raw string) (Selection, error) {
	var selection Selection
	if err := decodeStrict(raw, &selection); err != nil {
		return Selection{}, err
	}
	if len(selection.Paths) > 32 || len(selection.Expand) > 32 ||
		!stringList(selection.Missing, 32, 4096) || !stringList(selection.Limitations, 32, 4096) {
		return Selection{}, errProposal
	}
	actions := 0
	for _, present := range []bool{len(selection.Paths) != 0, len(selection.Expand) != 0, selection.NextPage} {
		if present {
			actions++
		}
	}
	if actions > 1 || (actions == 0 && len(selection.Missing) == 0) {
		return Selection{}, errProposal
	}
	if !validPaths(selection.Paths) || !validPaths(selection.Expand) {
		return Selection{}, errProposal
	}
	return selection, nil
}

func decodeStrict(raw string, destination any) error {
	content := []byte(raw)
	if len(content) == 0 || len(content) > maxProposalBytes || !utf8.Valid(content) ||
		!validUnicodeEscapes(raw) || (pv.CredentialMatcher{}).Match(content) {
		return errProposal
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	if !uniqueValue(decoder, 0) {
		return errProposal
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errProposal
	}
	if !exactShape(content, reflect.TypeOf(destination).Elem()) || json.Unmarshal(content, destination) != nil {
		return errProposal
	}
	return nil
}

func uniqueValue(decoder *json.Decoder, depth int) bool {
	if depth > 12 {
		return false
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return false
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return depth != 0
	}
	if depth == 0 && delimiter != '{' {
		return false
	}
	keys := make(map[string]bool)
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok || keys[strings.ToLower(name)] {
				return false
			}
			keys[strings.ToLower(name)] = true
		}
		if !uniqueValue(decoder, depth+1) {
			return false
		}
	}
	end, err := decoder.Token()
	return err == nil && ((delimiter == '{' && end == json.Delim('}')) || (delimiter == '[' && end == json.Delim(']')))
}

// encoding/json accepts case-folded struct names and missing fields. The model
// boundary does not: every non-omitempty field must appear with its exact name.
func exactShape(data []byte, schema reflect.Type) bool {
	switch schema.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(data, &fields) != nil || fields == nil {
			return false
		}
		for field := range schema.Fields() {
			name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
			value, found := fields[name]
			if !found {
				if options == "omitempty" {
					continue
				}
				return false
			}
			if !exactShape(value, field.Type) {
				return false
			}
			delete(fields, name)
		}
		return len(fields) == 0
	case reflect.Slice:
		var elements []json.RawMessage
		if json.Unmarshal(data, &elements) != nil || elements == nil {
			return false
		}
		for _, element := range elements {
			if !exactShape(element, schema.Elem()) {
				return false
			}
		}
		return true
	default:
		return !bytes.Equal(bytes.TrimSpace(data), []byte("null"))
	}
}

func validUnicodeEscapes(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			continue
		}
		index++
		if index >= len(value) || value[index] != 'u' {
			continue
		}
		if index+4 >= len(value) {
			return false
		}
		code, err := strconv.ParseUint(value[index+1:index+5], 16, 16)
		if err != nil {
			return false
		}
		index += 4
		if code < 0xd800 || code > 0xdfff {
			continue
		}
		if code > 0xdbff || index+6 >= len(value) || value[index+1:index+3] != `\u` {
			return false
		}
		low, err := strconv.ParseUint(value[index+3:index+7], 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		index += 6
	}
	return true
}
