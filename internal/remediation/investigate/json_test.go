package investigate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProposalStrictJSONAndBounds(t *testing.T) {
	valid := fixtureJSON(t, fixtureProposal(fixtureConfig().AllowedRepositoryRoots[0]))
	proposal, err := DecodeProposal(valid)
	require.NoError(t, err)
	require.NotEmpty(t, proposal.Problem)
	for name, invalid := range map[string]string{
		"empty":                "",
		"array":                "[" + valid + "]",
		"truncated":            valid[:len(valid)-1],
		"trailing":             valid + "\n{}",
		"markdown":             "```json\n" + valid + "\n```",
		"duplicate":            `{"problem":"duplicate",` + valid[1:],
		"case-duplicate":       `{"Problem":"duplicate",` + valid[1:],
		"unknown":              `{"execute":"untrusted",` + valid[1:],
		"case-folded-key":      strings.Replace(valid, `"problem":`, `"Problem":`, 1),
		"unknown-nested":       strings.Replace(valid, `"repository":`, `"execute":"untrusted","repository":`, 1),
		"duplicate-nested":     strings.Replace(valid, `"repository":`, `"repository":"duplicate","repository":`, 1),
		"null-array":           strings.Replace(valid, `"missing":[]`, `"missing":null`, 1),
		"null-field":           strings.Replace(valid, `"trigger":"Send the reported malformed request."`, `"trigger":null`, 1),
		"missing-field":        strings.Replace(valid, `"versionStatus":"single"`, `"unknown":"single"`, 1),
		"invalid-utf8":         strings.Replace(valid, "Malformed", string([]byte{0xff}), 1),
		"unpaired-surrogate":   strings.Replace(valid, "Malformed", `\ud800`, 1),
		"unpaired-low":         strings.Replace(valid, "Malformed", `\udfff`, 1),
		"oversized":            strings.Repeat(" ", maxProposalBytes) + valid,
		"repository-userinfo":  strings.Replace(valid, "https://github.com/", "https://synthetic@github.com/", 1),
		"repository-tree-url":  strings.Replace(valid, `parser","ref"`, `parser/tree/main","ref"`, 1),
		"version-range":        strings.Replace(valid, `"ref":"v1.2.3"`, `"ref":"v1.2.3..v1.2.4"`, 1),
		"revision-expression":  strings.Replace(valid, `"ref":"v1.2.3"`, `"ref":"main^"`, 1),
		"unknown-scope":        strings.Replace(valid, `"scope":"upstream-source"`, `"scope":"verified-production"`, 1),
		"unknown-version":      strings.Replace(valid, `"versionStatus":"single"`, `"versionStatus":"any"`, 1),
		"unknown-requirement":  strings.Replace(valid, `"kind":"process"`, `"kind":"execute-shell"`, 1),
		"unbounded-build-hint": strings.Replace(valid, `"Go module metadata"`, `"`+strings.Repeat("x", 1025)+`"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := DecodeProposal(invalid)
			require.ErrorIs(t, err, errProposal)
			require.Equal(t, Proposal{}, result, "never retain partial or malformed model claims")
			require.NotContains(t, err.Error(), "untrusted")
			require.NotContains(t, err.Error(), "Malformed")
		})
	}
	paired := strings.Replace(valid, "Malformed", `\ud83d\ude00`, 1)
	_, err = DecodeProposal(paired)
	require.NoError(t, err)
	escaped := strings.Replace(valid, "Malformed", `\\ud800`, 1)
	_, err = DecodeProposal(escaped)
	require.NoError(t, err, "a literal escaped backslash is not an unpaired surrogate")
}

func TestProposalListAndTextBoundaries(t *testing.T) {
	for _, count := range []int{4, 5} {
		proposal := fixtureProposal(fixtureConfig().AllowedRepositoryRoots[0])
		target := proposal.Targets[0]
		proposal.Targets = nil
		for range count {
			proposal.Targets = append(proposal.Targets, target)
		}
		_, err := DecodeProposal(fixtureJSON(t, proposal))
		if count == 4 {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, errProposal)
		}
	}
	for _, size := range []int{32768, 32769} {
		proposal := fixtureProposal(fixtureConfig().AllowedRepositoryRoots[0])
		proposal.Problem = strings.Repeat("x", size)
		_, err := DecodeProposal(fixtureJSON(t, proposal))
		if size == 32768 {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, errProposal)
		}
	}
}

func TestSelectionStrictJSONAndExclusiveActions(t *testing.T) {
	valid := fixtureJSON(t, fixtureSelection("src/check.go"))
	_, err := DecodeSelection(valid)
	require.NoError(t, err)
	for _, invalid := range []string{
		`{}`, valid + valid, valid[:len(valid)-1],
		`{"Paths":[],"expand":[],"nextPage":false,"missing":[],"limitations":[]}`,
		`{"paths":["src/check.go"],"Paths":[],"expand":[],"nextPage":false,"missing":[],"limitations":[]}`,
		`{"paths":["src/check.go"],"expand":["vendor"],"nextPage":false,"missing":[],"limitations":[]}`,
		`{"paths":["src/check.go"],"expand":[],"nextPage":true,"missing":[],"limitations":[]}`,
		`{"paths":[],"expand":[],"nextPage":false,"missing":[],"limitations":[]}`,
		`{"paths":null,"expand":[],"nextPage":true,"missing":[],"limitations":[]}`,
		`{"paths":[".git/config"],"expand":[],"nextPage":false,"missing":[],"limitations":[]}`,
		`{"paths":[],"expand":["vendor/../.git"],"nextPage":false,"missing":[],"limitations":[]}`,
		strings.Replace(valid, `"paths":`, `"commands":[],"paths":`, 1),
	} {
		result, err := DecodeSelection(invalid)
		require.ErrorIs(t, err, errProposal)
		require.Equal(t, Selection{}, result)
	}
}
