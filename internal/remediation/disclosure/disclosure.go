// Package disclosure gates bytes leaving the private build/intake boundary.
// Known formats and ambiguous credential-bearing values fail closed. A baseline
// hash or a test filename is not a disclosure authorization.
package disclosure

import (
	"errors"
	"regexp"
	"unicode/utf8"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

type Domain string

const (
	Model     Domain = "model"
	Candidate Domain = "candidate"
	Artifact  Domain = "artifact"
	maxBytes         = 8 << 20
)

var ErrBlocked = errors.New("content is not approved for disclosure")

var credentialURL = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s/?#"'<>]*@|[?&](?:access_token|token|api_key|password|secret|sig|signature)=[^&#\s"'<>]+`)

func Check(domain Domain, content []byte) error {
	switch domain {
	case Model, Candidate, Artifact:
	default:
		return ErrBlocked
	}
	if len(content) > maxBytes || !utf8.Valid(content) || credentialURL.Match(content) ||
		(pv.CredentialMatcher{}).Match(content) {
		return ErrBlocked
	}
	return nil
}
