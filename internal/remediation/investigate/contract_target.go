package investigate

import "strings"

// Open questions must not prevent reading the exact source selected by an
// operator contract. They remain in the plan; this authorizes no execution.
func canInspectContractTarget(proposal Proposal, config Config) bool {
	if len(proposal.Targets) != 1 || !validObjectID(proposal.Targets[0].Ref) {
		return false
	}
	target := proposal.Targets[0]
	for _, hint := range config.SourceCatalog {
		if hint.VerificationContract != "" && hint.Commit == target.Ref &&
			strings.EqualFold(canonicalRepository(hint.Repository), canonicalRepository(target.Repository)) {
			return true
		}
	}
	return false
}
