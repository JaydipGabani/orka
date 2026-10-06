package environment

import (
	"unicode/utf8"

	"github.com/orka-agents/orka/internal/remediation/disclosure"
	"github.com/orka-agents/orka/internal/remediation/provenance"
)

func validateBuildRequest(request BuildRequest) error {
	if !idPattern.MatchString(request.RunID) || !idPattern.MatchString(request.OperationID) ||
		(request.Role != RebuiltControl && request.Role != Candidate) ||
		(request.Role == RebuiltControl && (len(request.Patch) != 0 || request.PatchDigest != "")) ||
		(request.Role == Candidate && (len(request.Patch) == 0 || len(request.Patch) > provenance.MaxFileBytes ||
			!utf8.Valid(request.Patch) || digest(request.Patch) != request.PatchDigest ||
			disclosure.Check(disclosure.Candidate, request.Patch) != nil)) {
		return failure(NeedsAdapter, "invalid-build-request")
	}
	return nil
}
