package investigate

import (
	"slices"

	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/remediation/source"
)

func investigationScope(report intake.Report, proposal Proposal) string {
	if proposal.Scope == ScopeDownstream || downstreamReport(report) || len(proposal.DownstreamEvidenceRequired) != 0 {
		return ScopeDownstream
	}
	return proposal.Scope
}

func downstreamEvidence(proposal Proposal) []string {
	evidence := make([]string, 0, 2+len(proposal.DownstreamEvidenceRequired))
	evidence = append(evidence,
		"Before execution, bind this exact public source commit to a matched operator-approved downstream recipe and an immutable original image digest.",
		"Verify the applied distribution patches and build configuration; vanilla upstream source alone does not establish managed-image behavior.",
	)
	return append(evidence, proposal.DownstreamEvidenceRequired...)
}

func missingReport(report intake.Report) bool {
	return slices.Contains(report.Warnings, "missing_technical_details") ||
		slices.Contains(report.Warnings, "discussion_snapshot_incomplete")
}

// The complete inventory is only needed for selection. Keeping its selected
// subset in a Ready checkpoint preserves packet binding without carrying a
// multi-megabyte discovery listing beside the final source packet.
func selectedInventory(entries []source.Entry, paths []string) []source.Entry {
	selected := make([]source.Entry, 0, len(paths))
	for _, entry := range entries {
		if slices.Contains(paths, entry.Path) {
			selected = append(selected, entry)
		}
	}
	return selected
}
