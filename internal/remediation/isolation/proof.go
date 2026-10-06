package isolation

import (
	"net/netip"

	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
)

// ExportProof returns only a completed, cleaned-up proof. Both its input and
// output belong in the parent's private receipt store, never model context.
// The caller must still bind the subject's placement and unchanged policy set.
func ExportProof(receipt Receipt) (Proof, error) {
	if err := validateReceipt(receipt); err != nil {
		return Proof{}, err
	}
	if !receipt.CleanupComplete || receipt.Phase != Complete || receipt.Outcome != Passed {
		return Proof{}, &Error{Code: "proof-not-complete-or-not-cleaned"}
	}
	if err := proofEvidence(receipt); err != nil {
		return Proof{}, err
	}
	return cloneProof(receipt.Proof), nil
}

func proofEvidence(receipt Receipt) error {
	proof := receipt.Proof
	endpoint, err := netip.ParseAddrPort(proof.Endpoint.Address)
	if err != nil || endpoint.Port() != probe.Port || !endpoint.Addr().IsGlobalUnicast() ||
		!proof.Verified || !proof.SameNode || proof.Endpoint.Pod.UID == "" ||
		proof.Endpoint.NodeName == "" || imageID(proof.Endpoint.ImageID) == "" ||
		proof.Endpoint.ObservedAt.Before(receipt.StartedAt) ||
		proof.CompletedAt.Before(proof.Endpoint.ObservedAt) || proof.CompletedAt.After(receipt.Deadline) ||
		len(proof.Observations) != 3 {
		return &Error{Code: "proof-evidence-incomplete"}
	}
	server := receipt.Objects[roleIndex(receipt, serverRole)]
	if proof.Endpoint.Pod.UID != server.UID || proof.Endpoint.Pod.Name != server.Name ||
		proof.Endpoint.Pod.Namespace != server.Namespace {
		return &Error{Code: "proof-endpoint-identity-invalid"}
	}
	phases := []Phase{PositiveBefore, Negative, PositiveAfter}
	for i, observation := range proof.Observations {
		object := receipt.Objects[roleIndex(receipt, phaseRole(phases[i]))]
		expect := probe.Reachable
		if phases[i] == Negative {
			expect = probe.Blocked
		}
		if observation.Phase != phases[i] || observation.Pod.UID == "" || observation.Pod.UID != object.UID ||
			observation.Pod.Name != object.Name || observation.Pod.Namespace != object.Namespace ||
			imageID(observation.ImageID) != imageID(proof.Endpoint.ImageID) ||
			!probe.Matches(expect, observation.Result) || !validObservation(receipt, observation, proof.Observations[:i]) ||
			observation.ObservedAt.Before(proof.Endpoint.ObservedAt) || observation.ObservedAt.After(proof.CompletedAt) {
			return &Error{Code: "proof-observation-invalid"}
		}
	}
	return nil
}
