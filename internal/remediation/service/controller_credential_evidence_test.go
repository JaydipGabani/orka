package service

import (
	"testing"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/stretchr/testify/require"
)

func TestCredentialAttackEvidenceRequiresBothBaselineChallengesAndCandidateAbsence(t *testing.T) {
	require.False(t, controllerCredentialAttackReproduced(nil))
	require.False(t, controllerCredentialAttackAbsent(nil))
	for mask := range 8 {
		evidence := &controllerlab.PublishingEvidence{CredentialAttack: controllerlab.CredentialAttackEvidence{
			Observed: mask&1 != 0, InitialObserved: mask&2 != 0, FinalObserved: mask&4 != 0,
		}}
		require.Equal(t, mask == 7, controllerCredentialAttackReproduced(evidence), "baseline mask %d", mask)
		require.Equal(t, mask == 0, controllerCredentialAttackAbsent(evidence), "candidate mask %d", mask)
	}
}
