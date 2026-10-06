package service

import "github.com/orka-agents/orka/internal/remediation/controllerlab"

func controllerCredentialAttackReproduced(evidence *controllerlab.PublishingEvidence) bool {
	return evidence != nil && evidence.CredentialAttack.Observed &&
		evidence.CredentialAttack.InitialObserved && evidence.CredentialAttack.FinalObserved
}

func controllerCredentialAttackAbsent(evidence *controllerlab.PublishingEvidence) bool {
	return evidence != nil && evidence.CredentialAttack == (controllerlab.CredentialAttackEvidence{})
}
