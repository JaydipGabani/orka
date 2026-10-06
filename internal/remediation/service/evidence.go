package service

import "github.com/orka-agents/orka/internal/remediation/environment"

func verifiedOutcome(receipt environment.Receipt, check environment.Check, observed environment.HTTPResult) (environment.Outcome, error) {
	if check.HTTP == nil || check.Class != observed.Class || observed.PodUID == "" || observed.RuntimeImageID == "" ||
		observed.Image != receipt.Request.Subject.Image ||
		observed.Status < 100 || observed.Status > 599 || !validDigest(observed.BodyDigest) {
		return "", ErrInvalid
	}
	healthy, failure := environment.ExpectedHTTP(receipt, check)
	if observed.HealthyStatus != healthy.Status || observed.HealthyBodyDigest != Digest([]byte(healthy.Body)) {
		return "", ErrInvalid
	}
	actual := environment.OutcomeOther
	if observed.Status == healthy.Status && observed.BodyDigest == observed.HealthyBodyDigest {
		actual = environment.OutcomeHealthy
	}
	if failure != nil {
		if *failure == healthy || observed.FailureStatus != failure.Status || observed.FailureBodyDigest != Digest([]byte(failure.Body)) {
			return "", ErrInvalid
		}
		if observed.Status == failure.Status && observed.BodyDigest == observed.FailureBodyDigest {
			actual = environment.OutcomeFailure
		}
	} else if observed.FailureStatus != 0 || observed.FailureBodyDigest != "" || check.Class == environment.Reproduction {
		return "", ErrInvalid
	}
	if observed.Outcome != actual {
		return "", ErrInvalid
	}
	return actual, nil
}
