package lab

func validateResultShape(result Result) error {
	if result.Version != Version || (result.Operation != OperationBaseline && result.Operation != OperationVerify) ||
		!digestPattern.MatchString(result.RequestDigest) || !digestPattern.MatchString(result.ChecksDigest) ||
		len(result.Checks) > MaxChecks {
		return ErrInvalidResult
	}
	runtimes := []Runtime{result.Original, result.Control}
	if result.Patched != nil {
		runtimes = append(runtimes, *result.Patched)
	}
	for _, runtime := range runtimes {
		if (runtime.Image != "" && !digestPattern.MatchString(runtime.Image)) ||
			(runtime.UID != "" && !checkIDPattern.MatchString(runtime.UID)) {
			return ErrInvalidResult
		}
	}
	for _, check := range result.Checks {
		if (check.ID != "" && !checkIDPattern.MatchString(check.ID)) ||
			(check.Class != Reproduction && check.Class != Normal) {
			return ErrInvalidResult
		}
		for _, observation := range []Observation{check.Original, check.Control, check.Patched} {
			if observation != "" && observation != Pass && observation != Fail && observation != Unavailable {
				return ErrInvalidResult
			}
		}
	}
	if result.Cleanup.State != "" && result.Cleanup.State != CleanupComplete &&
		result.Cleanup.State != CleanupIncomplete && result.Cleanup.State != CleanupUnknown {
		return ErrInvalidResult
	}
	if result.Cleanup.ReceiptDigest != "" && !digestPattern.MatchString(result.Cleanup.ReceiptDigest) {
		return ErrInvalidResult
	}
	return nil
}

func validateResult(request Request, requestDigest string, result Result) error {
	if result.Version != Version || result.Operation != request.Operation ||
		result.RequestDigest != requestDigest || result.ChecksDigest != request.Profile.ChecksDigest ||
		len(result.Checks) > MaxChecks {
		return ErrInvalidResult
	}
	if !validRuntime(result.Original) || !validRuntime(result.Control) ||
		result.Original.Image != request.Profile.OriginalImage ||
		(request.Profile.ControlImage != "" && result.Control.Image != request.Profile.ControlImage) {
		return ErrInvalidResult
	}
	if result.Cleanup.State != CleanupComplete || !digestPattern.MatchString(result.Cleanup.ReceiptDigest) {
		return ErrInvalidResult
	}
	switch request.Operation {
	case OperationBaseline:
		if result.Patched != nil || request.Candidate != nil || request.Baseline != nil {
			return ErrInvalidResult
		}
	case OperationVerify:
		if request.Candidate == nil || request.Baseline == nil || result.Patched == nil ||
			!validRuntime(*result.Patched) ||
			result.Patched.Image == result.Original.Image || result.Patched.Image == result.Control.Image ||
			(request.Candidate.Image != "" && result.Patched.Image != request.Candidate.Image) ||
			result.Control.Image != request.Baseline.Control.Image ||
			result.Original.Image != request.Baseline.Original.Image {
			return ErrInvalidResult
		}
	default:
		return ErrInvalidResult
	}
	if err := validateChecks(request, result.Checks); err != nil {
		return err
	}
	if len(request.Profile.Gaps) != 0 {
		return ErrBlocked
	}
	return nil
}

func validRuntime(runtime Runtime) bool {
	return digestPattern.MatchString(runtime.Image) && checkIDPattern.MatchString(runtime.UID)
}

func validateChecks(request Request, checks []CheckResult) error {
	// Validate every binding first: an early failed assertion must not hide a
	// later missing observation or changed baseline check.
	if err := validateCheckBindings(request, checks); err != nil {
		return err
	}
	for _, check := range checks {
		expected := Pass
		if check.Class == Reproduction {
			expected = Fail
		}
		if check.Original != expected || check.Control != expected ||
			(request.Operation == OperationVerify && check.Patched != Pass) {
			return ErrBlocked
		}
	}
	return nil
}

func validateCheckBindings(request Request, checks []CheckResult) error {
	definitions := make([]Check, len(checks))
	for index, check := range checks {
		definitions[index] = Check{ID: check.ID, Class: check.Class}
	}
	manifest, err := DigestChecks(definitions)
	if err != nil || manifest != request.Profile.ChecksDigest {
		return ErrInvalidResult
	}
	prior := make(map[string]CheckResult)
	if request.Baseline != nil {
		if len(checks) != len(request.Baseline.Checks) {
			return ErrInvalidResult
		}
		for _, check := range request.Baseline.Checks {
			prior[check.ID] = check
		}
	}
	for _, check := range checks {
		if !observed(check.Original) || !observed(check.Control) {
			return ErrInvalidResult
		}
		if request.Operation == OperationBaseline {
			if check.Patched != "" {
				return ErrInvalidResult
			}
			continue
		}
		old, found := prior[check.ID]
		if !found || old.Class != check.Class || old.Original != check.Original ||
			old.Control != check.Control || !observed(check.Patched) {
			return ErrInvalidResult
		}
	}
	return nil
}

func observed(observation Observation) bool {
	return observation == Pass || observation == Fail
}
