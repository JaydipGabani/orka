package environment

// NotSubmitted is an acknowledged, durable prohibition on submitting this build
// operation, not an inference from an absent Kubernetes object. It contains only
// identities and digests; rejected input and validation messages are excluded.
type NotSubmitted struct {
	Version           int    `json:"version"`
	RunID             string `json:"runID"`
	OperationID       string `json:"operationID"`
	EnvironmentDigest string `json:"environmentDigest"`
	RequestDigest     string `json:"requestDigest"`
	HistoryDigest     string `json:"historyDigest"`
	ProofDigest       string `json:"proofDigest"`
}

func (*NotSubmitted) Error() string { return "environment: build-not-submitted" }

func (proof NotSubmitted) bindingDigest() string {
	proof.ProofDigest = ""
	return jsonDigest(proof)
}

// Matches checks the exact frozen request. RequireExisting is deliberately not
// part of the identity: recovery may inspect the proof but may never submit.
func (proof NotSubmitted) Matches(request BuildRequest) bool {
	return proof.Version == Version && proof.RunID == request.RunID && proof.OperationID == request.OperationID &&
		idPattern.MatchString(proof.RunID) && idPattern.MatchString(proof.OperationID) &&
		digestPattern.MatchString(proof.EnvironmentDigest) && digestPattern.MatchString(proof.HistoryDigest) &&
		proof.RequestDigest == buildRequestDigest(request) && proof.ProofDigest == proof.bindingDigest()
}

func buildRequestDigest(request BuildRequest) string {
	return jsonDigest(struct {
		Domain, RunID, OperationID string
		Plan                       Plan
		Role                       Role
		PatchDigest                string
	}{"orka.remediation.environment.build-request.v1", request.RunID, request.OperationID,
		request.Plan, request.Role, request.PatchDigest})
}

type buildCancellation struct {
	Version            int           `json:"version"`
	RunID              string        `json:"runID"`
	OperationID        string        `json:"operationID"`
	EnvironmentDigest  string        `json:"environmentDigest"`
	BindDigest         string        `json:"bindDigest"`
	HistoryDigest      string        `json:"historyDigest"`
	NoSubmissionProven bool          `json:"noSubmissionProven"`
	NotSubmitted       *NotSubmitted `json:"notSubmitted,omitempty"`
	Digest             string        `json:"digest"`
}

func buildCancellationDigest(cancellation buildCancellation) string {
	cancellation.Digest = ""
	return jsonDigest(cancellation)
}

func (a *Adapter) cancelledBuild(state *runJournal, runID, operationID string, bind Bind) (bool, error) {
	cancellation, found := state.BuildCancellations[operationID]
	if !found {
		return false, nil
	}
	if cancellation == nil || cancellation.Version != Version || cancellation.RunID != runID ||
		cancellation.OperationID != operationID || cancellation.EnvironmentDigest != a.digest ||
		cancellation.BindDigest != jsonDigest(bind) || !digestPattern.MatchString(cancellation.HistoryDigest) ||
		cancellation.Digest != buildCancellationDigest(*cancellation) {
		return false, failure(Unknown, "build-cancellation-binding-mismatch")
	}
	if proof := cancellation.NotSubmitted; proof != nil &&
		(!cancellation.NoSubmissionProven || proof.Version != Version || proof.RunID != runID || proof.OperationID != operationID ||
			proof.EnvironmentDigest != a.digest || proof.HistoryDigest != cancellation.HistoryDigest ||
			!digestPattern.MatchString(proof.RequestDigest) || proof.ProofDigest != proof.bindingDigest()) {
		return false, failure(Unknown, "build-cancellation-proof-mismatch")
	}
	return true, nil
}

// Only the complete local write-ahead history can prove descriptor absence.
// Every backend Start follows a successful descriptor and submission-intent
// fsync under this same flock. An accepted/ambiguous record is never eligible.
func (a *Adapter) proveBuildAbsent(state *runJournal, runID, operationID string, plan Plan) error {
	if state.BuildHistoryIncomplete || state.ConfigDigest != a.digest || state.BindDigest != jsonDigest(plan.Bind) ||
		(state.RunID != "" && state.RunID != runID) ||
		(state.RunID == "" && len(state.Builds)+len(state.Operations) == 0) {
		return failure(Unknown, "build-history-unavailable")
	}
	for id, record := range state.Builds {
		if record == nil || record.Job == nil || record.Job.Input.RunID != runID {
			return failure(Unknown, "build-history-binding-mismatch")
		}
		request := BuildRequest{RunID: runID, OperationID: record.Job.OperationID, Plan: plan,
			Role: record.Job.Role, PatchDigest: record.Job.PatchDigest}
		if a.buildIdentity(request) != id {
			return failure(Unknown, "build-history-binding-mismatch")
		}
		if _, err := a.validateBuildJob(request, id, record); err != nil {
			return err
		}
		if record.Job.OperationID == operationID {
			return failure(Unknown, "build-operation-already-recorded")
		}
	}
	for _, record := range state.Operations {
		if record == nil || record.Receipt.Request.RunID != runID || record.Receipt.Request.Plan.Bind != plan.Bind {
			return failure(Unknown, "build-history-binding-mismatch")
		}
	}
	for id := range state.BuildCancellations {
		if _, err := a.cancelledBuild(state, runID, id, plan.Bind); err != nil {
			return err
		}
	}
	if state.BuildHistoryVersion != 1 {
		return failure(Unknown, buildHistoryOriginUnavailable)
	}
	return nil
}

const buildHistoryOriginUnavailable = "build-history-origin-unavailable"

func (a *Adapter) recordBuildCancellation(state *runJournal, runID, operationID string, plan Plan, proven bool, proof *NotSubmitted) error {
	if len(state.Operations)+len(state.Builds)+len(state.BuildCancellations) >= a.config.Limits.MaxOperations {
		return failure(Unknown, "build-cancellation-journal-limit")
	}
	cancellation := &buildCancellation{
		Version: Version, RunID: runID, OperationID: operationID, EnvironmentDigest: a.digest,
		BindDigest: jsonDigest(plan.Bind), HistoryDigest: runJournalDigest(state), NoSubmissionProven: proven, NotSubmitted: proof,
	}
	cancellation.Digest = buildCancellationDigest(*cancellation)
	if state.BuildCancellations == nil {
		state.BuildCancellations = make(map[string]*buildCancellation)
	}
	state.BuildCancellations[operationID] = cancellation
	return a.saveRun(runID, state)
}

func (a *Adapter) rejectUnsubmittedBuild(state *runJournal, request BuildRequest, rejection error) error {
	if request.RequireExisting {
		return failure(Unknown, "existing-build-history-unavailable")
	}
	if !idPattern.MatchString(request.RunID) || !idPattern.MatchString(request.OperationID) ||
		request.Plan.Version != Version || !digestPattern.MatchString(request.Plan.Bind.ChecksDigest) ||
		ChecksDigest(request.Plan) != request.Plan.Bind.ChecksDigest {
		return rejection
	}
	if err := a.proveBuildAbsent(state, request.RunID, request.OperationID, request.Plan); err != nil {
		return err
	}
	proof := &NotSubmitted{
		Version: Version, RunID: request.RunID, OperationID: request.OperationID, EnvironmentDigest: a.digest,
		RequestDigest: buildRequestDigest(request), HistoryDigest: runJournalDigest(state),
	}
	proof.ProofDigest = proof.bindingDigest()
	// The operation-wide tombstone also fences late callers with a different
	// role or patch. Return proof only after it has been fsynced.
	if err := a.recordBuildCancellation(state, request.RunID, request.OperationID, request.Plan, true, proof); err != nil {
		return err
	}
	return proof
}
