package sqlite

import (
	"bytes"
	"encoding/json"
	"math"
	"mime"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/orka-agents/orka/internal/store"
)

var (
	remediationRunIDPattern    = regexp.MustCompile(`^rm-[a-f0-9]{32}$`)
	remediationRequestPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	remediationArtifactPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
)

func validateRemediationText(field, value string, limit int, required bool) error {
	if len(value) > limit || !utf8.ValidString(value) || (required && strings.TrimSpace(value) == "") {
		return store.ValidationErrorf("invalid remediation %s", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return store.ValidationErrorf("invalid remediation %s", field)
		}
	}
	return nil
}

func validateRemediationNamespace(namespace string) error {
	if namespace != strings.TrimSpace(namespace) {
		return store.ValidationErrorf("invalid remediation namespace")
	}
	return validateRemediationText("namespace", namespace, 253, true)
}

func validateRemediationIdentity(namespace, id string) error {
	if err := validateRemediationNamespace(namespace); err != nil {
		return err
	}
	if !remediationRunIDPattern.MatchString(id) {
		return store.ValidationErrorf("invalid remediation run ID")
	}
	return nil
}

func validateRemediationRequestID(id string) error {
	if len(id) > store.RemediationMaxRequestIDBytes || !remediationRequestPattern.MatchString(id) {
		return store.ValidationErrorf("invalid remediation request ID")
	}
	for label := range strings.SplitSeq(id, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return store.ValidationErrorf("invalid remediation request ID")
		}
	}
	return nil
}

func validateRemediationJSON(field string, value json.RawMessage, limit int) error {
	if len(value) > limit || !json.Valid(value) || !utf8.Valid(value) {
		return store.ValidationErrorf("invalid or oversized remediation %s", field)
	}
	return nil
}

func validateRemediationTime(value time.Time) error {
	if value.IsZero() || !time.Unix(0, value.UnixNano()).Equal(value) {
		return store.ValidationErrorf("invalid remediation timestamp")
	}
	return nil
}

func validateRemediationLease(owner string, now time.Time, lease time.Duration) error {
	if err := validateRemediationText("claim owner", owner, 256, true); err != nil {
		return err
	}
	if lease <= 0 || lease > store.RemediationMaxClaimLease {
		return store.ValidationErrorf("remediation lease must be positive and at most five minutes")
	}
	if err := validateRemediationTime(now); err != nil {
		return err
	}
	return validateRemediationTime(now.Add(lease))
}

func validateRemediationFence(owner string, epoch uint64, now time.Time) error {
	if err := validateRemediationText("claim owner", owner, 256, true); err != nil {
		return err
	}
	if epoch == 0 || epoch > math.MaxInt64 {
		return store.ValidationErrorf("invalid remediation claim epoch")
	}
	return validateRemediationTime(now)
}

func prepareRemediationRun(input *store.RemediationRun) (*store.RemediationRun, error) {
	if input == nil {
		return nil, store.ValidationErrorf("remediation run is required")
	}
	run := *input
	if err := validateRemediationIdentity(run.Namespace, run.ID); err != nil {
		return nil, err
	}
	if err := validateRemediationRequestID(run.RequestID); err != nil {
		return nil, err
	}
	if err := validateRemediationSubmission(&run); err != nil {
		return nil, err
	}
	run.RequestJSON = bytes.Clone(run.RequestJSON)
	run.Intake = bytes.Clone(run.Intake)
	if len(run.Intake) > store.RemediationMaxRequestBytes {
		return nil, store.ErrValidation
	}
	return &run, nil
}

func initializeRemediationRun(run *store.RemediationRun) error {
	if err := validateRemediationText("policy digest", run.PolicyDigest, 256, true); err != nil {
		return err
	}
	if err := validateRemediationJSON("policy JSON", run.PolicyJSON, store.RemediationMaxPolicyBytes); err != nil {
		return err
	}
	if err := validateRemediationInitialState(run); err != nil {
		return err
	}
	if run.CreatedAt.IsZero() {
		run.CreatedAt = time.Now().UTC()
	}
	if err := validateRemediationTime(run.CreatedAt); err != nil {
		return err
	}
	if !run.Deadline.IsZero() {
		if err := validateRemediationTime(run.Deadline); err != nil {
			return err
		}
		run.Deadline = run.Deadline.UTC()
	}
	run.CreatedAt = run.CreatedAt.UTC()
	run.UpdatedAt = run.CreatedAt
	run.Phase = store.RemediationPhaseQueued
	run.Revision = 1
	run.PolicyJSON = bytes.Clone(run.PolicyJSON)
	run.StateJSON = bytes.Clone(run.StateJSON)
	return nil
}

func validateRemediationSubmission(run *store.RemediationRun) error {
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{"submitter", run.SubmittedBy, 512},
		{"mode", run.Mode, 64},
		{"input digest", run.InputDigest, 256},
	} {
		if err := validateRemediationText(field.name, field.value, field.limit, true); err != nil {
			return err
		}
	}
	return validateRemediationJSON("request JSON", run.RequestJSON, store.RemediationMaxRequestBytes)
}

func validateRemediationInitialState(run *store.RemediationRun) error {
	if (run.Phase != "" && run.Phase != store.RemediationPhaseQueued) ||
		run.Revision > 1 || run.ClaimEpoch != 0 || run.ClaimOwner != "" || !run.ClaimUntil.IsZero() ||
		run.CancelRequested || run.ApprovalDigest != "" || run.ApprovedDigest != "" || run.ApprovedBy != "" || run.Cleanup != nil {
		return store.ValidationErrorf("remediation submission cannot set execution or approval state")
	}
	if len(run.StateJSON) == 0 {
		run.StateJSON = json.RawMessage(`{}`)
	}
	if err := validateRemediationJSON("state JSON", run.StateJSON, store.RemediationMaxStateBytes); err != nil {
		return err
	}
	return validateRemediationText("reason", run.Reason, store.RemediationMaxReasonBytes, false)
}

func validateRemediationUpdate(update store.RemediationUpdate, revision uint64) error {
	if revision == 0 || revision > math.MaxInt64 {
		return store.ValidationErrorf("invalid remediation revision")
	}
	switch update.Phase {
	case store.RemediationPhaseQueued, store.RemediationPhaseRunning,
		store.RemediationPhaseNeedsInput, store.RemediationPhaseNeedsAdapter, store.RemediationPhaseNeedsApproval,
		store.RemediationPhaseCancelling, store.RemediationPhaseSucceeded, store.RemediationPhaseFailed,
		store.RemediationPhaseCancelled, store.RemediationPhaseTimedOut:
	default:
		return store.ValidationErrorf("invalid remediation phase")
	}
	if (update.Phase == store.RemediationPhaseNeedsApproval) != (update.ApprovalDigest != "") {
		return store.ValidationErrorf("remediation approval digest is required only for NeedsApproval")
	}
	if err := validateRemediationText("approval digest", update.ApprovalDigest, 256, false); err != nil {
		return err
	}
	if err := validateRemediationText("reason", update.Reason, store.RemediationMaxReasonBytes, false); err != nil {
		return err
	}
	if len(update.StateJSON) != 0 {
		return validateRemediationJSON("state JSON", update.StateJSON, store.RemediationMaxStateBytes)
	}
	return nil
}

func validateRemediationArtifactName(name string) error {
	if len(name) > 256 || !remediationArtifactPattern.MatchString(name) {
		return store.ValidationErrorf("invalid remediation artifact name")
	}
	return nil
}

func validateRemediationArtifact(mediaType string, data []byte) error {
	if err := validateRemediationText("artifact media type", mediaType, 256, true); err != nil {
		return err
	}
	if _, _, err := mime.ParseMediaType(mediaType); err != nil {
		return store.ValidationErrorf("invalid remediation artifact media type")
	}
	if len(data) > store.RemediationMaxArtifactBytes {
		return store.ValidationErrorf("remediation artifact exceeds eight MiB")
	}
	return nil
}
