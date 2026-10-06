package validation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"time"

	kubevalidation "k8s.io/apimachinery/pkg/util/validation"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

const ReceiptVersion = 1

// Receipt is trusted durable state, not an idempotency key or a signature.
// Persist the complete callback value verbatim. InputDigest is SHA-256 of
// encoding/json.Marshal on the original pv.Request, before normalization or
// storage-path rewriting. It does not re-hash files during Resume; the previously
// checked source/check contents are bound by ManifestDigest instead.
type Receipt struct {
	Version         int    `json:"version"`
	Namespace       string `json:"namespace"`
	RequestID       string `json:"requestID"`
	InputDigest     string `json:"inputDigest"`
	ManifestDigest  string `json:"manifestDigest"`
	IdentityDigest  string `json:"identityDigest"`
	OriginalTaskUID string `json:"originalTaskUID,omitempty"`
	PatchedTaskUID  string `json:"patchedTaskUID,omitempty"`
	RunID           string `json:"runID,omitempty"`
}

// Version 1 hashes this exact envelope in field order, with CreatedAt in UTC.
// Mutable progress is excluded; any already observed task/run IDs are carried
// separately. Changing this encoding requires a receipt version change.
type receiptIdentity struct {
	Namespace        string    `json:"namespace"`
	RequestID        string    `json:"requestID"`
	SubmittedBy      string    `json:"submittedBy"`
	AttemptID        string    `json:"attemptID"`
	OriginalTaskName string    `json:"originalTaskName"`
	PatchedTaskName  string    `json:"patchedTaskName"`
	ManifestDigest   string    `json:"manifestDigest"`
	CreatedAt        time.Time `json:"createdAt"`
}

type receiptPersistenceError struct {
	cause error
}

func (e *receiptPersistenceError) Error() string {
	return "validation submission receipt could not be durably saved; do not resubmit"
}

func (e *receiptPersistenceError) Unwrap() error { return e.cause }

func requestDigest(request pv.Request) (string, error) {
	content, err := json.Marshal(request)
	if err != nil || len(content) > pv.MaxManifestBytes {
		return "", pv.ErrLimit
	}
	return pv.Digest(content), nil
}

func newReceipt(inputDigest string, submission *pv.KubernetesSubmission) (Receipt, error) {
	manifestDigest, err := pv.ManifestDigest(submission.Manifest)
	if err != nil {
		return Receipt{}, pv.ErrIntegrity
	}
	content, err := json.Marshal(receiptIdentity{
		Namespace: submission.Namespace, RequestID: submission.RequestID, SubmittedBy: submission.SubmittedBy,
		AttemptID: submission.AttemptID, OriginalTaskName: submission.OriginalTaskName,
		PatchedTaskName: submission.PatchedTaskName, ManifestDigest: manifestDigest, CreatedAt: submission.CreatedAt.UTC(),
	})
	if err != nil {
		return Receipt{}, pv.ErrIntegrity
	}
	return Receipt{Version: ReceiptVersion, Namespace: submission.Namespace, RequestID: submission.RequestID,
		InputDigest: inputDigest, ManifestDigest: manifestDigest, IdentityDigest: pv.Digest(content),
		OriginalTaskUID: submission.OriginalTaskUID, PatchedTaskUID: submission.PatchedTaskUID, RunID: submission.RunID}, nil
}

func (r Receipt) validate(namespace, inputDigest string, action pv.Action) error {
	if r.Version != ReceiptVersion || r.Namespace == "" || len(kubevalidation.IsDNS1123Label(r.Namespace)) != 0 ||
		!identifier.MatchString(r.RequestID) || !digestPattern.MatchString(r.InputDigest) ||
		!digestPattern.MatchString(r.ManifestDigest) || !digestPattern.MatchString(r.IdentityDigest) {
		return errors.Join(ErrSubmissionUnknown, errors.New("a complete supported durable validation receipt is required"))
	}
	if r.Namespace != namespace || r.InputDigest != inputDigest {
		return pv.ErrBinding
	}
	for _, id := range []string{r.OriginalTaskUID, r.PatchedTaskUID, r.RunID} {
		if id != "" && !identifier.MatchString(id) {
			return pv.ErrBinding
		}
	}
	if action == pv.ValidateReport && r.PatchedTaskUID != "" {
		return pv.ErrBinding
	}
	if r.RunID != "" && (r.OriginalTaskUID == "" || (action != pv.ValidateReport && r.PatchedTaskUID == "")) {
		return pv.ErrBinding
	}
	return nil
}

func (r Receipt) matches(submission *pv.KubernetesSubmission) error {
	actual, err := newReceipt(r.InputDigest, submission)
	if err != nil || actual.Namespace != r.Namespace || actual.RequestID != r.RequestID ||
		actual.ManifestDigest != r.ManifestDigest || actual.IdentityDigest != r.IdentityDigest ||
		(r.OriginalTaskUID != "" && actual.OriginalTaskUID != r.OriginalTaskUID) ||
		(r.PatchedTaskUID != "" && actual.PatchedTaskUID != r.PatchedTaskUID) ||
		(r.RunID != "" && actual.RunID != r.RunID) {
		return pv.ErrBinding
	}
	return nil
}

// Resume verifies a durable receipt against the original request and reads only
// the existing submission and its evidence. It needs only API and PollInterval:
// no local files, upload Pod, or staging configuration are used. It never POSTs,
// even on cancellation; a cancelled Resume does not cancel remote execution.
func (c Client) Resume(ctx context.Context, request pv.Request, receipt Receipt) (result *pv.Record, resultErr error) {
	if ctx == nil {
		return nil, errors.New("validation context is required")
	}
	operation, cancel := context.WithTimeout(ctx, validationTimeout)
	defer cancel()
	transport, err := newTransport(c.API)
	if err != nil {
		return nil, err
	}
	if transport.api.Namespace == "" || len(kubevalidation.IsDNS1123Label(transport.api.Namespace)) != 0 {
		return nil, errors.New("an explicit validation namespace is required")
	}
	if c.PollInterval < 0 {
		return nil, errors.New("validation poll interval cannot be negative")
	}
	interval := c.PollInterval
	if interval == 0 {
		interval = defaultPollInterval
	}
	inputDigest, err := requestDigest(request)
	if err != nil {
		return nil, err
	}
	if err := receipt.validate(transport.api.Namespace, inputDigest, request.Action); err != nil {
		return nil, err
	}
	request, err = normalizeRequest(request)
	if err != nil {
		return nil, err
	}
	var pinned *pv.KubernetesSubmission
	defer func() {
		if operation.Err() != nil {
			resultErr = errors.Join(resultErr, operation.Err())
		}
		if resultErr == nil {
			return
		}
		failure := &SubmissionError{Namespace: receipt.Namespace, RequestID: receipt.RequestID, RunID: receipt.RunID, Err: resultErr}
		if pinned != nil {
			failure.RunID, failure.InputDirectory = pinned.RunID, path.Dir(pinned.Manifest.Sources.Repository)
			result = incompleteRecord(pinned)
		} else {
			result = incompleteRecord(&pv.KubernetesSubmission{Manifest: pv.Manifest{Action: request.Action}})
			result.Binding.RunID, result.Binding.ManifestDigest = receipt.RunID, receipt.ManifestDigest
		}
		resultErr = failure
	}()
	if err := operation.Err(); err != nil {
		return nil, err
	}
	response, err := transport.request(operation, http.MethodGet, "/api/v1/validations/"+receipt.RequestID, nil, http.StatusOK, maxSubmissionBytes)
	if err != nil {
		return nil, err
	}
	var submission pv.KubernetesSubmission
	if err := decodeJSON(response, &submission); err != nil {
		return nil, err
	}
	if err := receipt.matches(&submission); err != nil {
		return nil, err
	}
	staged, err := resumeInputs(request, submission.Manifest, receipt.Namespace)
	if err != nil {
		return nil, err
	}
	if err := validateSubmission(receipt.Namespace, staged, nil, &submission); err != nil {
		return nil, err
	}
	pinned = &submission
	result, pinned, resultErr = transport.poll(operation, staged, pinned, interval, true)
	return result, resultErr
}

func resumeInputs(request pv.Request, manifest pv.Manifest, namespace string) (Staged, error) {
	parent := path.Dir(manifest.Sources.Repository)
	root := path.Dir(parent)
	if !path.IsAbs(root) || path.Clean(root) != root || path.Base(root) != namespace {
		return Staged{}, pv.ErrBinding
	}
	staged := Staged{Request: request, Sources: manifest.Sources, Files: manifest.Files}
	staged.Request.Repository, staged.Request.ChecksDir = manifest.Sources.Repository, path.Join(parent, "checks")
	if request.PatchFile != "" {
		staged.Request.PatchFile = path.Join(parent, "candidate.patch")
	}
	if err := validateStaged(root, request, staged); err != nil {
		return Staged{}, err
	}
	return staged, nil
}
