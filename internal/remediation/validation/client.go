package validation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"

	kubevalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/orka-agents/orka/internal/cli/client"
	pv "github.com/orka-agents/orka/internal/patchverification"
)

const (
	validationTimeout   = 35 * time.Minute
	cancellationTimeout = 10 * time.Second
	defaultPollInterval = time.Second
	policyKey           = "orka.kubernetes.policy"
	helperImageKey      = "orka.kubernetes.helper-image"
)

var (
	ErrSubmissionUnknown = errors.New("validation submission acknowledgement is unknown; do not resubmit automatically")
	identifier           = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	digestPattern        = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// SubmissionError retains safe receipts without including a remote response,
// local input data, or authentication material in its error text.
type SubmissionError struct {
	Namespace      string
	RequestID      string
	RunID          string
	InputDirectory string
	Err            error
}

func (e *SubmissionError) Error() string { return e.Err.Error() }
func (e *SubmissionError) Unwrap() error { return e.Err }

type Client struct {
	API          *client.Client
	Kubeconfig   string
	InputPod     string
	InputRoot    string
	PollInterval time.Duration
	Stage        StageFunc
}

func normalizeRequest(request pv.Request) (pv.Request, error) {
	if request.EarlierValidation != "" {
		return pv.Request{}, errors.New("linked validation requires stable remote inputs and is not supported by isolated staging")
	}
	if request.Action == "" {
		request.Action = pv.VerifyPatch
		if len(request.DeclaredChanges) == 0 {
			request.DeclaredChanges = []pv.DeclaredChange{{Kind: "source", Description: "supplied patch; legacy request did not declare paths"}}
		}
	}
	content, err := json.Marshal(request)
	if err != nil || len(content) > pv.MaxManifestBytes {
		return pv.Request{}, errors.New("validation request exceeds the request limit")
	}
	normalized, err := pv.DecodeRequestJSON(content)
	if err != nil {
		return pv.Request{}, errors.New("validation requires a complete standalone source/check request")
	}
	if !pinnedImage(normalized.Image) || (normalized.Platform != "linux/amd64" && normalized.Platform != "linux/arm64") ||
		(normalized.Profile != pv.Offline && normalized.Profile != pv.LocalServices) {
		return pv.Request{}, errors.New("validation requires an explicit digest-pinned image, Linux platform, and network profile")
	}
	if (pv.CredentialMatcher{}).Match(content) {
		return pv.Request{}, errInputSecret
	}
	return normalized, nil
}

func pinnedImage(image string) bool {
	name, digest, found := strings.Cut(image, "@")
	return found && name != "" && digestPattern.MatchString(digest) && !strings.ContainsAny(image, " \t\r\n\x00")
}

// Validate preserves the original interface without a durable receipt callback.
// A non-nil error always makes any accompanying record receipt-only.
func (c Client) Validate(ctx context.Context, request pv.Request) (*pv.Record, error) {
	return c.Start(ctx, request, nil)
}

// Start stages and submits exactly once. After validating the acknowledgement it
// calls started synchronously, before any polling or evidence reads. The caller
// must first persist submission intent, then durably save the callback's Receipt
// before returning nil. A callback must return promptly; it has no context of its
// own. A nil callback opts out of durable resumption, as Validate does.
func (c Client) Start(ctx context.Context, request pv.Request, started func(Receipt) error) (result *pv.Record, resultErr error) {
	if ctx == nil {
		return nil, errors.New("validation context is required")
	}
	operation, cancel := context.WithTimeout(ctx, validationTimeout)
	defer cancel()
	if err := operation.Err(); err != nil {
		return nil, err
	}
	transport, err := newTransport(c.API)
	if err != nil {
		return nil, err
	}
	if err := validateLocation(transport.api.Namespace, c.Kubeconfig, c.InputPod, c.InputRoot); err != nil {
		return nil, err
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
	request, err = normalizeRequest(request)
	if err != nil {
		return nil, err
	}
	content, _ := json.Marshal(request)
	screen := inventory{credentials: []string{transport.api.Token, transport.api.TxnToken}}
	if err := screen.screen(content); err != nil {
		return nil, err
	}
	stage := c.Stage
	if stage == nil {
		stage = (Stager{Namespace: transport.api.Namespace, Kubeconfig: c.Kubeconfig,
			InputPod: c.InputPod, InputRoot: c.InputRoot, credentials: screen.credentials}).Stage
	}
	staged, err := stage(operation, request)
	if err != nil {
		return nil, err
	}
	if err := validateStaged(c.InputRoot, request, staged); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(staged.Request)
	if err != nil || len(encoded) > pv.MaxManifestBytes {
		return nil, pv.ErrLimit
	}
	var pinned *pv.KubernetesSubmission
	cancelSubmission := false
	defer func() {
		if operation.Err() != nil {
			resultErr = errors.Join(resultErr, operation.Err())
			cancelSubmission = true
		}
		if cancelSubmission && pinned != nil {
			settle, stop := context.WithTimeout(context.WithoutCancel(ctx), cancellationTimeout)
			cancelErr := transport.cancel(settle, pinned, staged)
			stop()
			resultErr = errors.Join(resultErr, cancelErr)
		}
		if resultErr == nil {
			return
		}
		receipt := &SubmissionError{Namespace: transport.api.Namespace, InputDirectory: path.Dir(staged.Request.Repository), Err: resultErr}
		result = nil
		if pinned != nil {
			receipt.RequestID, receipt.RunID = pinned.RequestID, pinned.RunID
			result = incompleteRecord(pinned)
		}
		resultErr = receipt
	}()
	if err := operation.Err(); err != nil {
		return nil, err
	}
	response, err := transport.request(operation, http.MethodPost, "/api/v1/validations", encoded, http.StatusAccepted, maxSubmissionBytes)
	if err != nil {
		if !definiteRejection(err) {
			err = errors.Join(ErrSubmissionUnknown, err)
		}
		return nil, err
	}
	var submission pv.KubernetesSubmission
	if decodeJSON(response, &submission) != nil || validateSubmission(transport.api.Namespace, staged, nil, &submission) != nil {
		return nil, errors.Join(ErrSubmissionUnknown, errors.New("validation acknowledgement has no trustworthy submission binding"))
	}
	pinned = &submission
	receipt, err := newReceipt(inputDigest, pinned)
	if err != nil {
		return nil, errors.Join(ErrSubmissionUnknown, err)
	}
	if started != nil {
		if err := started(receipt); err != nil {
			cancelSubmission = true
			return nil, errors.Join(ErrSubmissionUnknown, &receiptPersistenceError{cause: err})
		}
	}
	result, pinned, resultErr = transport.poll(operation, staged, pinned, interval, false)
	return result, resultErr
}

func (t *transport) poll(ctx context.Context, staged Staged, pinned *pv.KubernetesSubmission, interval time.Duration, resumed bool) (*pv.Record, *pv.KubernetesSubmission, error) {
	endpoint := "/api/v1/validations/" + pinned.RequestID
	for pinned.State != pv.SubmissionTerminal {
		if err := wait(ctx, interval); err != nil {
			return nil, pinned, err
		}
		response, err := t.request(ctx, http.MethodGet, endpoint, nil, http.StatusOK, maxSubmissionBytes)
		if err != nil {
			return nil, pinned, err
		}
		var next pv.KubernetesSubmission
		if err := decodeJSON(response, &next); err != nil {
			return nil, pinned, err
		}
		if err := validateSubmission(t.api.Namespace, staged, pinned, &next); err != nil {
			return nil, pinned, err
		}
		pinned = &next
	}
	response, err := t.request(ctx, http.MethodGet, endpoint+"/evidence", nil, http.StatusOK, maxRecordBytes)
	if err != nil {
		return nil, pinned, err
	}
	var record pv.Record
	if err := decodeJSON(response, &record); err != nil {
		return nil, pinned, err
	}
	if resumed {
		// The durable manifest digest pins every required provenance digest.
		// Advertised sizes are untrusted until bounded blob reads verify both.
		staged.Provenance = record.Provenance
	}
	references, err := verifyRecord(staged, pinned, &record)
	if err != nil {
		return nil, pinned, err
	}
	for _, reference := range references {
		if err := t.blob(ctx, endpoint, reference); err != nil {
			return nil, pinned, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, pinned, err
	}
	return &record, pinned, nil
}

func validateStaged(root string, request pv.Request, staged Staged) error {
	parent := path.Dir(staged.Request.Repository)
	if path.Dir(parent) != root || !stageName.MatchString(path.Base(parent)) ||
		staged.Request.Repository != path.Join(parent, "repository") || staged.Request.ChecksDir != path.Join(parent, "checks") ||
		(request.PatchFile != "" && staged.Request.PatchFile != path.Join(parent, "candidate.patch")) ||
		(request.PatchFile == "" && staged.Request.PatchFile != "") {
		return errors.New("stager returned storage paths outside its generated input directory")
	}
	rewritten := staged.Request
	rewritten.Repository, rewritten.ChecksDir, rewritten.PatchFile = request.Repository, request.ChecksDir, request.PatchFile
	before, err := json.Marshal(request)
	if err != nil {
		return pv.ErrEvidence
	}
	after, err := json.Marshal(rewritten)
	if err != nil || !bytes.Equal(before, after) || staged.Sources.Repository != staged.Request.Repository ||
		staged.Sources.Original.Commit != request.OriginalCommit || staged.Sources.Patched.Commit != request.PatchedCommit ||
		(request.PatchFile != "" && !digestPattern.MatchString(staged.Sources.PatchDigest)) {
		return errors.New("stager changed validation inputs or failed to freeze source identities")
	}
	return nil
}

func validateSubmission(namespace string, staged Staged, previous, next *pv.KubernetesSubmission) error {
	if err := validateSubmissionIdentity(namespace, next); err != nil {
		return err
	}
	if err := matchManifest(staged, next.Manifest); err != nil {
		return err
	}
	if err := validateSubmissionProgress(next); err != nil {
		return err
	}
	if previous != nil {
		return validateSubmissionTransition(previous, next)
	}
	return nil
}

func validateSubmissionIdentity(namespace string, next *pv.KubernetesSubmission) error {
	if next.Namespace != namespace || !identifier.MatchString(next.RequestID) || !identifier.MatchString(next.AttemptID) ||
		next.SubmittedBy == "" || len(next.SubmittedBy) > 1024 || next.OriginalTaskName == "" ||
		len(kubevalidation.IsDNS1123Subdomain(next.OriginalTaskName)) != 0 ||
		next.CreatedAt.IsZero() || next.UpdatedAt.Before(next.CreatedAt) {
		return pv.ErrBinding
	}
	if next.Manifest.Action == pv.ValidateReport {
		if next.PatchedTaskName != "" || next.PatchedTaskUID != "" {
			return pv.ErrBinding
		}
	} else if next.PatchedTaskName == "" || next.PatchedTaskName == next.OriginalTaskName ||
		len(kubevalidation.IsDNS1123Subdomain(next.PatchedTaskName)) != 0 {
		return pv.ErrBinding
	}
	for _, uid := range []string{next.OriginalTaskUID, next.PatchedTaskUID} {
		if uid != "" && !identifier.MatchString(uid) {
			return pv.ErrBinding
		}
	}
	return nil
}

func validateSubmissionProgress(next *pv.KubernetesSubmission) error {
	required := len(pv.ActionSides(next.Manifest.Action)) * len(next.Manifest.Checks)
	if next.RequiredChecks != required || next.RecordedChecks < 0 || next.RecordedChecks > required {
		return pv.ErrEvidence
	}
	switch next.State {
	case pv.SubmissionPreparing, pv.SubmissionRunning, pv.SubmissionCancelling, pv.SubmissionTerminal:
	default:
		return pv.ErrEvidence
	}
	if next.RunID == "" {
		if next.Binding != nil || next.State == pv.SubmissionRunning || next.RecordedChecks != 0 {
			return pv.ErrBinding
		}
	} else if next.Binding == nil || pv.ValidateRunBinding(next.Manifest, *next.Binding) != nil ||
		next.Binding.RunID != next.RunID || next.Binding.AttemptID != next.AttemptID ||
		next.Binding.OriginalTaskID != next.OriginalTaskUID || next.Binding.PatchedTaskID != next.PatchedTaskUID ||
		next.State == pv.SubmissionPreparing {
		return pv.ErrBinding
	}
	return nil
}

func validateSubmissionTransition(previous, next *pv.KubernetesSubmission) error {
	before, _ := pv.ManifestDigest(previous.Manifest)
	after, _ := pv.ManifestDigest(next.Manifest)
	if next.RequestID != previous.RequestID || next.AttemptID != previous.AttemptID ||
		next.SubmittedBy != previous.SubmittedBy || next.OriginalTaskName != previous.OriginalTaskName ||
		next.PatchedTaskName != previous.PatchedTaskName || !next.CreatedAt.Equal(previous.CreatedAt) ||
		next.UpdatedAt.Before(previous.UpdatedAt) || before != after || next.RecordedChecks < previous.RecordedChecks ||
		(previous.OriginalTaskUID != "" && next.OriginalTaskUID != previous.OriginalTaskUID) ||
		(previous.PatchedTaskUID != "" && next.PatchedTaskUID != previous.PatchedTaskUID) ||
		(previous.RunID != "" && (next.RunID != previous.RunID || !reflect.DeepEqual(next.Binding, previous.Binding))) ||
		(previous.State != pv.SubmissionPreparing && next.State == pv.SubmissionPreparing) ||
		(previous.State == pv.SubmissionCancelling && next.State == pv.SubmissionRunning) ||
		(previous.State == pv.SubmissionTerminal && next.State != pv.SubmissionTerminal) {
		return pv.ErrBinding
	}
	return nil
}

func matchManifest(staged Staged, manifest pv.Manifest) error {
	if pv.ValidateManifest(manifest) != nil {
		return pv.ErrEvidence
	}
	request := staged.Request
	dependencies := manifest.Environment.Dependencies
	if dependencies[policyKey] != pv.KubernetesPolicyVersion || !pinnedImage(dependencies[helperImageKey]) {
		return pv.ErrEvidence
	}
	for key, value := range request.Dependencies {
		if actual, found := dependencies[key]; !found || actual != value {
			return pv.ErrEvidence
		}
	}
	for key := range dependencies {
		if _, supplied := request.Dependencies[key]; !supplied && key != policyKey && key != helperImageKey {
			return pv.ErrEvidence
		}
	}
	environment := pv.Environment{Image: request.Image, ImageID: manifest.Environment.ImageID,
		Platform: request.Platform, Profile: request.Profile, Variables: request.Variables,
		Dependencies: dependencies, Services: request.Services, Requirements: request.RequiredEnvironment}
	expected, err := pv.RequestManifest(request, &pv.PreparedSources{Sources: staged.Sources, Files: staged.Files}, environment)
	if err != nil {
		return pv.ErrEvidence
	}
	want, err := pv.ManifestDigest(expected)
	if err != nil {
		return pv.ErrEvidence
	}
	actual, err := pv.ManifestDigest(manifest)
	if err != nil || actual != want {
		return pv.ErrIntegrity
	}
	return nil
}

func incompleteRecord(submission *pv.KubernetesSubmission) *pv.Record {
	record := &pv.Record{Manifest: submission.Manifest, State: pv.RunInterrupted,
		Assessment: pv.Assessment{Conclusion: pv.UnavailableAction(submission.Manifest.Action),
			Reason: "validation adapter did not obtain verified terminal evidence; receipt only"}}
	if submission.Binding != nil {
		record.Binding = *submission.Binding
	}
	return record
}

func (t *transport) cancel(ctx context.Context, pinned *pv.KubernetesSubmission, staged Staged) error {
	response, err := t.request(ctx, http.MethodPost, "/api/v1/validations/"+pinned.RequestID+"/cancel", nil, http.StatusAccepted, maxSubmissionBytes)
	if err != nil {
		var status *statusError
		if errors.As(err, &status) && status.code == http.StatusConflict {
			return nil
		}
		return errors.Join(errors.New("exact validation submission cancellation could not be acknowledged"), err)
	}
	var next pv.KubernetesSubmission
	if decodeJSON(response, &next) != nil || validateSubmission(t.api.Namespace, staged, pinned, &next) != nil ||
		(next.State != pv.SubmissionCancelling && next.State != pv.SubmissionTerminal) {
		return errors.New("validation cancellation response lacks the exact cancelling or terminal submission")
	}
	*pinned = next
	return nil
}

func wait(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
