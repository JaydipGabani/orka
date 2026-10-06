package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/orka-agents/orka/internal/remediation/disclosure"
	"github.com/orka-agents/orka/internal/remediation/icm"
	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/store"
)

type Service struct {
	config   Config
	policies map[string]Policy
	owner    string
}

func New(ctx context.Context, config Config) (*Service, error) {
	if config.Store == nil || config.Processor == nil || len(kubevalidation.IsDNS1123Label(config.Namespace)) != 0 {
		return nil, ErrPolicy
	}
	if config.Interval == 0 {
		config.Interval = time.Second
	}
	if config.Lease == 0 {
		config.Lease = 30 * time.Second
	}
	if config.Workers == 0 {
		config.Workers = 2
	}
	if config.IntakeRetention == 0 {
		config.IntakeRetention = 30 * 24 * time.Hour
	}
	if config.IntakeRetentionInterval == 0 {
		config.IntakeRetentionInterval = time.Hour
	}
	if config.Interval < 10*time.Millisecond || config.Lease < 300*time.Millisecond || config.Lease > 5*time.Minute ||
		config.Workers < 1 || config.Workers > 8 || config.IntakeRetention <= 0 || config.IntakeRetentionInterval <= 0 {
		return nil, ErrPolicy
	}
	policies := make(map[string]Policy)
	for _, policy := range config.Policies {
		if err := validatePolicy(policy); err != nil || policy.Namespace != config.Namespace {
			return nil, ErrPolicy
		}
		if _, exists := policies[policy.Name]; exists {
			return nil, ErrPolicy
		}
		raw, err := json.Marshal(policy)
		if err != nil || len(raw) > MaxPolicyBytes {
			return nil, ErrPolicy
		}
		var frozen Policy
		if err := json.Unmarshal(raw, &frozen); err != nil {
			return nil, ErrPolicy
		}
		policies[policy.Name] = frozen
	}
	if len(policies) == 0 && !config.AdmissionDisabled {
		return nil, ErrPolicy
	}
	if err := config.Store.InitializeRemediationStore(ctx); err != nil {
		return nil, err
	}
	owner := make([]byte, 16)
	if _, err := rand.Read(owner); err != nil {
		return nil, err
	}
	return &Service{config: config, policies: policies, owner: hex.EncodeToString(owner)}, nil
}

func DecodeRequest(raw []byte) (Request, error) {
	var request Request
	if err := decodeObject(raw, MaxRequestBytes, &request); err != nil {
		return request, err
	}
	if request.Mode == "" {
		request.Mode = Generate
	}
	if len(request.RequestID) > 96 || len(kubevalidation.IsDNS1123Subdomain(request.RequestID)) != 0 ||
		(request.Policy != "" && len(kubevalidation.IsDNS1123Label(request.Policy)) != 0) ||
		(request.Mode != Generate && request.Mode != Validate && request.Mode != Verify) ||
		(request.Incident == "") == (len(request.Report) == 0) || len(request.Patch) > MaxPatchBytes ||
		(request.Mode == Verify) != (request.Patch != "") {
		return request, ErrInvalid
	}
	if request.Incident != "" {
		id, err := icm.IncidentID(request.Incident)
		if err != nil {
			return request, ErrInvalid
		}
		request.Incident = id
	}
	return request, nil
}

func (s *Service) PolicyName(namespace, name string) (string, error) {
	if s == nil || namespace != s.config.Namespace {
		return "", ErrPolicy
	}
	if s.config.AdmissionDisabled {
		return "", ErrDisabled
	}
	if name == "" && len(s.policies) == 1 {
		for candidate := range s.policies {
			name = candidate
		}
	}
	if _, ok := s.policies[name]; !ok {
		return "", ErrPolicy
	}
	return name, nil
}

func (s *Service) Submit(ctx context.Context, namespace, actor string, request Request) (Status, bool, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return Status{}, false, ErrInvalid
	}
	request, err = DecodeRequest(raw)
	if err != nil || strings.TrimSpace(actor) == "" || len(actor) > 1024 {
		return Status{}, false, ErrInvalid
	}
	if request.Incident != "" {
		return Status{}, false, ErrIntakeConnectorUnavailable
	}
	name, err := s.PolicyName(namespace, request.Policy)
	if err != nil {
		return Status{}, false, err
	}
	policy := s.policies[name]
	identity, err := actorFromContext(ctx, actor)
	if err != nil {
		return Status{}, false, err
	}
	if s.config.Authorize != nil {
		if err := s.config.Authorize(ctx, namespace, name, identity); err != nil {
			return Status{}, false, err
		}
	}
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return Status{}, false, ErrPolicy
	}
	submission := StoredRequest{
		RequestID:       "client-" + strings.TrimPrefix(Digest([]byte(actor+"\x00"+identity.UID+"\x00"+request.RequestID)), "sha256:")[:40],
		ClientRequestID: request.RequestID, Policy: name, Mode: request.Mode,
		Incident: request.Incident, Patch: request.Patch, Actor: identity,
	}
	if request.Patch != "" && disclosure.Check(disclosure.Candidate, []byte(request.Patch)) != nil {
		return Status{}, false, ErrInvalid
	}
	inputDigest := Digest([]byte("icm:" + request.Incident))
	if len(request.Report) != 0 {
		report, err := intake.Parse(request.Report)
		if err != nil {
			return Status{}, false, ErrInvalid
		}
		submission.Report, inputDigest = &report, report.SourceDigest
	}
	requestJSON, err := json.Marshal(submission)
	if err != nil {
		return Status{}, false, ErrInvalid
	}
	var sourceKind, sourceID string
	if submission.Report != nil {
		sourceKind, sourceID = submission.Report.SourceKind, submission.Report.SourceID
	}
	sourceOperation, err := store.RemediationSourceOperationKey(name, sourceKind, sourceID, inputDigest, string(request.Mode), request.Patch)
	if err != nil {
		return Status{}, false, ErrInvalid
	}
	candidate := &store.RemediationRun{
		Namespace: namespace, RequestID: submission.RequestID, SubmittedBy: actor,
		Mode: string(request.Mode), InputDigest: inputDigest, PolicyDigest: Digest(policyJSON),
		RequestJSON: requestJSON, PolicyJSON: policyJSON, Intake: request.Report,
		SourceOperationKey: sourceOperation,
	}
	existing, err := s.admitSubmission(ctx, candidate, policy)
	if err != nil {
		return Status{}, false, err
	}
	if existing != nil {
		status, err := statusOf(existing)
		return status, false, err
	}
	now := time.Now().UTC()
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return Status{}, false, err
	}
	candidate.ID, candidate.Phase = "rm-"+hex.EncodeToString(idBytes), store.RemediationPhaseQueued
	candidate.CreatedAt, candidate.UpdatedAt = now, now
	candidate.Deadline = now.Add(time.Duration(policy.MaxDurationSeconds) * time.Second)
	run, created, err := s.config.Store.CreateRemediationRun(ctx, candidate)
	if err != nil {
		return Status{}, false, err
	}
	status, err := statusOf(run)
	return status, created, err
}

type admissionStateProcessor interface {
	AdmissionState(context.Context, string, Policy) (json.RawMessage, error)
}

func (s *Service) admitSubmission(ctx context.Context, candidate *store.RemediationRun, policy Policy) (*store.RemediationRun, error) {
	existing, err := s.replaySubmission(ctx, candidate)
	if !errors.Is(err, store.ErrNotFound) {
		return existing, err
	}
	candidate.StateJSON = json.RawMessage(`{}`)
	admission, supported := s.config.Processor.(admissionStateProcessor)
	if !supported {
		return nil, nil
	}
	state, err := admission.AdmissionState(ctx, candidate.Namespace, policy)
	if err == nil {
		var object map[string]json.RawMessage
		if len(state) > store.RemediationMaxStateBytes || json.Unmarshal(state, &object) != nil || object == nil {
			err = ErrPolicy
		}
	}
	if err != nil {
		// A concurrent identical submission may have committed after our first
		// lookup. Its frozen boundary remains authoritative even if the live
		// dependency disappeared while this request was taking its snapshot.
		existing, replayErr := s.replaySubmission(ctx, candidate)
		if !errors.Is(replayErr, store.ErrNotFound) {
			return existing, replayErr
		}
		return nil, err
	}
	candidate.StateJSON = bytes.Clone(state)
	return nil, nil
}

func (s *Service) replaySubmission(ctx context.Context, candidate *store.RemediationRun) (*store.RemediationRun, error) {
	existing, err := s.config.Store.GetRemediationRunByRequestID(ctx, candidate.Namespace, candidate.RequestID)
	if err != nil {
		return nil, err
	}
	if existing == nil || existing.Namespace != candidate.Namespace || existing.RequestID != candidate.RequestID ||
		existing.SubmittedBy != candidate.SubmittedBy || existing.Mode != candidate.Mode ||
		existing.InputDigest != candidate.InputDigest || !bytes.Equal(existing.RequestJSON, candidate.RequestJSON) {
		return nil, store.ErrDuplicateMismatch
	}
	return existing, nil
}

func statusOf(run *store.RemediationRun) (Status, error) {
	var request StoredRequest
	if json.Unmarshal(run.RequestJSON, &request) != nil || request.Policy == "" {
		return Status{}, ErrInvalid
	}
	var state struct {
		Stage string `json:"stage"`
	}
	if json.Unmarshal(run.StateJSON, &state) != nil {
		return Status{}, ErrInvalid
	}
	return Status{
		ID: run.ID, Namespace: run.Namespace, RequestID: request.ClientRequestID, Mode: Mode(run.Mode),
		Policy: request.Policy, Phase: run.Phase, Stage: state.Stage, Reason: run.Reason, Revision: run.Revision,
		ApprovalDigest: run.ApprovalDigest, CancelRequested: run.CancelRequested,
		CreatedAt: run.CreatedAt, UpdatedAt: run.UpdatedAt, Deadline: run.Deadline,
		Cleanup: run.Cleanup,
	}, nil
}

// IsFinalResultArtifact identifies staged handoff artifacts that require a
// successful run, rather than merely a candidate that passed its checks.
func IsFinalResultArtifact(name string) bool {
	return name == "candidate.patch" || strings.HasPrefix(name, "verification-")
}

func (s *Service) Get(ctx context.Context, namespace, id string) (Status, error) {
	if s == nil || namespace != s.config.Namespace {
		return Status{}, store.ErrNotFound
	}
	run, err := s.config.Store.GetRemediationRun(ctx, namespace, id)
	if err != nil {
		return Status{}, err
	}
	artifacts, err := s.config.Store.ListRemediationArtifacts(ctx, namespace, id)
	if err != nil {
		return Status{}, err
	}
	status, err := statusOf(run)
	if err != nil {
		return Status{}, err
	}
	for _, artifact := range artifacts {
		if run.Phase != store.RemediationPhaseSucceeded && IsFinalResultArtifact(artifact.Name) {
			continue
		}
		status.Artifacts = append(status.Artifacts, artifact)
	}
	return status, nil
}

func (s *Service) Cancel(ctx context.Context, namespace, id string) (Status, error) {
	if s == nil || namespace != s.config.Namespace {
		return Status{}, store.ErrNotFound
	}
	run, err := s.config.Store.CancelRemediationRun(ctx, namespace, id, time.Now().UTC())
	if err != nil {
		return Status{}, err
	}
	return statusOf(run)
}

func (s *Service) Approve(ctx context.Context, namespace, id, digest, actor string) (Status, error) {
	if s == nil || namespace != s.config.Namespace {
		return Status{}, store.ErrNotFound
	}
	if s.config.AdmissionDisabled {
		return Status{}, ErrDisabled
	}
	run, err := s.config.Store.ApproveRemediationRun(ctx, namespace, id, digest, actor, time.Now().UTC())
	if err != nil {
		return Status{}, err
	}
	return statusOf(run)
}

func (s *Service) Artifact(ctx context.Context, namespace, id, name string) (*store.RemediationArtifact, []byte, error) {
	if s == nil || namespace != s.config.Namespace {
		return nil, nil, store.ErrNotFound
	}
	if IsFinalResultArtifact(name) {
		run, err := s.config.Store.GetRemediationRun(ctx, namespace, id)
		if err != nil {
			return nil, nil, err
		}
		if run.Phase != store.RemediationPhaseSucceeded {
			return nil, nil, store.ErrNotFound
		}
	}
	ref, raw, err := s.config.Store.GetRemediationArtifact(ctx, namespace, id, name)
	if err != nil {
		return nil, nil, err
	}
	if disclosure.Check(disclosure.Artifact, raw) != nil {
		return nil, nil, ErrPolicy
	}
	return ref, raw, nil
}

func (s *Service) NeedLeaderElection() bool { return true }

func (s *Service) Start(ctx context.Context) error {
	var workers sync.WaitGroup
	workers.Go(func() { s.retainIntake(ctx) })
	for range s.config.Workers {
		workers.Go(func() {
			s.worker(ctx)
		})
	}
	workers.Wait()
	return nil
}

func (s *Service) worker(ctx context.Context) {
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()
	for {
		if err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			log.FromContext(ctx).Error(err, "remediation scheduling failed", "namespace", s.config.Namespace)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) RunOnce(ctx context.Context) error {
	run, err := s.config.Store.ClaimNextRemediationRun(ctx, s.config.Namespace, s.owner, time.Now().UTC(), s.config.Lease)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.config.AdmissionDisabled && !run.CancelRequested {
		run, err = s.config.Store.CancelRemediationRun(ctx, run.Namespace, run.ID, time.Now().UTC())
		if err != nil {
			return err
		}
	}
	if !run.CancelRequested && run.Phase != store.RemediationPhaseCancelling && time.Now().Before(run.Deadline) &&
		s.config.Authorize != nil {
		var request StoredRequest
		if json.Unmarshal(run.RequestJSON, &request) != nil {
			return ErrInvalid
		}
		authErr := s.config.Authorize(ctx, run.Namespace, request.Policy, request.Actor)
		if errors.Is(authErr, ErrRetryable) {
			session := &Session{store: s.config.Store, run: run, owner: s.owner, epoch: run.ClaimEpoch}
			return session.Checkpoint(ctx, store.RemediationPhaseRunning, "waiting-for-authorization", run.StateJSON, "")
		}
		if _, exists := s.policies[request.Policy]; !exists || authErr != nil {
			run, err = s.config.Store.CancelRemediationRun(ctx, run.Namespace, run.ID, time.Now().UTC())
			if err != nil {
				return err
			}
		}
	}
	return s.process(ctx, run)
}

func (s *Service) process(ctx context.Context, run *store.RemediationRun) error {
	session := &Session{store: s.config.Store, run: run, owner: s.owner, epoch: run.ClaimEpoch}
	operation, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	monitorDone := make(chan struct{})
	stopMonitor := make(chan struct{})
	go func() {
		defer close(monitorDone)
		s.monitor(ctx, session, cancel, stopMonitor)
	}()
	defer func() {
		close(stopMonitor)
		<-monitorDone
	}()
	var runErr error
	if run.CancelRequested || run.Phase == store.RemediationPhaseCancelling || !time.Now().Before(run.Deadline) {
		cancel(context.Canceled)
	} else {
		runErr = s.config.Processor.Run(operation, session)
	}
	if ctx.Err() != nil || errors.Is(context.Cause(operation), ErrClaimLost) {
		return nil
	}
	if errors.Is(context.Cause(operation), ErrRetryable) {
		runErr = ErrRetryable
	}
	current, err := session.Current(ctx)
	if err != nil {
		stored, readErr := s.config.Store.GetRemediationRun(ctx, run.Namespace, run.ID)
		if readErr == nil && (store.IsRemediationTerminalPhase(stored.Phase) ||
			stored.Phase == store.RemediationPhaseNeedsInput || stored.Phase == store.RemediationPhaseNeedsAdapter ||
			stored.Phase == store.RemediationPhaseNeedsApproval) {
			return nil
		}
		return err
	}
	if current.CancelRequested || current.Phase == store.RemediationPhaseCancelling || !time.Now().Before(current.Deadline) {
		return s.settle(ctx, session, current, runErr)
	}
	if runErr == nil {
		return nil
	}
	if errors.Is(runErr, ErrAwaitApproval) {
		return nil
	}
	if errors.Is(runErr, ErrRetryable) {
		return session.Checkpoint(ctx, store.RemediationPhaseRunning, "waiting-for-infrastructure", current.StateJSON, "")
	}
	return s.settle(ctx, session, current, runErr)
}

func (s *Service) monitor(ctx context.Context, session *Session, cancel context.CancelCauseFunc, stop <-chan struct{}) {
	ticker := time.NewTicker(s.config.Lease / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			run, err := session.Current(ctx)
			if err != nil {
				cancel(ErrClaimLost)
				return
			}
			if err := s.config.Store.RenewRemediationClaim(ctx, run.Namespace, run.ID, s.owner, session.epoch,
				time.Now().UTC(), s.config.Lease); err != nil {
				cancel(ErrClaimLost)
				return
			}
			if run.CancelRequested || !time.Now().Before(run.Deadline) {
				cancel(context.Canceled)
			}
			if !run.CancelRequested && s.config.Authorize != nil {
				var request StoredRequest
				if json.Unmarshal(run.RequestJSON, &request) != nil {
					cancel(ErrClaimLost)
					return
				}
				authErr := s.config.Authorize(ctx, run.Namespace, request.Policy, request.Actor)
				if errors.Is(authErr, ErrRetryable) {
					cancel(ErrAuthorizationUnavailable)
					return
				}
				if authErr != nil {
					if _, err := s.config.Store.CancelRemediationRun(ctx, run.Namespace, run.ID, time.Now().UTC()); err != nil {
						cancel(ErrClaimLost)
						return
					}
					cancel(context.Canceled)
				}
			}
		}
	}
}

func failureState(err error) (string, string) {
	switch {
	case errors.Is(err, ErrNeedsAdapter):
		return "NeedsAdapter", "required-environment-not-supported"
	case errors.Is(err, ErrNeedsInput):
		return "NeedsInput", "target-or-input-requires-confirmation"
	case errors.Is(err, ErrUnknown):
		return "NeedsInput", "execution-requires-reconciliation"
	case errors.Is(err, ErrChecksProposal):
		return "Failed", "invalid-checks-proposal"
	default:
		return "Failed", "execution-failed"
	}
}
