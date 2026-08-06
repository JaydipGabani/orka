/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/harness"
	"github.com/orka-agents/orka/internal/store"
)

const (
	// DefaultHarnessV1DispatchInterval paces the leader-elected v1 scan loop.
	DefaultHarnessV1DispatchInterval = 2 * time.Second
	// DefaultHarnessV1StreamPollTimeout bounds one SSE poll per task per pass,
	// mirroring the legacy wrapper reconcile poll.
	DefaultHarnessV1StreamPollTimeout = 2 * time.Second
	// DefaultHarnessV1CancelSettlementTimeout bounds how long a requested
	// cancellation may stay unsettled before it is classified OutcomeUnknown.
	DefaultHarnessV1CancelSettlementTimeout = 2 * time.Minute

	harnessV1WrapperRuntimeName    = "wrapper"
	harnessV1AdoptedNoStateMessage = "adopted v1 turn has no recoverable executor state"
	harnessV1NoTimeoutDuration     = time.Hour * 24 * 365 * 100
)

// Bounded harness v1 attempt terminal/cause reason codes.
const (
	harnessV1ReasonCompleted            = "Completed"
	harnessV1ReasonTurnFailed           = "TurnFailed"
	harnessV1ReasonTurnCancelled        = "TurnCancelled"
	harnessV1ReasonSubmissionRejected   = "SubmissionRejected"
	harnessV1ReasonAdoptedTurnMissing   = "AdoptedTurnMissing"
	harnessV1ReasonSubmissionUnprovable = "SubmissionUnprovable"
	harnessV1ReasonCancelUnsettled      = "CancelUnsettled"
	harnessV1ReasonTurnStateLost        = "TurnStateLost"
	harnessV1ReasonTimeout              = "Timeout"
	harnessV1ReasonTaskDeleting         = "TaskDeleting"
)

// HarnessV1Dispatcher drives harness-v1-bound agent Tasks through the durable
// attempt state machine against the restored v1 wrapper. Task reconciliation
// only persists the write-once binding; this leader-elected runnable owns
// StartTurn submission, ambiguous-submission recovery, frame streaming with
// the persisted-frame journal backstop, cancellation, and terminal Task
// projection. It accepts only Tasks bound to orka.harness.v1 on the built-in
// harness-wrapper backend and never falls back to or from the v2 path.
type HarnessV1Dispatcher struct {
	Client    client.Client
	APIReader client.Reader
	Attempts  store.HarnessV1AttemptStore
	Snapshots store.AgentExecutionSnapshotStore
	// ExecutionEvents backs the harness.TurnJournal persisted-frame backstop:
	// a positive persisted-frame lookup proves the deterministic turn was
	// accepted and ran, and therefore suppresses another StartTurn.
	ExecutionEvents store.ExecutionEventStore
	Epochs          *ControllerEpochManager
	Recorder        record.EventRecorder
	// WrapperEndpoint is the non-secret base URL of the built-in v1 wrapper.
	WrapperEndpoint string
	// WrapperBearerToken authenticates controller calls to the wrapper. It is
	// held in memory only and never enters Task status, events, or logs.
	WrapperBearerToken string
	Interval           time.Duration
	// StreamPollTimeout bounds each per-task SSE poll so one task cannot stall
	// the scan loop.
	StreamPollTimeout time.Duration
	// CancelSettlementTimeout bounds CancelRequested settlement before the
	// attempt is classified OutcomeUnknown with reason CancelUnsettled.
	CancelSettlementTimeout time.Duration
}

// NeedLeaderElection restricts v1 dispatch to the elected controller.
func (d *HarnessV1Dispatcher) NeedLeaderElection() bool { return true }

// Start validates dependencies, waits for the fenced controller epoch, and
// runs the periodic dispatch scan until the manager context ends.
func (d *HarnessV1Dispatcher) Start(ctx context.Context) error {
	if d.Client == nil || d.Attempts == nil || d.Snapshots == nil || d.ExecutionEvents == nil || d.Epochs == nil {
		return fmt.Errorf("harness v1 dispatcher requires Kubernetes client, attempt store, snapshot store, execution event store, and epoch manager")
	}
	if strings.TrimSpace(d.WrapperEndpoint) == "" {
		return fmt.Errorf("harness v1 dispatcher requires the wrapper endpoint")
	}
	if _, err := d.wrapperClient(); err != nil {
		return err
	}
	if d.APIReader == nil {
		d.APIReader = d.Client
	}
	if d.Interval <= 0 {
		d.Interval = DefaultHarnessV1DispatchInterval
	}
	if _, err := d.Epochs.CurrentFence(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(d.Interval)
	defer ticker.Stop()
	for {
		if err := d.dispatchOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logf.FromContext(ctx).Error(err, "harness v1 dispatcher scan failed")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (d *HarnessV1Dispatcher) wrapperClient() (*harness.Client, error) {
	wrapper, err := harness.NewClient(d.WrapperEndpoint, harness.WithBearerToken(d.WrapperBearerToken))
	if err != nil {
		return nil, fmt.Errorf("invalid harness v1 wrapper endpoint: %w", err)
	}
	return wrapper, nil
}

// dispatchOnce lists Tasks uncached and drives every route-eligible harness v1
// Task one bounded step forward.
func (d *HarnessV1Dispatcher) dispatchOnce(ctx context.Context) error {
	fence, err := d.Epochs.CurrentFence(ctx)
	if err != nil {
		return err
	}
	reader := d.APIReader
	if reader == nil {
		reader = d.Client
	}
	var tasks corev1alpha1.TaskList
	if err := reader.List(ctx, &tasks); err != nil {
		return err
	}
	log := logf.FromContext(ctx)
	for i := range tasks.Items {
		task := &tasks.Items[i]
		if harnessV1DispatchBinding(task) == nil {
			continue
		}
		if task.Status.Phase != corev1alpha1.TaskPhasePending && task.Status.Phase != corev1alpha1.TaskPhaseRunning {
			continue
		}
		if err := d.driveTask(ctx, task.DeepCopy(), fence); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			log.Error(err, "harness v1 dispatch failed", "namespace", task.Namespace, "task", task.Name)
		}
	}
	return nil
}

// harnessV1DispatchBinding returns the Task's execution binding only when this
// dispatcher is the route authority for it: an execute-mode orka.harness.v1
// binding on the built-in harness-wrapper backend.
func harnessV1DispatchBinding(task *corev1alpha1.Task) *corev1alpha1.AgentExecutionBinding {
	if task == nil || task.Spec.Type != corev1alpha1.TaskTypeAgent {
		return nil
	}
	binding := task.Status.AgentExecutionBinding
	if binding == nil ||
		binding.ContractVersion != corev1alpha1.AgentRuntimeContractHarnessV1 ||
		binding.Backend != corev1alpha1.AgentExecutionBackendHarnessWrapper ||
		binding.Mode != corev1alpha1.AgentExecutionBindingModeExecute {
		return nil
	}
	return binding
}

// harnessV1SnapshotInputs is the loose, non-secret view of an immutable v1
// execution snapshot body needed to construct or observe one turn.
type harnessV1SnapshotInputs struct {
	adopted     bool
	prompt      string
	model       string
	sessionName string
}

func parseHarnessV1SnapshotBody(body []byte) (harnessV1SnapshotInputs, error) {
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return harnessV1SnapshotInputs{}, fmt.Errorf("decode harness v1 execution snapshot body: %w", err)
	}
	inputs := harnessV1SnapshotInputs{}
	if adopted, ok := decoded["adoption"].(bool); ok {
		inputs.adopted = adopted
	}
	if prompt, ok := decoded["prompt"].(string); ok {
		inputs.prompt = prompt
	}
	if model, ok := decoded["model"].(string); ok {
		inputs.model = model
	}
	if configuration, ok := decoded["configuration"].(map[string]any); ok {
		if model, ok := configuration["model"].(string); ok && inputs.model == "" {
			inputs.model = model
		}
	}
	if ref, ok := decoded["sessionRef"].(map[string]any); ok {
		if name, ok := ref["name"].(string); ok {
			inputs.sessionName = name
		}
	}
	return inputs, nil
}

// driveTask advances one Task a single bounded step: at most one wrapper
// control call plus one stream poll per pass.
func (d *HarnessV1Dispatcher) driveTask(ctx context.Context, task *corev1alpha1.Task, fence store.ControllerEpochFence) error {
	binding := harnessV1DispatchBinding(task)
	if binding == nil {
		return nil
	}
	snapshot, err := d.Snapshots.GetAgentExecutionSnapshot(ctx, store.AgentExecutionSnapshotKey{
		TaskUID: string(task.UID), Digest: binding.Snapshot.Digest,
	})
	if err != nil {
		return fmt.Errorf("load immutable v1 execution snapshot: %w", err)
	}
	inputs, err := parseHarnessV1SnapshotBody(snapshot.Body)
	if err != nil {
		return err
	}
	attempt, err := d.ensureAttempt(ctx, task, binding, inputs, fence)
	if err != nil || attempt == nil {
		return err
	}
	wrapper, err := d.wrapperClient()
	if err != nil {
		return err
	}
	journal := d.turnJournal(task)
	cancelWanted, cancelReason := harnessV1CancellationWanted(task)

	switch attempt.State {
	case store.HarnessV1AttemptPrepared:
		if inputs.adopted {
			// An adoption snapshot represents a pre-existing wrapper-owned
			// turn; Prepared never means locally-unsubmitted for it, so even a
			// cancelling Task must observe the remote turn instead of
			// terminating the attempt locally.
			return d.driveAdoptedObservation(ctx, task, attempt, wrapper, journal, fence)
		}
		if cancelWanted {
			return d.cancelUnstartedAttempt(ctx, task, attempt, fence, cancelReason)
		}
		return d.submitAttempt(ctx, task, attempt, inputs, wrapper, journal, fence)
	case store.HarnessV1AttemptSubmitting:
		if inputs.adopted {
			// Adoption never sends StartTurn, so a Submitting adopted attempt
			// carries no submission ambiguity: re-run the adoption evidence.
			return d.driveAdoptedObservation(ctx, task, attempt, wrapper, journal, fence)
		}
		// A durable Submitting state found at scan time is a crash window: the
		// request may or may not have reached the wrapper. Never resend.
		return d.recoverAmbiguousSubmission(ctx, attempt, journal, fence, false)
	case store.HarnessV1AttemptSubmittedUnknown:
		return d.resolveSubmittedUnknown(ctx, task, attempt, wrapper, journal, fence)
	case store.HarnessV1AttemptAccepted, store.HarnessV1AttemptRunning:
		if cancelWanted && attempt.CancelRequestedAt == nil {
			return d.requestCancellation(ctx, task, attempt, inputs, wrapper, fence, cancelReason)
		}
		return d.observeAcceptedTurn(ctx, task, attempt, wrapper, journal, fence)
	case store.HarnessV1AttemptCancelRequested:
		return d.driveCancelRequested(ctx, task, attempt, inputs, wrapper, journal, fence)
	case store.HarnessV1AttemptSettling:
		return d.finalizeSettlingAttempt(ctx, task, attempt, wrapper, journal, fence)
	default:
		return nil
	}
}

// ensureAttempt reuses the existing nonterminal attempt, re-projects a stale
// terminal attempt onto a nonterminal Task, or creates attempt N+1 in Prepared.
// It never creates a second concurrent attempt and never creates attempts for
// deleting Tasks.
func (d *HarnessV1Dispatcher) ensureAttempt(
	ctx context.Context,
	task *corev1alpha1.Task,
	binding *corev1alpha1.AgentExecutionBinding,
	inputs harnessV1SnapshotInputs,
	fence store.ControllerEpochFence,
) (*store.HarnessV1Attempt, error) {
	attempts, err := d.Attempts.ListHarnessV1AttemptsByTask(ctx, task.Namespace, string(task.UID))
	if err != nil {
		return nil, err
	}
	for i := len(attempts) - 1; i >= 0; i-- {
		if !store.IsTerminalHarnessV1AttemptState(attempts[i].State) {
			active := attempts[i]
			return &active, nil
		}
	}
	if len(attempts) > 0 {
		// Every attempt is terminal but the Task is still Pending/Running: the
		// terminal projection was lost. Re-project idempotently; retry class
		// none forbids creating another attempt.
		latest := attempts[len(attempts)-1]
		phase, message := harnessV1TerminalProjection(&latest)
		return nil, d.projectTaskTerminal(ctx, task, phase, message)
	}
	if !task.DeletionTimestamp.IsZero() {
		return nil, nil
	}
	number := max(task.Status.Attempts, 0) + 1
	turnID := fmt.Sprintf("%s-a%d", task.UID, number)
	if inputs.adopted {
		if legacy := strings.TrimSpace(task.Annotations[harnessWrapperTurnIDAnnotation]); legacy != "" {
			// The sealed inventory adopted a wrapper-owned turn; observe the
			// exact historical identity instead of minting a new one.
			turnID = legacy
		}
	}
	requestDigest, err := acpDomainDigest("harness-v1-request", map[string]any{
		"namespace": task.Namespace,
		"taskName":  task.Name,
		"taskUID":   string(task.UID),
		"attempt":   number,
		"turnID":    turnID,
		"adopted":   inputs.adopted,
		"prompt":    inputs.prompt,
		"model":     inputs.model,
	})
	if err != nil {
		return nil, err
	}
	attempt := &store.HarnessV1Attempt{
		Namespace:           task.Namespace,
		TaskName:            task.Name,
		TaskUID:             string(task.UID),
		Attempt:             number,
		BindingDigest:       binding.BindingDigest,
		SnapshotDigest:      binding.Snapshot.Digest,
		RequestDigest:       requestDigest,
		TurnID:              turnID,
		CorrelationID:       string(task.UID),
		Backend:             string(corev1alpha1.AgentExecutionBackendHarnessWrapper),
		BackendEndpoint:     d.WrapperEndpoint,
		State:               store.HarnessV1AttemptPrepared,
		DuplicateSafe:       false,
		RetryClass:          store.HarnessV1RetryClassNone,
		ControllerEpochName: fence.Name,
		ControllerEpoch:     fence.Epoch,
	}
	if err := d.Attempts.CreateHarnessV1Attempt(ctx, attempt); err != nil {
		return nil, err
	}
	return d.Attempts.GetHarnessV1Attempt(ctx, store.HarnessV1AttemptKey{
		Namespace: task.Namespace, TaskUID: string(task.UID), Attempt: number,
	})
}

// transitionAttempt applies one fenced, operation-stamped CAS transition.
func (d *HarnessV1Dispatcher) transitionAttempt(
	ctx context.Context,
	attempt *store.HarnessV1Attempt,
	target store.HarnessV1AttemptState,
	operation string,
	fence store.ControllerEpochFence,
	updates store.HarnessV1AttemptUpdates,
) (*store.HarnessV1Attempt, error) {
	key := store.HarnessV1AttemptKey{Namespace: attempt.Namespace, TaskUID: attempt.TaskUID, Attempt: attempt.Attempt}
	operationID := fmt.Sprintf("%s-%d", operation, fence.Epoch)
	digest, err := acpDomainDigest("harness-v1-attempt", map[string]any{
		"attempt":   key.CanonicalID(),
		"operation": operationID,
		"from":      string(attempt.State),
		"to":        string(target),
		"turnID":    attempt.TurnID,
		"epochName": fence.Name,
		"epoch":     fence.Epoch,
	})
	if err != nil {
		return nil, err
	}
	return d.Attempts.TransitionHarnessV1Attempt(ctx, store.HarnessV1AttemptTransition{
		Key:             key,
		ExpectedVersion: attempt.Version,
		ExpectedState:   attempt.State,
		TargetState:     target,
		OperationID:     operationID,
		OperationDigest: digest,
		Fence:           fence,
		Updates:         updates,
	})
}

// submitAttempt runs the full-snapshot v1 admission path: Submitting is
// durable before StartTurn, and every wire outcome maps onto the durable
// submission-state machine without ever resending an ambiguous request.
func (d *HarnessV1Dispatcher) submitAttempt(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	inputs harnessV1SnapshotInputs,
	wrapper *harness.Client,
	journal harness.TurnJournal,
	fence store.ControllerEpochFence,
) error {
	request := d.startTurnRequest(task, attempt, inputs)
	if err := request.Validate(); err != nil {
		// Definitive pre-submission rejection: the request was never sent.
		reason := harnessV1ReasonSubmissionRejected
		rejected, terr := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptRejected, "reject-invalid", fence,
			store.HarnessV1AttemptUpdates{TerminalReason: &reason})
		if terr != nil {
			return terr
		}
		phase, message := harnessV1TerminalProjection(rejected)
		d.recordTaskEvent(task, corev1.EventTypeWarning, "HarnessV1TurnRejected", message)
		return d.projectTaskTerminal(ctx, task, phase, message)
	}
	if verified, err := d.verifyTaskBeforeSideEffect(ctx, task, attempt); err != nil || !verified {
		return err
	}
	endpoint := d.WrapperEndpoint
	attempt, err := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptSubmitting, "submit", fence,
		store.HarnessV1AttemptUpdates{BackendEndpoint: &endpoint})
	if err != nil {
		return err
	}
	_, startErr := wrapper.StartTurn(ctx, request)
	switch classifyHarnessV1SubmitError(startErr) {
	case harnessV1SubmitAccepted:
		return d.markAccepted(ctx, task, attempt, request, wrapper, journal, fence, "accept")
	case harnessV1SubmitRejected:
		reason := harnessV1ReasonSubmissionRejected
		rejected, terr := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptRejected, "reject", fence,
			store.HarnessV1AttemptUpdates{TerminalReason: &reason})
		if terr != nil {
			return terr
		}
		message := fmt.Sprintf("harness wrapper rejected the v1 turn: %v", startErr)
		phase, _ := harnessV1TerminalProjection(rejected)
		d.recordTaskEvent(task, corev1.EventTypeWarning, "HarnessV1TurnRejected", message)
		return d.projectTaskTerminal(ctx, task, phase, message)
	default:
		// Acceptance is unprovable. Persist SubmittedUnknown and immediately run
		// the persisted-frame recovery check; escalation to OutcomeUnknown is
		// deferred to a later pass. The request is never resent.
		return d.recoverAmbiguousSubmission(ctx, attempt, journal, fence, true)
	}
}

// recoverAmbiguousSubmission handles a Submitting attempt whose StartTurn
// outcome is unknown: persisted frames prove acceptance; otherwise the attempt
// becomes durable SubmittedUnknown.
func (d *HarnessV1Dispatcher) recoverAmbiguousSubmission(
	ctx context.Context,
	attempt *store.HarnessV1Attempt,
	journal harness.TurnJournal,
	fence store.ControllerEpochFence,
	freshAmbiguity bool,
) error {
	hasFrames, err := journal.HasPersistedFrames(ctx, harness.HarnessTurnID(attempt.TurnID))
	if err != nil {
		return err
	}
	if hasFrames {
		_, err := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptAccepted, "recover-accept", fence,
			store.HarnessV1AttemptUpdates{})
		return err
	}
	operation := "submit-ambiguous"
	if !freshAmbiguity {
		operation = "submit-lost"
	}
	_, err = d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptSubmittedUnknown, operation, fence,
		store.HarnessV1AttemptUpdates{})
	return err
}

// resolveSubmittedUnknown runs the recovery order for an ambiguously submitted
// request: persisted frames, then an authoritative wrapper stream lookup, then
// terminal OutcomeUnknown. It never resends the request.
func (d *HarnessV1Dispatcher) resolveSubmittedUnknown(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	wrapper *harness.Client,
	journal harness.TurnJournal,
	fence store.ControllerEpochFence,
) error {
	hasFrames, err := journal.HasPersistedFrames(ctx, harness.HarnessTurnID(attempt.TurnID))
	if err != nil {
		return err
	}
	if !hasFrames {
		outcome := d.pollTurnFrames(ctx, wrapper, journal, attempt)
		hasFrames = outcome.sawFrame
	}
	if hasFrames {
		_, err := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptAccepted, "recover-accept", fence,
			store.HarnessV1AttemptUpdates{})
		return err
	}
	// Still unprovable on a later pass: terminal OutcomeUnknown. Absence of
	// frames is never proof of non-acceptance, so Rejected is not reachable
	// from here without ledger-backed evidence.
	reason := harnessV1ReasonSubmissionUnprovable
	unknown, err := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptOutcomeUnknown, "submission-unprovable", fence,
		store.HarnessV1AttemptUpdates{TerminalReason: &reason})
	if err != nil {
		return err
	}
	phase, message := harnessV1TerminalProjection(unknown)
	d.recordTaskEvent(task, corev1.EventTypeWarning, "HarnessV1OutcomeUnknown", message)
	return d.projectTaskTerminal(ctx, task, phase, message)
}

// driveAdoptedObservation observes a sealed-inventory adopted turn from
// Prepared or Submitting. The executable request cannot be reconstructed from
// an adoption snapshot, so StartTurn is never called: acceptance requires
// positive frame evidence, a wrapper 404 with no frames is the definitive
// nothing-ever-started proof, and everything else stays put and retries.
func (d *HarnessV1Dispatcher) driveAdoptedObservation(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	wrapper *harness.Client,
	journal harness.TurnJournal,
	fence store.ControllerEpochFence,
) error {
	hasEvidence, err := journal.HasPersistedFrames(ctx, harness.HarnessTurnID(attempt.TurnID))
	if err != nil {
		return err
	}
	if !hasEvidence {
		outcome := d.pollTurnFrames(ctx, wrapper, journal, attempt)
		if outcome.err != nil {
			if harnessV1TurnNotFoundError(outcome.err) {
				// Definitive non-acceptance proof for an adopted turn: the
				// wrapper does not know it and nothing was ever journaled.
				// Adoption never submits, so this holds from Submitting too.
				reason := harnessV1ReasonAdoptedTurnMissing
				rejected, terr := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptRejected, "reject-adopted", fence,
					store.HarnessV1AttemptUpdates{TerminalReason: &reason})
				if terr != nil {
					return terr
				}
				phase, message := harnessV1TerminalProjection(rejected)
				d.recordTaskEvent(task, corev1.EventTypeWarning, "HarnessV1TurnRejected", message)
				return d.projectTaskTerminal(ctx, task, phase, message)
			}
			// Ambiguous observation: stay put and retry next pass.
			return outcome.err
		}
		if !outcome.sawFrame {
			// A frameless poll is not ownership proof: a pre-response timeout
			// and an established-but-empty stream are indistinguishable here.
			// Only positive frame evidence may accept an adopted turn.
			return nil
		}
	}
	// Pass through the durable submission states without sending anything.
	if attempt.State == store.HarnessV1AttemptPrepared {
		endpoint := d.WrapperEndpoint
		attempt, err = d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptSubmitting, "adopt-submit", fence,
			store.HarnessV1AttemptUpdates{BackendEndpoint: &endpoint})
		if err != nil {
			return err
		}
	}
	attempt, err = d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptAccepted, "adopt-accept", fence,
		store.HarnessV1AttemptUpdates{})
	if err != nil {
		return err
	}
	agentExecutionV1Admissions.WithLabelValues("adopted").Inc()
	d.recordTaskEvent(task, corev1.EventTypeNormal, "HarnessV1AdoptedTurn", "driving adopted harness v1 turn "+attempt.TurnID)
	if err := d.projectTaskRunning(ctx, task, attempt); err != nil {
		return err
	}
	return d.observeAcceptedTurn(ctx, task, attempt, wrapper, journal, fence)
}

// markAccepted persists acceptance, projects the Task to Running, and performs
// this pass's single stream poll.
func (d *HarnessV1Dispatcher) markAccepted(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	request harness.StartTurnRequest,
	wrapper *harness.Client,
	journal harness.TurnJournal,
	fence store.ControllerEpochFence,
	operation string,
) error {
	runtimeSessionID := string(request.RuntimeSessionID)
	correlationID := request.CorrelationID
	accepted, err := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptAccepted, operation, fence,
		store.HarnessV1AttemptUpdates{RuntimeSessionID: &runtimeSessionID, CorrelationID: &correlationID})
	if err != nil {
		return err
	}
	d.recordTaskEvent(task, corev1.EventTypeNormal, "HarnessV1TurnAccepted", "harness wrapper accepted v1 turn "+accepted.TurnID)
	if err := d.projectTaskRunning(ctx, task, accepted); err != nil {
		return err
	}
	return d.observeAcceptedTurn(ctx, task, accepted, wrapper, journal, fence)
}

// harnessV1StreamOutcome is the result of one bounded frame poll.
type harnessV1StreamOutcome struct {
	sawFrame bool
	lastSeq  int64
	terminal *harness.HarnessEventFrame
	err      error
}

// pollTurnFrames performs one short SSE poll, journaling every new frame. A
// poll deadline is a normal end-of-poll, not an error.
func (d *HarnessV1Dispatcher) pollTurnFrames(
	ctx context.Context,
	wrapper *harness.Client,
	journal harness.TurnJournal,
	attempt *store.HarnessV1Attempt,
) harnessV1StreamOutcome {
	outcome := harnessV1StreamOutcome{lastSeq: attempt.LastEventSeq}
	journalState, err := journal.Open(ctx)
	if err != nil {
		outcome.err = err
		return outcome
	}
	pollTimeout := d.StreamPollTimeout
	if pollTimeout <= 0 {
		pollTimeout = DefaultHarnessV1StreamPollTimeout
	}
	streamCtx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	turnID := harness.HarnessTurnID(attempt.TurnID)
	streamErr := wrapper.StreamFrames(streamCtx, turnID, attempt.LastEventSeq, func(frame harness.HarnessEventFrame) error {
		if frame.TurnID != turnID {
			return fmt.Errorf("harness frame identity does not match driven turn")
		}
		if attempt.RuntimeSessionID != "" && string(frame.RuntimeSessionID) != attempt.RuntimeSessionID {
			return fmt.Errorf("harness frame identity does not match driven turn")
		}
		if _, _, err := journalState.AppendFrameIfNew(streamCtx, frame); err != nil {
			return err
		}
		outcome.sawFrame = true
		if frame.Seq > outcome.lastSeq {
			outcome.lastSeq = frame.Seq
		}
		switch frame.Type {
		case harness.FrameTurnCompleted, harness.FrameTurnFailed, harness.FrameTurnCancelled:
			terminal := frame
			outcome.terminal = &terminal
		}
		return nil
	})
	if streamErr != nil && !errors.Is(streamErr, context.DeadlineExceeded) && !errors.Is(streamErr, context.Canceled) {
		outcome.err = streamErr
	}
	return outcome
}

// observeAcceptedTurn advances an Accepted/Running/Settling attempt from one
// stream poll: sequence progress, terminal settlement, and turn-state-loss
// classification.
func (d *HarnessV1Dispatcher) observeAcceptedTurn(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	wrapper *harness.Client,
	journal harness.TurnJournal,
	fence store.ControllerEpochFence,
) error {
	if attempt.State == store.HarnessV1AttemptAccepted || attempt.State == store.HarnessV1AttemptRunning {
		if err := d.projectTaskRunning(ctx, task, attempt); err != nil {
			return err
		}
	}
	outcome := d.pollTurnFrames(ctx, wrapper, journal, attempt)
	if outcome.terminal != nil {
		// A journaled terminal frame is authoritative and settles the attempt
		// even when the stream errored after emitting it; requiring a clean
		// poll would let a wrapper that drops the connection after its
		// terminal frame livelock the attempt forever.
		return d.settleTerminalFrame(ctx, task, attempt, outcome.terminal, fence)
	}
	if outcome.err != nil {
		if harnessV1TurnNotFoundError(outcome.err) {
			if attempt.State == store.HarnessV1AttemptCancelRequested {
				// CancelRequested settles only from a terminal frame or the
				// bounded settlement timeout; a lost turn must not preempt a
				// still-recoverable cancellation receipt.
				return nil
			}
			// Accepted is already durable proof the turn was admitted, and
			// replaying is forbidden; an authoritative 404 means the accepted
			// state is lost, so the outcome is irreducibly unknown. Waiting
			// indefinitely would leave the attempt with no exit.
			return d.markAttemptOutcomeUnknown(ctx, task, attempt, fence, "turn-state-lost", harnessV1ReasonTurnStateLost)
		}
		return outcome.err
	}
	if attempt.State == store.HarnessV1AttemptAccepted && outcome.sawFrame {
		// Checkpoint only non-terminal cursors so a crash before terminal
		// settlement replays the terminal frame (the journal deduplicates).
		seq := outcome.lastSeq
		running, err := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptRunning, "running", fence,
			store.HarnessV1AttemptUpdates{LastEventSeq: &seq})
		if err != nil {
			return err
		}
		attempt = running
	} else if attempt.State == store.HarnessV1AttemptRunning && outcome.sawFrame {
		// Intra-Running progress has no legal self-transition; the journal
		// remains the replay-safe cursor authority between passes.
		logf.FromContext(ctx).V(1).Info("harness v1 frame progress observed", "turnID", attempt.TurnID, "lastSeq", outcome.lastSeq)
	}
	return nil
}

// settleTerminalFrame drives Settling plus the exact terminal state for one
// authoritative terminal frame and projects the Task. The terminal decision
// (bounded reason plus receipt digest) is persisted atomically with Settling
// so a crash before the terminal transition can finalize from the durable
// record without depending on the live wrapper stream.
func (d *HarnessV1Dispatcher) settleTerminalFrame(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	frame *harness.HarnessEventFrame,
	fence store.ControllerEpochFence,
) error {
	target, operation, reason := harnessV1TerminalFrameState(attempt, frame)
	receiptDigest, err := acpDomainDigest("harness-v1-terminal-receipt", map[string]any{
		"turnID": attempt.TurnID,
		"type":   string(frame.Type),
		"seq":    frame.Seq,
		"reason": reason,
	})
	if err != nil {
		return err
	}
	if attempt.State != store.HarnessV1AttemptSettling {
		settling, err := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptSettling, "settle", fence,
			store.HarnessV1AttemptUpdates{TerminalReceiptDigest: &receiptDigest, TerminalReason: &reason})
		if err != nil {
			return err
		}
		attempt = settling
	}
	seq := frame.Seq
	terminal, err := d.transitionAttempt(ctx, attempt, target, operation, fence, store.HarnessV1AttemptUpdates{
		LastEventSeq:          &seq,
		TerminalReceiptDigest: &receiptDigest,
		TerminalReason:        &reason,
	})
	if err != nil {
		return err
	}
	phase, message := harnessV1TerminalProjection(terminal)
	if frame.Type == harness.FrameTurnFailed && frame.Failed != nil {
		detail := strings.TrimSpace(strings.TrimSpace(frame.Failed.Reason) + ": " + strings.TrimSpace(frame.Failed.Message))
		detail = strings.Trim(detail, ": ")
		if detail != "" {
			message = "harness v1 turn failed: " + detail
		}
	}
	return d.projectTaskTerminal(ctx, task, phase, message)
}

// finalizeSettlingAttempt recovers a Settling attempt. The terminal decision
// persisted with the Settling transition is authoritative; only a legacy
// record without one falls back to replaying the wrapper stream.
func (d *HarnessV1Dispatcher) finalizeSettlingAttempt(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	wrapper *harness.Client,
	journal harness.TurnJournal,
	fence store.ControllerEpochFence,
) error {
	target, operation, ok := harnessV1SettlingRecoveryTarget(attempt.TerminalReason)
	if !ok {
		// No durable decision was recorded (pre-decision Settling record):
		// replay the stream; the journal deduplicates the terminal frame.
		return d.observeAcceptedTurn(ctx, task, attempt, wrapper, journal, fence)
	}
	terminal, err := d.transitionAttempt(ctx, attempt, target, operation, fence, store.HarnessV1AttemptUpdates{})
	if err != nil {
		return err
	}
	phase, message := harnessV1TerminalProjection(terminal)
	return d.projectTaskTerminal(ctx, task, phase, message)
}

// harnessV1SettlingRecoveryTarget maps the durable terminal reason recorded at
// Settling onto the exact terminal state.
func harnessV1SettlingRecoveryTarget(reason string) (store.HarnessV1AttemptState, string, bool) {
	switch reason {
	case harnessV1ReasonCompleted:
		return store.HarnessV1AttemptSucceeded, "succeeded", true
	case harnessV1ReasonTurnFailed:
		return store.HarnessV1AttemptFailed, "failed", true
	case harnessV1ReasonTurnCancelled, harnessV1ReasonTimeout, harnessV1ReasonTaskDeleting:
		return store.HarnessV1AttemptCancelled, "cancelled", true
	default:
		return "", "", false
	}
}

// harnessV1TerminalFrameState maps a terminal frame onto the attempt machine.
func harnessV1TerminalFrameState(attempt *store.HarnessV1Attempt, frame *harness.HarnessEventFrame) (store.HarnessV1AttemptState, string, string) {
	switch frame.Type {
	case harness.FrameTurnFailed:
		return store.HarnessV1AttemptFailed, "failed", harnessV1ReasonTurnFailed
	case harness.FrameTurnCancelled:
		reason := harnessV1ReasonTurnCancelled
		switch attempt.TerminalReason {
		case harnessV1ReasonTimeout, harnessV1ReasonTaskDeleting:
			reason = attempt.TerminalReason
		}
		return store.HarnessV1AttemptCancelled, "cancelled", reason
	default:
		return store.HarnessV1AttemptSucceeded, "succeeded", harnessV1ReasonCompleted
	}
}

// requestCancellation durably records cancellation intent before the wire
// call. CancelRequested is nonterminal: settlement needs a terminal frame or a
// bounded escalation to OutcomeUnknown.
func (d *HarnessV1Dispatcher) requestCancellation(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	inputs harnessV1SnapshotInputs,
	wrapper *harness.Client,
	fence store.ControllerEpochFence,
	reason string,
) error {
	now := time.Now().UTC()
	requested, err := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptCancelRequested, "cancel-request", fence,
		store.HarnessV1AttemptUpdates{CancelRequestedAt: &now, TerminalReason: &reason})
	if err != nil {
		return err
	}
	d.recordTaskEvent(task, corev1.EventTypeNormal, "HarnessV1CancelRequested", "requested cancellation of harness v1 turn "+requested.TurnID)
	d.cancelTurn(ctx, task, requested, inputs, wrapper, reason)
	return nil
}

// cancelTurn issues the idempotent wrapper cancellation; failures are logged
// and retried on later passes while CancelRequested remains durable.
func (d *HarnessV1Dispatcher) cancelTurn(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	inputs harnessV1SnapshotInputs,
	wrapper *harness.Client,
	reason string,
) {
	request := harness.CancelTurnRequest{
		Version:          harness.ProtocolVersion,
		Namespace:        task.Namespace,
		TaskName:         task.Name,
		SessionName:      harnessV1SessionName(task, inputs),
		RuntimeSessionID: harness.RuntimeSessionID(harnessV1RuntimeSessionID(attempt)),
		TurnID:           harness.HarnessTurnID(attempt.TurnID),
		CorrelationID:    harnessV1CorrelationID(attempt),
		Reason:           reason,
	}
	if _, err := wrapper.CancelTurn(ctx, request); err != nil {
		logf.FromContext(ctx).V(1).Info("harness v1 cancel call did not settle", "turnID", attempt.TurnID, "error", err.Error())
	}
}

// driveCancelRequested waits for authoritative settlement of a requested
// cancellation and escalates to OutcomeUnknown when settlement times out.
func (d *HarnessV1Dispatcher) driveCancelRequested(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	inputs harnessV1SnapshotInputs,
	wrapper *harness.Client,
	journal harness.TurnJournal,
	fence store.ControllerEpochFence,
) error {
	settlementTimeout := d.CancelSettlementTimeout
	if settlementTimeout <= 0 {
		settlementTimeout = DefaultHarnessV1CancelSettlementTimeout
	}
	if attempt.CancelRequestedAt != nil && time.Since(*attempt.CancelRequestedAt) > settlementTimeout {
		return d.markAttemptOutcomeUnknown(ctx, task, attempt, fence, "cancel-unsettled", harnessV1ReasonCancelUnsettled)
	}
	d.cancelTurn(ctx, task, attempt, inputs, wrapper, attempt.TerminalReason)
	return d.observeAcceptedTurn(ctx, task, attempt, wrapper, journal, fence)
}

// cancelUnstartedAttempt terminates a Prepared attempt whose turn was never
// submitted; nothing exists remotely to settle.
func (d *HarnessV1Dispatcher) cancelUnstartedAttempt(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	fence store.ControllerEpochFence,
	reason string,
) error {
	cancelled, err := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptCancelled, "cancel-unstarted", fence,
		store.HarnessV1AttemptUpdates{TerminalReason: &reason})
	if err != nil {
		return err
	}
	phase, message := harnessV1TerminalProjection(cancelled)
	return d.projectTaskTerminal(ctx, task, phase, message)
}

// markAttemptOutcomeUnknown records terminal irreducible ambiguity and
// projects OutcomeUnknown semantics onto the Task compatibility phase.
func (d *HarnessV1Dispatcher) markAttemptOutcomeUnknown(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	fence store.ControllerEpochFence,
	operation string,
	reason string,
) error {
	unknown, err := d.transitionAttempt(ctx, attempt, store.HarnessV1AttemptOutcomeUnknown, operation, fence,
		store.HarnessV1AttemptUpdates{TerminalReason: &reason})
	if err != nil {
		return err
	}
	phase, message := harnessV1TerminalProjection(unknown)
	d.recordTaskEvent(task, corev1.EventTypeWarning, "HarnessV1OutcomeUnknown", message)
	return d.projectTaskTerminal(ctx, task, phase, message)
}

// harnessV1TerminalProjection maps a terminal attempt onto the v1
// compatibility Task phase and message.
func harnessV1TerminalProjection(attempt *store.HarnessV1Attempt) (corev1alpha1.TaskPhase, string) {
	switch attempt.State {
	case store.HarnessV1AttemptSucceeded:
		return corev1alpha1.TaskPhaseSucceeded, "harness v1 turn completed"
	case store.HarnessV1AttemptFailed:
		return corev1alpha1.TaskPhaseFailed, "harness v1 turn failed"
	case store.HarnessV1AttemptCancelled:
		switch attempt.TerminalReason {
		case harnessV1ReasonTimeout:
			return corev1alpha1.TaskPhaseFailed, "harness v1 turn cancelled after task timeout"
		case harnessV1ReasonTaskDeleting:
			return corev1alpha1.TaskPhaseCancelled, "harness v1 turn cancelled for task deletion"
		default:
			return corev1alpha1.TaskPhaseCancelled, "harness v1 turn cancelled"
		}
	case store.HarnessV1AttemptRejected:
		if attempt.TerminalReason == harnessV1ReasonAdoptedTurnMissing {
			return corev1alpha1.TaskPhaseFailed, harnessV1AdoptedNoStateMessage
		}
		return corev1alpha1.TaskPhaseFailed, "harness wrapper rejected the v1 turn"
	case store.HarnessV1AttemptOutcomeUnknown:
		reason := attempt.TerminalReason
		if reason == "" {
			reason = "Unknown"
		}
		return corev1alpha1.TaskPhaseFailed,
			fmt.Sprintf("harness v1 execution outcome is OutcomeUnknown (%s); the turn was never resent and requires manual verification", reason)
	default:
		return corev1alpha1.TaskPhaseFailed, "harness v1 attempt ended in unexpected state " + string(attempt.State)
	}
}

// startTurnRequest builds the minimal v1 StartTurnRequest from the immutable
// snapshot inputs. It never carries credentials.
func (d *HarnessV1Dispatcher) startTurnRequest(
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
	inputs harnessV1SnapshotInputs,
) harness.StartTurnRequest {
	now := time.Now().UTC()
	deadline := now.Add(harnessV1NoTimeoutDuration)
	if task.Spec.Timeout != nil && task.Spec.Timeout.Duration > 0 {
		deadline = now.Add(task.Spec.Timeout.Duration)
	}
	metadata := map[string]string{
		"taskUID": string(task.UID),
		"attempt": strconv.Itoa(int(attempt.Attempt)),
	}
	if inputs.model != "" {
		metadata["model"] = inputs.model
	}
	return harness.StartTurnRequest{
		Version:          harness.ProtocolVersion,
		Namespace:        task.Namespace,
		TaskName:         task.Name,
		SessionName:      harnessV1SessionName(task, inputs),
		RuntimeSessionID: harness.RuntimeSessionID(harnessV1RuntimeSessionID(attempt)),
		TurnID:           harness.HarnessTurnID(attempt.TurnID),
		CorrelationID:    harnessV1CorrelationID(attempt),
		Deadline:         deadline,
		AuthIdentity:     harness.AuthIdentity{Subject: "task:" + task.Namespace + "/" + task.Name},
		Input:            harness.TurnInput{Prompt: inputs.prompt},
		Metadata:         metadata,
	}
}

func harnessV1SessionName(task *corev1alpha1.Task, inputs harnessV1SnapshotInputs) string {
	if task.Spec.SessionRef != nil && strings.TrimSpace(task.Spec.SessionRef.Name) != "" {
		return task.Spec.SessionRef.Name
	}
	if strings.TrimSpace(inputs.sessionName) != "" {
		return inputs.sessionName
	}
	return task.Name
}

func harnessV1RuntimeSessionID(attempt *store.HarnessV1Attempt) string {
	if attempt.RuntimeSessionID != "" {
		return attempt.RuntimeSessionID
	}
	return fmt.Sprintf("%s-r%d", attempt.TaskUID, attempt.Attempt)
}

func harnessV1CorrelationID(attempt *store.HarnessV1Attempt) string {
	if attempt.CorrelationID != "" {
		return attempt.CorrelationID
	}
	return attempt.TaskUID
}

// harnessV1CancellationWanted reports whether the Task demands cancellation of
// its in-flight turn and the bounded cause.
func harnessV1CancellationWanted(task *corev1alpha1.Task) (bool, string) {
	if !task.DeletionTimestamp.IsZero() {
		return true, harnessV1ReasonTaskDeleting
	}
	if task.Spec.Timeout != nil && task.Spec.Timeout.Duration > 0 && task.Status.StartTime != nil &&
		time.Since(task.Status.StartTime.Time) > task.Spec.Timeout.Duration {
		return true, harnessV1ReasonTimeout
	}
	return false, ""
}

// harnessV1SubmitClass classifies one StartTurn wire outcome.
type harnessV1SubmitClass int

const (
	harnessV1SubmitAccepted harnessV1SubmitClass = iota
	harnessV1SubmitRejected
	harnessV1SubmitAmbiguous
)

// classifyHarnessV1SubmitError maps a StartTurn error onto the durable
// submission-state machine. Anything unprovable is ambiguous and is never
// resent.
func classifyHarnessV1SubmitError(err error) harnessV1SubmitClass {
	if err == nil {
		return harnessV1SubmitAccepted
	}
	clientErr, ok := harnessV1ClientError(err)
	if !ok {
		return harnessV1SubmitAmbiguous
	}
	switch {
	case clientErr.IsDuplicateTurn():
		// The wrapper deterministically knows this turn identity: acceptance
		// already happened.
		return harnessV1SubmitAccepted
	case clientErr.RemoteAccepted:
		return harnessV1SubmitAccepted
	case clientErr.RemoteAcceptanceUnknown:
		return harnessV1SubmitAmbiguous
	case clientErr.StatusCode >= 400 && clientErr.StatusCode < 500:
		// Definitive remote non-acceptance.
		return harnessV1SubmitRejected
	case clientErr.StatusCode >= 200:
		// The wire round-tripped but the response is unusable; acceptance is
		// unprovable.
		return harnessV1SubmitAmbiguous
	case clientErr.IsRemoteRejected():
		// The wrapper answered accepted=false.
		return harnessV1SubmitRejected
	default:
		return harnessV1SubmitAmbiguous
	}
}

func harnessV1ClientError(err error) (harness.ClientError, bool) {
	var value harness.ClientError
	if errors.As(err, &value) {
		return value, true
	}
	var pointer *harness.ClientError
	if errors.As(err, &pointer) && pointer != nil {
		return *pointer, true
	}
	return harness.ClientError{}, false
}

func harnessV1TurnNotFoundError(err error) bool {
	clientErr, ok := harnessV1ClientError(err)
	return ok && clientErr.IsTurnNotFound()
}

// turnJournal builds the persisted-frame journal for one Task. The session key
// is the real Session name only; a task-name fallback would collide a
// SessionRef-less task's events into a same-name Session timeline.
func (d *HarnessV1Dispatcher) turnJournal(task *corev1alpha1.Task) harness.TurnJournal {
	journal := harness.TurnJournal{EventStore: d.ExecutionEvents}
	sessionName := ""
	if task.Spec.SessionRef != nil {
		sessionName = task.Spec.SessionRef.Name
	}
	agentName := ""
	if task.Spec.AgentRef != nil {
		agentName = task.Spec.AgentRef.Name
	}
	journal.MapContext = harness.EventMapContext{
		Namespace:   task.Namespace,
		TaskName:    task.Name,
		SessionName: sessionName,
		AgentName:   agentName,
	}
	return journal
}

// verifyTaskBeforeSideEffect re-reads the Task uncached immediately before the
// first executor side effect of this pass. A changed Task is skipped, never
// dispatched.
func (d *HarnessV1Dispatcher) verifyTaskBeforeSideEffect(
	ctx context.Context,
	task *corev1alpha1.Task,
	attempt *store.HarnessV1Attempt,
) (bool, error) {
	reader := d.APIReader
	if reader == nil {
		reader = d.Client
	}
	current := &corev1alpha1.Task{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: task.Namespace, Name: task.Name}, current); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if current.UID != task.UID || !current.DeletionTimestamp.IsZero() {
		return false, nil
	}
	binding := harnessV1DispatchBinding(current)
	if binding == nil || binding.BindingDigest != attempt.BindingDigest {
		return false, nil
	}
	if current.Status.Phase != corev1alpha1.TaskPhasePending && current.Status.Phase != corev1alpha1.TaskPhaseRunning {
		return false, nil
	}
	return true, nil
}

// projectTaskRunning moves a Pending Task to Running with the v1 compatibility
// harness runtime status. It never touches v2 execution or delivery state.
func (d *HarnessV1Dispatcher) projectTaskRunning(ctx context.Context, task *corev1alpha1.Task, attempt *store.HarnessV1Attempt) error {
	return d.patchTaskStatus(ctx, types.NamespacedName{Namespace: task.Namespace, Name: task.Name}, task.UID,
		func(latest *corev1alpha1.Task) bool {
			changed := false
			if latest.Status.Phase == corev1alpha1.TaskPhasePending || latest.Status.Phase == "" {
				now := metav1.Now()
				latest.Status.Phase = corev1alpha1.TaskPhaseRunning
				latest.Status.StartTime = &now
				latest.Status.Attempts = attempt.Attempt
				latest.Status.Message = "harness v1 turn running"
				changed = true
			}
			if latest.Status.Phase == corev1alpha1.TaskPhaseRunning && latest.Status.HarnessRuntime == nil {
				latest.Status.HarnessRuntime = d.harnessRuntimeStatus()
				changed = true
			}
			return changed
		})
}

// projectTaskTerminal records the terminal v1 compatibility phase exactly once.
func (d *HarnessV1Dispatcher) projectTaskTerminal(ctx context.Context, task *corev1alpha1.Task, phase corev1alpha1.TaskPhase, message string) error {
	return d.patchTaskStatus(ctx, types.NamespacedName{Namespace: task.Namespace, Name: task.Name}, task.UID,
		func(latest *corev1alpha1.Task) bool {
			if taskPhaseTerminal(latest.Status.Phase) {
				return false
			}
			now := metav1.Now()
			latest.Status.Phase = phase
			latest.Status.Message = message
			latest.Status.CompletionTime = &now
			if latest.Status.HarnessRuntime == nil {
				latest.Status.HarnessRuntime = d.harnessRuntimeStatus()
			}
			return true
		})
}

func (d *HarnessV1Dispatcher) harnessRuntimeStatus() *corev1alpha1.HarnessRuntimeStatus {
	return &corev1alpha1.HarnessRuntimeStatus{
		ContractVersion: harness.ProtocolVersion,
		Endpoint:        d.WrapperEndpoint,
		RuntimeName:     harnessV1WrapperRuntimeName,
	}
}

// patchTaskStatus applies one guarded status mutation with conflict retry and
// a fresh read per try. The mutation must never touch status.execution or
// status.delivery: the CRD forbids new v2 state under a v1 binding.
func (d *HarnessV1Dispatcher) patchTaskStatus(
	ctx context.Context,
	key types.NamespacedName,
	uid types.UID,
	mutate func(*corev1alpha1.Task) bool,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &corev1alpha1.Task{}
		if err := d.Client.Get(ctx, key, latest); err != nil {
			return client.IgnoreNotFound(err)
		}
		if latest.UID != uid {
			return nil
		}
		base := latest.DeepCopy()
		if !mutate(latest) {
			return nil
		}
		return d.Client.Status().Patch(ctx, latest, client.MergeFrom(base))
	})
}

func (d *HarnessV1Dispatcher) recordTaskEvent(task *corev1alpha1.Task, eventType, reason, message string) {
	if d.Recorder == nil {
		return
	}
	d.Recorder.Event(task, eventType, reason, message)
}
