package environment

import (
	"context"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/orka-agents/orka/internal/remediation/buildjob"
	"github.com/orka-agents/orka/internal/security"
)

// Only the descriptor and measured evidence enter the private run journal.
// Source and patch bytes remain in the approved catalog and immutable Secret.
type buildJobRecord struct {
	Version             int                      `json:"version"`
	OperationID         string                   `json:"operationID"`
	Role                Role                     `json:"role"`
	PatchDigest         string                   `json:"patchDigest,omitempty"`
	EnvironmentDigest   string                   `json:"environmentDigest"`
	ConfigurationDigest string                   `json:"configurationDigest"`
	Input               buildjob.Input           `json:"input"`
	SourcePaths         []string                 `json:"sourcePaths,omitempty"`
	Base                BuildResult              `json:"base"`
	DescriptorDigest    string                   `json:"descriptorDigest"`
	SubmissionAttempted bool                     `json:"submissionAttempted,omitempty"`
	Receipt             *buildjob.Receipt        `json:"receipt,omitempty"`
	Outcome             *buildjob.Result         `json:"outcome,omitempty"`
	Cleanup             *buildjob.CleanupReceipt `json:"cleanup,omitempty"`
	CancelRequested     bool                     `json:"cancelRequested,omitempty"`
}

func (a *Adapter) buildIdentity(request BuildRequest) string {
	return jsonDigest(struct {
		Domain, Config, Run, Operation string
		Bind                           Bind
		Role                           Role
		Patch                          string
	}{"orka.remediation.environment.build.v1", a.digest, request.RunID, request.OperationID,
		request.Plan.Bind, request.Role, request.PatchDigest})
}

func (a *Adapter) jobInput(request BuildRequest, id string, files map[string][]byte) buildjob.Input {
	config, recipe := a.config.BuildJobs, request.Plan.Bind.Recipe
	var privateInputs map[string]string
	for _, entry := range a.catalog {
		if entry.bind.Recipe == recipe {
			privateInputs = maps.Clone(entry.buildOnly)
			break
		}
	}
	return buildjob.Input{
		RunID: request.RunID, OperationID: "b-" + strings.TrimPrefix(id, "sha256:")[:60],
		Files: files, RecipePath: recipe.Path, Frontend: recipe.FrontendImage, Worker: recipe.WorkerImage,
		WorkerArg: config.WorkerArg, WorkerContext: config.WorkerContext,
		Target: recipe.Target, Platform: recipe.Platform, OutputRepository: config.OutputRepository,
		Args:            maps.Clone(config.Args),
		BuildOnlyInputs: privateInputs,
	}
}

func (a *Adapter) jobBackend(input buildjob.Input, paths []string) (*buildjob.Backend, error) {
	if !a.HasDurableBuildBackend() {
		return nil, failure(NeedsAdapter, "durable-build-kubernetes-client-required")
	}
	if len(input.BuildOnlyInputs) != 0 && !a.privateBuildInputsApproved(input) {
		return nil, failure(NeedsAdapter, "private-build-input-binding-mismatch")
	}
	return a.recordedJobBackend(input, paths)
}

func (a *Adapter) recordedJobBackend(input buildjob.Input, paths []string) (*buildjob.Backend, error) {
	if !a.HasDurableBuildBackend() {
		return nil, failure(NeedsAdapter, "durable-build-kubernetes-client-required")
	}
	config := a.config.BuildJobs
	backend, err := buildjob.New(buildjob.Config{
		Kube: a.kube, APIReader: a.kube, Namespace: config.Namespace, WorkerImage: config.WorkerImage,
		BuildKitAddress: config.BuildKitAddress, TLS: config.TLS, Limits: config.Limits,
		RegistrySecretName: config.RegistrySecretName,
		Policies: []buildjob.Policy{{
			RecipePath: input.RecipePath, Frontend: input.Frontend, Worker: input.Worker,
			WorkerArg: config.WorkerArg, WorkerContext: config.WorkerContext, Target: input.Target, Platform: input.Platform,
			OutputRepository: config.OutputRepository, Args: maps.Clone(config.Args), SourcePaths: slices.Clone(paths),
			BuildOnlyInputs: maps.Clone(input.BuildOnlyInputs),
		}},
	})
	if err != nil {
		return nil, buildJobError(err)
	}
	return backend, nil
}

func (a *Adapter) buildWithJobs(ctx context.Context, request BuildRequest, id string) (BuildResult, error) {
	interval := a.config.BuildJobs.Limits.PollInterval
	if interval == 0 {
		interval = 250 * time.Millisecond
	}
	for {
		result, done, err := a.advanceBuildJob(ctx, request, id)
		if done || err != nil {
			return result, err
		}
		// No run lock is held while waiting. An explicit CancelBuild can fence
		// the operation even while its original caller is still polling.
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return BuildResult{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (a *Adapter) advanceBuildJob(ctx context.Context, request BuildRequest, id string) (BuildResult, bool, error) {
	if ctx.Err() != nil {
		return BuildResult{}, false, ctx.Err()
	}
	state, unlock, err := a.lockRun(ctx, request.RunID, request.Plan.Bind, !request.RequireExisting)
	if err != nil {
		return BuildResult{}, false, buildJobContextError(ctx, err)
	}
	defer unlock()
	if cancelled, err := a.cancelledBuild(state, request.RunID, request.OperationID, request.Plan.Bind); err != nil {
		return BuildResult{}, false, err
	} else if cancelled {
		return BuildResult{}, true, failure(Infrastructure, "build-operation-cancelled")
	}
	record := state.Builds[id]
	if record == nil && state.BuildHistoryIncomplete && !request.RequireExisting {
		return BuildResult{}, false, failure(Unknown, "existing-build-history-unavailable")
	}
	if err := a.validateFrozenBuild(request.Plan); err != nil {
		return BuildResult{}, false, a.rejectUnsubmittedBuild(state, request, err)
	}
	if err := validateBuildRequest(request); err != nil {
		return BuildResult{}, false, a.rejectUnsubmittedBuild(state, request, err)
	}
	if record == nil {
		record, err = a.prepareBuildJob(request, id)
		if err != nil {
			return BuildResult{}, false, a.rejectUnsubmittedBuild(state, request, err)
		}
		if err := a.admitOperation(state, id); err != nil {
			return BuildResult{}, false, err
		}
		state.Builds[id] = record
		if err := a.saveRun(request.RunID, state); err != nil {
			return BuildResult{}, false, err
		}
	}
	backend, err := a.validateBuildJob(request, id, record)
	if err != nil {
		return BuildResult{}, false, err
	}
	if record.State != buildStarted {
		result, err := completedBuildJob(record)
		return result, true, err
	}
	if record.Job.Receipt == nil || !completeJobReceipt(*record.Job.Receipt) {
		if err := a.recoverBuildJob(ctx, request, record, state, backend); err != nil {
			return BuildResult{}, false, err
		}
	}
	if record.Job.CancelRequested || record.Job.Outcome != nil {
		result, err := a.finishBuildJob(ctx, request.RunID, record, state, backend)
		return result, err == nil || record.State != buildStarted, err
	}
	measured, err := backend.Observe(ctx, *record.Job.Receipt)
	if err != nil {
		return BuildResult{}, false, buildJobError(err)
	}
	if !measured.Done {
		return BuildResult{}, false, nil
	}
	if err := validateBuildJobOutcome(record.Job, measured); err != nil {
		return BuildResult{}, false, err
	}
	record.Job.Outcome = &measured
	result, terminalErr := buildJobResult(record.Job)
	record.Result, record.Failure = &result, terminalErr
	// Persist terminal evidence before starting any destructive cleanup. A
	// crash during cleanup resumes from this evidence, not from a deleted Pod.
	if err := a.saveRun(request.RunID, state); err != nil {
		return BuildResult{}, false, err
	}
	result, err = a.finishBuildJob(ctx, request.RunID, record, state, backend)
	return result, err == nil || record.State != buildStarted, err
}

func (a *Adapter) prepareBuildJob(request BuildRequest, id string) (*buildRecord, error) {
	snapshot, err := a.recipeSnapshot(request)
	if err != nil {
		return nil, err
	}
	input := a.jobInput(request, id, snapshot.files)
	input.InputDigest, err = buildjob.CanonicalInputDigest(input)
	if err != nil {
		return nil, buildJobError(err)
	}
	paths, err := buildJobSourcePaths(snapshot)
	if err != nil {
		return nil, err
	}
	backend, err := a.jobBackend(input, paths)
	if err != nil {
		return nil, err
	}
	if err := backend.ValidateInput(input); err != nil {
		return nil, buildJobError(err)
	}
	input.Files = nil
	job := &buildJobRecord{
		Version: Version, OperationID: request.OperationID, Role: request.Role, PatchDigest: request.PatchDigest,
		EnvironmentDigest: a.digest, ConfigurationDigest: backend.ConfigurationDigest(),
		Input: input, SourcePaths: paths,
		Base: BuildResult{
			ID: id, Bind: request.Plan.Bind, Baseline: snapshot.baseline, Built: snapshot.built,
			OriginalRecipeDigest: snapshot.baseline.ContentDigest, BuildRecipeDigest: snapshot.built.ContentDigest,
		},
	}
	job.Base.CommandDigest = jsonDigest(struct {
		Domain, Config string
		Input          buildjob.Input
	}{"orka.remediation.environment.build-job-command.v1", job.ConfigurationDigest, input})
	job.DescriptorDigest = buildJobDescriptorDigest(job)
	result := job.Base
	return &buildRecord{ID: id, State: buildStarted, Result: &result, Job: job}, nil
}

func buildJobDescriptorDigest(job *buildJobRecord) string {
	return jsonDigest(struct {
		Version                           int
		OperationID                       string
		Role                              Role
		Patch, Environment, Configuration string
		Input                             buildjob.Input
		SourcePaths                       []string
		Base                              BuildResult
	}{job.Version, job.OperationID, job.Role, job.PatchDigest, job.EnvironmentDigest,
		job.ConfigurationDigest, job.Input, job.SourcePaths, job.Base})
}

func (a *Adapter) validateBuildJob(request BuildRequest, id string, record *buildRecord) (*buildjob.Backend, error) {
	job := record.Job
	if job == nil || record.ID != id || job.Version != Version ||
		job.OperationID != request.OperationID || job.Role != request.Role || job.PatchDigest != request.PatchDigest ||
		job.EnvironmentDigest != a.digest || job.DescriptorDigest != buildJobDescriptorDigest(job) ||
		job.Base.ID != id || job.Base.Bind != request.Plan.Bind || record.Result == nil ||
		(record.State != buildStarted && record.State != buildComplete && record.State != buildFailed) {
		return nil, failure(Unknown, "build-job-journal-binding-mismatch")
	}
	expected := a.jobInput(request, id, nil)
	// Accepted cleanup is bound to the journal, not today's mutable catalog.
	// New submission separately validates these identities before Start.
	expected.BuildOnlyInputs = maps.Clone(job.Input.BuildOnlyInputs)
	expected.InputDigest = job.Input.InputDigest
	if !digestPattern.MatchString(expected.InputDigest) || !sameJSON(expected, job.Input) ||
		job.Base.OriginalRecipeDigest != request.Plan.Bind.Recipe.ContentDigest ||
		security.CanonicalRepositoryCloneURL(job.Base.Baseline.UpstreamRepoURL) != request.Plan.Bind.SourceTarget.Repository ||
		job.Base.Baseline.UpstreamCommit != request.Plan.Bind.SourceTarget.Commit {
		return nil, failure(Unknown, "build-job-input-binding-mismatch")
	}
	backend, err := a.recordedJobBackend(job.Input, job.SourcePaths)
	if err != nil {
		return nil, err
	}
	if job.ConfigurationDigest != backend.ConfigurationDigest() {
		return nil, failure(Unknown, "build-job-configuration-binding-mismatch")
	}
	if job.Receipt != nil {
		if err := validateBuildJobReceipt(job, *job.Receipt); err != nil {
			return nil, err
		}
	}
	if job.Outcome != nil {
		if err := validateBuildJobOutcome(job, *job.Outcome); err != nil {
			return nil, err
		}
	}
	return backend, nil
}

func (a *Adapter) recoverBuildJob(
	ctx context.Context, request BuildRequest, record *buildRecord, state *runJournal, backend *buildjob.Backend,
) error {
	snapshot, err := a.recipeSnapshot(request)
	if err != nil {
		return err
	}
	input := record.Job.Input
	input.Files = snapshot.files
	if len(input.BuildOnlyInputs) != 0 && !a.privateBuildInputsApproved(input) {
		return failure(NeedsAdapter, "private-build-input-binding-mismatch")
	}
	if actual, err := buildjob.CanonicalInputDigest(input); err != nil || actual != record.Job.Input.InputDigest {
		return failure(Unknown, "build-job-source-snapshot-changed")
	}
	input.RequireExisting = request.RequireExisting || record.Job.SubmissionAttempted || record.Job.CancelRequested
	if record.Job.Receipt != nil {
		input.ExpectedJobUID = record.Job.Receipt.JobUID
	}
	record.Job.SubmissionAttempted = true
	if err := a.saveRun(request.RunID, state); err != nil {
		return err
	}
	receipt, startErr := backend.Start(ctx, input)
	if receipt.Version != 0 {
		if err := validateBuildJobReceipt(record.Job, receipt); err != nil {
			return err
		}
		merged, err := mergeBuildJobReceipt(record.Job.Receipt, receipt)
		if err != nil {
			return err
		}
		record.Job.Receipt = &merged
	}
	// Saving is intentionally not gated on ctx.Err: an accepted UID must remain
	// durable even when the caller loses its deadline immediately after Create.
	if err := a.saveRun(request.RunID, state); err != nil {
		return err
	}
	return buildJobError(startErr)
}

func validateBuildJobReceipt(job *buildJobRecord, receipt buildjob.Receipt) error {
	if receipt.Version != buildjob.Version || receipt.RunID != job.Input.RunID ||
		receipt.OperationID != job.Input.OperationID || receipt.InputDigest != job.Input.InputDigest ||
		receipt.ConfigurationDigest != job.ConfigurationDigest {
		return failure(Unknown, "build-job-receipt-binding-mismatch")
	}
	return nil
}

func mergeBuildJobReceipt(previous *buildjob.Receipt, next buildjob.Receipt) (buildjob.Receipt, error) {
	if previous == nil {
		return next, nil
	}
	if next.TLSSecrets == (buildjob.TLSSecrets{}) {
		next.TLSSecrets = previous.TLSSecrets
	} else if previous.TLSSecrets != (buildjob.TLSSecrets{}) && next.TLSSecrets != previous.TLSSecrets {
		return buildjob.Receipt{}, failure(Unknown, "build-job-tls-identity-changed")
	}
	if next.RegistrySecret == (buildjob.SecretIdentity{}) {
		next.RegistrySecret = previous.RegistrySecret
	} else if previous.RegistrySecret != (buildjob.SecretIdentity{}) && next.RegistrySecret != previous.RegistrySecret {
		return buildjob.Receipt{}, failure(Unknown, "build-job-registry-identity-changed")
	}
	// A failed recovery may return only part of the handle. Never discard a
	// previously accepted UID or allow namespace/owner replacement.
	before := []string{previous.Namespace, string(previous.NamespaceUID), previous.LedgerName, string(previous.LedgerUID),
		previous.AnchorName, string(previous.AnchorUID), previous.JobName, string(previous.JobUID)}
	after := []*string{&next.Namespace, (*string)(&next.NamespaceUID), &next.LedgerName, (*string)(&next.LedgerUID),
		&next.AnchorName, (*string)(&next.AnchorUID), &next.JobName, (*string)(&next.JobUID)}
	for i, value := range before {
		if *after[i] == "" {
			*after[i] = value
		} else if value != "" && *after[i] != value {
			return buildjob.Receipt{}, failure(Unknown, "build-job-accepted-identity-changed")
		}
	}
	return next, nil
}

func completeJobReceipt(receipt buildjob.Receipt) bool {
	return receipt.NamespaceUID != "" && receipt.LedgerUID != "" && receipt.AnchorUID != "" && receipt.JobUID != ""
}

func validateBuildJobOutcome(job *buildJobRecord, outcome buildjob.Result) error {
	if job.Receipt == nil || !completeJobReceipt(*job.Receipt) || !outcome.Done ||
		outcome.Receipt != *job.Receipt || outcome.Version != buildjob.Version ||
		outcome.InputDigest != job.Input.InputDigest || outcome.Receipt.ConfigurationDigest != job.ConfigurationDigest ||
		outcome.PodUID == "" || outcome.ContainerImageID == "" || outcome.ResultDigest != outcome.BindingDigest() {
		return failure(Unknown, "build-job-result-binding-mismatch")
	}
	if outcome.BuildOutcome == buildjob.Success {
		if !digestPattern.MatchString(outcome.ImmutableImageDigest) ||
			outcome.Image != job.Input.OutputRepository+"@"+outcome.ImmutableImageDigest {
			return failure(Unknown, "build-job-image-binding-mismatch")
		}
	} else if outcome.Image != "" || outcome.ImmutableImageDigest != "" {
		return failure(Unknown, "failed-build-job-carried-image")
	}
	switch outcome.BuildOutcome {
	case buildjob.Success, buildjob.CompileFailure, buildjob.TestFailure, buildjob.Infrastructure, buildjob.Cancelled:
	default:
		return failure(Unknown, "build-job-outcome-unsupported")
	}
	return nil
}

func buildJobResult(job *buildJobRecord) (BuildResult, *Error) {
	result := job.Base
	if job.CancelRequested {
		return result, &Error{Kind: Infrastructure, Code: "build-job-cancelled"}
	}
	if job.Outcome == nil {
		return result, &Error{Kind: Unknown, Code: "build-job-result-unavailable", Retryable: true}
	}
	outcome := job.Outcome
	result.WorkerEvidenceDigest, result.MetadataDigest = outcome.ResultDigest, outcome.ResultDigest
	result.OutputTruncated = outcome.OutputTruncated
	for _, diagnostic := range outcome.Diagnostics {
		code, identifier := "compiler-diagnostic", diagnostic.Symbol
		if outcome.BuildOutcome == buildjob.TestFailure {
			code, identifier = "go-test-failure", diagnostic.TestName
		}
		result.Diagnostics = append(result.Diagnostics, Diagnostic{
			Code: code, Count: 1, Path: diagnostic.Path, Line: diagnostic.Line,
			Column: diagnostic.Column, Identifier: identifier,
		})
	}
	switch outcome.BuildOutcome {
	case buildjob.Success:
		result.Subject = Subject{Role: job.Role, Image: outcome.Image, BuildID: job.Base.ID, PatchDigest: job.PatchDigest}
		return result, nil
	case buildjob.CompileFailure:
		return result, &Error{Kind: BuildFailed, Code: "build-job-compile-failed"}
	case buildjob.TestFailure:
		return result, &Error{Kind: BuildFailed, Code: "build-job-tests-failed"}
	case buildjob.Cancelled:
		return result, &Error{Kind: Infrastructure, Code: "build-job-cancelled"}
	default:
		return result, &Error{Kind: Infrastructure, Code: "build-job-infrastructure-failed"}
	}
}

func (a *Adapter) finishBuildJob(
	ctx context.Context, runID string, record *buildRecord, state *runJournal, backend *buildjob.Backend,
) (BuildResult, error) {
	job := record.Job
	if job.Receipt == nil || job.Receipt.AnchorUID == "" {
		return BuildResult{}, failure(Unknown, "build-job-cleanup-receipt-unavailable")
	}
	if job.CancelRequested {
		result, terminalErr := buildJobResult(job)
		record.Result, record.Failure = &result, terminalErr
		if err := a.saveRun(runID, state); err != nil {
			return BuildResult{}, err
		}
	}
	// Cleanup is Cancel's implementation with its durable acknowledgement
	// returned. Calling Cancel alone would discard the evidence needed here.
	cleanup, cleanupErr := backend.Cleanup(ctx, *job.Receipt)
	if cleanup.Version != 0 {
		if err := validateBuildJobReceipt(job, cleanup.Receipt); err != nil {
			return BuildResult{}, err
		}
		merged, err := mergeBuildJobReceipt(job.Receipt, cleanup.Receipt)
		if err != nil {
			return BuildResult{}, err
		}
		if merged != cleanup.Receipt {
			return BuildResult{}, failure(Unknown, "build-job-cleanup-identity-incomplete")
		}
		job.Receipt = &merged
		job.Cleanup = &cleanup
	}
	if cleanupErr != nil || !buildJobCleaned(job) {
		if err := a.saveRun(runID, state); err != nil {
			return BuildResult{}, err
		}
		if cleanupErr != nil {
			return BuildResult{}, buildJobError(cleanupErr)
		}
		return BuildResult{}, failure(Unknown, "build-job-cleanup-unsettled")
	}
	result, terminalErr := buildJobResult(job)
	record.Result, record.Failure, record.State = &result, terminalErr, buildComplete
	if terminalErr != nil {
		record.State = buildFailed
	}
	if err := a.saveRun(runID, state); err != nil {
		return BuildResult{}, err
	}
	if terminalErr != nil {
		return result, terminalErr
	}
	return result, nil
}

func buildJobCleaned(job *buildJobRecord) bool {
	return job.Receipt != nil && job.Cleanup != nil && job.Cleanup.Stopped && job.Cleanup.SubmissionSettled &&
		job.Cleanup.DaemonSettled &&
		job.Cleanup.Receipt == *job.Receipt && job.Cleanup.CleanupDigest == job.Cleanup.BindingDigest()
}

func completedBuildJob(record *buildRecord) (BuildResult, error) {
	if !buildJobCleaned(record.Job) {
		return BuildResult{}, failure(Unknown, "build-job-cleanup-not-acknowledged")
	}
	result, terminalErr := buildJobResult(record.Job)
	if !sameJSON(record.Result, &result) || !sameJSON(record.Failure, terminalErr) ||
		(record.State == buildComplete) != (terminalErr == nil) {
		return BuildResult{}, failure(Unknown, "build-job-completed-result-mismatch")
	}
	if terminalErr != nil {
		return result, terminalErr
	}
	return result, nil
}

// CancelBuild cancels journaled operations with exact Kubernetes identities.
// Descriptor absence is useful only in an intact, bound write-ahead journal:
// cancellation then persists an operation-wide tombstone under the run flock.
// Missing history or submission evidence stays unknown and never causes Start.
func (a *Adapter) CancelBuild(ctx context.Context, runID, operationID string, plan Plan) error {
	if !idPattern.MatchString(runID) || !idPattern.MatchString(operationID) {
		return failure(NeedsAdapter, "invalid-build-cancellation")
	}
	// Cleanup uses the saved operation, not present-day catalog admission.
	// Re-reading recipes here could strand an accepted Job after file drift.
	if plan.Version != Version || !digestPattern.MatchString(plan.Bind.ChecksDigest) ||
		ChecksDigest(plan) != plan.Bind.ChecksDigest {
		return failure(Unknown, "frozen-build-cancellation-plan-required")
	}
	state, unlock, err := a.lockRun(ctx, runID, plan.Bind, false)
	if err != nil {
		return buildJobContextError(ctx, err)
	}
	defer unlock()
	return a.cancelBuildRun(ctx, runID, operationID, plan, state)
}

func (a *Adapter) cancelBuildRun(ctx context.Context, runID, operationID string, plan Plan, state *runJournal) error {
	if !state.persisted {
		return failure(Unknown, "build-job-cancellation-history-unavailable")
	}
	if cancelled, err := a.cancelledBuild(state, runID, operationID, plan.Bind); err != nil {
		return err
	} else if cancelled {
		if !state.BuildCancellations[operationID].NoSubmissionProven {
			return failure(Unknown, buildHistoryOriginUnavailable)
		}
		return a.proveBuildAbsent(state, runID, operationID, plan)
	}
	matched := false
	for id, record := range state.Builds {
		if record == nil {
			return failure(Unknown, "build-job-cancellation-record-unavailable")
		}
		if record.Job == nil || record.Job.OperationID != operationID {
			continue
		}
		matched = true
		request := BuildRequest{RunID: runID, OperationID: operationID, Plan: plan,
			Role: record.Job.Role, PatchDigest: record.Job.PatchDigest}
		if a.buildIdentity(request) != id {
			return failure(Unknown, "build-job-cancellation-binding-mismatch")
		}
		backend, err := a.validateBuildJob(request, id, record)
		if err != nil {
			return err
		}
		if record.State != buildStarted {
			if !buildJobCleaned(record.Job) {
				return failure(Unknown, "build-job-cleanup-not-acknowledged")
			}
			continue
		}
		record.Job.CancelRequested = true
		if err := a.saveRun(runID, state); err != nil {
			return err
		}
		if record.Job.Receipt == nil || record.Job.Receipt.AnchorUID == "" {
			return failure(Unknown, "build-job-cancellation-receipt-unavailable")
		}
		if _, err := a.finishBuildJob(ctx, runID, record, state, backend); err != nil {
			if !buildJobCleaned(record.Job) || record.State == buildStarted || !sameJSON(err, record.Failure) {
				return err
			}
		}
	}
	if !matched {
		if err := a.proveBuildAbsent(state, runID, operationID, plan); err != nil {
			// Pre-protocol journals do not attest whether an earlier recovery
			// rebuilt only part of their history. Fence late calls, but never
			// acknowledge no effects from such an ambiguous legacy snapshot.
			if failure, ok := errors.AsType[*Error](err); ok && failure.Code == buildHistoryOriginUnavailable {
				if saveErr := a.recordBuildCancellation(state, runID, operationID, plan, false, nil); saveErr != nil {
					return saveErr
				}
			}
			return err
		}
		return a.recordBuildCancellation(state, runID, operationID, plan, true, nil)
	}
	return nil
}

func buildJobSourcePaths(snapshot recipeSnapshot) ([]string, error) {
	known := make(map[string]bool)
	for _, patch := range snapshot.built.OrderedPatches {
		if err := collectBuildJobPatchPaths(snapshot.files[patch.Path], patch.Strip, known); err != nil {
			return nil, err
		}
	}
	paths := make([]string, 0, len(known))
	for name := range known {
		paths = append(paths, name)
	}
	slices.Sort(paths)
	// Primaries retain priority across the entire patch series. Over-limit
	// primary sets still reach the worker's existing policy rejection.
	for _, name := range paths {
		if len(paths) >= 512 {
			break
		}
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			sibling := strings.TrimSuffix(name, ".go") + "_test.go"
			if !known[sibling] && buildjob.SourcePath(sibling) == nil {
				paths = append(paths, sibling)
				known[sibling] = true
			}
		}
	}
	slices.Sort(paths)
	return paths, nil
}

const invalidBuildDiagnosticPatchCode = "invalid-build-diagnostic-patch"

var buildJobHunkPattern = regexp.MustCompile(`^@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@.*$`)

func collectBuildJobPatchPaths(raw []byte, strip int, known map[string]bool) error {
	var remaining [2]int
	oldHeader := false
	// SplitSeq's final empty token is not an additional context line.
	for line := range strings.SplitSeq(strings.TrimSuffix(string(raw), "\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		// Hunk counts take precedence over header-looking source text.
		if remaining[0] != 0 || remaining[1] != 0 {
			if line == `\ No newline at end of file` {
				continue
			}
			if line == "" {
				line = " "
			}
			switch line[0] {
			case ' ', '\t':
				remaining[0]--
				remaining[1]--
			case '-':
				remaining[0]--
			case '+':
				remaining[1]--
			default:
				return failure(NeedsAdapter, invalidBuildDiagnosticPatchCode)
			}
			if remaining[0] < 0 || remaining[1] < 0 {
				return failure(NeedsAdapter, invalidBuildDiagnosticPatchCode)
			}
			continue
		}
		if strings.HasPrefix(line, "@@") {
			var err error
			remaining, err = buildJobHunkCounts(line)
			if err != nil {
				return err
			}
			oldHeader = false
			continue
		}
		name, newHeader := strings.CutPrefix(line, "+++ ")
		paired := oldHeader && newHeader
		oldHeader = strings.HasPrefix(line, "--- ")
		if !paired {
			continue
		}
		name, _, _ = strings.Cut(name, "\t")
		parts := strings.Split(name, "/")
		if strip < 0 || strip >= len(parts) ||
			slices.ContainsFunc(parts[:strip], func(part string) bool { return buildjob.SourcePath(part) != nil }) {
			continue
		}
		name = strings.Join(parts[strip:], "/")
		if buildjob.SourcePath(name) == nil {
			known[name] = true
		}
	}
	if remaining[0] != 0 || remaining[1] != 0 {
		return failure(NeedsAdapter, invalidBuildDiagnosticPatchCode)
	}
	return nil
}

func buildJobHunkCounts(line string) ([2]int, error) {
	var remaining [2]int
	match := buildJobHunkPattern.FindStringSubmatch(line)
	if match == nil {
		return remaining, failure(NeedsAdapter, invalidBuildDiagnosticPatchCode)
	}
	for i := range remaining {
		text := match[i+1]
		if text == "" {
			text = "1"
		}
		count, err := strconv.ParseUint(text, 10, 32)
		if err != nil || count > buildjob.MaxInputBytes {
			return remaining, failure(NeedsAdapter, invalidBuildDiagnosticPatchCode)
		}
		remaining[i] = int(count)
	}
	return remaining, nil
}

func buildJobContextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func buildJobError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, buildjob.ErrInvalid), errors.Is(err, buildjob.ErrLimit):
		return failure(NeedsAdapter, "durable-build-input-or-configuration-rejected")
	case errors.Is(err, buildjob.ErrIdentity), errors.Is(err, buildjob.ErrLost), errors.Is(err, buildjob.ErrIndeterminate):
		return &Error{Kind: Unknown, Code: "durable-build-identity-or-acknowledgement-unavailable", Retryable: true}
	default:
		return &Error{Kind: Infrastructure, Code: "durable-build-api-or-cleanup-unavailable", Retryable: true}
	}
}
