package local

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"time"

	"github.com/google/uuid"
	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/store/sqlite"
)

const ExecutionBackend = "local-docker"

type Runner interface {
	ResolveImage(context.Context, string, string) (pv.Environment, error)
	FreezeEnvironment(pv.Environment) (pv.Environment, error)
	RunCheck(context.Context, pv.Manifest, pv.Binding, string, pv.Check, string, string) (pv.ExecutionEvidence, error)
}

type PrepareFunc func(context.Context, pv.Request) (*pv.PreparedSources, error)

type Dependencies struct {
	Prepare      PrepareFunc
	Release      func(*pv.PreparedSources) error
	Runner       Runner
	Quiescent    func(context.Context) error
	PollInterval time.Duration
	Timeout      time.Duration
}

type Service struct {
	database     *sql.DB
	storage      *sqlite.Store
	dbPath       string
	dependencies Dependencies
}

type Progress struct {
	Required int `json:"required"`
	Recorded int `json:"recorded"`
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

type Summary struct {
	Action            pv.Action                      `json:"action,omitempty"`
	ReportDigest      string                         `json:"reportDigest,omitempty"`
	EarlierValidation *pv.EarlierValidationReference `json:"earlierValidation,omitempty"`
	RunID             string                         `json:"runID,omitempty"`
	AttemptID         string                         `json:"attemptID,omitempty"`
	ExecutionBackend  string                         `json:"executionBackend"`
	JobStatus         string                         `json:"jobStatus"`
	State             pv.RunState                    `json:"state,omitempty"`
	Progress          Progress                       `json:"progress"`
	Overall           pv.Assessment                  `json:"overall"`
	Incidents         int                            `json:"incidents"`
	AuxiliaryWarning  bool                           `json:"auxiliaryWarning,omitempty"`
}

func New(ctx context.Context, dbPath string, dependencies Dependencies) (*Service, error) {
	if dependencies.PollInterval == 0 {
		dependencies.PollInterval = 500 * time.Millisecond
	}
	if dependencies.Timeout == 0 {
		dependencies.Timeout = 30 * time.Minute
	}
	if dependencies.PollInterval <= 0 || dependencies.Timeout <= 0 {
		return nil, errors.New("positive poll interval and run timeout are required")
	}
	database, storage, canonical, err := openDatabase(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	return &Service{database: database, storage: storage, dbPath: canonical, dependencies: dependencies}, nil
}

func (service *Service) Close() error { return service.database.Close() }

func Failed(reason string) Summary {
	return FailedAction(pv.VerifyPatch, reason)
}

func FailedAction(action pv.Action, reason string) Summary {
	return Summary{Action: pv.ActionOrDefault(action), ExecutionBackend: ExecutionBackend, JobStatus: "failed",
		Overall: pv.Assessment{Conclusion: pv.UnavailableAction(action), Reason: reason}}
}

func summarize(record *pv.Record) Summary {
	if record == nil {
		return Failed("verification record is unavailable")
	}
	status := map[pv.RunState]string{pv.RunRunning: "running", pv.RunFinalized: "completed", pv.RunCancelled: "cancelled", pv.RunInterrupted: "interrupted", pv.RunInvalid: "failed"}[record.State]
	result := Summary{RunID: record.Binding.RunID, AttemptID: record.Binding.AttemptID, ExecutionBackend: ExecutionBackend, JobStatus: status, State: record.State, Overall: record.Assessment, Incidents: len(record.Incidents)}
	result.Action, result.ReportDigest = pv.ActionOrDefault(record.Manifest.Action), record.Manifest.ReportDigest
	result.EarlierValidation = record.Manifest.EarlierValidation
	result.Progress.Required = len(pv.ActionSides(record.Manifest.Action)) * len(record.Manifest.Checks)
	result.Progress.Recorded = len(record.Evidence)
	for _, entry := range record.Evidence {
		if entry.Rejection == "" {
			result.Progress.Accepted++
		} else {
			result.Progress.Rejected++
		}
	}
	return result
}

func (service *Service) Record(ctx context.Context, runID string) (*pv.Record, error) {
	return service.storage.GetPatchVerificationRun(ctx, runID)
}

func (service *Service) Get(ctx context.Context, runID string) (Summary, error) {
	record, err := service.Record(ctx, runID)
	result := summarize(record)
	if err != nil {
		result.Overall = FailedAction(result.Action, "validation record could not be validated").Overall
	}
	return result, err
}

func (service *Service) Blob(ctx context.Context, runID, digest string, limit int) ([]byte, error) {
	if limit < 1 || limit > pv.MaxOutputBytes {
		return nil, errors.New("blob inspection limit must be between 1 and 65536 bytes")
	}
	content, err := service.storage.GetPatchVerificationBlob(ctx, runID, digest)
	if err != nil {
		return nil, err
	}
	if len(content) > limit {
		return nil, errors.New("blob exceeds inspection limit; inspect its digest and size in evidence JSON")
	}
	return content, nil
}

func (service *Service) Cancel(ctx context.Context, runID string) (Summary, error) {
	record, err := service.Record(ctx, runID)
	if err != nil {
		return summarize(record), err
	}
	record, err = service.storage.CancelPatchVerificationRun(ctx, record.Binding)
	result := summarize(record)
	result.AuxiliaryWarning = service.saveAuxiliary(ctx, record) != nil
	return result, err
}

func (service *Service) Recover(ctx context.Context, runID string) (Summary, error) {
	record, err := service.Record(ctx, runID)
	if err != nil {
		return summarize(record), err
	}
	owner, err := AcquireOwner(service.dbPath, runID)
	if err != nil {
		return FailedAction(record.Manifest.Action, "recovery requires an absent supervisor"), err
	}
	defer func() { _ = owner.Close() }()
	record, err = service.Record(ctx, runID)
	if err != nil {
		return summarize(record), err
	}
	if record.State == pv.RunRunning {
		if service.dependencies.Quiescent == nil {
			return summarize(record), errors.New("recovery requires an executor quiescence check")
		}
		if err := service.dependencies.Quiescent(ctx); err != nil {
			return summarize(record), errors.New("recovery refused: runner containers remain or Docker cannot confirm quiescence")
		}
	}
	record, err = service.storage.RecoverInterruptedPatchVerificationRun(ctx, record.Binding)
	result := summarize(record)
	result.AuxiliaryWarning = service.saveAuxiliary(ctx, record) != nil
	return result, err
}

func (service *Service) Start(ctx context.Context, request pv.Request, started func(Summary) error) (result Summary, resultErr error) {
	result = FailedAction(request.Action, "preparation did not complete")
	if err := pv.ValidateRequestAction(request); err != nil {
		return result, err
	}
	if request.Action == "" {
		request.Action = pv.VerifyPatch
		if len(request.DeclaredChanges) == 0 {
			request.DeclaredChanges = []pv.DeclaredChange{{Kind: "source",
				Description: "supplied patch; legacy request did not declare paths"}}
		}
	}
	dependencies := service.dependencies
	if dependencies.Prepare == nil || dependencies.Release == nil || dependencies.Runner == nil {
		return result, errors.New("source preparer, source cleanup, and real runner must be supplied")
	}
	runCtx, stopRun := context.WithTimeout(ctx, dependencies.Timeout)
	defer stopRun()
	if runCtx.Err() != nil {
		return FailedAction(request.Action, "cancelled before preparation"), errors.New("cancelled before preparation")
	}
	request, earlier, restored, err := service.linkedRequest(runCtx, request)
	if err != nil {
		return result, err
	}
	if restored != nil {
		defer func() { _ = restored.Close() }()
	}
	prepared, err := dependencies.Prepare(runCtx, request)
	if err != nil || prepared == nil {
		if prepared != nil {
			_ = dependencies.Release(prepared)
		}
		return result, errors.New("source preparation failed; no verification run was created")
	}
	released := false
	release := func() error {
		if released {
			return nil
		}
		released = true
		err := dependencies.Release(prepared)
		if restored != nil {
			err = errors.Join(err, restored.Close())
		}
		return err
	}
	defer func() { _ = release() }()
	for _, directory := range []string{request.Repository, request.ChecksDir, prepared.Root, prepared.OriginalDir, prepared.PatchedDir, prepared.ChecksDir} {
		if within(directory, service.dbPath) {
			return result, errors.New("persistent database must be outside source and check workspaces")
		}
	}
	manifest, binding, err := service.freezeRun(runCtx, request, prepared, earlier)
	if err != nil {
		return result, err
	}
	owner, err := AcquireOwner(service.dbPath, binding.RunID)
	if err != nil {
		return result, err
	}
	defer func() { _ = owner.Close() }()
	if err := service.storage.CreatePatchVerificationRun(runCtx, manifest, binding, prepared.Provenance); err != nil {
		return result, errors.New("frozen provenance was rejected or could not be persisted")
	}
	defer func() {
		result, resultErr = service.completeRun(runCtx, manifest.Action, binding, release, resultErr)
	}()
	initialRecord, err := service.Record(runCtx, binding.RunID)
	initial := summarize(initialRecord)
	if err != nil {
		return initial, errors.New("created run could not be read")
	}
	initial.AuxiliaryWarning = service.saveAuxiliary(runCtx, initialRecord) != nil
	if started != nil {
		if err := started(initial); err != nil {
			stopRun()
			return initial, errors.New("run ID could not be written to the caller")
		}
	}
	if len(pv.MissingRequirements(manifest.Environment)) != 0 {
		return initial, nil
	}
	workCtx, stopWork := context.WithCancel(runCtx)
	watchDone := make(chan error, 1)
	go func() { watchDone <- service.watch(workCtx, binding.RunID, stopWork) }()
	defer func() {
		stopWork()
		if err := <-watchDone; err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	return result, service.executeChecks(workCtx, dependencies.Runner, manifest, binding, prepared)
}

func (service *Service) freezeRun(ctx context.Context, request pv.Request, prepared *pv.PreparedSources,
	earlier *pv.Record) (pv.Manifest, pv.Binding, error) {
	environment, err := service.dependencies.Runner.ResolveImage(ctx, request.Image, request.Platform)
	if err != nil {
		return pv.Manifest{}, pv.Binding{}, errors.New("pinned local image or platform could not be resolved")
	}
	environment.Profile = request.Profile
	environment.Variables = maps.Clone(request.Variables)
	environment.Dependencies = maps.Clone(request.Dependencies)
	environment.Services, environment.Requirements = request.Services, request.RequiredEnvironment
	if len(pv.MissingRequirements(environment)) == 0 {
		environment, err = service.dependencies.Runner.FreezeEnvironment(environment)
		if err != nil {
			return pv.Manifest{}, pv.Binding{}, errors.New("runner profile could not be frozen")
		}
	}
	manifest, err := pv.RequestManifest(request, prepared, environment)
	if err != nil {
		return manifest, pv.Binding{}, err
	}
	if earlier != nil {
		manifest.EarlierValidation = &pv.EarlierValidationReference{
			RunID: earlier.Binding.RunID, ReportDigest: earlier.Manifest.ReportDigest,
			ManifestDigest: earlier.Binding.ManifestDigest, SealDigest: earlier.Seal.Digest,
		}
	}
	content, err := json.Marshal(manifest)
	var frozen pv.Manifest
	if err != nil || len(content) > pv.MaxManifestBytes || json.Unmarshal(content, &frozen) != nil {
		return manifest, pv.Binding{}, errors.New("manifest could not be frozen within its size limit")
	}
	patchedTaskID := ""
	if frozen.Action == pv.VerifyPatch {
		patchedTaskID = uuid.NewString()
	}
	binding, err := pv.NewRunBinding(frozen, uuid.NewString(), uuid.NewString(), patchedTaskID)
	if err != nil {
		return frozen, binding, errors.New("frozen source, environment, or check manifest is invalid")
	}
	return frozen, binding, nil
}

func (service *Service) completeRun(runCtx context.Context, action pv.Action, binding pv.Binding,
	release func() error, resultErr error) (Summary, error) {
	finishCtx, stopFinish := context.WithTimeout(context.Background(), 15*time.Second)
	defer stopFinish()
	if release() != nil {
		resultErr = errors.New("source cleanup failed")
	}
	record, readErr := service.Record(finishCtx, binding.RunID)
	if readErr == nil && runCtx.Err() != nil {
		record, readErr = service.storage.CancelPatchVerificationRun(finishCtx, binding)
	} else if readErr == nil && record.State == pv.RunRunning {
		if resultErr != nil {
			record, readErr = service.storage.RecoverInterruptedPatchVerificationRun(finishCtx, binding)
		} else {
			record, readErr = service.storage.FinalizePatchVerificationRun(finishCtx, binding)
		}
	}
	if readErr != nil {
		resultErr = errors.New("verification completion could not be persisted or validated")
	}
	result := summarize(record)
	if record == nil {
		result = FailedAction(action, "validation completion is unavailable")
		result.RunID, result.AttemptID = binding.RunID, binding.AttemptID
	}
	if readErr != nil {
		result.Overall = FailedAction(result.Action, "validation completion is unavailable").Overall
	}
	result.AuxiliaryWarning = service.saveAuxiliary(finishCtx, record) != nil
	return result, resultErr
}

func (service *Service) executeChecks(ctx context.Context, runner Runner, manifest pv.Manifest, binding pv.Binding, prepared *pv.PreparedSources) error {
	for _, side := range pv.ActionSides(manifest.Action) {
		if ctx.Err() != nil {
			return nil
		}
		if side == pv.Patched {
			current, err := service.Record(ctx, binding.RunID)
			if err != nil {
				return errors.New("original evidence could not be validated")
			}
			observations := make([]pv.Observation, 0, len(current.Evidence))
			for _, entry := range current.Evidence {
				observations = append(observations, entry.Observation)
			}
			if current.State != pv.RunRunning || !pv.OriginalReady(manifest, binding, observations) {
				return nil
			}
		}
		for _, check := range manifest.Checks {
			if err := service.executeCheck(ctx, runner, manifest, binding, prepared, side, check); err != nil {
				return err
			}
		}
	}
	return nil
}

func (service *Service) executeCheck(ctx context.Context, runner Runner, manifest pv.Manifest, binding pv.Binding,
	prepared *pv.PreparedSources, side string, check pv.Check) error {
	current, err := service.Record(ctx, binding.RunID)
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return errors.New("run status could not be validated before execution")
	}
	if current.State != pv.RunRunning {
		return nil
	}
	sourceDir := prepared.OriginalDir
	if side == pv.Patched {
		sourceDir = prepared.PatchedDir
	}
	evidence, runErr := runner.RunCheck(ctx, manifest, binding, side, check, sourceDir, prepared.ChecksDir)
	if runErr != nil || evidence.Observation.SetupError != "" {
		evidence.Observation.SetupError = "local check setup, execution, or cleanup failed"
	}
	writeCtx, stopWrite := context.WithTimeout(context.Background(), 15*time.Second)
	defer stopWrite()
	recordErr := service.storage.RecordPatchVerificationEvidence(writeCtx, binding, evidence)
	after, readErr := service.Record(writeCtx, binding.RunID)
	if readErr == nil {
		_ = service.saveAuxiliary(writeCtx, after)
	}
	if recordErr != nil && !errors.Is(recordErr, pv.ErrClosed) {
		return errors.New("attempt evidence was rejected or could not be persisted")
	}
	if readErr != nil {
		return errors.New("attempt evidence could not be validated")
	}
	return nil
}

func (service *Service) watch(ctx context.Context, runID string, stop context.CancelFunc) error {
	ticker := time.NewTicker(service.dependencies.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			var state string
			if err := service.database.QueryRowContext(ctx, `SELECT state FROM patch_verification_runs WHERE run_id = ?`, runID).Scan(&state); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				stop()
				return errors.New("durable cancellation status could not be read")
			}
			if pv.RunState(state) != pv.RunRunning {
				stop()
				return nil
			}
		}
	}
}
