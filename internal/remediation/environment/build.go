package environment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func (a *Adapter) Build(ctx context.Context, request BuildRequest) (BuildResult, error) {
	if a.config.BuildJobs != nil {
		return a.buildWithJobs(ctx, request, a.buildIdentity(request))
	}
	if err := a.validateFrozenBuild(request.Plan); err != nil {
		return BuildResult{}, err
	}
	if err := validateBuildRequest(request); err != nil {
		return BuildResult{}, err
	}
	if a.config.BuildKit == nil && a.config.BuildJobs == nil {
		return BuildResult{}, failure(NeedsAdapter, "buildkit-adapter-not-configured")
	}
	id := a.buildIdentity(request)
	state, unlock, err := a.lockRun(ctx, request.RunID, request.Plan.Bind, !request.RequireExisting)
	if err != nil {
		return BuildResult{}, err
	}
	defer unlock()
	if cancelled, err := a.cancelledBuild(state, request.RunID, request.OperationID, request.Plan.Bind); err != nil {
		return BuildResult{}, err
	} else if cancelled {
		return BuildResult{}, failure(Infrastructure, "build-operation-cancelled")
	}
	if previous := state.Builds[id]; previous != nil {
		if previous.State == buildComplete && previous.Result != nil {
			return *previous.Result, nil
		}
		if previous.State == buildFailed && previous.Result != nil && previous.Failure != nil {
			return *previous.Result, previous.Failure
		}
		return BuildResult{}, failure(Unknown, "build-outcome-not-replayable")
	}
	if request.RequireExisting {
		return BuildResult{}, failure(Unknown, "existing-build-not-found")
	}
	if state.BuildHistoryIncomplete {
		return BuildResult{}, failure(Unknown, "build-history-unavailable")
	}
	if err := a.admitOperation(state, id); err != nil {
		return BuildResult{}, err
	}
	snapshot, err := a.recipeSnapshot(request)
	if err != nil {
		return BuildResult{}, err
	}
	state.Builds[id] = &buildRecord{ID: id, State: buildStarted}
	if err := a.saveRun(request.RunID, state); err != nil {
		return BuildResult{}, err
	}
	result, buildErr := a.executeBuild(ctx, request, id, snapshot)
	record := state.Builds[id]
	record.State = buildFailed
	var measuredFailure *Error
	if errors.As(buildErr, &measuredFailure) && measuredFailure.Kind == BuildFailed {
		record.Result, record.Failure = &result, measuredFailure
	}
	if buildErr == nil {
		record.State, record.Result = buildComplete, &result
	}
	if err := a.saveRun(request.RunID, state); err != nil {
		return BuildResult{}, failure(Unknown, "build-result-not-persisted")
	}
	return result, buildErr
}

func (a *Adapter) executeBuild(ctx context.Context, request BuildRequest, id string, snapshot recipeSnapshot) (result BuildResult, resultErr error) {
	configuration := *a.config.BuildKit
	name := "build-" + strings.TrimPrefix(id, "sha256:")
	directory := filepath.Join(a.config.TemporaryRoot, name)
	if err := os.Mkdir(directory, 0700); err != nil {
		return BuildResult{}, failure(Unknown, "build-directory-already-consumed")
	}
	// All candidate inputs are created by this process, not mounted from the
	// source tree. The builder receives no kubeconfig, registry auth, or journal.
	defer func() {
		if err := os.RemoveAll(directory); err != nil {
			resultErr = failure(Infrastructure, "build-staging-cleanup-failed")
		}
	}()
	for _, child := range []string{"context", "home", "scratch"} {
		if os.Mkdir(filepath.Join(directory, child), 0700) != nil {
			return BuildResult{}, failure(Infrastructure, "build-staging-failed")
		}
	}
	contextRoot := filepath.Join(directory, "context")
	for name, content := range snapshot.files {
		if err := os.MkdirAll(filepath.Join(contextRoot, filepath.Dir(name)), 0700); err != nil {
			return BuildResult{}, failure(Infrastructure, "build-staging-failed")
		}
		if err := writePrivate(contextRoot, name, content); err != nil {
			return BuildResult{}, err
		}
	}
	output := configuration.OutputRepository + ":rem-" + strings.TrimPrefix(id, "sha256:")
	metadataPath := filepath.Join(directory, "metadata.json")
	arguments := buildArguments(configuration, request.Plan.Bind.Recipe, contextRoot, metadataPath, output)
	result = BuildResult{
		ID: id, Bind: request.Plan.Bind,
		Baseline: snapshot.baseline, Built: snapshot.built,
		OriginalRecipeDigest: snapshot.baseline.ContentDigest, BuildRecipeDigest: snapshot.built.ContentDigest,
		WorkerEvidenceDigest: configuration.WorkerEvidenceDigest,
		CommandDigest: jsonDigest(struct {
			Executable string
			Arguments  []string
		}{configuration.ExecutableDigest, arguments}),
	}
	bounded, cancel := context.WithTimeout(ctx, a.config.Limits.BuildTimeout)
	defer cancel()
	log, truncated, err := runBuildctl(bounded, configuration, arguments, directory, a.config.Limits.MaxOutputBytes)
	result.OutputTruncated = truncated
	result.Diagnostics = compilerDiagnostics(log)
	if err != nil {
		return result, err
	}
	metadata, err := readApprovedFile(directory, "metadata.json", 64<<10)
	if err != nil || rejectDuplicateJSON(metadata) != nil {
		return result, failure(BuildFailed, "buildkit-image-metadata-unavailable")
	}
	var fields map[string]json.RawMessage
	var imageDigest string
	if json.Unmarshal(metadata, &fields) != nil || json.Unmarshal(fields["containerimage.digest"], &imageDigest) != nil ||
		!digestPattern.MatchString(imageDigest) {
		return result, failure(BuildFailed, "buildkit-immutable-output-required")
	}
	result.MetadataDigest = digest(metadata)
	result.Subject = Subject{
		Role: request.Role, Image: configuration.OutputRepository + "@" + imageDigest,
		PatchDigest: request.PatchDigest, BuildID: id,
	}
	return result, nil
}

func (a *Adapter) validateSubject(request Request, state *runJournal) error {
	s := request.Subject
	if !immutableImage(s.Image) || !validRole(s.Role) ||
		(s.Role == Candidate && !digestPattern.MatchString(s.PatchDigest)) ||
		(s.Role != Candidate && s.PatchDigest != "") {
		return failure(NeedsAdapter, "immutable-subject-binding-required")
	}
	_, recipe, err := a.policy(request.Plan.Bind)
	if err != nil {
		return err
	}
	if s.Role == PublishedOriginal && s.Image != recipe.OriginalImage {
		return failure(NeedsAdapter, "published-original-image-mismatch")
	}
	if s.Role == PublishedOriginal && s.ExternalBindingID == "" && s.BuildID == "" {
		return nil
	}
	if s.BuildID != "" && s.ExternalBindingID == "" {
		record := state.Builds[s.BuildID]
		if record != nil && record.State == buildComplete && record.Result != nil &&
			record.Result.Bind == request.Plan.Bind && record.Result.Subject == s {
			return nil
		}
		return failure(NeedsAdapter, "build-image-binding-not-found")
	}
	if s.ExternalBindingID == "" || s.BuildID != "" {
		return failure(NeedsAdapter, "verified-external-image-binding-required")
	}
	for _, binding := range a.config.ImageBindings {
		if binding.ID == s.ExternalBindingID && binding.Role == s.Role && binding.Image == s.Image &&
			binding.SourceTarget == request.Plan.Bind.SourceTarget && binding.Recipe == request.Plan.Bind.Recipe &&
			binding.PatchDigest == s.PatchDigest {
			return nil
		}
	}
	return failure(NeedsAdapter, "external-image-binding-mismatch")
}

func sameJSON(a, b any) bool {
	first, _ := json.Marshal(a)
	second, _ := json.Marshal(b)
	return bytes.Equal(first, second)
}
