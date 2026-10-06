package kube

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	pv "github.com/orka-agents/orka/internal/patchverification"
)

func (s *Service) SubmitRequest(ctx context.Context, namespace, submittedBy string, request pv.Request) (*pv.KubernetesSubmission, error) {
	if err := s.confineRequestPaths(namespace, &request); err != nil {
		return nil, err
	}
	if err := pv.ValidateRequestAction(request); err != nil {
		return nil, err
	}
	var earlier *pv.Record
	var restored *pv.PreparedSources
	if request.EarlierValidation != "" {
		if _, err := s.LinkedValidation(ctx, namespace, request.EarlierValidation); err != nil {
			return nil, err
		}
		var err error
		earlier, err = s.store.GetCompletedReportValidation(ctx, request.EarlierValidation)
		if err != nil {
			return nil, err
		}
		if err := pv.MatchLinkedRequest(request, earlier.Manifest); err != nil {
			return nil, err
		}
		if request.ChecksDir != "" || request.ProvidedFields["checksDir"] {
			if err := pv.ValidateFrozenChecks(ctx, request.ChecksDir, earlier.Manifest); err != nil {
				return nil, err
			}
		}
		request = pv.HydrateLinkedRequest(request, earlier.Manifest)
		// Revalidate the saved repository under this namespace before restoring
		// controller-owned checks outside the caller's input tree.
		if err := s.confineRequestPaths(namespace, &request); err != nil {
			return nil, err
		}
		restored, err = pv.RestoreFrozenChecks(ctx, earlier.Manifest)
		if err != nil {
			return nil, err
		}
		defer func() { _ = restored.Close() }()
		request.ChecksDir = restored.ChecksDir
	}
	for _, value := range []struct{ supplied, allowed string }{
		{request.Image, s.config.ToolImage}, {request.Platform, s.config.Platform}, {request.Profile, s.config.Profile},
	} {
		if value.supplied != "" && value.supplied != value.allowed {
			return nil, fmt.Errorf("requested environment differs from the configured validation environment")
		}
		for key, value := range map[string]string{
			"orka.kubernetes.policy": pv.KubernetesPolicyVersion, helperImageKey: s.config.HelperImage,
		} {
			if supplied, found := request.Dependencies[key]; found && supplied != value {
				return nil, fmt.Errorf("frozen runner policy differs from the configured validation environment")
			}
		}
	}
	request.Image = s.config.ToolImage
	request.Platform = s.config.Platform
	request.Profile = s.config.Profile
	request.Dependencies = maps.Clone(request.Dependencies)
	if request.Dependencies == nil {
		request.Dependencies = map[string]string{}
	}
	request.Dependencies["orka.kubernetes.policy"] = pv.KubernetesPolicyVersion
	request.Dependencies[helperImageKey] = s.config.HelperImage
	prepared, err := pv.PrepareSources(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("prepare validation sources: %w", err)
	}
	environment := pv.Environment{Image: s.config.ToolImage, ImageID: s.config.ToolImageID,
		Platform: s.config.Platform, Profile: s.config.Profile, Variables: request.Variables,
		Dependencies: request.Dependencies, Services: request.Services, Requirements: request.RequiredEnvironment}
	manifest, err := pv.RequestManifest(request, prepared, environment)
	if err != nil {
		return nil, errors.Join(err, prepared.Close())
	}
	if earlier != nil {
		manifest.EarlierValidation = &pv.EarlierValidationReference{RunID: earlier.Binding.RunID,
			ReportDigest: earlier.Manifest.ReportDigest, ManifestDigest: earlier.Binding.ManifestDigest, SealDigest: earlier.Seal.Digest}
	}
	if err := prepared.Close(); err != nil {
		return nil, err
	}
	if restored != nil {
		if err := restored.Close(); err != nil {
			return nil, err
		}
	}
	return s.Submit(ctx, namespace, submittedBy, manifest, prepared.Provenance)
}

func (s *Service) confineRequestPaths(namespace string, request *pv.Request) error {
	if s == nil || !s.config.Enabled || request == nil || namespace != s.config.Namespace || !filepath.IsAbs(s.config.InputRoot) {
		return fmt.Errorf("validation input root is unavailable")
	}
	inputRoot, err := filepath.EvalSymlinks(s.config.InputRoot)
	if err != nil {
		return fmt.Errorf("validation input root is unavailable")
	}
	expectedRoot := filepath.Join(inputRoot, namespace)
	root, err := filepath.EvalSymlinks(expectedRoot)
	if err != nil {
		return fmt.Errorf("validation namespace input root is unavailable")
	}
	if root != expectedRoot {
		return fmt.Errorf("validation namespace input root cannot be a symlink")
	}
	for _, target := range []*string{&request.Repository, &request.PatchFile, &request.ChecksDir} {
		if *target == "" {
			continue
		}
		parsed, parseErr := url.Parse(*target)
		if parseErr != nil || parsed.Scheme != "" || parsed.Host != "" {
			return fmt.Errorf("remote validation inputs are not supported")
		}
		candidate := *target
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(root, candidate)
		}
		resolved, resolveErr := filepath.EvalSymlinks(candidate)
		if resolveErr != nil {
			return fmt.Errorf("validation input is unavailable")
		}
		relative, relErr := filepath.Rel(root, resolved)
		if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("validation input is outside the namespace root")
		}
		*target = resolved
	}
	return nil
}

func (s *Service) GetSubmission(ctx context.Context, namespace, requestID string) (*pv.KubernetesSubmission, error) {
	submission, err := s.store.GetKubernetesValidationSubmission(ctx, namespace, requestID)
	if err != nil {
		return nil, err
	}
	submission.RequiredChecks = len(pv.ActionSides(submission.Manifest.Action)) * len(submission.Manifest.Checks)
	if submission.RunID != "" {
		record, err := s.store.GetPatchVerificationRun(ctx, submission.RunID)
		if err != nil && !errors.Is(err, pv.ErrIntegrity) {
			return nil, err
		}
		if record != nil {
			submission.Assessment = &record.Assessment
			submission.RecordedChecks = len(record.Evidence)
		}
	} else if submission.State == pv.SubmissionTerminal {
		submission.Assessment = &pv.Assessment{Conclusion: pv.UnavailableAction(submission.Manifest.Action), Reason: submission.Failure}
		for _, check := range submission.Manifest.Checks {
			submission.Assessment.Checks = append(submission.Assessment.Checks,
				pv.CheckResult{CheckID: check.ID, Outcome: pv.OutcomeUntested, Reason: "execution did not start"})
		}
	}
	return submission, nil
}

func (s *Service) LinkedValidation(ctx context.Context, namespace, runID string) (*pv.KubernetesSubmission, error) {
	return s.store.GetKubernetesValidationSubmissionByRun(ctx, namespace, runID)
}

func (s *Service) Cancel(ctx context.Context, namespace, requestID string) error {
	return s.store.RequestKubernetesValidationCancellation(ctx, namespace, requestID)
}

func (s *Service) Evidence(ctx context.Context, namespace, requestID string) (*pv.Record, error) {
	submission, err := s.store.GetKubernetesValidationSubmission(ctx, namespace, requestID)
	if err != nil {
		return nil, err
	}
	if submission.RunID == "" {
		return nil, pv.ErrRunNotFound
	}
	return s.store.GetPatchVerificationRun(ctx, submission.RunID)
}

func (s *Service) EvidenceBlob(ctx context.Context, namespace, requestID, digest string) ([]byte, error) {
	submission, err := s.store.GetKubernetesValidationSubmission(ctx, namespace, requestID)
	if err != nil {
		return nil, err
	}
	if submission.RunID == "" {
		return nil, pv.ErrRunNotFound
	}
	return s.store.GetPatchVerificationBlob(ctx, submission.RunID, digest)
}
