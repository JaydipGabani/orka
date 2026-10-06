package patchverification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

type Conclusion string

type Action string

const (
	ValidateReport   Action     = "validate-report"
	VerifyPatch      Action     = "verify-patch"
	Reproduced       Conclusion = "Reproduced"
	NotReproduced    Conclusion = "Not reproduced under these conditions"
	UnableToValidate Conclusion = "Unable to validate"
	Verified         Conclusion = "Verified for these checks"
	NotFixed         Conclusion = "Not fixed"
	PartiallyFixed   Conclusion = "Partially fixed"
	Regression       Conclusion = "Introduces a regression"
	UnableToVerify   Conclusion = "Unable to verify"
	Original                    = "original"
	Patched                     = "patched"
	Reproduction                = "reproduction"
	Normal                      = "normal"
	Offline                     = "offline"
	LocalServices               = "local-services"
	SchemaVersion               = 1
)

type Expectation struct {
	ExitCode int               `json:"exitCode"`
	Stdout   string            `json:"stdout"`
	Services map[string]string `json:"services,omitempty"`
}

type Check struct {
	ID             string      `json:"id"`
	Kind           string      `json:"kind"`
	Command        []string    `json:"command"`
	HTTP           *HTTPCheck  `json:"http,omitempty"`
	Stdin          string      `json:"stdin,omitempty"`
	Healthy        Expectation `json:"healthy"`
	Failure        Expectation `json:"failure"`
	TimeoutSeconds int         `json:"timeoutSeconds"`
	Lifecycle      []string    `json:"lifecycle,omitempty"`
}

type FrozenFile struct {
	Path       string `json:"path"`
	Content    []byte `json:"content"`
	Digest     string `json:"digest"`
	Executable bool   `json:"executable,omitempty"`
}

type SourceIdentity struct {
	Commit        string `json:"commit,omitempty"`
	Tree          string `json:"tree"`
	ArchiveDigest string `json:"archiveDigest"`
}

type Sources struct {
	Repository  string         `json:"repository"`
	Original    SourceIdentity `json:"original"`
	Patched     SourceIdentity `json:"patched"`
	PatchDigest string         `json:"patchDigest,omitempty"`
	DiffDigest  string         `json:"diffDigest"`
}

type Service struct {
	ID          string   `json:"id"`
	Command     []string `json:"command"`
	Port        int      `json:"port"`
	ReadyOutput string   `json:"readyOutput"`
}

type Environment struct {
	Image        string                   `json:"image"`
	ImageID      string                   `json:"imageID"`
	Platform     string                   `json:"platform"`
	Profile      string                   `json:"profile"`
	Variables    map[string]string        `json:"variables,omitempty"`
	Dependencies map[string]string        `json:"dependencies,omitempty"`
	Services     []Service                `json:"services,omitempty"`
	Requirements []EnvironmentRequirement `json:"requirements,omitempty"`
}

type Manifest struct {
	Version           int                         `json:"version"`
	Action            Action                      `json:"action,omitempty"`
	ReportDigest      string                      `json:"reportDigest,omitempty"`
	EarlierValidation *EarlierValidationReference `json:"earlierValidation,omitempty"`
	DeclaredChanges   []DeclaredChange            `json:"declaredChanges,omitempty"`
	Problem           string                      `json:"problem"`
	Scope             []string                    `json:"scope"`
	Gaps              []string                    `json:"gaps"`
	Sources           Sources                     `json:"sources"`
	Environment       Environment                 `json:"environment"`
	Files             []FrozenFile                `json:"files"`
	Checks            []Check                     `json:"checks"`
}

type Binding struct {
	RunID          string `json:"runID"`
	AttemptID      string `json:"attemptID"`
	OriginalTaskID string `json:"originalTaskID"`
	PatchedTaskID  string `json:"patchedTaskID"`
	ManifestDigest string `json:"manifestDigest"`
}

type CapturedOutput struct {
	Digest    string `json:"digest"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

type Observation struct {
	RunID           string                    `json:"runID"`
	AttemptID       string                    `json:"attemptID"`
	TaskID          string                    `json:"taskID"`
	ManifestDigest  string                    `json:"manifestDigest"`
	Side            string                    `json:"side"`
	CheckID         string                    `json:"checkID"`
	SourceTree      string                    `json:"sourceTree"`
	ImageID         string                    `json:"imageID"`
	ContainerID     string                    `json:"containerID"`
	JobUID          string                    `json:"jobUID,omitempty"`
	PodUID          string                    `json:"podUID,omitempty"`
	Origin          string                    `json:"origin"`
	StartedAt       time.Time                 `json:"startedAt"`
	FinishedAt      time.Time                 `json:"finishedAt"`
	Executed        bool                      `json:"executed"`
	HTTPCompleted   bool                      `json:"httpCompleted,omitempty"`
	ExitCode        *int                      `json:"exitCode,omitempty"`
	StdoutDigest    string                    `json:"stdoutDigest,omitempty"`
	StdoutBytes     int                       `json:"stdoutBytes"`
	StderrDigest    string                    `json:"stderrDigest,omitempty"`
	StderrBytes     int                       `json:"stderrBytes"`
	TimedOut        bool                      `json:"timedOut"`
	Skipped         bool                      `json:"skipped"`
	OutputTruncated bool                      `json:"outputTruncated"`
	SetupError      string                    `json:"setupError,omitempty"`
	ServiceOutputs  map[string]CapturedOutput `json:"serviceOutputs,omitempty"`
}

type CheckResult struct {
	CheckID         string `json:"checkID"`
	Outcome         string `json:"outcome"`
	Reason          string `json:"reason,omitempty"`
	OriginalOutcome string `json:"originalOutcome,omitempty"`
	PatchedOutcome  string `json:"patchedOutcome,omitempty"`
}

type ExecutionEvidence struct {
	Observation Observation       `json:"observation"`
	Blobs       map[string][]byte `json:"blobs"`
}

type Assessment struct {
	Conclusion Conclusion    `json:"conclusion"`
	Reason     string        `json:"reason"`
	Checks     []CheckResult `json:"checks"`
}

var identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var sha256Pattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var gitIdentityPattern = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)

func Digest(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func ManifestDigest(manifest Manifest) (string, error) {
	if !validManifestUTF8(reflect.ValueOf(manifest)) {
		return "", fmt.Errorf("manifest strings must be valid UTF-8")
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("encode frozen manifest: %w", err)
	}
	return Digest(content), nil
}

func validManifestUTF8(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		return value.IsNil() || validManifestUTF8(value.Elem())
	case reflect.String:
		return utf8.ValidString(value.String())
	case reflect.Struct:
		for _, field := range value.Fields() {
			if !validManifestUTF8(field) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return true
		}
		for index := 0; index < value.Len(); index++ {
			if !validManifestUTF8(value.Index(index)) {
				return false
			}
		}
	case reflect.Map:
		entries := value.MapRange()
		for entries.Next() {
			if !validManifestUTF8(entries.Key()) || !validManifestUTF8(entries.Value()) {
				return false
			}
		}
	}
	return true
}

func ValidateManifest(manifest Manifest) error {
	if !validManifestUTF8(reflect.ValueOf(manifest)) {
		return fmt.Errorf("manifest strings must be valid UTF-8")
	}
	if manifest.Version != SchemaVersion || strings.TrimSpace(manifest.Problem) == "" || len(manifest.Scope) == 0 {
		return fmt.Errorf("version, problem description, and tested scope are required")
	}
	if len(manifest.Checks) == 0 || len(manifest.Checks) > 100 {
		return fmt.Errorf("between 1 and 100 frozen checks are required")
	}
	if manifest.Action != "" && manifest.Action != ValidateReport && manifest.Action != VerifyPatch {
		return fmt.Errorf("unsupported validation action")
	}
	if manifest.Action != "" || manifest.ReportDigest != "" {
		digest, err := StableReportDigest(manifest.Problem, manifest.Scope)
		if err != nil || manifest.ReportDigest != digest {
			return fmt.Errorf("report digest does not match the frozen problem and scope")
		}
	}
	if err := validateActionSources(manifest); err != nil {
		return err
	}
	if err := validateManifestMetadata(manifest); err != nil {
		return err
	}
	if err := validateHTTPManifest(manifest); err != nil {
		return err
	}
	protectedHTTP := manifest.Checks[0].HTTP != nil
	services, err := validateManifestEnvironment(manifest.Environment, protectedHTTP)
	if err != nil {
		return err
	}
	if err := validateManifestChecks(manifest.Checks, services, ActionOrDefault(manifest.Action)); err != nil {
		return err
	}
	for _, file := range manifest.Files {
		if file.Digest != Digest(file.Content) {
			return fmt.Errorf("frozen file digest mismatch")
		}
	}
	return nil
}

func validateActionSources(manifest Manifest) error {
	if manifest.Action != ValidateReport {
		return validateManifestSources(manifest.Sources)
	}
	sources := manifest.Sources
	if sources.Repository == "" || !gitIdentityPattern.MatchString(sources.Original.Commit) ||
		!gitIdentityPattern.MatchString(sources.Original.Tree) || !sha256Pattern.MatchString(sources.Original.ArchiveDigest) {
		return fmt.Errorf("report validation requires an exact original source identity")
	}
	if sources.Patched != (SourceIdentity{}) || sources.PatchDigest != "" || sources.DiffDigest != "" {
		return fmt.Errorf("report validation cannot contain a patch")
	}
	return nil
}

func validateManifestSources(sources Sources) error {
	if sources.Repository == "" || !gitIdentityPattern.MatchString(sources.Original.Commit) || !sha256Pattern.MatchString(sources.DiffDigest) {
		return fmt.Errorf("exact original commit, repository, and source diff digest are required")
	}
	for _, source := range []SourceIdentity{sources.Original, sources.Patched} {
		if !gitIdentityPattern.MatchString(source.Tree) || !sha256Pattern.MatchString(source.ArchiveDigest) {
			return fmt.Errorf("exact source trees and archive digests are required")
		}
	}
	if (sources.Patched.Commit == "") == (sources.PatchDigest == "") {
		return fmt.Errorf("exactly one patched commit or patch digest is required")
	}
	if sources.Patched.Commit != "" && !gitIdentityPattern.MatchString(sources.Patched.Commit) {
		return fmt.Errorf("patched commit must be an exact git identity")
	}
	if sources.PatchDigest != "" && !sha256Pattern.MatchString(sources.PatchDigest) {
		return fmt.Errorf("patch digest must be SHA-256")
	}
	return nil
}

func validateManifestEnvironment(environment Environment, protectedHTTP bool) (map[string]bool, error) {
	imageParts := strings.Split(environment.Image, "@")
	if len(imageParts) != 2 || imageParts[0] == "" || !sha256Pattern.MatchString(imageParts[1]) || !validResolvedImageID(environment.ImageID) || environment.Platform == "" {
		return nil, fmt.Errorf("digest-pinned tool image, resolved image identity, and platform are required")
	}
	if environment.Profile != Offline && environment.Profile != LocalServices {
		return nil, fmt.Errorf("unsupported test network profile")
	}
	if environment.Profile == Offline && len(environment.Services) != 0 {
		return nil, fmt.Errorf("offline profile cannot provide network services")
	}
	services := make(map[string]bool)
	ports := make(map[int]bool)
	for _, service := range environment.Services {
		if !identifierPattern.MatchString(service.ID) || services[service.ID] || service.Port < 1024 || service.Port > 65535 || ports[service.Port] || len(service.Command) == 0 || service.Command[0] == "" || service.ReadyOutput == "" || len(service.ReadyOutput) > 1024 {
			return nil, fmt.Errorf("invalid service identity, command, readiness output, or unprivileged port")
		}
		services[service.ID], ports[service.Port] = true, true
	}
	if environment.Profile == LocalServices && len(services) == 0 && !protectedHTTP {
		return nil, fmt.Errorf("local-services profile requires a frozen service")
	}
	return services, nil
}

func validResolvedImageID(imageID string) bool {
	if sha256Pattern.MatchString(imageID) {
		return true
	}
	_, digest, found := strings.Cut(imageID, "@")
	return found && sha256Pattern.MatchString(digest) && !strings.ContainsAny(imageID, "\r\n\x00")
}

func validateManifestChecks(checks []Check, services map[string]bool, action Action) error {
	seen := make(map[string]bool)
	reproductions, normal := 0, 0
	for _, check := range checks {
		if err := validateLifecycle(check.Lifecycle); err != nil {
			return err
		}
		command := CheckExecutable(check)
		if !identifierPattern.MatchString(check.ID) || seen[check.ID] || len(command) == 0 || command[0] == "" || check.TimeoutSeconds < 1 || check.TimeoutSeconds > 300 {
			return fmt.Errorf("invalid or duplicate check identity, command, or timeout")
		}
		seen[check.ID] = true
		switch check.Kind {
		case Reproduction:
			reproductions++
		case Normal:
			normal++
		default:
			return fmt.Errorf("unsupported check kind")
		}
		if reflect.DeepEqual(check.Healthy, check.Failure) || check.Healthy.ExitCode < 0 || check.Healthy.ExitCode > 124 || check.Failure.ExitCode < 0 || check.Failure.ExitCode > 124 || len(check.Healthy.Stdout) > 8192 || len(check.Failure.Stdout) > 8192 {
			return fmt.Errorf("checks require distinct bounded healthy and failure observations without reserved exit codes")
		}
		for _, expectation := range []Expectation{check.Healthy, check.Failure} {
			if len(expectation.Services) != len(services) {
				return fmt.Errorf("every expectation must cover all frozen service observations")
			}
			for serviceID, output := range expectation.Services {
				if !services[serviceID] || len(output) > 8192 {
					return fmt.Errorf("unknown service or oversized expected output")
				}
			}
		}
	}
	if reproductions == 0 || (action == VerifyPatch && normal == 0) {
		return fmt.Errorf("both reproduction and normal-use checks are required")
	}
	return nil
}

func ValidateObservation(manifest Manifest, binding Binding, observation Observation) error {
	digest, err := ManifestDigest(manifest)
	if err != nil {
		return err
	}
	if err := ValidateBinding(manifest.Action, binding); err != nil || digest != binding.ManifestDigest {
		return fmt.Errorf("invalid run or attempt binding")
	}
	expectedTask, expectedTree := binding.OriginalTaskID, manifest.Sources.Original.Tree
	if observation.Side == Patched {
		if manifest.Action == ValidateReport {
			return fmt.Errorf("report validation cannot accept patched evidence")
		}
		expectedTask, expectedTree = binding.PatchedTaskID, manifest.Sources.Patched.Tree
	} else if observation.Side != Original {
		return fmt.Errorf("unknown source side")
	}
	if observation.RunID != binding.RunID || observation.AttemptID != binding.AttemptID || observation.TaskID != expectedTask || observation.ManifestDigest != binding.ManifestDigest || observation.SourceTree != expectedTree || observation.ImageID != manifest.Environment.ImageID || observation.Origin != "runner" {
		return fmt.Errorf("observation does not match the frozen run, task, attempt, source, image, and runner identities")
	}
	for _, check := range manifest.Checks {
		if check.ID == observation.CheckID {
			if check.HTTP == nil && observation.HTTPCompleted {
				return fmt.Errorf("a command-only check cannot claim protected HTTP completion")
			}
			return nil
		}
	}
	return fmt.Errorf("observation names an unknown check")
}

func Evaluate(manifest Manifest, binding Binding, observations []Observation) Assessment {
	if manifest.Action == ValidateReport {
		return evaluateReport(manifest, binding, observations)
	}
	if manifest.Action == VerifyPatch {
		return evaluateVerification(manifest, binding, observations)
	}
	assessment := Assessment{Conclusion: UnableToVerify, Reason: "required evidence is missing"}
	if err := ValidateManifest(manifest); err != nil {
		assessment.Reason = err.Error()
		return assessment
	}
	byCheck := make(map[string]Observation)
	for _, observation := range observations {
		if err := ValidateObservation(manifest, binding, observation); err != nil {
			assessment.Reason = err.Error()
			return assessment
		}
		key := observation.Side + ":" + observation.CheckID
		if previous, found := byCheck[key]; found && !reflect.DeepEqual(previous, observation) {
			assessment.Reason = "conflicting observations for the same check"
			return assessment
		}
		byCheck[key] = observation
	}
	fixed, unfixed, regressions, incomplete := 0, 0, 0, false
	for _, check := range manifest.Checks {
		original, hasOriginal := byCheck[Original+":"+check.ID]
		patched, hasPatched := byCheck[Patched+":"+check.ID]
		result := CheckResult{CheckID: check.ID, Outcome: "unable"}
		switch {
		case !hasOriginal || !hasPatched:
			result.Reason = "required check is missing from one or both versions"
		case !usableCheck(check, original) || !usableCheck(check, patched):
			result.Reason = "check was not executed completely, or setup, timeout, skip, or output capture failed"
		case check.Kind == Reproduction && !matches(original, check.Failure):
			result.Reason = "original did not reproduce the stated problem"
		case check.Kind == Normal && !matches(original, check.Healthy):
			result.Reason = "required normal behavior was not established on the original"
		case matches(patched, check.Healthy):
			result.Outcome = OutcomePassed
			if check.Kind == Reproduction {
				fixed++
			}
		case matches(patched, check.Failure):
			if check.Kind == Reproduction {
				result.Outcome = OutcomeNotFixed
				unfixed++
			} else {
				result.Outcome = OutcomeRegression
				regressions++
			}
		default:
			result.Reason = "observed output and exit code match neither frozen expectation"
		}
		incomplete = incomplete || result.Outcome == "unable"
		assessment.Checks = append(assessment.Checks, result)
	}
	switch {
	case incomplete:
		assessment.Reason = "one or more required comparisons could not be verified"
	case regressions > 0:
		assessment.Conclusion, assessment.Reason = Regression, "required normal behavior fails on the patch"
	case fixed > 0 && unfixed > 0:
		assessment.Conclusion, assessment.Reason = PartiallyFixed, "some demonstrated cases remain unfixed"
	case unfixed > 0:
		assessment.Conclusion, assessment.Reason = NotFixed, "all demonstrated cases remain unfixed"
	default:
		assessment.Conclusion, assessment.Reason = Verified, "all stated problems reproduced on the original; patched checks and required normal behavior passed"
	}
	return assessment
}

func usable(observation Observation) bool {
	return observation.Executed && observation.ContainerID != "" && !observation.StartedAt.IsZero() && !observation.FinishedAt.Before(observation.StartedAt) && observation.ExitCode != nil && *observation.ExitCode >= 0 && *observation.ExitCode < 125 && sha256Pattern.MatchString(observation.StdoutDigest) && observation.StdoutBytes >= 0 && sha256Pattern.MatchString(observation.StderrDigest) && observation.StderrBytes >= 0 && !observation.TimedOut && !observation.Skipped && !observation.OutputTruncated && observation.SetupError == ""
}

func usableCheck(check Check, observation Observation) bool {
	return usable(observation) && (check.HTTP == nil || observation.HTTPCompleted)
}

func matches(observation Observation, expectation Expectation) bool {
	if *observation.ExitCode != expectation.ExitCode || observation.StdoutBytes != len(expectation.Stdout) || observation.StdoutDigest != Digest([]byte(expectation.Stdout)) || len(observation.ServiceOutputs) != len(expectation.Services) {
		return false
	}
	for serviceID, expected := range expectation.Services {
		observed, found := observation.ServiceOutputs[serviceID]
		if !found || observed.Truncated || observed.Bytes != len(expected) || observed.Digest != Digest([]byte(expected)) {
			return false
		}
	}
	return true
}
