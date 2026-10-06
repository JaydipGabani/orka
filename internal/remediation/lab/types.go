package lab

import (
	"errors"
	"time"
)

const (
	Version               = 1
	MaxProfileBytes       = 64 << 10
	MaxDriverBytes        = 64 << 20
	MaxConfigurationBytes = 1 << 20
	MaxPatchBytes         = 4 << 20
	MaxRequestBytes       = 1 << 20
	MaxResultBytes        = 256 << 10
	MaxReceiptBytes       = 512 << 10
	MaxStderrBytes        = 1 << 20
	MaxChecks             = 128
	MaxRuntime            = 30 * time.Minute

	TrustStatement = "Observations come from a human-approved trusted lab driver, not remote attestation. " +
		"Kind observations do not establish managed AKS policy."
)

var (
	ErrInvalidProfile = errors.New("lab: invalid profile")
	ErrInvalidInput   = errors.New("lab: invalid input")
	ErrUnsafePath     = errors.New("lab: unsafe path, ownership, or permissions")
	ErrTooLarge       = errors.New("lab: input or output limit exceeded")
	ErrDigestMismatch = errors.New("lab: approved file digest mismatch")
	ErrApproval       = errors.New("lab: explicit approval of the exact profile is required")
	ErrRunExists      = errors.New("lab: run name already consumed; execution will not be repeated")
	ErrUnknown        = errors.New("lab: execution outcome is unknown; operator reconciliation is required")
	ErrBaseline       = errors.New("lab: an unchanged saved successful baseline is required")
	ErrInvalidResult  = errors.New("lab: driver result does not match the required contract")
	ErrBlocked        = errors.New("lab: complete observations failed required assertions or profile scope has gaps")
	ErrDriver         = errors.New("lab: trusted driver execution failed; inspect private artifacts")
	ErrIO             = errors.New("lab: private artifact operation failed")
	ErrUnsupported    = errors.New("lab: Linux is required for safe driver execution")
)

type FileIdentity struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type Profile struct {
	Version       int          `json:"version"`
	Repository    string       `json:"repository"`
	Commit        string       `json:"commit"`
	OriginalImage string       `json:"originalImage"`
	ControlImage  string       `json:"controlImage,omitempty"`
	Platform      string       `json:"platform"`
	Driver        FileIdentity `json:"driver"`
	Configuration FileIdentity `json:"configuration"`
	ChecksDigest  string       `json:"checksDigest"`
	Scope         []string     `json:"scope"`
	Gaps          []string     `json:"gaps"`
}

// Candidate includes an optional expected image. Without Image, the approved
// driver builds the exact patch snapshot and reports its actual immutable image.
type Candidate struct {
	Patch FileIdentity `json:"patch"`
	Image string       `json:"image,omitempty"`
}

type Operation string

const (
	OperationBaseline Operation = "baseline"
	OperationVerify   Operation = "verify"
)

type CheckClass string

const (
	Reproduction CheckClass = "reproduction"
	Normal       CheckClass = "normal"
)

type Check struct {
	ID    string     `json:"id"`
	Class CheckClass `json:"class"`
}

type Observation string

const (
	Pass        Observation = "pass"
	Fail        Observation = "fail"
	Unavailable Observation = "unavailable"
)

type CheckResult struct {
	ID       string      `json:"id"`
	Class    CheckClass  `json:"class"`
	Original Observation `json:"original"`
	Control  Observation `json:"control"`
	Patched  Observation `json:"patched,omitempty"`
}

type Runtime struct {
	Image string `json:"image"`
	UID   string `json:"uid"`
}

type CleanupState string

const (
	CleanupComplete   CleanupState = "complete"
	CleanupIncomplete CleanupState = "incomplete"
	CleanupUnknown    CleanupState = "unknown"
)

type CleanupReceipt struct {
	State         CleanupState `json:"state"`
	ReceiptDigest string       `json:"receiptDigest"`
}

type Result struct {
	Version       int            `json:"version"`
	Operation     Operation      `json:"operation"`
	RequestDigest string         `json:"requestDigest"`
	ChecksDigest  string         `json:"checksDigest"`
	Original      Runtime        `json:"original"`
	Control       Runtime        `json:"control"`
	Patched       *Runtime       `json:"patched,omitempty"`
	Checks        []CheckResult  `json:"checks"`
	Cleanup       CleanupReceipt `json:"cleanup"`
}

// Request is private driver input, never a model prompt. Configuration and patch
// paths refer to byte-verified private snapshots, not caller-writable originals.
type Request struct {
	Version       int          `json:"version"`
	Name          string       `json:"name"`
	Operation     Operation    `json:"operation"`
	ProfileDigest string       `json:"profileDigest"`
	Profile       Profile      `json:"profile"`
	Configuration FileIdentity `json:"configuration"`
	Candidate     *Candidate   `json:"candidate,omitempty"`
	Baseline      *Result      `json:"baseline,omitempty"`
}

type State string

const (
	BaselineReady State = "baseline-ready"
	Verified      State = "verified"
	Blocked       State = "blocked"
	Unknown       State = "unknown"
)

// Receipt is a bridge decision plus the driver's bounded observations. It has no
// raw diagnostics, credential/configuration content or model-produced text.
type Receipt struct {
	Version        int       `json:"version"`
	Name           string    `json:"name"`
	Operation      Operation `json:"operation"`
	ProfileDigest  string    `json:"profileDigest"`
	RequestDigest  string    `json:"requestDigest"`
	ResultDigest   string    `json:"resultDigest,omitempty"`
	State          State     `json:"state"`
	Result         *Result   `json:"result,omitempty"`
	TrustStatement string    `json:"trustStatement"`
}

type intent struct {
	Version       int       `json:"version"`
	Name          string    `json:"name"`
	Operation     Operation `json:"operation"`
	ProfileDigest string    `json:"profileDigest"`
	RequestDigest string    `json:"requestDigest"`
}
