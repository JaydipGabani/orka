package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/journal"
	"github.com/orka-agents/orka/internal/remediation/lab"
	"github.com/orka-agents/orka/internal/remediation/source"
)

const (
	remediationLabPlanCommand      = "lab-plan"
	remediationLabValidateCommand  = "lab-validate"
	remediationLabRunCommand       = "lab-run"
	remediationLabVerifyCommand    = "lab-verify"
	remediationLabSourceChangeKind = "source"
)

type remediationLabOptions struct {
	stateDir          string
	agentName         string
	taskType          string
	tokenFile         string
	workDir           string
	profileFile       string
	approval          string
	patchFile         string
	changeDescription string
	sourceFiles       []string
	modelApproved     bool
	timeout           time.Duration
}

func newRemediationLabCommands() []*cobra.Command {
	return []*cobra.Command{
		newRemediationLabCommand(remediationLabPlanCommand),
		newRemediationLabCommand(remediationLabValidateCommand),
		newRemediationLabCommand(remediationLabRunCommand),
		newRemediationLabCommand(remediationLabVerifyCommand),
	}
}

func newRemediationLabCommand(operation string) *cobra.Command {
	var options remediationLabOptions
	command := &cobra.Command{
		Use: operation,
		Short: map[string]string{
			remediationLabPlanCommand:     "Propose a lab plan from pinned public-source files and an explicit profile",
			remediationLabValidateCommand: "Validate the exact approved lab plan",
			remediationLabRunCommand:      "Execute the exact approved lab plan",
			remediationLabVerifyCommand:   "Verify a supplied reviewed patch with the approved lab driver, without a model",
		}[operation],
		Long: "Use an existing private remediation journal and explicit external scratch directory.\n" +
			"Only lab-run uses the Orka model API; lab-plan reads public source anonymously.\n" +
			"The lab driver is human-approved and privileged; candidate isolation is separate.\n" +
			"These commands do not automatically provision AKS.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return writeRemediationLabSummary(cmd, remediation.Summary{}, errors.New("lab commands do not accept positional arguments"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			summary, err := options.run(cmd, operation)
			return writeRemediationLabSummary(cmd, summary, err)
		},
	}
	command.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return writeRemediationLabSummary(cmd, remediation.Summary{}, &remediationLabError{
			message: "invalid lab command flags; use --help", cause: err,
		})
	})
	flags := command.Flags()
	flags.StringVar(&options.stateDir, "state-dir", "", "existing absolute private workflow journal directory")
	flags.StringVar(&options.agentName, "agent", "", "approved Orka proposal Agent; required only for lab-run")
	flags.StringVar(&options.taskType, "task-type", cliTaskTypeAI, "lab-run proposal Task type: ai or agent; no automatic fallback")
	flags.StringVar(&options.tokenFile, "token-file", "", "lab-run private bearer-token file; values are never printed")
	flags.BoolVar(&options.modelApproved, "model-data-approved", false, "lab-run: assert the model is approved for the report's necessary technical content")
	flags.DurationVar(&options.timeout, "timeout", remediation.DefaultTimeout, "whole-command deadline, positive and at most two hours")
	flags.StringVar(&options.workDir, "work-dir", "", "existing absolute mode-0700 scratch directory outside Git checkouts and the journal")
	if operation == remediationLabPlanCommand {
		flags.StringVar(&options.profileFile, "lab-profile", "", "explicit lab profile JSON file, at most 64 KiB")
		flags.StringArrayVar(&options.sourceFiles, "source-file", nil, "repository-relative source file; repeat for 1 to 32 files")
	} else {
		flags.StringVar(&options.approval, "approve-plan", "", "exact proposed plan digest: sha256: followed by 64 lowercase hexadecimal digits")
	}
	if operation == remediationLabVerifyCommand {
		flags.StringVar(&options.patchFile, "patch-file", "", "private mode-0600 diff file, at most 256 KiB")
		flags.StringVar(&options.changeDescription, "change-description", "", "required description of the reviewed source change, at most 16 KiB")
	}
	return command
}

func (o remediationLabOptions) validate(operation string) error {
	if o.stateDir == "" || !filepath.IsAbs(o.stateDir) || filepath.Clean(o.stateDir) != o.stateDir {
		return errors.New("--state-dir must name an existing canonical absolute private journal")
	}
	if operation == remediationLabRunCommand {
		if strings.TrimSpace(o.agentName) == "" {
			return errors.New("--agent is required for lab-run")
		}
		if o.taskType != cliTaskTypeAI && o.taskType != cliTaskTypeAgent {
			return errors.New("--task-type must be ai or agent")
		}
	}
	if o.timeout <= 0 || o.timeout > 2*time.Hour {
		return errors.New("--timeout must be positive and at most two hours")
	}
	if operation == remediationLabPlanCommand {
		if o.profileFile == "" {
			return errors.New("--lab-profile is required")
		}
		if len(o.sourceFiles) < 1 || len(o.sourceFiles) > 32 {
			return errors.New("--source-file must be supplied between 1 and 32 times")
		}
		for _, name := range o.sourceFiles {
			if strings.TrimSpace(name) == "" {
				return errors.New("--source-file must not be empty")
			}
		}
	} else if !validRemediationLabDigest(o.approval) {
		return errors.New("--approve-plan must be an exact canonical sha256 digest")
	}
	if operation == remediationLabVerifyCommand {
		if o.patchFile == "" {
			return errors.New("--patch-file is required")
		}
		if strings.TrimSpace(o.changeDescription) == "" || len(o.changeDescription) > 16<<10 || !utf8.ValidString(o.changeDescription) {
			return errors.New("--change-description must be nonblank UTF-8 and at most 16 KiB")
		}
	}
	return validateRemediationLabWorkDir(o.workDir, o.stateDir)
}

func validRemediationLabDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func validateRemediationLabWorkDir(directory, stateDir string) error {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return errors.New("--work-dir must be an explicit canonical absolute private scratch directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("--work-dir must be an existing private directory with mode 0700")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return errors.New("--work-dir must not contain symlink aliases")
	}
	if directory == stateDir || strings.HasPrefix(directory, stateDir+string(filepath.Separator)) ||
		strings.HasPrefix(stateDir, directory+string(filepath.Separator)) {
		return errors.New("--work-dir must not overlap the workflow journal")
	}
	for ancestor := directory; ; ancestor = filepath.Dir(ancestor) {
		if _, err := os.Lstat(filepath.Join(ancestor, ".git")); err == nil {
			return errors.New("--work-dir must be outside Git checkouts")
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("--work-dir ancestry could not be verified")
		}
		if filepath.Dir(ancestor) == ancestor {
			return nil
		}
	}
}

func (o remediationLabOptions) readInputs(operation string) (profile []byte, token string, err error) {
	if operation == remediationLabPlanCommand {
		profile, err = readRemediationFile(o.profileFile, lab.MaxProfileBytes, false)
		if err != nil {
			return nil, "", err
		}
		if len(profile) == 0 {
			return nil, "", errors.New("--lab-profile must not be empty")
		}
	}
	if operation == remediationLabRunCommand && o.tokenFile != "" {
		raw, err := readRemediationFile(o.tokenFile, 16<<10, true)
		if err != nil {
			return nil, "", err
		}
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return nil, "", errors.New("authentication file is empty")
		}
	}
	return profile, token, nil
}

func (o remediationLabOptions) suppliedPatchProposal() (remediation.PatchProposal, error) {
	raw, err := readRemediationFile(o.patchFile, 256<<10, true)
	if err != nil {
		return remediation.PatchProposal{}, err
	}
	if !utf8.Valid(raw) || strings.TrimSpace(string(raw)) == "" {
		return remediation.PatchProposal{}, errors.New("--patch-file must contain a nonempty UTF-8 diff")
	}
	return remediation.PatchProposal{
		Summary: o.changeDescription,
		Patch:   string(raw),
		DeclaredChanges: []pv.DeclaredChange{
			{Kind: remediationLabSourceChangeKind, Description: o.changeDescription},
		},
		Limitations: []string{},
	}, nil
}

func (o remediationLabOptions) run(cmd *cobra.Command, operation string) (summary remediation.Summary, err error) {
	if err := o.validate(operation); err != nil {
		return summary, err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	profile, token, err := o.readInputs(operation)
	if err != nil {
		return summary, err
	}
	store, err := journal.Open(o.stateDir)
	if err != nil {
		return summary, &remediationLabError{message: "could not open the private workflow journal", cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, &remediationLabError{message: "could not close the private workflow journal", cause: closeErr})
		}
	}()
	publicSource := source.Client{HTTPClient: &http.Client{Timeout: 30 * time.Second}}
	engine := remediation.Engine{
		Store: store, WorkDir: o.workDir, ApprovePlanDigest: o.approval,
		Resolver: publicSource, SourcePacket: publicSource.Packet,
	}
	if operation == remediationLabRunCommand {
		api := newClientFromCmd(cmd)
		api.HTTPClient = &http.Client{Timeout: 90 * time.Second}
		if o.tokenFile != "" {
			api.Token = token
		}
		engine.Generator = modelagent.Client{
			API: api, AgentName: o.agentName, TaskType: o.taskType, PollInterval: 2 * time.Second,
		}
		engine.ModelDataApproved = o.modelApproved
	}
	switch operation {
	case remediationLabPlanCommand:
		summary, err = engine.ProposeLab(ctx, profile, o.sourceFiles)
	case remediationLabValidateCommand:
		summary, err = engine.ValidateLab(ctx)
	case remediationLabRunCommand:
		summary, err = engine.ExecuteLab(ctx)
	case remediationLabVerifyCommand:
		var proposal remediation.PatchProposal
		proposal, err = o.suppliedPatchProposal()
		if err == nil {
			summary, err = engine.VerifyLab(ctx, proposal)
		}
	default:
		err = errors.New("unsupported lab command")
	}
	return summary, err
}

type remediationLabError struct {
	message string
	cause   error
}

func (e *remediationLabError) Error() string { return e.message }
func (e *remediationLabError) Unwrap() error { return e.cause }

func writeRemediationLabSummary(cmd *cobra.Command, summary remediation.Summary, err error) error {
	if err != nil && summary.Phase == "" {
		summary.Phase, summary.Reason = "blocked", "lab_command_failed"
	}
	if writeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(summary); writeErr != nil {
		return errors.Join(err, &remediationLabError{message: "could not write the lab summary", cause: writeErr})
	}
	return err
}
