package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/orka-agents/orka/internal/cli/client"
	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/remediation"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/icm"
	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/remediation/journal"
	"github.com/orka-agents/orka/internal/remediation/source"
	remediationvalidation "github.com/orka-agents/orka/internal/remediation/validation"
)

const (
	remediationPlanOperation   = "plan"
	remediationRunOperation    = "run"
	remediationStatusOperation = "status"
)

func newRemediationCmd() *cobra.Command {
	command := &cobra.Command{
		Use:   "remediate",
		Short: "Prepare private report-driven patches with pinned targets and recorded validation",
	}
	command.AddCommand(newRemediationExportCmd(), newRemediationIngestCmd())
	command.AddCommand(newRemediationWorkCmd(remediationPlanOperation), newRemediationWorkCmd(remediationRunOperation), newRemediationWorkCmd(remediationStatusOperation))
	command.AddCommand(newRemediationLabCommands()...)
	command.AddCommand(newRemediationStartCmd(), newRemediationApproveCmd(), newRemediationCancelCmd(), newRemediationDownloadCmd())
	command.AddCommand(newRemediationOperatorCommands()...)
	return command
}

func newRemediationExportCmd() *cobra.Command {
	var directory, binary, auth string
	command := &cobra.Command{
		Use:   "export <incident-id-or-url>",
		Short: "Capture one read-only IcM snapshot in a new private directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if directory == "" {
				return errors.New("--output-dir is required")
			}
			receipt, err := (icm.Exporter{Binary: binary, Auth: auth}).Capture(cmd.Context(), args[0], directory)
			if writeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(receipt); writeErr != nil {
				return errors.Join(err, writeErr)
			}
			return err
		},
	}
	command.Flags().StringVar(&directory, "output-dir", "", "new absolute private export directory")
	command.Flags().StringVar(&binary, "icm-cli", "icm-cli", "installed IcM CLI executable")
	command.Flags().StringVar(&auth, "icm-auth", "azcli", "explicit IcM authentication mode: azcli or env")
	return command
}

func newRemediationIngestCmd() *cobra.Command {
	var filename, directory, checksFile string
	command := &cobra.Command{
		Use:   "ingest",
		Short: "Normalize a JSON report/export and initialize its private workflow journal",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if filename == "" || directory == "" {
				return errors.New("--input and --state-dir are required")
			}
			raw, err := readRemediationFile(filename, 8<<20, false)
			if err != nil {
				return err
			}
			report, err := intake.Parse(raw)
			if err != nil {
				return err
			}
			var checks []byte
			if checksFile != "" {
				checks, err = readRemediationFile(checksFile, 256<<10, false)
				if err != nil {
					return err
				}
				if _, err := remediation.DecodeCheckProposal(string(checks)); err != nil {
					return err
				}
			}
			store, err := journal.Create(directory, report.SourceDigest)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			summary, err := remediation.Initialize(store, raw, checks)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(summary)
		},
	}
	command.Flags().StringVar(&filename, "input", "", "JSON input file; raw incident data is never printed")
	command.Flags().StringVar(&directory, "state-dir", "", "new absolute private workflow state directory")
	command.Flags().StringVar(&checksFile, "checks", "", "optional supplied check proposal JSON instead of agent-generated checks")
	return command
}

func newRemediationWorkCmd(operation string) *cobra.Command {
	var directory, agentName, tokenFile, image, platform, profile, workDir, approval string
	var validationServer, validationNamespace, validationTokenFile, inputPod, inputRoot string
	var modelApproved bool
	var timeout time.Duration
	command := &cobra.Command{
		Use:   operation,
		Short: map[string]string{remediationPlanOperation: "Propose exact public-source targets without executing checks", remediationRunOperation: "Continue an explicitly approved report-to-patch workflow", remediationStatusOperation: "Read saved workflow state without model or network access"}[operation],
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if operation == remediationStatusOperation && len(args) == 1 {
				return remediationRemoteStatus(cmd, args[0])
			}
			if directory == "" {
				return errors.New("--state-dir is required")
			}
			store, err := journal.Open(directory)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			engine := remediation.Engine{Store: store}
			if operation == remediationStatusOperation {
				summary, err := engine.Inspect()
				if err != nil {
					return err
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(summary)
			}
			if timeout <= 0 || timeout > 2*time.Hour {
				return errors.New("timeout must be positive and at most two hours")
			}
			api := newClientFromCmd(cmd)
			api.HTTPClient = &http.Client{Timeout: 90 * time.Second}
			if tokenFile != "" {
				raw, err := readRemediationFile(tokenFile, 16<<10, true)
				if err != nil {
					return err
				}
				api.Token = strings.TrimSpace(string(raw))
				if api.Token == "" {
					return errors.New("authentication file is empty")
				}
			}
			if agentName == "" {
				return errors.New("--agent is required")
			}
			engine.Generator = modelagent.Client{API: api, AgentName: agentName, PollInterval: 2 * time.Second}
			engine.Resolver = source.Client{HTTPClient: &http.Client{Timeout: 30 * time.Second}}
			engine.Materialize = source.Materialize
			engine.ModelDataApproved, engine.ApprovePlanDigest = modelApproved, approval
			engine.Image, engine.Platform, engine.Profile, engine.WorkDir = image, platform, profile, workDir
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			var summary remediation.Summary
			if operation == remediationPlanOperation {
				summary, err = engine.Propose(ctx)
			} else {
				if validationServer == "" || validationNamespace == "" || inputPod == "" || inputRoot == "" {
					return errors.New("--validation-server, --validation-namespace, --input-pod and --input-root are required")
				}
				kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
				if kubeconfig == "" || !filepath.IsAbs(kubeconfig) {
					return errors.New("an explicit absolute --kubeconfig is required for input staging")
				}
				validationAPI := client.NewWithNamespace(validationServer, api.Token, validationNamespace)
				validationAPI.HTTPClient = &http.Client{Timeout: 90 * time.Second}
				if validationTokenFile != "" {
					raw, readErr := readRemediationFile(validationTokenFile, 16<<10, true)
					if readErr != nil {
						return readErr
					}
					validationAPI.Token = strings.TrimSpace(string(raw))
					if validationAPI.Token == "" {
						return errors.New("validation authentication file is empty")
					}
				}
				engine.Validator = remediationvalidation.Client{
					API: validationAPI, Kubeconfig: kubeconfig, InputPod: inputPod, InputRoot: inputRoot,
					PollInterval: 2 * time.Second,
				}
				summary, err = engine.Execute(ctx)
			}
			if writeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(summary); writeErr != nil {
				return errors.Join(err, writeErr)
			}
			return err
		},
	}
	command.Flags().StringVar(&directory, "state-dir", "", "absolute private workflow journal directory")
	if operation == remediationStatusOperation {
		command.Use = "status [RUN_ID]"
		command.Short = "Read remote run status, or saved local state with --state-dir"
		command.Args = func(_ *cobra.Command, args []string) error {
			if len(args) == 1 && directory == "" || len(args) == 0 && directory != "" {
				return nil
			}
			return errors.New("provide RUN_ID for remote status or --state-dir for local status, not both")
		}
		addRemediationRemoteTokenFlag(command)
		return command
	}
	command.Flags().StringVar(&agentName, "agent", "", "approved Orka coding Agent")
	command.Flags().StringVar(&tokenFile, "token-file", "", "private bearer-token file; values are never printed")
	command.Flags().BoolVar(&modelApproved, "model-data-approved", false, "assert the configured model is approved for this report's necessary technical content")
	command.Flags().DurationVar(&timeout, "timeout", remediation.DefaultTimeout, "whole-command deadline, at most two hours")
	command.Flags().StringVar(&image, "tool-image", "", "explicit digest-pinned validation tool image")
	command.Flags().StringVar(&platform, "platform", "linux/amd64", "validation worker platform")
	command.Flags().StringVar(&profile, "profile", pv.Offline, "declared validation environment: offline or local-services")
	if operation == remediationRunOperation {
		command.Flags().StringVar(&workDir, "work-dir", "", "absolute private staging directory outside the source checkout")
		command.Flags().StringVar(&approval, "approve-plan", "", "exact proposed plan digest to confirm")
		command.Flags().StringVar(&validationServer, "validation-server", "", "existing standalone validation API URL")
		command.Flags().StringVar(&validationNamespace, "validation-namespace", "", "namespace watched by the standalone validation controller")
		command.Flags().StringVar(&validationTokenFile, "validation-token-file", "", "private validation API token file, if different")
		command.Flags().StringVar(&inputPod, "input-pod", "", "operator-provisioned, private input-PVC uploader Pod")
		command.Flags().StringVar(&inputRoot, "input-root", "", "absolute controller input root including validation namespace")
	}
	return command
}

func readRemediationFile(filename string, limit int64, private bool) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || (private && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("input file is unavailable, not regular/private, or exceeds its size limit")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("input file could not be opened")
	}
	defer func() { _ = file.Close() }()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return nil, errors.New("input file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fmt.Errorf("input could not be read within its %d-byte limit", limit)
	}
	return raw, nil
}
