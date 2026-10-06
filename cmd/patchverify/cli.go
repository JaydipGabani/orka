package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"time"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/patchverification/local"
)

type configuration struct {
	launcherPath   string
	launcherDigest string
	timeout        time.Duration
}

type dependencyFactory func(configuration) local.Dependencies

const (
	commandStart    = "start"
	commandEvidence = "evidence"
)

type cliOptions struct {
	operation   string
	dbPath      string
	runID       string
	requestFile string
	digest      string
	limit       int
	raw         bool
	config      configuration
}

func parseOptions(arguments []string) (cliOptions, error) {
	if len(arguments) == 0 {
		return cliOptions{}, errors.New(
			"usage: patchverify <start|get|evidence|cancel|recover> --db /absolute/path/evidence.db",
		)
	}
	options := cliOptions{
		operation: arguments[0], limit: pv.MaxOutputBytes,
		config: configuration{timeout: 30 * time.Minute},
	}
	flags := flag.NewFlagSet(options.operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.dbPath, "db", "", "absolute private SQLite database path")
	switch options.operation {
	case commandStart:
		flags.StringVar(&options.requestFile, "request", "", "request JSON file; local paths resolve relative to this file")
		flags.StringVar(&options.config.launcherPath, "network-launcher", "", "trusted absolute static Landlock helper path")
		flags.StringVar(&options.config.launcherDigest, "network-launcher-sha256", "", "independently trusted sha256: digest")
		flags.DurationVar(
			&options.config.timeout, "timeout", options.config.timeout,
			"whole-run timeout including preparation and all checks",
		)
	case "get", "cancel", "recover", commandEvidence:
		flags.StringVar(&options.runID, "run", "", "verification run ID")
		if options.operation == commandEvidence {
			flags.StringVar(&options.digest, "digest", "", "digest of a bounded blob to inspect")
			flags.IntVar(&options.limit, "max-bytes", options.limit, "blob inspection bound, at most 65536")
			flags.BoolVar(&options.raw, "raw", false, "emit exact blob bytes instead of a base64 JSON envelope")
		}
	default:
		return options, errors.New("unknown command; use start, get, evidence, cancel, or recover")
	}
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || !options.valid() {
		return options, errors.New(
			"invalid or missing flags; database paths must be absolute; inspect help in the POC guide",
		)
	}
	return options, nil
}

func (options cliOptions) valid() bool {
	return options.dbPath != "" &&
		(options.operation != commandStart || options.requestFile != "") &&
		(options.operation == commandStart || options.runID != "") &&
		(!options.raw || options.digest != "") &&
		options.limit >= 1 && options.limit <= pv.MaxOutputBytes &&
		options.config.timeout > 0 && options.config.timeout <= 24*time.Hour
}

func runCLI(ctx context.Context, arguments []string, stdout, stderr io.Writer, factory dependencyFactory) int {
	options, err := parseOptions(arguments)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if runtime.GOOS != "linux" {
		_, _ = fmt.Fprintln(stderr, "local patch verification requires Linux")
		return 2
	}
	encoder := json.NewEncoder(stdout)
	var request pv.Request
	if options.operation == commandStart {
		request, err = local.ReadRequest(options.requestFile)
		if err != nil {
			_ = encoder.Encode(local.FailedAction(request.Action, err.Error()))
			return 2
		}
	}
	dependencies := local.Dependencies{}
	if factory != nil {
		dependencies = factory(options.config)
	}
	service, err := local.New(ctx, options.dbPath, dependencies)
	if err != nil {
		_ = encoder.Encode(local.FailedAction(request.Action, err.Error()))
		return 2
	}
	defer func() { _ = service.Close() }()
	var summary local.Summary
	switch options.operation {
	case commandStart:
		summary, err = service.Start(ctx, request, func(initial local.Summary) error { return encoder.Encode(initial) })
	case "get":
		summary, err = service.Get(ctx, options.runID)
	case "cancel":
		summary, err = service.Cancel(ctx, options.runID)
	case "recover":
		summary, err = service.Recover(ctx, options.runID)
	case commandEvidence:
		return writeEvidence(ctx, service, options, stdout, stderr)
	}
	if writeErr := encoder.Encode(summary); writeErr != nil {
		return 2
	}
	if err != nil {
		if errors.Is(err, local.ErrLiveOwner) {
			_, _ = fmt.Fprintln(stderr, "recovery refused: supervisor still owns this run")
		} else {
			_, _ = fmt.Fprintln(stderr, "operation failed; no favorable conclusion is implied; inspect the durable record")
		}
		return 2
	}
	if options.operation == commandStart {
		return startExitCode(summary)
	}
	return 0
}

func startExitCode(summary local.Summary) int {
	if summary.State != pv.RunFinalized {
		return 2
	}
	if summary.Action == pv.ValidateReport {
		if summary.Overall.Conclusion == pv.Reproduced || summary.Overall.Conclusion == pv.NotReproduced {
			return 0
		}
		return 2
	}
	switch summary.Overall.Conclusion {
	case pv.Verified:
		return 0
	case pv.NotFixed, pv.PartiallyFixed, pv.Regression:
		return 1
	default:
		return 2
	}
}

func writeEvidence(ctx context.Context, service *local.Service, options cliOptions, stdout, stderr io.Writer) int {
	encoder := json.NewEncoder(stdout)
	if options.digest != "" {
		content, err := service.Blob(ctx, options.runID, options.digest, options.limit)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "blob unavailable, corrupt, or larger than the inspection bound")
			return 2
		}
		if options.raw {
			_, err = stdout.Write(content)
		} else {
			err = encoder.Encode(struct {
				RunID  string `json:"runID"`
				Digest string `json:"digest"`
				Bytes  int    `json:"bytes"`
				Data   []byte `json:"data"`
			}{options.runID, options.digest, len(content), content})
		}
		if err != nil {
			return 2
		}
		return 0
	}
	record, err := service.Record(ctx, options.runID)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "verification evidence is unavailable or failed integrity validation")
		return 2
	}
	if err := encoder.Encode(struct {
		ExecutionBackend string     `json:"executionBackend"`
		Record           *pv.Record `json:"record"`
	}{local.ExecutionBackend, record}); err != nil {
		return 2
	}
	return 0
}
