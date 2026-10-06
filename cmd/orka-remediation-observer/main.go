package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
)

type configFlag struct {
	value string
	set   bool
}

func (f *configFlag) String() string { return "" }

func (f *configFlag) Set(value string) error {
	if f.set || value == "" {
		return errors.New("configuration flag must be specified once with a path")
	}
	f.value, f.set = value, true
	return nil
}

func loadCLIConfig(args []string, lookup func(string) (string, bool)) (config, error) {
	flags := flag.NewFlagSet("orka-remediation-observer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var path configFlag
	flags.Var(&path, "config", "path to bounded trusted JSON configuration")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return config{}, flag.ErrHelp
		}
		return config{}, errors.New("invalid command flags")
	}
	value, environmentSet := lookup(configEnvironment)
	if flags.NArg() != 0 || path.set == environmentSet {
		return config{}, errors.New("provide exactly one config file or observer config environment variable")
	}
	var data []byte
	if path.set {
		var err error
		data, err = readBoundedFile(path.value, maxConfigBytes, false)
		if err != nil {
			return config{}, err
		}
	} else {
		if len(value) > maxConfigBytes {
			return config{}, errors.New("configuration size is invalid")
		}
		data = []byte(value)
	}
	defer clear(data)
	return parseConfig(data)
}

func run(ctx context.Context, args []string, lookup func(string) (string, bool), output io.Writer) int {
	logger := log.New(output, "remediation-observer: ", 0)
	cfg, err := loadCLIConfig(args, lookup)
	if errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprintln(output, "Usage: orka-remediation-observer -config FILE")
		_, _ = fmt.Fprintln(output, "Alternatively set ORKA_REMEDIATION_OBSERVER_CONFIG to trusted JSON.")
		return 0
	}
	if err != nil {
		logger.Print("configuration rejected")
		return 1
	}
	server, err := startServer(cfg)
	if err != nil {
		logger.Print("startup failed")
		return 1
	}
	logger.Print("started")
	result := 0
	select {
	case <-ctx.Done():
	case <-server.failures:
		logger.Print("listener failed")
		result = 1
	}
	if err := server.shutdown(); err != nil {
		logger.Print("shutdown failed")
		return 1
	}
	logger.Print("stopped")
	return result
}

func main() {
	os.Exit(mainExit())
}

func mainExit() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return run(ctx, os.Args[1:], os.LookupEnv, os.Stderr)
}
