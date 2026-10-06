package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"time"

	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
)

const terminationPath = "/dev/termination-log"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		return 1
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "connect":
		result, exit := connect(args[1:])
		message, err := json.Marshal(result)
		if err != nil || len(message) > probe.MaxMessageBytes {
			return 1
		}
		// Kubelet mounts this one writeable termination file even with a read-only
		// root filesystem. Do not create directories/files or fall back to logs.
		file, err := os.OpenFile(terminationPath, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return 1
		}
		_, writeErr := file.Write(message)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return 1
		}
		return exit
	default:
		return 1
	}
}

func serve(args []string) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	nonce := flags.String("nonce", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !probe.ValidNonce(*nonce) {
		return 1
	}
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		return 1
	}
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if probe.Serve(ctx, listener, *nonce) != nil {
		return 1
	}
	return 0
}

func connect(args []string) (probe.Result, int) {
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	target := flags.String("target", "", "")
	nonce := flags.String("nonce", "", "")
	expect := flags.String("expect", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 ||
		(*expect != string(probe.Reachable) && *expect != string(probe.Blocked)) {
		return probe.Result{FailureClass: probe.InvalidArguments}, 1
	}
	result := probe.Connect(*target, *nonce)
	if probe.Matches(probe.Expectation(*expect), result) {
		return result, 0
	}
	return result, 1
}
