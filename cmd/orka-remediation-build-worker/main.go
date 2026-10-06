package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/orka-agents/orka/internal/remediation/buildjob"
)

func main() {
	var options buildjob.WorkerOptions
	flag.StringVar(&options.BundleDirectory, "bundle", "/bundle", "Read-only input Secret mount")
	flag.StringVar(&options.WorkspaceDirectory, "workspace", "/workspace", "Private emptyDir mount")
	flag.StringVar(&options.TerminationPath, "termination", "/dev/termination-log", "Kubelet termination-message file")
	flag.Parse()
	if flag.NArg() != 0 || buildjob.LimitWorkerProcess() != nil {
		os.Exit(1)
	}
	options.PhaseOutput = os.Stdout
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	os.Exit(buildjob.RunWorker(ctx, options))
}
