package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	pv "github.com/orka-agents/orka/internal/patchverification"
	"github.com/orka-agents/orka/internal/patchverification/local"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runCLI(ctx, os.Args[1:], os.Stdout, os.Stderr, func(config configuration) local.Dependencies {
		runner := pv.DockerRunner{
			LauncherPath: config.launcherPath, LauncherDigest: config.launcherDigest, MaxOutputBytes: pv.MaxOutputBytes,
		}
		return local.Dependencies{
			Prepare: pv.PrepareSources,
			Release: func(prepared *pv.PreparedSources) error { return prepared.Close() },
			Runner:  runner, Quiescent: local.DockerQuiescent, Timeout: config.timeout,
		}
	})
	stop()
	os.Exit(code)
}
