//go:build !linux

package environment

import "context"

func (a *Adapter) lock(context.Context, string) (func(), error) {
	return nil, failure(NeedsAdapter, "linux-executor-required")
}

func (a *Adapter) lockFile(context.Context, string) (func(), bool, error) {
	return nil, false, failure(NeedsAdapter, "linux-executor-required")
}

func runBuildctl(context.Context, BuildKitConfig, []string, string, int64) ([]byte, bool, error) {
	return nil, false, failure(NeedsAdapter, "linux-executor-required")
}

func compilerDiagnostics([]byte) []Diagnostic { return nil }
