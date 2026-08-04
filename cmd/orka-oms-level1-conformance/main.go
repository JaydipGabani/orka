/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/orka-agents/orka/pkg/oms/specv01"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	flags := flag.NewFlagSet("orka-oms-level1-conformance", flag.ContinueOnError)
	flags.SetOutput(stderr)
	endpoint := flags.String("endpoint", "", "KD6 OMS Level 1 facade base URL")
	tokenEnv := flags.String("token-env", "ORKA_OMS_BEARER_TOKEN", "environment variable containing the bearer token")
	tenantID := flags.String("tenant-id", "orka-level1-conformance", "isolated tenant identity")
	agentID := flags.String("agent-id", "orka-level1-conformance", "conformance agent identity")
	timeout := flags.Duration("timeout", 15*time.Second, "per-request timeout")
	overallTimeout := flags.Duration("overall-timeout", 5*time.Minute, "overall conformance timeout")
	disableProxy := flags.Bool("disable-proxy", true, "disable HTTP proxy use for conformance traffic")
	insecureLoopbackOnly := flags.Bool(
		"insecure-loopback-only", false,
		"allow plaintext HTTP only to a literal loopback address (local testing only)",
	)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*endpoint) == "" {
		_, _ = fmt.Fprintln(stderr, "--endpoint is required")
		return 2
	}
	token := strings.TrimSpace(getenv(*tokenEnv))
	if token == "" {
		_, _ = fmt.Fprintf(stderr, "%s is required\n", *tokenEnv)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *overallTimeout)
	defer cancel()
	result := specv01.CheckLevel1(ctx, specv01.Target{
		BaseURL: *endpoint, AuthorizationValue: "Bearer " + token,
		TenantID: strings.TrimSpace(*tenantID), AgentID: strings.TrimSpace(*agentID),
		Timeout: *timeout, DisableProxy: *disableProxy, InsecureLoopbackOnly: *insecureLoopbackOnly,
	})
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		_, _ = fmt.Fprintf(stderr, "encode result: %v\n", err)
		return 2
	}
	if !result.Passed {
		return 1
	}
	return 0
}
