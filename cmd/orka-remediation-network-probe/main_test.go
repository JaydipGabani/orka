package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	"github.com/stretchr/testify/require"
)

func TestConnectCommand(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	nonce := strings.Repeat("ab", probe.NonceBytes)
	done := make(chan error, 1)
	go func() { done <- probe.Serve(ctx, listener, nonce) }()
	defer func() {
		cancel()
		require.NoError(t, <-done)
	}()
	result, exit := connect([]string{"--target", listener.Addr().String(), "--expect", "reachable", "--nonce", nonce})
	require.Zero(t, exit)
	require.True(t, result.NonceMatched)
	result, exit = connect([]string{"--target", listener.Addr().String(), "--expect", "blocked", "--nonce", nonce})
	require.Equal(t, 1, exit)
	require.True(t, result.Reachable)
}

func TestCommandRejectsUntrustedOptions(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		nil, {"--expect", "maybe"}, {"--expect", "reachable", "--env", "value"},
		{"--expect", "blocked", "--target", "example.test:8080", "--nonce", strings.Repeat("ab", 32)},
		{"--expect", "reachable", "--target", "127.0.0.1:8080", "extra"},
	} {
		result, exit := connect(args)
		require.Equal(t, 1, exit)
		require.Equal(t, probe.InvalidArguments, result.FailureClass)
	}
	require.Equal(t, 1, run(nil))
	require.Equal(t, 1, run([]string{"unknown"}))
	require.Equal(t, 1, serve([]string{"--nonce", "not-synthetic"}))
}
