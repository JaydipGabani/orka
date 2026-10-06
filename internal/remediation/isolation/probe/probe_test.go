package probe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConnectExactNonce(t *testing.T) {
	t.Parallel()
	nonce := strings.Repeat("ab", NonceBytes)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, nonce) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	result := Connect(listener.Addr().String(), nonce)
	require.True(t, Matches(Reachable, result))
	require.False(t, Matches(Blocked, result))
	message, err := json.Marshal(result)
	require.NoError(t, err)
	require.Less(t, len(message), MaxMessageBytes)
	require.NotContains(t, string(message), nonce)
	require.NotContains(t, string(message), listener.Addr().String())
	decoded, err := Decode(string(message))
	require.NoError(t, err)
	require.Equal(t, result, decoded)

	result = Connect(listener.Addr().String(), strings.Repeat("cd", NonceBytes))
	require.True(t, result.Reachable)
	require.False(t, result.NonceMatched)
	require.False(t, Matches(Reachable, result))
	require.False(t, Matches(Blocked, result))
}

func TestRefusalIsNotBlocking(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	result := Connect(address, strings.Repeat("ab", NonceBytes))
	require.Equal(t, ConnectionRefused, result.FailureClass)
	require.False(t, Matches(Blocked, result))
}

func TestAcceptedSilentConnectionIsNotBlocking(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { require.NoError(t, listener.Close()) }()
	done := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		_, copyErr := io.Copy(io.Discard, conn)
		_ = conn.Close()
		done <- copyErr
	}()
	start := time.Now()
	result := Connect(listener.Addr().String(), strings.Repeat("ab", NonceBytes))
	require.Less(t, time.Since(start), 3*time.Second)
	require.Equal(t, Result{Reachable: true, FailureClass: ExchangeFailed}, result)
	require.False(t, Matches(Blocked, result))
	require.NoError(t, <-done)
}

func TestLiteralTargetsAndSyntheticNoncesOnly(t *testing.T) {
	t.Parallel()
	nonce := strings.Repeat("ab", NonceBytes)
	for _, target := range []string{
		"localhost:8080", "http://127.0.0.1:8080", "127.0.0.1", "127.0.0.1:0",
		"user:pass@127.0.0.1:8080", "0.0.0.0:8080", "[::]:8080", "[fe80::1%eth0]:8080",
	} {
		require.Equal(t, InvalidArguments, Connect(target, nonce).FailureClass, target)
	}
	for _, badNonce := range []string{"", "not-a-nonce", strings.Repeat("AB", NonceBytes), strings.Repeat("z", NonceBytes*2)} {
		require.Equal(t, InvalidArguments, Connect("127.0.0.1:8080", badNonce).FailureClass)
	}
}

func TestProbeIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	nonce := strings.Repeat("ab", NonceBytes)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, nonce) }()
	require.True(t, Matches(Reachable, Connect(listener.Addr().String(), nonce)))
	cancel()
	require.NoError(t, <-done)
}

func TestDialClassifications(t *testing.T) {
	t.Parallel()
	require.Equal(t, DialTimeout, classifyDial(&net.OpError{Op: "dial", Err: context.DeadlineExceeded}))
	require.Equal(t, Unreachable, classifyDial(&net.OpError{Op: "dial", Err: syscall.ENETUNREACH}))
	require.Equal(t, Unreachable, classifyDial(&net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}))
	require.Equal(t, ConnectionRefused, classifyDial(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}))
	require.Equal(t, DialFailed, classifyDial(errors.New("opaque")))
	require.True(t, Matches(Blocked, Result{FailureClass: DialTimeout}))
	require.False(t, Matches(Blocked, Result{Reachable: true, FailureClass: DialTimeout}))
}

func TestDecodeFixedStructureAndByteLimit(t *testing.T) {
	t.Parallel()
	message := `{"reachable":false,"nonceMatched":false,"failureClass":"dial-timeout"}`
	for _, malformed := range []string{
		`{}`, `{"reachable":false,"nonceMatched":false}`, message + message,
		`{"reachable":false,"reachable":false,"nonceMatched":false,"failureClass":"dial-timeout"}`,
		`{"reachable":false,"nonceMatched":false,"failureClass":"dial-timeout","rawError":"reflected"}`,
		`{"reachable":"false","nonceMatched":false,"failureClass":"dial-timeout"}`,
		`{"reachable":false,"nonceMatched":false,"failureClass":"arbitrary-reflected-error"}`,
		`{"reachable":true,"nonceMatched":false,"failureClass":"dial-timeout"}`,
	} {
		_, err := Decode(malformed)
		require.Error(t, err)
	}
	for _, size := range []int{MaxMessageBytes - 1, MaxMessageBytes} {
		_, err := Decode(message + strings.Repeat(" ", size-len(message)))
		require.NoError(t, err)
	}
	_, err := Decode(message + strings.Repeat(" ", MaxMessageBytes+1-len(message)))
	require.Error(t, err)
}
