// Package probe implements the bounded, credential-free canary wire protocol.
// It deliberately imports no Kubernetes, HTTP, proxy or DNS client packages.
package probe

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

const (
	Timeout         = 2 * time.Second
	Port            = 8080
	MaxMessageBytes = 4096
	NonceBytes      = 32
)

type FailureClass string

const (
	None              FailureClass = "none"
	DialTimeout       FailureClass = "dial-timeout"
	ConnectionRefused FailureClass = "connection-refused"
	Unreachable       FailureClass = "unreachable"
	InvalidArguments  FailureClass = "invalid-arguments"
	DialFailed        FailureClass = "dial-failed"
	ExchangeFailed    FailureClass = "exchange-failed"
	NonceMismatch     FailureClass = "nonce-mismatch"
)

type Expectation string

const (
	Reachable Expectation = "reachable"
	Blocked   Expectation = "blocked"
)

// Result is the entire termination-message protocol. Never add the address,
// nonce, raw errors, reflected bytes or unconstrained text to this structure.
type Result struct {
	Reachable    bool         `json:"reachable"`
	NonceMatched bool         `json:"nonceMatched"`
	FailureClass FailureClass `json:"failureClass"`
}

func ValidNonce(nonce string) bool {
	if len(nonce) != NonceBytes*2 || strings.ToLower(nonce) != nonce {
		return false
	}
	_, err := hex.DecodeString(nonce)
	return err == nil
}

func Matches(expect Expectation, result Result) bool {
	switch expect {
	case Reachable:
		return result == (Result{Reachable: true, NonceMatched: true, FailureClass: None})
	case Blocked:
		return result == (Result{FailureClass: DialTimeout})
	default:
		return false
	}
}

// Decode accepts only the canonical fixed structure emitted by this worker.
// Canonical comparison also rejects duplicate keys, missing fields, extra JSON
// values and string/bool coercions that a permissive decoder could overlook.
func Decode(message string) (Result, error) {
	var result Result
	if len(message) > MaxMessageBytes || json.Unmarshal([]byte(message), &result) != nil {
		return Result{}, errors.New("invalid-probe-result")
	}
	encoded, err := json.Marshal(result)
	if err != nil || !bytes.Equal(encoded, bytes.TrimSpace([]byte(message))) || !validResult(result) {
		return Result{}, errors.New("invalid-probe-result")
	}
	return result, nil
}

func validResult(result Result) bool {
	switch result.FailureClass {
	case None:
		return result.Reachable && result.NonceMatched
	case DialTimeout, ConnectionRefused, Unreachable, InvalidArguments, DialFailed:
		return !result.Reachable && !result.NonceMatched
	case ExchangeFailed, NonceMismatch:
		return result.Reachable && !result.NonceMatched
	default:
		return false
	}
}

// Connect uses a literal IP and direct TCP only. The adapter, not a model,
// chooses the address from the UID-verified canary Pod. Only a dial timeout is
// evidence of blocking; refusal, routing errors and read timeouts never are.
func Connect(target, nonce string) Result {
	address, err := netip.ParseAddrPort(target)
	if err != nil || address.Port() == 0 || address.Addr().Zone() != "" ||
		address.Addr().IsUnspecified() || address.Addr().IsMulticast() || !ValidNonce(nonce) {
		return Result{FailureClass: InvalidArguments}
	}
	deadline := time.Now().Add(Timeout)
	conn, err := net.DialTimeout("tcp", address.String(), Timeout)
	if err != nil {
		return Result{FailureClass: classifyDial(err)}
	}
	defer func() { _ = conn.Close() }()
	result := Result{Reachable: true, FailureClass: ExchangeFailed}
	if conn.SetDeadline(deadline) != nil {
		return result
	}
	request := wire(nonce)
	if _, err := io.WriteString(conn, request); err != nil {
		return result
	}
	response := make([]byte, len(request))
	if _, err := io.ReadFull(conn, response); err != nil {
		return result
	}
	if string(response) != request {
		result.FailureClass = NonceMismatch
		return result
	}
	return Result{Reachable: true, NonceMatched: true, FailureClass: None}
}

func classifyDial(err error) FailureClass {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ConnectionRefused
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return Unreachable
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return DialTimeout
	}
	return DialFailed
}

func wire(nonce string) string { return "orka-network-probe-v1:" + nonce + "\n" }

// Serve handles one small exchange at a time, with no per-connection goroutine
// growth. Readiness TCP connections may close without sending an application
// request. The listener and all active connections are closed on cancellation.
func Serve(ctx context.Context, listener net.Listener, nonce string) error {
	if !ValidNonce(nonce) {
		return errors.New("invalid-probe-nonce")
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("probe-listener-failed")
		}
		exchange(ctx, conn, nonce)
	}
}

func exchange(ctx context.Context, conn net.Conn, nonce string) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer func() { _ = conn.Close() }()
	if conn.SetDeadline(time.Now().Add(Timeout)) != nil {
		return
	}
	expected := wire(nonce)
	request := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, request); err != nil || string(request) != expected {
		return
	}
	_, _ = io.WriteString(conn, expected)
}
