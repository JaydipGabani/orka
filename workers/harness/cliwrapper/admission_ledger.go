package cliwrapper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/orka-agents/orka/internal/harness"
	"github.com/orka-agents/orka/internal/harness/ledger"
)

// Bearer-auth-protected wrapper admin endpoints backing the controller's drain
// protocol. Both require the durable admission ledger to be configured.
const (
	// AdminCloseAdmissionPath durably and idempotently closes new turn
	// admission (POST).
	AdminCloseAdmissionPath = "/v1/admin/close-admission"
	// AdminUnsettledTurnsPath lists every Admitted or Accepted ledger turn for
	// drain inventory (GET).
	AdminUnsettledTurnsPath = "/v1/admin/unsettled-turns"
)

// StartTurn metadata keys consulted for durable admission identity. When the
// controller does not provide them, admission falls back to the turn ID and
// attempt 1.
const (
	ledgerTaskUIDMetadataKey = "taskUID"
	ledgerAttemptMetadataKey = "attempt"
)

const ledgerOpTimeout = 15 * time.Second

// CloseAdmissionResponse is the response body of AdminCloseAdmissionPath.
type CloseAdmissionResponse struct {
	Version  string    `json:"version"`
	Closed   bool      `json:"closed"`
	ClosedAt time.Time `json:"closedAt"`
}

// UnsettledTurn is one unsettled durable admission record.
type UnsettledTurn struct {
	TurnID        string    `json:"turnID"`
	TaskUID       string    `json:"taskUID"`
	Attempt       int32     `json:"attempt"`
	RequestDigest string    `json:"requestDigest"`
	State         string    `json:"state"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// UnsettledTurnsResponse is the response body of AdminUnsettledTurnsPath.
type UnsettledTurnsResponse struct {
	Version    string          `json:"version"`
	Generation string          `json:"generation"`
	Turns      []UnsettledTurn `json:"turns"`
}

// ledgerTerminalReceipt is the canonical durable receipt persisted for a
// terminal frame. It carries the terminal result payload, not full frame or
// transcript storage.
type ledgerTerminalReceipt struct {
	Type      harness.FrameType      `json:"type"`
	Seq       int64                  `json:"seq"`
	Completed *harness.TurnCompleted `json:"completed,omitempty"`
	Failed    *harness.TurnFailed    `json:"failed,omitempty"`
}

// ledgerOpContext bounds ledger mutations without inheriting the request
// context, so durable records survive client disconnects exactly like the
// in-memory registry transitions they mirror.
func ledgerOpContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), ledgerOpTimeout)
}

// canonicalStartTurnRequestDigest returns the sha256 digest of the canonical
// (re-marshaled) StartTurn request body.
func canonicalStartTurnRequestDigest(request harness.StartTurnRequest) (string, error) {
	canonical, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("marshal canonical StartTurn request: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ledgerTaskUID(request harness.StartTurnRequest) string {
	if uid := strings.TrimSpace(request.Metadata[ledgerTaskUIDMetadataKey]); uid != "" {
		return uid
	}
	return string(request.TurnID)
}

func ledgerAttempt(request harness.StartTurnRequest) int32 {
	raw := strings.TrimSpace(request.Metadata[ledgerAttemptMetadataKey])
	if raw == "" {
		return 1
	}
	parsed, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || parsed < 1 {
		return 1
	}
	return int32(parsed)
}

// admitTurnToLedger durably admits the turn before it starts running. Without
// a configured ledger it reports a fresh admission so the in-memory registry
// remains the only gate (pre-coexistence compatibility).
func (s *Server) admitTurnToLedger(request harness.StartTurnRequest) (ledger.AdmitOutcome, *ledger.TurnRecord, error) {
	if s.admissionLedger == nil {
		return ledger.AdmitOutcomeAdmitted, nil, nil
	}
	digest, err := canonicalStartTurnRequestDigest(request)
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := ledgerOpContext()
	defer cancel()
	return s.admissionLedger.AdmitTurn(ctx, string(request.TurnID), ledgerTaskUID(request), ledgerAttempt(request), digest)
}

// writeLedgerAdmissionError maps durable admission failures onto safe HTTP
// responses: digest replays are permanent 400-class rejections and a closed
// admission fails with a 503-class draining response.
func writeLedgerAdmissionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ledger.ErrDigestMismatch):
		writeSafeError(w, http.StatusBadRequest,
			"turn ID was already admitted with a different request digest; turn permanently rejected")
	case errors.Is(err, ledger.ErrAdmissionClosed):
		writeSafeError(w, http.StatusServiceUnavailable,
			"wrapper turn admission is closed for drain")
	default:
		writeSafeError(w, http.StatusInternalServerError, "failed to durably admit turn")
	}
}

// writeDuplicateLedgerTurn returns the same idempotent duplicate-turn
// responses the in-memory registry produces, keyed off durable state when the
// registry no longer knows the turn (for example after a wrapper restart).
func (s *Server) writeDuplicateLedgerTurn(
	w http.ResponseWriter,
	turnID harness.HarnessTurnID,
	record *ledger.TurnRecord,
) {
	if s.turnRegistry.lookup(turnID) != nil {
		writeSafeError(w, http.StatusConflict, "turn already exists")
		return
	}
	if record != nil && record.Settled() {
		writeSafeError(w, http.StatusConflict, "turn already completed")
		return
	}
	writeSafeError(w, http.StatusConflict, "turn already exists")
}

// markLedgerTurnAccepted durably records acceptance once the turn is
// registered. Failures degrade to the unsettled Admitted state, which drain
// inventory still surfaces, so they are logged instead of failing the turn.
func (s *Server) markLedgerTurnAccepted(turnID harness.HarnessTurnID) {
	if s.admissionLedger == nil {
		return
	}
	ctx, cancel := ledgerOpContext()
	defer cancel()
	if err := s.admissionLedger.MarkTurnAccepted(ctx, string(turnID)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to durably mark turn %s accepted: %v\n", turnID, err)
	}
}

// markLedgerTurnRejected durably records a definitive pre-execution rejection,
// the only ledger state that proves a safe resend is possible.
func (s *Server) markLedgerTurnRejected(turnID harness.HarnessTurnID, reason string) {
	if s.admissionLedger == nil {
		return
	}
	ctx, cancel := ledgerOpContext()
	defer cancel()
	if err := s.admissionLedger.MarkTurnRejected(ctx, string(turnID), reason); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to durably mark turn %s rejected: %v\n", turnID, err)
	}
}

// recordLedgerTurnTerminal persists the authoritative terminal receipt when a
// terminal frame (completed, failed, or cancelled) has been emitted.
func (s *Server) recordLedgerTurnTerminal(turn *turnState) {
	if s.admissionLedger == nil || turn == nil {
		return
	}
	frame, ok := turn.terminalFrame()
	if !ok {
		return
	}
	receipt, err := json.Marshal(ledgerTerminalReceipt{
		Type:      frame.Type,
		Seq:       frame.Seq,
		Completed: frame.Completed,
		Failed:    frame.Failed,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to encode terminal receipt for turn %s: %v\n", turn.id(), err)
		return
	}
	ctx, cancel := ledgerOpContext()
	defer cancel()
	if err := s.admissionLedger.RecordTurnTerminal(ctx, string(turn.id()), receipt, false); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to durably record terminal receipt for turn %s: %v\n", turn.id(), err)
	}
}

func (s *Server) handleCloseAdmission(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeSafeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.admissionLedger == nil {
		writeSafeError(w, http.StatusServiceUnavailable, "wrapper admission ledger is not configured")
		return
	}
	ctx, cancel := ledgerOpContext()
	defer cancel()
	if err := s.admissionLedger.CloseAdmission(ctx); err != nil {
		writeSafeError(w, http.StatusInternalServerError, "failed to close turn admission")
		return
	}
	closed, closedAt, err := s.admissionLedger.AdmissionClosed(ctx)
	if err != nil || !closed {
		writeSafeError(w, http.StatusInternalServerError, "failed to read turn admission close marker")
		return
	}
	harness.WriteJSON(w, http.StatusOK, CloseAdmissionResponse{
		Version:  harness.ProtocolVersion,
		Closed:   true,
		ClosedAt: closedAt.UTC(),
	})
}

func (s *Server) handleUnsettledTurns(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeSafeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.admissionLedger == nil {
		writeSafeError(w, http.StatusServiceUnavailable, "wrapper admission ledger is not configured")
		return
	}
	ctx, cancel := ledgerOpContext()
	defer cancel()
	records, err := s.admissionLedger.ListUnsettledTurns(ctx)
	if err != nil {
		writeSafeError(w, http.StatusInternalServerError, "failed to list unsettled turns")
		return
	}
	generation, err := s.admissionLedger.Generation(ctx)
	if err != nil {
		writeSafeError(w, http.StatusInternalServerError, "failed to read ledger generation")
		return
	}
	turns := make([]UnsettledTurn, 0, len(records))
	for _, record := range records {
		turns = append(turns, UnsettledTurn{
			TurnID:        record.TurnID,
			TaskUID:       record.TaskUID,
			Attempt:       record.Attempt,
			RequestDigest: record.RequestDigest,
			State:         string(record.State),
			CreatedAt:     record.CreatedAt.UTC(),
			UpdatedAt:     record.UpdatedAt.UTC(),
		})
	}
	harness.WriteJSON(w, http.StatusOK, UnsettledTurnsResponse{
		Version:    harness.ProtocolVersion,
		Generation: generation,
		Turns:      turns,
	})
}
