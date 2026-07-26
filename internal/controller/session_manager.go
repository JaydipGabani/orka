/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"github.com/orka-agents/orka/internal/session"
	"github.com/orka-agents/orka/internal/store"
)

// SessionManager is retained as a controller compatibility alias. Shared
// session orchestration is owned by the dependency-neutral session package.
type SessionManager = session.Manager

// NewSessionManager creates a session manager backed by the given store.
func NewSessionManager(ss store.SessionStore) *SessionManager {
	return session.NewManager(ss)
}
