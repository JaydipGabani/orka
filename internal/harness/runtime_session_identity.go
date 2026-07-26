/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package harness

import "github.com/orka-agents/orka/internal/runtimesession"

// RuntimeSessionIdentityInput is retained as a harness compatibility alias.
type RuntimeSessionIdentityInput = runtimesession.RuntimeSessionIdentityInput

// RuntimeSessionIdentity is retained as a harness compatibility alias.
type RuntimeSessionIdentity = runtimesession.RuntimeSessionIdentity

// ResolveRuntimeSessionIdentity derives the canonical runtime session identity
// and owner metadata.
func ResolveRuntimeSessionIdentity(input RuntimeSessionIdentityInput) RuntimeSessionIdentity {
	return runtimesession.ResolveRuntimeSessionIdentity(input)
}
