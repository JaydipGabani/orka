// Package v2 defines the portable orka.harness.v2 wire contract.
//
// The package intentionally contains protocol types, validation, canonical
// request digesting, replay/fence classification, lifecycle rules, and bounded
// NDJSON framing only. It does not implement a runtime supervisor, persistence,
// authentication transport, or provider process management.
//
// DeleteRuntimeSessionRequest.AbandonUnvalidatedPrompt explicitly retires a
// completed prompt after its controller durably abandons delivery. Its exact
// prompt identity is required; active validation and prepared publication remain
// deletion barriers. Omitting the option preserves ordinary deletion semantics.
// Older supervisors reject the additional JSON field, so an upgrade must not
// manufacture cleanup receipts for an old boot which cannot prove retirement.
// The controller's historical-epoch recovery uses this option only for settled
// standalone Tasks on Deployment-backed pools. Session-bound recovery retains
// its existing publication and deletion policy.
package v2
