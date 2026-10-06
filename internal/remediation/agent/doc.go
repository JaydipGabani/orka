// Package agent submits read-only proposal Tasks to Orka. It does not apply
// proposals, acquire source, or grant publication credentials.
//
// Callers must persist the deterministic TaskName before calling Generate and
// reuse the same name and proposal inputs when resuming. Persist any returned
// TaskUID and supply it as Request.ExpectedTaskUID on subsequent calls. A nonempty
// ExpectedTaskUID permits only the matching existing Task: missing or replaced
// Tasks fail without any POST. Errors retain that expected UID even when the Task
// cannot be read. Without a saved UID, the adapter cannot distinguish a
// never-created name from a previously deleted Task. Completed stages must be
// recovered from the caller's journal, not submitted again.
// The result endpoint carries no UID; the adapter checks the Task identity
// before and after reading output, but the API offers no atomic result fence.
// Output is the endpoint's result string unchanged, including any JSON encoded
// within that string. Parsing and validating the proposal belongs to the caller.
// Missing text and the ACP no-text placeholder are errors, not proposals.
//
// Client.TaskType is "agent" by default; its only other value is "ai". Selection
// is explicit and must remain stable when resuming; the adapter never falls back
// between Task types, models, or endpoints. Native AI uses the same AgentRef and
// top-level prompt but no AgentRuntime or workspace. Repository and Commit must
// both be empty; the parent supplies any pinned source packet within Prompt.
// Native AI reads /api/v1/auth/whoami and matches the server-stamped RequestedBy
// on every Task observation; it never sends RequestedBy in a create request.
// TokenReview authentication does not stamp RequestedBy, so it cannot establish
// the original creator through that field; the parent's saved TaskUID is needed.
// The parent must provision a native Provider-backed Agent without tools,
// coordination, skills, or model fallbacks. Native tools are additive, so this
// Task shape cannot override them with a deny-all policy. The standard AI worker
// also auto-enables memory tools when controller context is present; the parent
// must set ORKA_MEMORY_TOOLS_AUTO_ENABLE=false and
// ORKA_MEMORY_CONTEXT_ENABLED=false in the native worker to disable automatic
// memory tools and ambient memory loading. These opt-outs do not disable tools
// explicitly configured on the Agent. Native model/output limits and worker
// iteration limits remain governed by the Agent and worker, not Request.MaxTurns.
//
// Cancellation stops local waiting, not the remote Task. Orka's Task deletion
// endpoint has no caller-supplied UID precondition, so this adapter never sends
// DELETE. The Task has a 15-minute execution timeout; each Generate call waits at
// most 20 minutes. Individual HTTP requests take at most 30 seconds, reads have
// at most three attempts, and writes are never retried. Responses are limited to
// 2 MiB each, and prompts to 256 KiB. MaxTurns defaults to 50 for agent Tasks;
// explicit values must be in 1..1000. PollInterval defaults to one second.
//
// Repository URLs must be credential-free HTTPS GitHub repository roots pinned
// to a full commit. Public visibility must be established by the caller; this
// adapter does not contact GitHub. Source-free agent Tasks explicitly deny all
// tools. Source-backed agent Tasks request only Read, Glob, and Grep. Runtime
// policy may narrow that set: OpenCode normalizes these aliases case-insensitively
// and disables Grep for read intent, leaving only read and glob. The adapter never
// widens permissions to bypass provider restrictions.
package agent
