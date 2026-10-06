// Package validation bridges approved, local remediation inputs to Orka's
// standalone validation API. It does not enable that API, provision resources,
// change roles, acquire source, or receive incident reports or model credentials.
//
// The caller must provision an input-upload Pod with only the controller's
// namespace input PVC mounted at InputRoot. InputRoot is the absolute namespace
// directory (for example /validation/orka-validation), not its parent. The Pod
// must provide mkdir and tar supporting the long options used by Stager.
// Its filesystem identity must let the controller read the private 0700
// directories and 0600/0700 files (normally the same UID on the shared PVC).
// Authentication is explicit: API credentials stay in HTTP headers; kubectl uses
// the supplied kubeconfig and a minimal environment, not ambient cloud/model
// credentials or the user's home directory.
//
// Staging accepts a self-contained, detached, clean public Git checkout, external
// frozen checks, and optionally a patch. SHA-1 and SHA-256 repositories retain
// their private Git metadata, including shallow boundaries, packed objects and
// indexes, attributes, source markers, and empty metadata directories. Markers
// stay bound to the original physical source directory; this adapter never
// passes an uploaded copy back to source materialization. It preserves executable
// check modes, rejects links and special files, and never scans a surrounding
// report/journal directory. Callers remain responsible for approving the
// check/patch content and public-source provenance. Credential screening is
// defense in depth, not a general incident-data classifier.
// The 128 MiB tar and 32768 pathname caps include Git metadata; existing core
// source/check preparation limits also apply.
//
// Each call has a new private PVC directory. The caller owns its retention and
// cleanup, including abandoned uploads: an uncertain POST must not race deletion
// of inputs the controller might still be preparing. EarlierValidation is not
// supported because the standalone linked-request contract freezes an earlier
// repository pathname, whereas this adapter isolates every call.
//
// Before Start, the parent must durably record submission intent. Start never
// retries POST and calls its receipt callback immediately after a validated
// acknowledgement, before polling. The callback must save the complete Receipt
// durably before returning nil; failure stops polling and requests cancellation
// of that exact submission. Validate wraps Start without saving a receipt.
//
// Resume is read-only: it compares the original request JSON digest and namespace
// with a trusted durable Receipt, then checks the existing requestID, frozen
// manifest, immutable submission identity, and any previously observed task/run
// IDs. It does not stage, submit, or cancel; local inputs need not still exist.
// Cancellation of Resume returns an error while remote execution may continue.
//
// The current API has no caller operation key. Intent without a durable receipt,
// including a crash before POST, a lost acknowledgement, or failed receipt
// persistence, requires ErrSubmissionUnknown and manual reconciliation, never
// automatic Start replay. Neither an intent phase nor an artifact hash proves
// server receipt. Automatic replay across that gap still needs server-side
// idempotency support. Known IDs are returned in SubmissionError and receipt-only
// error Records, which never assert a favorable assessment or remote cancellation.
//
// Only fully checked terminal records are returned without error. This verifies
// transport, input, binding, seal, and blob integrity; it does not promote raw
// model-generated checks to authoritative observations. That policy belongs to
// the coordinator. Protected Check.HTTP declarations and Observation.HTTPCompleted
// are preserved through the shared types; the core evaluator owns their meaning.
// The adapter uses the current Kubernetes worker policy and has no Docker path.
// Tests use synthetic inputs and fake HTTP/subprocess endpoints; this package
// does not require or assume an enabled validation deployment.
package validation
