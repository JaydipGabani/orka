# Local Verification Persistence POC

The SQLite implementation is a dedicated evidence store, not a Task artifact or
MonitorEvent store. No Task foreign keys, cleanup hooks, workspace paths, or
delete APIs own its lifetime. Use a persistent SQLite file outside the temporary
execution workspace and keep the database and its WAL together when backing up.

## Caller API

The `patchverification` package supplies these additional binding helpers:

```go
func NewRunBinding(manifest Manifest, attemptID, originalTaskID, patchedTaskID string) (Binding, error)
func ValidateRunBinding(manifest Manifest, binding Binding) error
```

The following methods are on `sqlite.Store`. The types below are from
`patchverification`; `ctx` is `context.Context`.

```go
InitializePatchVerificationStore(ctx) error
CreatePatchVerificationRun(ctx, manifest Manifest, binding Binding, provenance map[string][]byte) error
GetPatchVerificationRun(ctx, runID string) (*Record, error)
RecordPatchVerificationEvidence(ctx, binding Binding, evidence ExecutionEvidence) error
FinalizePatchVerificationRun(ctx, binding Binding) (*Record, error)
CancelPatchVerificationRun(ctx, binding Binding) (*Record, error)
RecoverInterruptedPatchVerificationRun(ctx, binding Binding) (*Record, error)
GetPatchVerificationBlob(ctx, runID, digest string) ([]byte, error)
```

1. Open the existing SQLite store and explicitly initialize the verification
   tables. Initialization is idempotent and does not change global migrations.
2. Freeze the manifest and mint the binding with `NewRunBinding`. Run IDs include
   the manifest digest, the single attempt ID, and both immutable Task identities.
  Manifest validation and digest creation reject invalid UTF-8 in all string
  fields and map keys. Frozen file content remains binary-safe.
3. Create the run with the exact original archive, patched archive, diff, and
   optional patch bytes keyed by SHA-256 digest. Frozen file bytes come from the
   manifest; extra undeclared blobs are rejected.
4. Submit runner `ExecutionEvidence` under the independently trusted binding.
   Executed observations require both stdout and stderr digests, including the
   digest of empty stderr, plus every frozen service output. Referenced bytes
   must be supplied or already be present and verified in this run.
5. Finalize once. The store invokes `Evaluate`, checks all
   referenced content, and seals manifest/binding/provenance/evidence hashes and
   the computed assessment. Missing checks seal an Unable result, not a success.
6. Read `Record.Assessment` for the effective result. `Record.Seal.Assessment` is
  historical: conflicts or integrity failures can invalidate an earlier successful
   seal without rewriting it. `Record.Binding` identifies the one attempt;
   `Record.Evidence` contains its observations, hashes, and rejected entries.

## Failure and Concurrency Semantics

- Identical creation, observation delivery, finalization, and cancellation are
  idempotent. A duplicate previously rejected observation returns `ErrEvidence`.
- A same-binding manifest substitution or different observation for an occupied
  side/check records a conflict and returns `ErrConflict`. Original bytes remain
  unchanged, including after sealing. Wrong run/Task/attempt/manifest bindings
  return `ErrBinding` or `ErrRunNotFound` without poisoning another run.
- Invalid bound execution attempts are retained as rejected observations or
  bounded incident fingerprints. Failed, timed-out, skipped, or truncated checks
  cannot be replaced with a successful retry. A new attempt needs a distinct run;
  there is no API that selects the best of multiple attempts.
- Cancellation and finalization are serialized; the first terminal operation
  wins. A late cancellation leaves a healthy finalized result unchanged.
  Later evidence cannot resume a closed run.
- Recovery is explicit and single-run. The local authority must establish that
  this attempt's runner has stopped before recovering it. Merely opening the
  database never invalidates another process's live attempt. Interrupted runs
  become terminal Unable; finalized runs are left unchanged.
- A dedicated SQLite write-lock row is updated before transaction reads, so
  operations serialize across independent connections and processes rather than
  relying on an in-process mutex. Existing SQLite busy timeout behavior applies.
- Missing bytes, hash mismatches, inconsistent metadata, and seal mismatches
  return `ErrIntegrity` and never a successful effective assessment. Detected
  corruption is recorded durably; restoring bytes does not restore success.
  Stored bindings must match their canonical JSON bytes and pass integrity
  validation before caller comparison. Corrupt stored bindings record integrity
  incidents, while a foreign caller cannot invalidate a healthy record.
- Distinct rejected delivery fingerprints are retained up to `MaxIncidents`
  (256), followed by one durable overflow marker. Oversized rejected inputs use
  a bounded rejection fingerprint rather than hashing or storing unbounded data.

## Limits and Trust Boundary

Limits are 1 MiB manifest JSON, 32 KiB observation JSON, 64 KiB per captured
output, 32 MiB per provenance blob, 128 MiB of unique blobs per run, 128 frozen
files, eight services, and the core limit of 100 checks. Reads hash-check bounded
content; invalid deliveries never persist rejected raw output. No retention or
garbage collection is included, so the local authority must manage database
capacity and the number of runs.

This is a local-authority API, not production authentication. The CLI/controller
must derive the binding from its trusted run record, not trust a binding supplied
by a project process. No network endpoint, authorization token, or credential
storage is introduced. Only credential-free source archives and captures are
valid inputs. Common plaintext credential forms, credential-bearing environment
names, and URL user information are rejected, but this is not a general secret
scanner and does not unpack compressed archives. Suspected secret-bearing output
must be treated as failed capture without submitting its raw bytes, not redacted
into a successful observation. Hashes detect corruption; they are not protection
against an administrator rewriting the database and all associated hashes.

The store does not start runners, reap processes, provision Tasks, retry checks,
or infer that another process has died. Keep those responsibilities in the local
controller. Broad repository gates and end-to-end runner wiring remain integration
responsibilities.
