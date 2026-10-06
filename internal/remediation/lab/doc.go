// Package lab is a bounded Linux bridge to a human-approved external lab driver.
// It is not a remediation orchestrator, model tool, cloud client, build service,
// sandbox or remote attestation verifier.
//
// # Approval and isolation
//
// The operator reviews Profile, the exact driver/configuration bytes and the
// check ID/class manifest, then approves DigestProfile(profile). New requires
// that digest and an existing, current-user-owned 0700 runs directory. Supplying
// approval is a trusted caller action, not proof that a human actually reviewed
// it; never allow model/candidate input to choose a profile, grant approval, or
// access the private run root. Public HTTPS repository syntax is checked offline;
// the approving caller must separately establish public repository visibility.
//
// Driver is trusted executable code with the caller's privileges. Configuration
// is opaque, private data, and may reference credentials used only by that driver.
// Neither configuration bytes, inherited cloud/Kubernetes credentials, reports,
// raw model output nor raw diagnostics are sent to a model by this package.
// Candidate input is only a digest-checked inert patch and an optional expected
// image digest. The driver must isolate candidate execution from its credentials,
// observer, recipe base and host. This bridge never executes candidate code, and
// is not an isolation boundary against malicious trusted drivers or same-UID
// processes. Approving a driver includes approving its interpreter/dependencies.
//
// The caller workflow, never agent output, selects the trust profile and whether
// to supply Candidate.Image. When Image is omitted, the approved verify driver
// builds the exact Request.Candidate.Patch snapshot using the frozen profile and
// configuration, then tests it and reports the actual Patched.Image and UID.
// There is no separate Build API or caller prebuild requirement. The bridge
// checks identities and observations; it does not execute a build itself.
//
// The parent stores the exact Profile and bridge runs root in private state,
// separately from any source packet. Do not include Profile, Request, driver
// configuration or credential artifacts in a source packet or model input.
// The bridge has no source-packet, orchestrator or CLI API.
//
// Input paths are absolute and canonical. Every path component is opened with
// O_NOFOLLOW. Regular files must be singly linked, without setuid/setgid/sticky
// bits or group/world write access. Driver ownership is root or the current user,
// with execute permission; configuration and patch files must be current-user
// owned, owner-readable, nonexecutable and inaccessible to group/other. Ancestors
// must be root/current-user owned and non-writable by group/other, except
// root-owned sticky ancestors such as /tmp. The runs root itself is strictly
// private, never a symlink. Approved inputs are checked again for every run,
// snapshotted byte-identically, and rechecked before accepting driver output.
//
// # Wire contract
//
// Profile/request/result/receipt are bounded single JSON objects. Nulls,
// duplicate/case-colliding keys, unknown fields, extra JSON values, invalid UTF-8
// and excessive depth/value counts fail closed. Digests are lowercase
// "sha256:<64 hex>"; commits are full lowercase 40- or 64-hex Git object IDs.
// Images are digests, not tags. Profile requires a nonempty Scope and explicit
// Gaps array. Any gap blocks a successful observation decision.
//
// DigestProfile uses encoding/json's v1 Profile field order, including scope/gap
// array order. DigestChecks hashes the JSON encoding of []Check sorted by ID;
// IDs are unique and at least one reproduction and one normal check are required.
// Driver/configuration hashes separately freeze the observer/check implementation.
//
// The bridge directly invokes the pinned driver snapshot, via its open file
// descriptor, with exactly two arguments:
//
//	driver baseline /absolute/private/run/request.json
//	driver verify /absolute/private/run/request.json
//
// There is no shell command construction. A script's own approved shebang is
// honored. Only fixed PATH, private HOME/TMPDIR and C locale variables are passed;
// stdin is empty. Configuration and candidate patch paths in Request identify
// private read-only snapshots. RequestDigest is sha256 of the exact request.json
// bytes, with no appended newline. The driver must return exactly one Result on
// stdout, and send diagnostics only to stderr. Stderr remains a private bounded
// stderr.log artifact and is never interpolated into errors or receipts.
//
// Result must bind RequestDigest and the exact expected ChecksDigest, carry
// immutable image digests and a nonempty observed runtime UID for each image,
// and report a cleanup state plus a digest of the driver's own cleanup receipt.
// This package does not perform or assert cluster cleanup on the driver's behalf.
// Cleanup must be complete before observations can pass.
//
// Baseline requires original AND control reproduction checks to fail, with every
// normal check passing. If Profile.ControlImage is omitted, the trusted driver
// must still report a pinned control image; the baseline freezes that identity.
// Verify requires the caller to supply the old successful baseline Receipt; the
// bridge re-reads its private request/intent/result/receipt before execution.
// Original/control images, check IDs/classes and outcomes must stay equal to
// that baseline, and ALL patched checks must pass. Re-created runtimes may have
// new UIDs, but empty UIDs, missing checks, unavailable observations or unresolved
// gaps block verification. The returned Patched.Image is always required to be
// immutable and distinct from both baseline images, even when no expected image
// was supplied. A supplied Candidate.Image must be an immutable digest, distinct
// from original/control, and match Patched.Image exactly. No driver-supplied
// "verified" boolean is accepted.
//
// To delegate build-and-verify without expecting an image in advance, pass
// Candidate{Patch: patch}; its JSON omits "image" rather than emitting null.
// Result.RequestDigest still binds the exact request, including patch snapshot
// path/digest, profile identity and frozen configuration path/digest. Acceptance
// of the returned actual image remains trust in the human-approved driver,
// not a remote attestation or independent proof of the build derivation.
//
// Receipts distinguish baseline-ready, verified, blocked and unknown. Verified
// means only that the human-approved driver's contract passed. TrustStatement is
// always present: these are observations, not remote attestations, and Kind
// cannot substitute for managed AKS policy. Scope limitations remain authoritative.
//
// # Driver check-ID schema and example
//
// Profile.ChecksDigest commits to the exact set of {id, class} pairs. Both
// classes must be present, there may be 2..MaxChecks entries, and IDs must be
// unique and match [a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}. Class is exactly
// "reproduction" or "normal". Result check order need not match the manifest;
// changing an ID, changing its class, omitting a check, or adding an extra check
// is a contract error. The same ID/class manifest is used for both operations.
//
// For example, DigestChecks([]Check{{ID: "repro-boundary", Class: Reproduction},
// {ID: "normal-flow", Class: Normal}}) hashes the UTF-8 bytes of this canonical
// JSON, with no trailing newline:
//
//	[{"id":"normal-flow","class":"normal"},{"id":"repro-boundary","class":"reproduction"}]
//
// Its digest is
// sha256:09b45bfe61b040718084ebe77b2a11ac134723a45850766b4b86bb31cbc06e24.
// The driver must emit one result object, not a bridge Receipt and not a report.
// This synthetic verify result represents a measured candidate reproduction
// failure, with the normal check passing:
//
//	{
//	  "version": 1,
//	  "operation": "verify",
//	  "requestDigest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
//	  "checksDigest": "sha256:09b45bfe61b040718084ebe77b2a11ac134723a45850766b4b86bb31cbc06e24",
//	  "original": {
//	    "image": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
//	    "uid": "observed-original-runtime"
//	  },
//	  "control": {
//	    "image": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
//	    "uid": "observed-control-runtime"
//	  },
//	  "patched": {
//	    "image": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
//	    "uid": "observed-patched-runtime"
//	  },
//	  "checks": [
//	    {"id": "repro-boundary", "class": "reproduction", "original": "fail", "control": "fail", "patched": "fail"},
//	    {"id": "normal-flow", "class": "normal", "original": "pass", "control": "pass", "patched": "pass"}
//	  ],
//	  "cleanup": {
//	    "state": "complete",
//	    "receiptDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
//	  }
//	}
//
// Replace every synthetic image, UID and receipt digest with actual observations.
// requestDigest must be computed from the received request.json bytes; the d's
// above are only a placeholder. Original/control images must match the profile
// and old baseline. The patched image is the driver's actual built/tested image;
// it must also equal Request.Candidate.Image when that expected digest is present.
// cleanup.receiptDigest identifies the trusted driver's own cleanup evidence;
// it is not the digest of the bridge's final receipt.json.
//
// For baseline, set operation to "baseline", use that baseline request's digest,
// omit the top-level patched object AND every per-check patched field, and
// report original/control reproduction checks as fail and normal checks as pass.
// Omitted optional fields are omitted, never null. For verify, all patched
// observations must be pass to verify. "unavailable" is permitted on the wire
// to report that a measurement could not be made, but is never a test failure
// from which to infer candidate correctness.
//
// # Parent error and receipt handling
//
// A driver exits zero after emitting any complete result, including one with
// measured failed assertions. Nonzero exit, missing/malformed output, unavailable
// or missing observations/cleanup, changed check identities, image mismatches,
// and changed original/control baseline outcomes are execution/contract errors.
// In particular, failure of an early assertion cannot mask a later missing check.
// Contract errors return ErrInvalidResult with an Unknown receipt and nil Result;
// process failures return ErrDriver (or a cancellation/limit error) similarly.
//
// A complete, correctly bound failed assertion instead returns ErrBlocked,
// Receipt.State == Blocked, a non-nil Receipt.Result and ResultDigest. result.json
// and receipt.json are persisted before return. ReadReceipt returns the same
// receipt AND ErrBlocked, so the parent must retain the receipt even when err is
// non-nil. Nonempty profile Gaps also produce ErrBlocked, not verified evidence.
// Only ErrBlocked with State == Blocked and a non-nil Result is a recorded blocked
// outcome. A receipt-persistence failure returns an Unknown receipt and ErrUnknown
// plus ErrIO, not ErrBlocked, even if the candidate's assertions also failed.
//
// The example above therefore remains available to the parent as an observed
// reproduction failure; it never becomes Verified. The parent owns whether to
// produce another candidate. It must not retry the same execution name, and
// unknown outcomes require operator reconciliation rather than a new-name retry.
//
// # Persistence and cancellation
//
// Keep one privateRunsDir for a baseline and its verification attempts. Pass a
// fresh child name (not an absolute path) to each Baseline/Verify call; the bridge
// creates privateRunsDir/name itself. The parent must not pre-create that child
// directory. Reopening New with the exact saved Profile, runs root and approval
// digest permits ReadReceipt and verification without re-executing the baseline.
//
// A run name atomically reserves a new private directory. intent.json, private
// snapshots and request.json are created exclusively and fsynced before process
// start. A name is consumed even after start failure, cancellation, missing
// output or a crash. Baseline/Verify never adopt, overwrite or automatically
// repeat an existing name. ReadReceipt performs no execution; incomplete or
// unknown runs require explicit operator reconciliation, including remote cleanup.
// Successful/blocked receipts are written only after bound result persistence.
// The caller must retain the private run root as long as replay protection matters.
//
// Execution has a MaxRuntime ceiling and honors earlier context cancellation.
// Stdout/stderr overflow cancels the process. Only the newly created child
// process group is killed; its leader is observed with waitid(WNOWAIT) and reaped
// after group cleanup so its PID cannot be recycled before signaling. This also
// stops local descendants left behind by a normally exiting driver. The trusted
// driver must not detach descendants into other groups and owns all remote
// resource cleanup. This is not a resource sandbox or filesystem quota.
//
// File and JSON bounds are exported above. Runs contain only a bounded number of
// bridge-owned artifacts; repeated, explicitly named operations consume storage
// until an operator archives them. No network access or cloud-specific behavior
// is implemented here. Other operating systems fail closed.
package lab
