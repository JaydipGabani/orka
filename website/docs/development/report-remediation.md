---
slug: /report-remediation
description: "Experimental private report ingestion, reproduction, and evidence-backed patch workflows."
---

# Report-driven remediation (experimental)

`orka remediate` connects private JSON intake, exact source selection, Orka
proposal Tasks, and independent validation. A successful model Task is **not**
a verified patch. Only the configured validation contract can make that decision.

For a command-by-command walkthrough, see the
[report-remediation demo README](../../../examples/report-remediation/README.md).
Real incident fixtures and host-specific replay instructions remain outside
the checkout.

For the proposed single-submit Copilot architecture, current integration gaps,
delivery milestones, and direct-IcM versus GitHub issue/label decision, see the
[autonomous remediation design](../../../docs/design/autonomous-report-remediation.md).
That design is not a claim that the current POC completes every stage
autonomously.

The current workflows are:

| Goal | Entry points | Model required? |
| --- | --- | --- |
| Normalize a supplied report | `export`, `ingest` | No |
| Infer public-source targets for a process-level case | `plan` | Yes |
| Freeze an explicitly reviewed cluster/lab profile | `lab-plan` | No |
| Reproduce a report without generating a patch | `lab-validate` | No |
| Propose and verify a patch after reproduction | `run`, `lab-run` | Yes |
| Verify a supplied or reviewed patch in a lab | `lab-verify` | No |

Proactive vulnerability discovery, automatic cloud-environment provisioning,
and PR publication are not implemented by these commands. A lab profile is
repository-specific integration, not evidence that every report or environment
is supported.

## Private intake and durable state

### Server-managed single submission

The experimental server path is separate from the older local journal/driver
commands below. After one-time operator onboarding, the CLI can acquire the
incident and submit it without per-incident source lists or shell drivers:

```bash
umask 077
orka --server "$ORKA_URL" --namespace "$ORKA_NAMESPACE" remediate start \
  --incident "$ICM_ID_OR_URL" \
  --policy "$APPROVED_POLICY" \
  --request-id "$REQUEST_ID" \
  --token-file "$CALLER_TOKEN_FILE" \
  --wait

orka --server "$ORKA_URL" --namespace "$ORKA_NAMESPACE" remediate status \
  "$RUN_ID" --token-file "$CALLER_TOKEN_FILE"

orka --server "$ORKA_URL" --namespace "$ORKA_NAMESPACE" remediate download \
  "$RUN_ID" --output-dir "$NEW_PRIVATE_OUTPUT_DIRECTORY" \
  --token-file "$CALLER_TOKEN_FILE"
```

Use `--input /absolute/private/report.json` instead of `--incident` for supplied
JSON. `--mode generate` is the default; `validate` reproduces without generating
a patch, and `verify --patch /absolute/private/candidate.patch` verifies supplied
bytes. The CLI prints the request ID before submission. After a lost connection,
query an acknowledged run ID or retry only the identical input and request ID;
do not invent a new ID for a possibly accepted operation.

The operator must configure a private persistent controller installation,
encryption key, approved policy, model identity, exact source/build catalog,
and a separate qualified execution cluster. Current chart installation alone
does not enable remediation: the controller requires `--remediation-enabled`,
`--remediation-private-namespace`, and a private `--remediation-policy-file`.
This remains a POC configuration path, not turnkey cloud provisioning.

For `copilot-acp-v1`, Copilot CLI runs inside an ACP Pod and uses the configured
model gateway. GitHub Copilot hosted inference does **not** require Azure
OpenAI. The upstream GitHub credential belongs only in the gateway's Secret;
the CLI child receives a scoped local proxy capability, not that credential.
The model/account route and permission to disclose technical report content
must be approved explicitly. A local Pod does not make inference local.

Copilot result acceptance retains the exact Task, prompt, runtime and session
identity while tolerating terminal status redelivery and monotonic controller
recovery. Cancellation remains pending until execution settles; a recorded
`Cancelled` phase alone is not proof of runtime shutdown. Status write conflicts
revalidate the same Task on the next cleanup pass, without replacing it or
repeatedly rewriting an acknowledged cancellation. Dependency failures remain
subject to the bounded cleanup policy.

Runtime retirement after abandoned delivery is limited to durably settled
standalone Tasks on Deployment-backed pools, at the current or a previous
controller epoch. Historical-epoch retirement additionally requires closed
admission on that old boot. It cannot admit or replay a prompt, and it
does not change ordinary Session-bound recovery or publication policy. Standalone
cleanup without exact runtime proof remains blocked for that Task; it must not prevent
unrelated ACP admission or idle-pool maintenance. Older supervisor images that
cannot acknowledge retirement remain quarantined rather than receiving a
fabricated cleanup receipt.

Before repairing a rejected controller build, the coordinator settles that
build's exact durable operation. A build failure is not cleanup proof: pending settlement
keeps the lab lease and delays further proposals. A later successful candidate
cannot bypass an earlier build's cleanup or turn uncertain effects into a
verified result. The verified handoff (`candidate.patch` and `verification-*`)
is exposed only after the run reaches `Succeeded`. Intermediate proposals,
candidate artifacts and observations remain private diagnostic evidence, not a
verified handoff. Legacy HTTP adapters using synchronous BuildKit keep their
existing build lifecycle.

Public repository discovery remains anonymous. Inventory reads the root tree
first and batches non-vendor subtrees into bounded recursive GitHub requests.
Every returned tree is reconstructed and hash-verified before any metadata is
used. Oversized or truncated recursive results are discarded, and that subtree
uses bounded nonrecursive traversal without disabling batching for its siblings.
After four discarded batches the remaining operation becomes nonrecursive.
Nested dependency directories remain deferred. This reduces requests without increasing the output budget or
accepting a truncated prefix. GitHub's anonymous rate limit still applies, and
no credential fallback or rate-limit bypass is attempted.
An explicit GitHub rate-limit response checkpoints the retry time and preserves
the selected source operation. The run waits without reissuing requests or
regenerating file-selection prompts until that time; its overall deadline still
applies. Selections whose declared raw size already exceeds the plan's encoded
budget are rejected before blob fetches, and the exact encoded size is checked
again after fetching.
When test changes are allowed, existing adjacent Go test files can be added
automatically from the same verified tree. They share the packet's file/byte
limits and content screening. Optional additions that exceed those limits or
fail content screening are omitted with recorded limitations; the required
model-selected files are never silently dropped, and unselected tests remain
outside the patch allowlist.
Size-based selection retains small useful test files when another adjacent
test is oversized, and encoded-size trimming removes optional files
individually. Failing test identifiers can select bounded function excerpts
from the already verified packet for repair context; this never fetches new
files or permits editing omitted files.
Trusted build workers retain bounded structured Go-test failure metadata while
streaming output, so a long trailing stack dump does not erase the initial
failure. A nonzero test exit is separate from build cancellation or
infrastructure failure; it never produces a successful image. Feedback contains
only approved relative locations and safe test identifiers, not assertion text
or raw logs. An unresolved location remains explicitly unknown. This metadata
is repair advice, not permission to fetch additional source or claim a fix.
Recipe onboarding must also preflight diagnostic path extraction. The POC does
not support every permissive GNU `patch` input variant—for example a final
hunk whose trailing context was removed—and reports an unsupported adapter
input rather than guessing additional paths.

The `dalec-keda-events` adapter uses the compiled namespace-event scenario,
exact original/control/candidate image identities, durable build Jobs, and
measured network isolation. Redis and unimplemented controller scenarios return
`NeedsAdapter`; HTTP checks are not substitutes for them. Operator-acquired
baseline patches marked `BuildOnly` retain exact bytes solely within the private
build boundary. Their path/digest bindings are derived automatically from the
approved catalog, not from a model or a new per-file disclosure exemption.
Changed or additional candidate bytes remain subject to strict disclosure
checks. Configure `podPidsLimit` on **every eligible build node**; per-UID
`RLIMIT_NPROC` does not isolate Pods that share the same nonroot UID.
The API-server allow rule must match the address and port enforced by the CNI,
which can be the EndpointSlice backend after Service DNAT rather than the
Kubernetes Service IP. For a Cilium lab using a node-address CIDR, enable
`policyCIDRMatchMode: [nodes]` so the exact node `/32` rule applies. Do not replace
the rule with broad node or Internet access. Verify connectivity, then obtain
a fresh positive/negative/positive isolation proof after any CNI or policy
change; a prior proof does not qualify the new configuration.

The opt-in `keda-event-publishing-v2` controller capability adds controlled
HTTPS/Event Grid request and synthetic-header observations. It is currently
restricted to the approved KEDA v2.17.3 source commit. Operators must select
that exact capability and enable event publishing; a model cannot downgrade it
to the older HTTP-only plan. The controlled receiver does not establish
Azure-side authorization, subscription ownership, or managed-cluster behavior.
The credential attack is independent of cross-namespace event delivery: a
namespaced source referencing a cluster-wide shared key must not send that key
to a namespace writer's endpoint. Merely naming a ClusterTriggerAuthentication
is not delegation. The pinned runtime has no explicit delegation mechanism to
qualify an exception. Namespace-local authentication and cluster-scoped HTTP
delivery remain normal controls. Earlier publishing-v1 receipts are not
reinterpreted as proof of this stronger credential contract.
The pinned KEDA version can leave event-source `Active` conditions at `Unknown`
despite installed handlers. The verifier therefore checks the live runtime and
exact source/auth bindings, then relies on real positive receiver observations.
An `Active` condition—whether True, False or Unknown—is not reproduction,
readiness or protection evidence.

Publishing candidates also receive a separate source-free automated review
before building or executing them. The review is bound to the exact patch,
source, frozen checks and reviewer identity, runs within the approved model
boundary, and does not receive the incident instructions, generator rationale,
conversation, canaries or observer configuration. Each exact patch-and-context
pair receives one recorded decision per run. Ordinary behavioral or scope findings can feed
bounded repair. Integrity findings (test-specific behavior, fixture tampering,
or unrelated network/credential access) stop the run without feeding the
reviewer's details into another candidate attempt. Uncertainty or malformed
review output cannot become approval.

Only a valid `uncertain` verdict whose findings are **all** `insufficient-context`
can request automatic read-only source supplementation. A separate model Task
selects paths from a newly verified inventory of the same frozen public
repository, commit and tree. The runtime admits only regular, nondependency
code files; build, configuration and credential paths are not authorized.
The selection index prioritizes the supplied files' parent directories, then
broader eligible source. Its encoded size is at most 64 KiB, and it explicitly
records truncation rather than claiming to describe the complete repository.
Selected files are required evidence: unavailable, invalid or oversized files
are never silently dropped.

The entire run, including repaired candidates, permits at most **two context
rounds, four supplemental files and 64 KiB of JSON-encoded supplemental packets**.
Selection and augmented review Tasks share the existing global model-call and
time budgets; they do not reset candidate limits. The source adapter verifies
the target, regular-file membership and Git blob identities, the runtime checks
actual and encoded sizes, and shared disclosure policy gates every model input.
The original source plan, editable-path allowlist, generator context, frozen
checks and original/control execution remain unchanged. Supplemental packets
are independent-review evidence only, not permission to edit more files.

An augmented review has a different Task identity bound to the exact patch,
base packet and target, supplemental packet digests and frozen checks. The
original uncertain receipt remains intact, and the final review receipt links
its predecessor and supplemental artifacts. Accepted Task identities, inventory,
selection, packets and rate-limit retry times are checkpointed: recovery reuses
the same model Tasks, and anonymous source requests wait until a persisted reset
time. Approval, rejection, integrity findings and malformed verdicts do not
trigger context gathering or a repeat review of the same context. Missing new
context, exhausted bounds or a still-uncertain reviewer safely pause at
`NeedsInput`, not semantic repair or automatic approval. Final verification
links the exact approving receipt. Independence is in context, not a claim
that a different model or provider reviewed the patch.

When publishing is configured for a lab, all controller runs targeting that
same lab in the frozen policy share a durable cluster-identity lease. They wait
instead of racing the fixture's cluster-scoped resources. The lease remains
held through resource cleanup; elapsed time alone never permits another run to
take it over. Drain existing controller runs before introducing this
coordination into a legacy installation, and configure every installation
sharing a lab consistently. Unresolved cleanup retains exclusivity rather than
allowing another run to operate on a contaminated lab.

These are complementary checks, not a formal security boundary against an
adversarial candidate. Code that knows the test interfaces can deliberately
imitate expected traffic, and automated review can miss such code or other
defects. Results describe the observed behavior and review for the declared
checks; they do not prove a general vulnerability fix or justify automatic
publication without the repository's normal review process.

Exact-edit proposals default to one literal match. An explicit `occurrences`
integer from 1 through 16 can request the same replacement at several sites;
the compiler still refuses any actual-count mismatch and computes the diff
locally. There is no implicit replace-all or fuzzy matching. Repair feedback
identifies the edit index, path, expected count and actual count without
echoing source or replacement text.

`Succeeded` must be interpreted together with the mode and evidence. A
successful `validate` run is a reproduced report, not a generated patch.
Generated/verified patches are qualified only for the frozen checks and normal
controls. Admission, one model response, or one successful build is not an
end-to-end verification result.

Keep exports, journals, scratch data, diagnostics, and patches outside Git
checkouts in private directories. Do not commit real incidents or credentials.
Reserve `bin/` for compiled binaries and build tools, not one-off Go probe
sources: Git-ignored directories are still discovered by `go list ./...` and
can enter builds, tests and generation. Keep historical review snapshots with
private evidence rather than presenting them as current operator documentation.
Local cleanup may discard reproducible build caches and coverage output, but
must retain verified handoffs, recovery journals and inputs still used by a lab.

The read-only IcM exporter requires an installed
[IcM CLI](https://github.com/azure/icm-cli) and explicit existing authentication.
It captures only the named incident, checks pagination and before/after
consistency, and does not update the incident.

```bash
umask 077
export CASE=/absolute/private/case
install -d -m 700 "$CASE" "$CASE/scratch"

orka remediate export "$ICM_ID_OR_URL" --output-dir "$CASE/export"
orka remediate ingest \
  --input "$CASE/export/input.json" \
  --state-dir "$CASE/state"
orka remediate status --state-dir "$CASE/state"
```

`ingest` also accepts generic JSON reports. Normalization removes administrative
fields and screens recognized sensitive text, but is not an exhaustive secret
detector. Review the necessary technical data before enabling model access.
Incomplete discussions or missing technical evidence block model/execution work.

Journals contain immutable artifacts, revisions, named model Task identities,
and execution intents. Resume the same journal and exact inputs. An unknown
submission is not permission to create another run. Model Task replacement,
changed target identity, changed driver inputs, and changed supplied patches
fail closed.

## Process-level validation

`plan` proposes public GitHub repositories and version refs; the CLI resolves
them to exact commits and trees. `run` requires the resulting plan digest,
private staging, an explicitly configured validation API, and a digest-pinned
tool image.

Automatically generated checks require the protected HTTP-observation protocol:
the runner, not patch-controlled stdout, observes a fixed request/response.
Use matching controller/worker protocol versions. Full-cluster, controller,
external-service, or additional-identity requirements cannot be satisfied by
a process-only substitute.

See the [patch-verification examples](../../../examples/patch-verification/README.md)
for the existing supplied-check and supplied-patch contracts.

## Trusted lab profiles

Cluster cases use a **human-reviewed privileged driver**. This is not a sandbox
for driver code. The driver is responsible for isolating candidate code from
its Kubernetes/cloud credentials, frozen observer, recipe inputs, and host.

A profile freezes:

- Public repository and full commit.
- Original and optional unchanged-control **manifest digests**, such as
  `sha256:...`, not tagged or registry-qualified image references.
- Platform, exact driver bytes, and private configuration bytes.
- Exact reproduction/normal check IDs and classes, scope, and gaps.

Qualified image references, kubeconfig paths, downstream recipe inputs, and
other privileged configuration remain inside the driver's private configuration;
they are not model inputs. Preserve downstream patches, dependencies, build
flags, and toolchain inputs. Distinguish published images from rebuilt controls,
and inferred recipe mappings from authenticated provenance.

The driver returns observed image digests, runtime UIDs, individual check
outcomes, and its cleanup receipt. It must not return an agent-written
`verified: true` assertion. Missing evidence, unavailable checks, unresolved
gaps, or incomplete cleanup cannot pass.

The [driver wire contract](../../../internal/remediation/lab/doc.go) describes
the exact bounded JSON protocol, filesystem requirements, outcome semantics,
and trust limitations. A script's interpreter and dependencies are part of
the trusted deployment. Kind application observations do not establish managed
AKS admission, identity, networking, or add-on policy.

### Profile and driver wire format

Create a JSON profile with these fields. Replace the placeholders with measured
identities; placeholder digests are not valid configuration.

```json
{
  "version": 1,
  "repository": "https://github.com/owner/repository",
  "commit": "<full lowercase Git object ID>",
  "originalImage": "sha256:<64 lowercase hex digits>",
  "controlImage": "sha256:<64 lowercase hex digits>",
  "platform": "linux/amd64",
  "driver": {
    "path": "/absolute/private/driver",
    "digest": "sha256:<SHA-256 of exact executable bytes>"
  },
  "configuration": {
    "path": "/absolute/private/driver-configuration.json",
    "digest": "sha256:<SHA-256 of exact configuration bytes>"
  },
  "checksDigest": "sha256:<canonical check manifest digest>",
  "scope": ["Explicitly state the behavior and environment covered"],
  "gaps": []
}
```

Paths and every ancestor must be canonical and owned by root or the current
user, without group/other write access (root-owned sticky temporary ancestors
are allowed). The driver must be executable; its private configuration and
candidate patch must be owner-readable, nonexecutable, and inaccessible to
group/other. Inputs must be regular, singly linked files, not symlinks.
Use an existing current-user-owned mode-0700 scratch directory.

The check manifest is a JSON array of `{id,class}` objects sorted by ID, with
no whitespace or trailing newline. Hash its exact UTF-8 bytes with SHA-256 and
prefix the hex digest with `sha256:`. Both `reproduction` and `normal` classes
are required. For example:

```json
[{"id":"normal-flow","class":"normal"},{"id":"repro-boundary","class":"reproduction"}]
```

This manifest's digest is
`sha256:09b45bfe61b040718084ebe77b2a11ac134723a45850766b4b86bb31cbc06e24`.
IDs must be unique and match `[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}`.

The bridge invokes the pinned driver directly:

```text
driver baseline /absolute/private/run/request.json
driver verify /absolute/private/run/request.json
```

The request contains `version`, `name`, `operation`, `profileDigest`, `profile`,
and `configuration: {path,digest}`. Verification additionally includes
`candidate: {patch: {path,digest}, image?}` and the successful baseline result
as `baseline`. Configuration and patch paths point to private, byte-verified
snapshots. An absent expected candidate image means the driver must build the
snapshot and report the actual resulting image.

Return exactly one JSON result on stdout:

| Field | Required value |
| --- | --- |
| `version` | `1` |
| `operation` | The requested `baseline` or `verify` |
| `requestDigest` | SHA-256 of the exact request file bytes, prefixed `sha256:` |
| `checksDigest` | Exact digest from the approved profile |
| `original`, `control` | Each `{image: "<manifest digest>", uid: "<observed runtime UID>"}` |
| `patched` | Same shape; required only for verification, with a distinct image |
| `checks` | One `{id,class,original,control,patched?}` per approved check |
| `cleanup` | `{state: "complete", receiptDigest: "sha256:<driver cleanup receipt hash>"}` |

Check outcomes are `pass`, `fail`, or `unavailable`. A baseline needs `fail`
for original/control reproduction checks and `pass` for all normal checks.
Verification retains those baseline outcomes and requires every patched
outcome to be `pass`. `unavailable` cannot pass.

Exit zero for a complete measured result, including failed assertions. A
nonzero exit, malformed output, missing identities, or unresolved cleanup
does not authorize retry or a verified decision. Send diagnostics only to
stderr; they remain private. Omit absent optional fields rather than sending
`null`. Repeating a consumed run name never launches the driver again.

## Plan, validate, then generate or supply a patch

The paths below are examples; select actual source files from the reviewed
repository, including relevant helpers and tests. The source reader revalidates
public visibility, commit/tree linkage, tree entries, and blob hashes. It reads
at most 32 regular UTF-8 files totaling 256 KiB, without materializing an entire
large vendored repository.

```bash
orka remediate lab-plan \
  --state-dir "$CASE/state" --work-dir "$CASE/scratch" \
  --lab-profile "$CASE/reviewed-profile.json" \
  --source-file src/handler.go --source-file src/handler_test.go

# Review the saved plan and use its exact digest.
orka remediate lab-validate \
  --state-dir "$CASE/state" --work-dir "$CASE/scratch" \
  --approve-plan "$PLAN_DIGEST"
```

`lab-validate` must reproduce the problem on the original and unchanged control,
while normal checks pass. It saves evidence without proposing a patch.

To generate a candidate using an approved Orka Agent:

```bash
orka remediate lab-run \
  --state-dir "$CASE/state" --work-dir "$CASE/scratch" \
  --approve-plan "$PLAN_DIGEST" \
  --server "$ORKA_SERVER" --namespace "$ORKA_NAMESPACE" \
  --agent "$PROPOSAL_AGENT" --task-type ai \
  --token-file "$PRIVATE_CALLER_TOKEN_FILE" --model-data-approved
```

Task type selection is explicit (`ai` or `agent`), never an automatic model or
provider fallback. A native AI proposal Agent must have no tools, coordination,
skills, or model fallbacks. Provision its worker with
`ORKA_MEMORY_TOOLS_AUTO_ENABLE=false` and `ORKA_MEMORY_CONTEXT_ENABLED=false`;
an empty Agent tool list alone does not disable automatic memory integration.
The new auto-enable opt-out leaves normal worker behavior unchanged when unset.

The model receives normalized technical report data, a pinned source packet,
and safe baseline observations, not driver configuration or credentials.
Exact text edits are compiled into a diff locally. Malformed proposals receive
at most three bounded repair attempts. A failed build, unknown driver execution,
or failed verification remains blocked for review; these are not silently
retried or relabeled successful. Review-generated corrections require renewed
validation with the same frozen checks.

To verify a supplied patch, including a reviewed Orka-generated candidate:

```bash
orka remediate lab-verify \
  --state-dir "$CASE/state" --work-dir "$CASE/scratch" \
  --approve-plan "$PLAN_DIGEST" \
  --patch-file "$CASE/candidate.patch" \
  --change-description "Describe the intended source and behavior changes"
```

This path does not contact a model. The exact patch and declaration are frozen;
changing them cannot reuse a previous verified result. Do not switch a journal
that already has a different candidate into a new candidate run.

`status` reports durable progress and artifact references. The final conclusion
is only **verified for the recorded checks and scope**. Retain the private
patch, original/control/candidate identities, input and observer digests,
failure history, and cleanup evidence for review. No command publishes a PR or
changes the originating incident.

## Operator recovery and key rotation

Server-managed `start` runs are durable. Stopping a CLI does not cancel remote
work. Cancellation first settles the recorded effects, retaining their exact
UIDs, epochs, inputs, and active source reservation until observed cleanup
succeeds. `NeedsInput` and `NeedsAdapter` are terminal non-success outcomes, not
resumable executions; `NeedsApproval` is the only approval pause.

Cleanup has a five-minute wall-clock budget and at most eight **failed**
attempts. Normal asynchronous cleanup observations do not consume the failure
count and do not restart the wall clock. If a new worker claim resumes after an
outage has consumed the wall-clock budget, it may reserve **one additional
cleanup attempt, limited to 30 seconds**, provided fewer than eight failures were
recorded. The reservation is durable before cleanup runs and is usable only once
per cleanup window, not once per restart. An interrupted reservation is treated
as consumed; repeated restarts cannot replay it. The resumed call must either
prove completion or quarantine, even when it reports normal pending progress.
The original `StartedAt` and failure count are not reset by restart.
When either budget is exhausted without this one reserved recovery attempt, the
run stays `Cancelling` with reason `cleanup-quarantined`; it does not silently
release effects, active-run capacity, or the source reservation. Small typed
cleanup columns and operator audit receipts remain writable at the 512 MiB
namespace payload quota. This does not exempt arbitrary state or artifacts from
their existing limits, and it is not a guarantee against a physically full disk.

An operator with the precise
[remediation permissions](../reference/api-authorization.md) can inspect all
retained work and explicitly re-drive cleanup:

```bash
orka remediate list --namespace "$ORKA_NAMESPACE" --limit 100 \
  --token-file "$PRIVATE_CALLER_TOKEN_FILE"
# If present, use the response's continue value for the next metadata page.
orka remediate list --namespace "$ORKA_NAMESPACE" --limit 100 \
  --continue "$CONTINUE_RUN_ID" --token-file "$PRIVATE_CALLER_TOKEN_FILE"
orka remediate drain --namespace "$ORKA_NAMESPACE" \
  --token-file "$PRIVATE_CALLER_TOKEN_FILE"
orka remediate status "$RUN_ID" --namespace "$ORKA_NAMESPACE" \
  --token-file "$PRIVATE_CALLER_TOKEN_FILE"
# After correcting the cleanup dependency, use the exact observed revision.
orka remediate reconcile "$RUN_ID" --revision "$RUN_REVISION" \
  --namespace "$ORKA_NAMESPACE" --token-file "$PRIVATE_CALLER_TOKEN_FILE"
```

`list` never loads request, policy, state JSON, or artifact bodies. `drain` is a
read-only full-namespace count, not a bulk-cancel command or a first-page
approximation. `reconcile` accepts only quarantined cleanup; a stale revision,
foreign namespace, nonquarantined run, or still-live legacy worker claim returns
an error without changing work. Re-drive records the authenticated operator,
prior revision/claim epoch, and timestamp in the atomic
`remediation_cleanup_audit` receipt. It advances the worker fence and grants
another bounded **cleanup-only** budget. It never requeues model/build/test
execution, re-enables admission, edits resource identities, or force-releases a
source. Check status after an uncertain acknowledgement; do not blindly retry
with a newly fetched revision.

Disabling remediation admission retains the service for inspection, cancellation,
cleanup, and intake retention. Existing nonterminal runs are cancelled; existing
quarantines remain quarantined until this explicit operator action. A drained
namespace has `complete: true` only when both `active` and `quarantined` are zero.

### Ambiguous creates: accepted POC limitation

A create request can have an ambiguous outcome if its acknowledgement is lost
and no exact accepted resource UID was durably recovered. This POC deliberately
keeps that work visible and fail-closed in `cleanup-quarantined`. Repeated
`reconcile` requests may remain unresolved or return to quarantine: a cleanup
re-drive is permission to perform another bounded reconciliation, **not a
guarantee of eventual cleanup**.

A name-only `NotFound` observation, elapsed time, or repeated retries do not prove
that the create never committed or that a delayed request cannot still take
effect. There is no timer-only absence proof, force-release operation, or
permanent inert-name tombstone mechanism in this POC.

Until exact identity and cleanup can be established, the run retains its source
reservation, active-run quota, stored payload quota, and encrypted intake.
Consequently namespace drain can remain incomplete and snapshot-key rotation
can remain blocked, even with remediation admission disabled. Keep the existing
valid key; do not delete the run, source claim, or intake to bypass these
protections. This is an **accepted scope limit of the POC**, not pending automatic
recovery behavior.

### A quarantined publishing lab

A publishing run may retain its cluster lease when an exact resource identity
cannot be established or an unknown finalizer prevents safe teardown. This
blocks subsequent coordinated runs in that lab; a lease timeout is never
permission to start another controller.

1. Inspect `status`, `drain`, and the private downloaded controller observations
   and receipts. Keep the recorded cluster, namespace, object and lease UIDs.
2. Stop admitting work into that lab and cancel waiting runs. Do not delete the
   lease to make a second run proceed around the quarantined resources.
3. For an ordinary dependency outage, restore API connectivity or the approved
   permissions and use the exact-revision `reconcile` command. Normal cleanup
   stops the subject, checks Pod absence, and removes only the known KEDA
   finalizer with UID/resourceVersion preconditions.
4. For an unknown finalizer or identity replacement, establish which controller
   owns the dependency before taking any manual action. The POC has no supported
   force-release or conversion of a quarantined child receipt into verified
   cleanup. Removing an object by hand does not mark the run complete.
5. If that lab cannot be reconciled safely, leave its evidence and reservation
   intact and onboard a separate disposable lab under a new explicit policy.
   Retiring the old lab requires separate operator approval; it is not performed
   by the remediation service. The original run remains unresolved, with the
   retention and key-rotation consequences described above.

This procedure does not convert uncertain cleanup into a successful result.

### Encrypted intake retention

The original report snapshot is stored atomically with its run using the shared
AES-256 execution-snapshot key. It is absent from normal artifacts and HTTP
responses. Terminal-only retention defaults to **30 days after settlement**,
with a maximum of **100 intake rows per hourly pass** and an initial pass when
the service starts. The controller's existing
`--agent-execution-snapshot-retention` and
`--agent-execution-snapshot-retention-interval` flags (and their
`ORKA_AGENT_EXECUTION_SNAPSHOT_RETENTION` /
`ORKA_AGENT_EXECUTION_SNAPSHOT_RETENTION_INTERVAL` environment defaults) configure
both intake retention and ordinary execution-snapshot retention. Both durations
must be positive. Keep production values aligned with the private audit and
backup policy; short intervals are appropriate only for synthetic tests.
Active, paused, quarantined, orphaned, or still-unsettled
snapshots are never pruned. Retention removes only raw encrypted intake; run
metadata, immutable artifacts, submission idempotency, and audit receipts remain.
An exact replay does not recreate a pruned raw snapshot. Preserve any required
private export before the retention window ends.

For planned snapshot-key rotation:

1. Disable admission and keep the previous valid key configured while cleanup
   and retention run. Do not replace the key as a way of discarding retained data.
2. Use all list pages and the full drain counts. Repair dependencies and
   explicitly reconcile any quarantined run; there is no force-release path.
   If an ambiguous create still has no exact UID, reconciliation may remain
   unresolved: stop the rotation procedure and retain the existing valid key.
3. Wait for terminal intake to age out and for `retainedIntakes: 0` /
   `intakeDrained: true`. `complete: true` alone does **not** prove this.
4. Independently drain the ordinary reference-aware Agent execution-snapshot
   retention path: the key is shared, and its retained rows also prevent rotation.
5. Stop readers/writers and configure the new key for restart. Startup
   authenticates every retained ciphertext with the proposed key and fails closed
   on a wrong key or corrupt snapshot, even when remediation admission is off.

Retention does not re-encrypt data or securely erase database free pages, WAL
files, exports, or backups. Manage those separately and retain the prior key for
any backups that still require it. Do not remove the old key until that private
retention/backup policy permits it.

### Upgrading existing runs

Initialization backfills active source reservations from each frozen stored
request (policy plus source kind/ID, or input digest; mode and patch digest are
also part of the identity). Distinct client keys still conflict after restart;
exact request replays still return the original run. If legacy active runs
already duplicate the same source operation, **every** unresolved run retains a
reservation until it settles. Unrecognizable legacy input conservatively blocks
new source admission in that namespace until the owning run is settled; it is
not treated as evidence that external effects disappeared. Never manually delete
source claims to work around this protection.
