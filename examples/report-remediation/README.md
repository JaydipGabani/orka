# Demo: report to an evidence-backed private patch

This is the command walkthrough for the **experimental local changes**, not the
released Orka CLI. Build from the checkout containing these changes.

For the newer server-managed `remediate start --incident ... --policy ...`
path, see [single-submission setup and commands](../../website/docs/development/report-remediation.md#server-managed-single-submission).
It requires one-time approved model/catalog/lab onboarding. The walkthrough
below remains the older, explicitly reviewed local-driver demonstration; it
must not be mistaken for proof that unattended remediation is qualified.

For reusable **local-only operator onboarding**, see
[the Kind subject-lab bootstrap](LOCAL_KIND.md) and its
[private-input template](local-kind-operator.example.json). It reuses an already
approved private Orka/model-gateway control installation, creates a fresh subject
lab and independent BuildKit/TLS state, and stages an unchanged-semantics policy
clone. It is not a production Helm installer and never invokes a model.

## Recommended: one server-managed submission

After the operator has installed the private control plane and approved the
model, build catalog and isolated lab, the caller does not supply source-file
lists, a shell driver or a candidate patch:

```bash
set -euo pipefail
umask 077
make build-cli

export CASE=/absolute/private/new-remediation-demo
install -d -m 700 "$CASE"
export REQUEST_ID="incident-demo-$(date -u +%Y%m%dT%H%M%SZ)"

bin/orka --server "$ORKA_URL" --namespace "$ORKA_NAMESPACE" remediate start \
  --incident "$ICM_ID_OR_URL" \
  --icm-cli "$(command -v icm-cli)" \
  --policy "$APPROVED_POLICY" \
  --request-id "$REQUEST_ID" \
  --token-file "$CALLER_TOKEN_FILE" \
  --wait > "$CASE/submission.jsonl"

RUN_ID="$(jq -er -s 'last | select(
  .phase == "Succeeded" and .mode == "generate" and .stage == "verified"
) | .id' "$CASE/submission.jsonl")"
export RUN_ID

bin/orka --server "$ORKA_URL" --namespace "$ORKA_NAMESPACE" remediate download \
  "$RUN_ID" --output-dir "$CASE/handoff" \
  --token-file "$CALLER_TOKEN_FILE" > "$CASE/download.json"

sha256sum "$CASE/handoff/candidate.patch"
jq '{phase, stage, artifacts: [.artifacts[] |
  select(.name == "candidate.patch" or (.name | startswith("verification-")))]}' \
  "$CASE/download.json"
```

Keep the same request ID when retrying an uncertain submission. A new ID is for
a new intentional run, not a way around a held source claim or quarantined
cleanup. `NeedsInput`, `NeedsAdapter`, `NeedsApproval`, `Cancelled` and failed
runs are not verified patches. Follow the returned state instead of continuing
the success-only commands above.

The pipeline acquires and normalizes the report, investigates public source,
selects the approved adapter, compares original and rebuilt-control behavior,
generates and repairs bounded candidates, and returns private evidence.
Unsupported repositories, recipes and scenarios stop explicitly. The result is
qualified for its frozen checks and normal controls, not a general security
guarantee or publisher-signed downstream provenance. Nothing is published to
the incident or source repository.

## Older local-journal demonstrations

The remainder documents three explicitly reviewed local-driver demonstrations:

| Demo | Needs a model? | Needs a running lab? |
| --- | --- | --- |
| Inspect a completed private journal | No | No |
| Reproduce a report and verify a reviewed patch | No | Yes |
| Generate a new candidate through Orka, then verify it | Yes | Yes |

**For the retained incident POC on the original development host:** use the
private `README-DEMO.md` alongside its handoff and patch. It supplies the actual
paths, exact cluster/container identities, expired test-certificate renewal,
expected results, and cleanup commands. The incident, downstream recipes,
driver, credentials, and patch are intentionally **not** examples in this
repository. The generic commands below require your own reviewed lab profile.

## 1. Understand the change

```bash
git status --short
git diff --stat

# New untracked implementation is not included in ordinary git diff.
git ls-files --others --exclude-standard \
  internal/remediation internal/patchverification workers/validation \
  cmd/cli examples/report-remediation
```

| Surface | Purpose |
| --- | --- |
| [CLI](../../cmd/cli/remediation.go), [lab commands](../../cmd/cli/remediation_lab.go) | Export, ingest, plan, validate, generate, verify, status |
| [Coordinator](../../internal/remediation/) | Approval, bounded proposals, private artifacts, resume |
| [Intake](../../internal/remediation/intake/), [IcM exporter](../../internal/remediation/icm/) | Read-only, bounded report acquisition and normalization |
| [Source](../../internal/remediation/source/) | Public repository, commit/tree, and selected blob verification |
| [Journal](../../internal/remediation/journal/) | Immutable private checkpoints, locking, evidence references |
| [Lab bridge](../../internal/remediation/lab/) | Pinned, explicitly approved privileged driver and observation receipts |
| [Process checks](../../internal/patchverification/), [worker](../../workers/validation/) | Protected process-level observation; not a replacement for cluster checks |

Read the [operator and driver contract](../../website/docs/development/report-remediation.md)
before granting a lab driver access to Kubernetes or cloud credentials.

## 2. Build the CLI

Linux, Go with automatic toolchain selection, Git, Make, and `jq` are required.
Use an absolute private directory **outside every Git checkout** for reports and
scratch. Do not use a shared temporary root directly as the case directory.

```bash
set -euo pipefail
umask 077
export REPO="$(git rev-parse --show-toplevel)"
export CASE=/absolute/private/report-demo  # Choose your own directory.
install -d -m 700 "$CASE" "$CASE/go-tmp"

cd "$REPO"
TMPDIR="$CASE/go-tmp" make build-cli
export ORKA="$REPO/bin/orka"
"$ORKA" remediate --help
```

The help must list `export`, `ingest`, `plan`, `run`, `status`, `lab-plan`,
`lab-validate`, `lab-run`, and `lab-verify`. No controller deployment is needed
for `ingest`, `status`, or the model-free lab commands.

## 3. Select an input

For an existing JSON report or complete export:

```bash
export INPUT="$CASE/report.json"  # Supply this file; do not paste it into logs.
test -s "$INPUT"
```

Alternatively, acquire a **new** read-only snapshot of an incident you are
authorized to access. This requires `icm-cli`, Azure CLI authentication, and
network access:

```bash
export ICM_ID_OR_URL='<authorized incident ID or URL>'
export ICM_EXPORT="$CASE/export-$(date -u +%Y%m%dT%H%M%SZ)"
"$ORKA" remediate export "$ICM_ID_OR_URL" \
  --icm-cli "$(command -v icm-cli)" --icm-auth azcli \
  --output-dir "$ICM_EXPORT" > "$CASE/export-receipt.json"
jq -e '.state == "complete"' "$CASE/export-receipt.json"
export INPUT="$ICM_EXPORT/input.json"
```

The current exporter writes **`input.json`**. Historical manually captured
bundles may have other names; use their recorded paths. Do not continue from an
incomplete capture or overwrite an earlier export.

## 4. Freeze a reviewed lab plan

A lab profile is not created by the model. Provide an executable, reviewed
driver, its private configuration, the original/control image digests, an exact
public source commit, and a frozen check manifest. Provision its isolated lab
first, following that driver's instructions. The CLI does not create AKS.

```bash
export PROFILE="$CASE/reviewed-profile.json"
export PATCH="$CASE/reviewed-candidate.patch"
test -s "$PROFILE"
test -s "$PATCH"
test "$(stat -c %a "$PATCH")" = 600

export DEMO="$(mktemp -d "$CASE/run.XXXXXXXX")"
export STATE="$DEMO/state"          # Do not pre-create the journal.
export SCRATCH="$DEMO/scratch"
mkdir -m 700 "$SCRATCH"

"$ORKA" remediate ingest --input "$INPUT" --state-dir "$STATE" \
  > "$DEMO/ingest.json"

# Replace these with relevant real files from the profile's repository.
SOURCE_ARGS=(
  --source-file src/handler.go
  --source-file src/handler_test.go
)
"$ORKA" remediate lab-plan \
  --state-dir "$STATE" --work-dir "$SCRATCH" \
  --lab-profile "$PROFILE" "${SOURCE_ARGS[@]}" \
  > "$DEMO/plan.json"

jq '{phase, planDigest, targets, lab}' "$DEMO/plan.json"
export PLAN_DIGEST="$(jq -er '.planDigest' "$DEMO/plan.json")"
```

`lab-plan` fetches selected public source anonymously and verifies Git
commit/tree/blob identities. It does not call Orka or a model. Review the profile,
source selection, scope, and exact plan digest before the next command.

## 5. Validate the report without creating a patch

```bash
"$ORKA" remediate lab-validate \
  --state-dir "$STATE" --work-dir "$SCRATCH" \
  --approve-plan "$PLAN_DIGEST" --timeout 30m \
  > "$DEMO/baseline.json"

jq -e '.phase == "report-validated"
       and .targets[0].conclusion == "Reproduced"
       and .targets[0].patch == null
       and .lab.verified == false' "$DEMO/baseline.json"
export LAB_RUNS="$(jq -er '.lab.runsDirectory' "$DEMO/baseline.json")"
jq '.result.checks' "$LAB_RUNS/baseline/receipt.json"
```

Reproduction checks must fail on original and unchanged control; normal checks
must pass. A setup error, missing observation, or non-reproduction is not a
successful report validation.

## 6. Verify the reviewed patch

```bash
"$ORKA" remediate lab-verify \
  --state-dir "$STATE" --work-dir "$SCRATCH" \
  --approve-plan "$PLAN_DIGEST" --patch-file "$PATCH" \
  --change-description "Describe the reviewed source and behavior changes" \
  --timeout 30m > "$DEMO/verification.json"

jq -e '.phase == "completed" and .lab.verified == true
       and .targets[0].conclusion == "Verified for these checks"' \
  "$DEMO/verification.json"
jq '{state, trustStatement, result}' "$LAB_RUNS/verify-0/receipt.json"
```

All patched reproduction **and normal** checks must pass. Driver receipts must
bind the same check set, image identities, runtime UIDs, and successful cleanup.
A verified result is scoped evidence, not a guarantee about untested behavior.

## 7. Optional: generate instead of supplying a patch

Use a **separate fresh journal**, repeat steps 4-5, and choose this command
instead of step 6. Do not switch a journal with an existing supplied candidate
into generated-candidate mode.

```bash
export ORKA_SERVER='http://127.0.0.1:18372'
export ORKA_NAMESPACE='orka-system'
export PROPOSAL_AGENT='<approved tool-free Agent>'
export CALLER_TOKEN_FILE='/absolute/private/caller.token'

"$ORKA" remediate lab-run \
  --state-dir "$STATE" --work-dir "$SCRATCH" \
  --approve-plan "$PLAN_DIGEST" \
  --server "$ORKA_SERVER" --namespace "$ORKA_NAMESPACE" \
  --agent "$PROPOSAL_AGENT" --task-type ai \
  --token-file "$CALLER_TOKEN_FILE" --model-data-approved \
  --timeout 30m > "$DEMO/generated-run.json"
```

This requires an already-running Orka deployment and a model boundary approved
for the report. Keep native automatic memory tools and ambient memory disabled;
see the [Agent requirements](../../website/docs/development/report-remediation.md).
Do not use an unapproved fallback provider.

The demonstrated incident required review and corrections. `lab-run` may block
on a bad proposal/build rather than produce a verified patch. A Task marked
`Succeeded` alone is not evidence. Discovery, universal environment provisioning,
and PR publication are not implemented.

## 8. Resume, inspect, and clean up

```bash
"$ORKA" remediate status --state-dir "$STATE" | jq .
```

Keep the state directory, scratch receipts, private driver diagnostics, and
patch. Repeating a completed request retrieves existing evidence; it is **not**
a fresh comparison. Use a new journal for a new demonstration.

For `unknown` execution, reconcile the actual driver/build/cluster and cleanup
before deciding on a new run. Never erase the intent, edit a checkpoint, or
change a digest to force a pass. Shut down only the exact lab resources and
tunnels started for your run using its driver-specific instructions. Do not
delete shared clusters, prune Docker globally, or change the global kubeconfig.

## 9. Check the implementation locally

These tests use synthetic fixtures; they do not send the private incident to a
model or provision cloud infrastructure.

```bash
cd "$REPO"
TMPDIR="$CASE/go-tmp" go test -race -p 1 \
  ./internal/remediation/... ./internal/patchverification/... \
  ./workers/validation ./internal/publisher/service
TMPDIR="$CASE/go-tmp" go test -race ./cmd/cli ./workers/ai \
  -run 'TestRemediation|TestAutoEnableMemoryTools'
make lint
```

The full developer gate is `make lint-fix && make test`; it can regenerate or
format files. Do not equate focused tests with a fully green repository:
the recorded full run had shared-environment failures, and independent
autoreview was blocked by its credential scanner. Those readiness limitations
are separate from the scoped live case evidence.
