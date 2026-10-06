# Issue 542 integration contract

This note describes the local POC API contract after the two-action alignment.
The runnable examples and delivery plan are integrated. The POC does not claim
production authorization, cluster execution, or independent attestation of
scenario lifecycle steps.

## Actions and compatibility

- `validate-report` requires a report, scope, exact original repository commit,
  frozen checks, and a pinned tool image/setup. It rejects patches, declared
  changes, and earlier-validation references. At least one reproduction check is
  required; normal-use checks are optional. There is one original Task UID and
  no patched tree, patch/diff provenance, or patched Task UID.
- `verify-patch` requires a new supplied patched commit or patch file, explicit
  `declaredChanges`, reproduction checks, and normal-use checks. All original
  checks run first. Every required original reproduction and normal-use check
  must establish its expected behavior before any patched check runs. Both arms
  use the same frozen checks and setup. No retry or setup mutation is automatic.
- A blank request action remains accepted as legacy patch input. New starts
  normalize it to explicit `verify-patch` and, if necessary, record a `source`
  declaration explaining that the legacy request did not declare paths.
- A stored manifest with a blank action retains exact legacy adjudication and
  JSON encoding. New manifest, environment, check, and assessment fields use
  `omitempty`. Existing manifest/seal byte compatibility is tested.

## Report identity and linking

`StableReportDigest(problem string, scope []string) (string, error)` returns
`sha256:` plus the lowercase hexadecimal SHA-256 of the bytes produced by Go's
`encoding/json.Marshal` for this ordered structure, without a trailing newline:

```go
report := struct {
  Problem string   `json:"problem"`
  Scope   []string `json:"scope"`
}{Problem: problem, Scope: scope}
content, err := json.Marshal(report)
```

Whitespace, case, scope order, and the standard JSON escaping are significant.
The service computes the value, `ValidateManifest` verifies it, and request JSON
cannot claim a `reportDigest`. The digest identifies the report and scope, not
the affected version; the manifest separately binds the exact source identity.

`Request.EarlierValidation` is a run ID in the same open private database. It
must resolve to an intact, finalized `validate-report` record with a seal and no
incidents. The verified lookup is read-only even on failure. Local authorization
means normal private-file ownership, mode, regular-file, and link-count checks;
it is not a production tenant/principal authorization system. Caller-supplied
foreign-principal metadata is not accepted by the request decoder.

Linked requests may omit the report, scope, repository, original commit,
checks/setup, and image/platform. Supplied values must exactly match the frozen
record. A supplied `checksDir` must match the stored file bytes and executable
flags. Omitted checks are reconstructed into a new private directory from
stored bytes, without depending on the old live directory. The new source
preparation rereads the exact original commit; creation also checks repository,
commit, tree, archive digest, checks, files, gaps, and environment against the
earlier record. A changed runner policy/image identity is not silently accepted.

The new manifest stores `earlierValidation` with `runID`, `reportDigest`,
`manifestDigest`, and `sealDigest`. Neither original observations nor the earlier
conclusion are reused. The earlier seal, evidence, result, and Task artifacts
remain unchanged. A reproduction-only report cannot supply the normal-use checks
required for linked verification; use a new direct run with a complete check set.

Minimal linked request, replacing the run ID and commit with real identities:

```json
{
  "action": "verify-patch",
  "earlierValidation": "pv-COMPLETED_REPORT_RUN_ID",
  "patchedCommit": "2222222222222222222222222222222222222222",
  "declaredChanges": [
    {
      "kind": "configuration",
      "paths": ["config/settings.json"],
      "description": "Persist the managed setting"
    }
  ]
}
```

`patchFile` can replace `patchedCommit`; exactly one is required. Request paths
are resolved relative to the request JSON file. Marshaling a minimal Go `Request`
omits optional empty fields. Explicit JSON empty overrides are not treated as
permission to silently replace earlier metadata.

## New metadata

- `DeclaredChange`: `kind`, optional `paths`, and required `description`.
  Kinds are `source`, `dependency`, `deployment`, `configuration`, `permission`.
  Paths must be safe repository-relative paths. They are declarations, not an
  automatic classification or completeness check of the actual source diff.
- `EnvironmentRequirement`: `kind`, required `name`, optional `description`.
  Request field: `requiredEnvironment`; frozen field: `environment.requirements`.
  Kinds are `process`, `local-services`, `cluster`, `controller`,
  `external-service`, `test-identity`. Only process and properly configured local
  services are supported. A local-service name must match the required fixture ID.
  Missing requirements are individually named in a
  finalized action-appropriate unable result, with every check retained as
  untested and zero workload executions. Image resolution may still occur.
- `Check.Lifecycle`: an ordered list of `install`, `reconcile`, `restart`,
  `upgrade`. The frozen command is the independent scenario driver. Each check
  has its own fresh container, so stateful sequences belong inside a single
  check and may use private `/tmp`; checks do not share process or filesystem
  state. A modeled manager uses a `process` requirement. A real `controller`
  requirement remains unsupported and must not be replaced with that model.

Example original-only request for a modeled configuration lifecycle. The caller
must provide the named local repository, pinned image, and independent scripts:

```json
{
  "action": "validate-report",
  "problem": "A managed setting is exposed again after reconciliation or restart",
  "scope": ["modeled installation, reconciliation, restart, and retained-state update"],
  "gaps": ["No real controller or cluster is exercised"],
  "repository": "repo",
  "originalCommit": "1111111111111111111111111111111111111111",
  "checksDir": "checks",
  "image": "fixture/tool@sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "platform": "linux/amd64",
  "profile": "offline",
  "requiredEnvironment": [
    {"kind": "process", "name": "modeled-manager", "description": "Disposable configuration manager model"}
  ],
  "checks": [
    {
      "id": "managed-lifecycle",
      "kind": "reproduction",
      "command": ["/checks/scenario.sh", "lifecycle"],
      "timeoutSeconds": 30,
      "lifecycle": ["install", "reconcile", "restart", "upgrade"],
      "healthy": {"exitCode": 0, "stdout": "install=protected\nreconcile=protected\nrestart=protected\nupgrade=protected\n"},
      "failure": {"exitCode": 0, "stdout": "install=exposed\nreconcile=exposed\nrestart=exposed\nupgrade=exposed\n"}
    },
    {
      "id": "normal-use",
      "kind": "normal",
      "command": ["/checks/scenario.sh", "normal"],
      "timeoutSeconds": 30,
      "healthy": {"exitCode": 0, "stdout": "normal-ok\n"},
      "failure": {"exitCode": 0, "stdout": "normal-failed\n"}
    }
  ]
}
```

For a direct verification, change `action` to `verify-patch`, add one patch
input and `declaredChanges`, and retain the same check/setup fields.

## Evidence and lifecycle claims

Lifecycle metadata cannot prove that a step ran. The engine compares actual
runner-captured output and exit status against the frozen healthy/failure
expectations; it does not adjudicate from lifecycle labels. The driver should
report the relevant effective states in both expected outputs, including the
state after management reapplies settings, restart, and retained-state update.
The runnable `examples/patch-verification/config/` fixture exercises this
contract with a process model, installed-state output, and a separate HTTP
observer; it does not stand in for a required real controller.

`Observation` binds `runID`, `attemptID`, `taskID`, `manifestDigest`, `side`,
`checkID`, `sourceTree`, `imageID`, `containerID`, execution times/status, and
stdout/stderr digests and byte counts. `origin: runner` identifies the record
producer; captured stdout remains project/driver-reported content. Arbitrary
JSON stdout is never promoted to independent installed-state authority.

`ExecutionEvidence.Blobs` supplies the bytes for those digests. For a confined
HTTP fixture, `Expectation.Services` and `Observation.ServiceOutputs` bind the
separate fake service's captured output. Both healthy/failure expectations must
cover every frozen service. The configuration fixture combines driver state
output with independently observed HTTP effects and distinguishes a
modeled process from a real controller. Runner source/image identities are not
inferred from declarative requirement names. Seccomp, Landlock, static launcher,
source resource limits, and evidence write separation remain in place.

## Public helpers and CLI outputs

- `ActionOrDefault`, `ActionSides`, `UnavailableAction`, and the `Outcome*`
  constants provide shared action and per-check vocabulary.
- `RequestManifest` computes an explicit-action manifest/report identity.
  `ValidateRequestAction` checks action-specific inputs.
- `RestoreFrozenChecks` and `ValidateFrozenChecks` restore/compare saved checks;
  release the returned private snapshot using `PreparedSources.Close`.
- `EvaluateOriginal` returns all original per-check results; `OriginalReady`
  requires every reproduction plus required normal behavior before comparison.
- `MissingRequirements` lists unsupported named requirements.
- `sqlite.Store.GetCompletedReportValidation` verifies a completed report without
  mutating it; the local service applies private-database access checks.
- CLI operations remain `start --request`, `get`, `evidence`, `cancel`, `recover`.
  `Summary` adds `action`, `reportDigest`, and optional `earlierValidation`.
  `progress.required` is one slot per check for reports, two for verification.
- Reports return `Reproduced`, `Not reproduced under these conditions`, or
  `Unable to validate`. The first two have start exit code 0; unable has 2.
- Verification keeps exit codes 0 (verified), 1 (not fixed/partial/regression),
  and 2 (unable or operation failure). New per-check comparisons include
  `originalOutcome` and `patchedOutcome`; missing patched slots are `untested`.
- Report case outcomes are `reproduced`, `not-reproduced`, `untested`, and
  `passed` for established normal-use checks. Simultaneous unfixed and regression
  comparisons are retained even when the overall result is regression.
- Task objects remain local auxiliary projections, not new CRDs or reconciled
  Kubernetes workloads. Reports project one object; verification projects two.

## Verification and limitations

Existing demos with no action still work as legacy request inputs. Explicit
verification examples must add declared changes. Update expected check counts:
a failed baseline now records original checks only and never executes the patch.
New explicit-action outcomes use `untested` plus separate original/patched
outcomes; old stored blank-action assessments keep `unable`. Existing artifacts
remain inspectable. Rejected/conflicting slots are excluded from current case
conclusions without discarding valid neighbors or changing historical seals.
Missing-requirement descriptions occur once at overall level so maximum-size
requests can finalize without exceeding the seal budget.

Focused race tests passed for core, local orchestration, CLI, and SQLite. The
58 live scenarios, 328 observations, full-gate outcome, and retained evidence
locations are recorded in the delivery plan. No repository commits, pushes, or
GitHub writes were performed. The protected source mode test remained byte-identical:
`1f5f17d0b75652dadf84d62842319b2a019ee6a5f49a28f0d260d3b003989639`.

Files changed in this handoff, relative to the integration worktree:

- `internal/patchverification/action.go`, `action_test.go`, `metadata.go`
- `internal/patchverification/evaluate.go`, `report.go`, `report_test.go`
- `internal/patchverification/request.go`, `record.go`, `source.go`, `docker_runner.go`
- `internal/patchverification/local/request.go`, `request_test.go`
- `internal/patchverification/local/service.go`, `service_test.go`, `tasks.go`, `action_service_test.go`
- `internal/store/sqlite/patch_verification_store.go`, `patch_verification_lifecycle.go`, `report_validation_test.go`
- `cmd/patchverify/cli.go`, `cli_test.go`
- This new alignment-contract note
