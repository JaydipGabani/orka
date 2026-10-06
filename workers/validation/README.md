# Supervised Kubernetes validation worker

This helper image supplies two **static** binaries in `/artifacts`:
`orka-validation-worker` and `orka-validation-guard`. An init container copies
them into the dedicated `/runner` EmptyDir. The digest-pinned tool image runs:

```text
/runner/orka-validation-worker --input /input/bundle.gz
```

The worker accepts the bounded gzip `patchverification.PodInput` protocol,
revalidates the frozen binding, archive digest, check inventory, native platform,
and exported `patchverification.KubernetesPolicyVersion`, and emits exactly one
bounded `PodReport` JSON document. It never connects child output to its own
stdout/stderr. A validly bound setup failure is a report with unusable evidence,
not a successful check. Task and Pod UIDs come from
`ORKA_VALIDATION_TASK_UID` and `ORKA_VALIDATION_POD_UID`; the task UID must equal
the frozen binding.

## Pod contract

- Standard Linux amd64/arm64 nodes with container `RuntimeDefault` seccomp and
  ordinary process seccomp BPF support. No Docker socket, privileged Pod, host
  namespace, node configuration, node-local profile, gVisor, or Landlock is used.
- Root supervisor (`runAsUser: 0`, `runAsGroup: 0`),
  `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`.
  Run the worker directly as container PID 1 in its private PID namespace.
- Drop all capabilities; add **only** `CHOWN`, `FOWNER`, `KILL`, `SETGID`,
  `SETUID`. No inheritable or ambient capabilities. Do not mount ServiceAccount
  tokens or other credentials. Resource and EmptyDir limits belong to the
  controller's immutable Pod template.
- Root-owned EmptyDirs at `/runner`, `/input`, `/src`, `/checks`, `/work`, and
  `/tmp`. `/src` and `/checks` start empty. The supervisor restricts `/input`
  to `0700`, `/runner` to `0500`, and `/work` and `/tmp` to `0711`. If `/input`
  or `/runner` is mounted read-only in the main container, the init container
  must set these directory modes first. It also makes `/dev/shm` root-private.
- Each role gets a distinct UID/GID (20000 for the subject, 20001–20008 for
  fixtures), private `0700` work and scratch directories, no supplementary
  groups or effective/permitted/inheritable/ambient capabilities, and an exact
  allowlisted environment. `TMPDIR`, `HOME`, and Go caches are per-role.
  **Checks must use `$TMPDIR`, not hard-coded writable `/tmp` paths.**
- Source and frozen checks are root-owned read-only snapshots. Commands must
  execute an executable frozen file under `/checks`; build outputs go in the
  role's private work directory or `$TMPDIR`. Child input has no manifest,
  report writer, observer control channel, or parent environment access.

## Network and fixture lifecycle

The static C guard checks the syscall architecture, sets no-new-privileges,
closes inherited descriptors, drops identity, and installs an inherited
default-deny process filter before `exec`. Offline roles can create only Unix
domain sockets. Local-service roles can create only stream TCP or Unix sockets:
no UDP, raw sockets, namespace changes, io_uring, ptrace, process-vm access, or
TCP Fast Open connect bypass. Subjects cannot bind, listen, or accept. Fixtures
cannot connect, bind, or listen; only `accept`/`accept4` on FD3 is allowed.

For each declared service the supervisor opens one dual-stack IPv6 TCP listener
on the declared port and passes it as **FD3** with `ORKA_LISTEN_FD=3`. The fixture
must adopt that listener, start stdout with its exact declared `readyOutput`, remain alive
through the check, and handle **SIGTERM followed by exit 0 within two seconds**.
Its complete stdout, including readiness and shutdown output, is separately
hashed and compared by the evaluator; any fixture stderr makes evidence
unusable. A fixture shell should `exec` its service so the observed process owns
the shutdown handler. Close FD3 when running build subprocesses that do not
need the listener.

Local-services additionally requires controller-installed deny-all Pod ingress
and egress policies and a trusted, independently reachable numeric canary IP
and TCP port. Before starting any child, the supervisor must observe a timed-out
canary connection. A successful connection, refusal, routing error, missing
canary, or cancellation fails closed. The CNI must enforce NetworkPolicy for
all enabled address families; a single canary is a deployment enforcement
check, not a substitute for an enforcing CNI.

## Evidence and cleanup

Each subject stream and each fixture stream is bounded by
`patchverification.MaxOutputBytes`. Overflow remains drained but makes
evidence unusable. The observer—not child JSON—records times, actual exit
status, timeout, readiness, and lifecycle facts. Skipped exit 77, reserved exit
codes, undeclared exits, signal death, premature fixture death, and unclean
shutdown are not usable evidence.

The supervisor is a subreaper. It retains pidfds for direct children, discovers
only assigned-UID descendants, verifies identities before signaling, and
reaps orphaned descendants even after `setsid`. Leftover subject descendants
invalidate evidence. Cancellation and failures use bounded exact-process
cleanup, never process-name kills. Allow at least the five-second cleanup and
two-second output-drain budgets in the Pod termination grace period. Normal
fixture stopping is cancellation-aware: SIGTERM interrupts sequential fixture
shutdown and enters those cleanup/drain budgets rather than waiting another
two seconds for every fixture.

This is a shared-kernel, least-privilege process boundary, not a VM boundary.
The pinned tool image, helper image, kernel/container runtime, and enforcing CNI
are trusted inputs. Pod resource limits bound denial of service; no claim is
made to protect against kernel vulnerabilities or a malicious tool image.

## Protected HTTP observations

Pod protocol 2 and policy `kubernetes-v3-http-observation` additionally support
optional `Check.http` contracts:

```json
{
  "id": "quantity-boundary",
  "kind": "reproduction",
  "command": [],
  "http": {
    "version": 1,
    "serverCommand": ["/checks/server"],
    "path": "/quantity?value=-1"
  },
  "healthy": {"exitCode": 0, "stdout": "{\"status\":400,\"body\":\"rejected\"}"},
  "failure": {"exitCode": 0, "stdout": "{\"status\":200,\"body\":\"accepted\"}"},
  "timeoutSeconds": 10
}
```

Use `patchverification.HTTPExpectation(status, body)` to construct canonical
expectations. The legacy command and stdin must be empty. All checks in this
manifest must use the HTTP contract, with the `local-services` profile and no
additional declared services. The subject server is the single implicit
service. Existing NetworkPolicy/canary requirements still apply; `offline`
does not grant the server's required TCP role.

The supervisor assigns an ephemeral IPv6 loopback listener and passes FD3 to
the untrusted server in the existing isolated, accept-only process role. The
server must adopt FD3 (`ORKA_LISTEN_FD=3`), remain alive during observation, and
exit 0 after SIGTERM within the existing shutdown budget. No readiness output
is required or trusted. Accept must use FD3 itself; listener APIs that duplicate
it, such as Go's `net.FileListener`, do not satisfy the existing guard policy.
Build subprocesses should close FD3. The fixed trusted
supervisor sends one GET to the assigned `[::1]` endpoint, without proxies,
redirect following, decompression, or subject code in the observer process.
Responses require complete framing, bounded headers, a final status, and a
UTF-8 body of at most 4096 bytes whose canonical JSON fits the expectation limit.
Headers and internal subject execution are not part of the declared assertion.

Only the complete canonical response becomes observation stdout. Subject stdout
and stderr are bounded diagnostics, never completion or verdict claims.
`httpCompleted` is set by the supervisor only after the response and orderly
server stop; failure, timeout, truncation, or cleanup errors prevent acceptance.
Observer exit 0 does not mean the response is healthy: the evaluator still
compares its exact status/body against the frozen healthy and failure cases.

In-process tests, outbound access, extra services, cluster/controller lifecycle,
and additional test identities are unsupported and rejected. Old workers reject
the new protocol/policy, and the unchanged Docker runner rejects these checks
rather than executing the server as a raw check. Historical command-only records
remain readable with their original scope: the protected completion guarantee
does not extend to arbitrary raw checks or prove that generated observations
adequately represent a report.

Rootless tests exercise live loopback HTTP, supervised completion, constructor
exit before main, forged healthy output/JSON, premature death, and late replies:

```sh
go test ./internal/patchverification ./workers/validation \
  -run 'HTTP|StagePodInput'
```

These tests do not replace live Pod validation of UID separation and the
deployment's CNI enforcement. A positive C server fixture also serves HTTP on
FD3 under the existing real accept-only seccomp filter, including an assertion
that outbound connect is denied.

## Helper image build

From the repository root:

```sh
docker build --platform=linux/amd64 --pull=false \
  -f workers/validation/Dockerfile -t orka-validation-helper:issue542 .
```

The Dockerfile-specific ignore file admits only the module files, required Go
sources, and guard C source; it does not change the repository-wide build
context policy.

The build and final stages use digest-pinned Go 1.26.5/trixie and Alpine 3.22.
The builder explicitly selects the repository's Go 1.27.0 toolchain rather
than inheriting the base image's toolchain policy. Unless already in
the BuildKit module cache, that toolchain and modules require network access
during the build; the host Go cache is not implicitly shared with the builder.
Both shipped binaries are static. Use `linux/arm64` when building for arm64.

## Focused validation

Run from the repository root with a repository-local build-work directory:

```sh
mkdir -p bin/validation-work
TMPDIR="$PWD/bin/validation-work" GOTMPDIR="$PWD/bin/validation-work" \
  go test ./workers/validation ./internal/patchverification \
    -run 'Test(StagePodInput|DecodePodInput|ReadPodInput|Report|Capture|ChildEnvironment|Process|Fixture|Cleanup|ValidateSubjectExit|Canary|Guard)'
```

The tests compile the static guard using the existing `cc`, execute its real
seccomp filters without root, and exercise bounded decoding/capture, descriptor
closure, architecture rejection, networking roles, timeout/cancellation,
fixture death/shutdown, detached descendant reaping, and real C/Go builds under
the filter. Full UID separation,
container security-context validation, and CNI enforcement also require the
controller's live Pod integration tests; no node or Docker configuration is
changed by this package.
