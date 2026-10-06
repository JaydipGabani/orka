# Durable remediation build Jobs

This is an opt-in backend, not a deployment manager. It does not integrate or
replace the existing environment adapter. It runs a **trusted BuildKit client**
in a Kubernetes Job; candidate compilation runs only in an independently
approved, isolated BuildKit daemon. It never executes candidate instructions on
the controller host or inside the client worker.

Anonymous registry access is **synthetic/public only**. Restricted/private
reports require an operator `RegistrySecretName` and the parent's confidentiality
gate. There are no credential bytes, arbitrary commands, arbitrary CLI options,
SSH agents, BuildKit secret mounts, or host paths in the input API. Operator references select
mandatory BuildKit mTLS CA/client Secrets. Only the trusted client mounts them;
their contents are never sent into the LLB context.

## Integration contract

```go
backend, err := buildjob.New(buildjob.Config{
    Kube:            directClientset,
    APIReader:       directClientset, // optional; must be uncached and the same API server
    Namespace:       "remediation-build",
    WorkerImage:     approvedClientImage, // canonical repository@sha256:...
    BuildKitAddress: "tcp://buildkit.remediation-build.svc:1234",
    RegistrySecretName: "private-registry-v1",
    TLS: &buildjob.TLS{
        CASecretName:     "buildkit-ca-v1",
        ClientSecretName: "buildkit-client-v1",
        ServerName:       "buildkit.remediation-build.svc",
    },
    Policies: []buildjob.Policy{{
        RecipePath:       "recipe.yml",
        Frontend:         approvedDalecFrontend,
        Worker:           approvedDalecWorker,
        WorkerContext:    "dalec-azlinux3-worker",
        Target:           approvedTarget,
        Platform:         "linux/amd64",
        OutputRepository: approvedPrivateOutputRepository,
        SourcePaths:      approvedCompilerSourcePaths,
    }},
})
```

`New` validates and copies operator configuration without contacting Kubernetes.
It does not require an output directory or host journal.

| API | Contract |
| --- | --- |
| `CanonicalInputDigest(Input) (string, error)` | Versioned canonical digest of run/operation identity, every file byte, and exact build options. Recovery hints and the supplied digest are excluded. |
| `Start(ctx, Input) (Receipt, error)` | Submit once or recover the exact deterministic Job. Copy the policy fields into `Input` and supply `Files`, `RunID`, and `OperationID`. A nonempty `InputDigest` must match the canonical digest. |
| `Observe(ctx, Receipt) (Result, error)` | One bounded observation, not a polling loop. `Done=false` means pending. A terminal result is tied to actual Kubernetes identities and trusted worker termination evidence. |
| `Cancel(ctx, Receipt) error` | Explicit UID-fenced cleanup; nil means cleanup completed. Cancelling a `Start`/`Observe` context does **not** cancel or delete accepted work. |
| `Cleanup(ctx, Receipt) (CleanupReceipt, error)` | Same explicit cleanup, with durable evidence. Require nil error, `Stopped`, `SubmissionSettled`, `DaemonSettled`, and the bound receipt before downstream final verification. |

Persist every returned receipt, including partial receipts on errors. A complete
receipt contains namespace, metadata-ledger, input-Secret, and Job UIDs, plus the
configuration and input digests. After acceptance, recovery calls to `Start`
should set `RequireExisting=true` and `ExpectedJobUID` to the persisted UID.
Normally reconstruction only needs `New` with the same operator configuration
and `Observe` with the saved receipt. It does not need source files again.

The configuration digest is deliberately exact, including limits and the policy
catalog. Preserve the original configuration while operations are live; drain
and clean them before changing client images, TLS settings, limits, or policies.
Changing configuration is not permission to adopt or replay old work.

`Result.BuildOutcome` is `success`, `compile-failure`, `infrastructure`, or
`cancelled`. Only `success` carries `ImmutableImageDigest` and `Image`, where the
latter is the approved repository plus the resolved digest. A compile failure
requires a nonzero worker exit and recognized diagnostics from known source
paths. Other buildctl failures are conservatively infrastructure failures.
Neither an LLB-produced file nor a stdout “success” claim is accepted as evidence.

`ResultDigest` and `CleanupDigest` are deterministic binding hashes, **not**
signatures or portable attestations. They are useful only with the trusted
controller's API observations and durable workflow records.

### Failure and recovery states

1. A deterministic, immutable-data ConfigMap reserves the operation. It contains
   only safe identifiers/digests and mutable lifecycle annotations.
2. A deterministic immutable Secret holds `manifest.json` and `files.tar.gz`.
   Its accepted UID is durably bound to the ledger before any Job submission.
3. The Secret records submission intent before `Create(Job)`. The Job is owned
   by the Secret's exact UID; the Secret is **not** owned by the Job. A timeout or
   lost create acknowledgement is followed by `Get`, never a blind second create.
4. Accepted Job and observed Pod UIDs are durably recorded on Secret metadata.
   Namespace, ledger, Secret, Job, Pod, template, input, and runtime image
   identities are checked again before accepting termination evidence.
5. Explicit cleanup closes submission and uses foreground deletes with exact UID
   preconditions. A Pod retention finalizer preserves worker termination evidence
   while kubelet delivers SIGTERM. Only the exact trusted worker's matching-ref
   daemon completion proof permits release of that finalizer. The proof is first
   persisted on the metadata ledger so controller restart or later Pod loss does
   not discard it. Every observed worker must be covered before cleanup can
   acknowledge daemon settlement; it then waits for Pods and Job disappearance
   and deletes the private input Secret. No TTL deletes evidence before acknowledgement.
6. The metadata-only ledger survives with the cleanup receipt. Do not delete it
   while operation identities can still be retried. It prevents post-cleanup
   replay and counts toward the per-run operation budget.

| Error category | Handling |
| --- | --- |
| `ErrInvalid`, `ErrLimit` | Correct operator/input configuration or stop the operation. Inputs are never partially truncated. |
| `ErrAPI` | Retry reads/recovery with backoff and the same receipt. Do not mint another operation automatically. Raw API errors and source bytes are not returned. |
| `ErrIdentity`, `ErrLost` | Fail closed. An accepted object was changed, replaced, or lost; do not recreate it or accept an image. |
| `ErrIndeterminate` | Submission intent exists but its Job is not observable. Retry the same recovery lookup; never resubmit. |
| `ErrCleanup` | Cleanup is still pending. Retain the receipt and retry; final verification remains blocked. |

A process crash between persisting submission intent and sending `Create(Job)`
cannot be distinguished from an in-flight request. If no exact Job ever becomes
observable, that operation remains indeterminate and cleanup cannot acknowledge
submission settlement. This is intentional: Kubernetes has no cross-object
transaction to revoke a pending create. Operator recovery must quiesce the
submitter and establish absence independently; this package has no “force
successful cleanup” shortcut.

## Bounds and worker behavior

- At most **768 KiB** total source bytes plus path names, and independently
  **768 KiB** of combined Secret data, including metadata and compressed archive.
  The default individual file bound is 384 KiB; defaults allow 128 files.
  Multipart inputs, PVCs, and oversized inputs are unsupported.
- Canonical relative text files only: no NUL/binary content, symlinks, hardlinks,
  hidden/config/credential paths, traversal, duplicate entries, or file/directory
  collisions. The parent must still validate recipe/base/patch provenance and
  exclude credentials; these conservative checks are not a general secret scanner.
- Dalec recipes use the operator-approved pinned frontend's default
  `build.network_mode: none`, or declare `none` explicitly. Approved recipe bytes
  are not rewritten just to insert the default. Aliases,
  duplicate mappings, multiple documents, alternate network modes, and shared
  Dalec cache mounts are rejected. The parent owns complete Dalec schema and
  source validation.
- The entire frontend/worker/worker-argument/target/platform/output tuple must
  match an operator `Policy`. Both images must be digest-pinned. Extra build
  arguments are limited to operator-fixed `SOURCE_DATE_EPOCH` and
  `BUILDKIT_MULTI_PLATFORM=1`; there is no arbitrary argument vector.
- Exactly one worker selector is required. `WorkerContext: dalec-azlinux3-worker`
  emits the deployed Dalec selector
  `--opt context:dalec-azlinux3-worker=docker-image://REPOSITORY@sha256:DIGEST`.
  Context names are bounded DNS labels and cannot replace `context`, `dockerfile`,
  or `source`. `WorkerArg` remains available only for a frontend whose approved
  contract actually implements that argument; it emits `--opt build-arg:NAME=IMAGE`.
  Neither selector is guessed, and the complete choice is frozen in the input
  and configuration digests.
- BuildKit endpoints must be `tcp://SERVICE.NAMESPACE.svc:PORT` (also accepting
  `.svc.cluster.local`) in the dedicated build namespace. Unix sockets, IPs,
  credentials in URLs, cross-namespace endpoints, and remote hosts are rejected.
  TCP requires mTLS: an immutable `Opaque` CA Secret with exactly `ca.crt`, an
  immutable `kubernetes.io/tls` client Secret with exactly `tls.crt` and `tls.key`,
  and a server name exactly equal to the endpoint hostname. All keys must be
  nonempty; Secret names must be valid and distinct. Neither plaintext nor a
  CA-only client is accepted. There is no TLS-skip-verification mode.
- The client projection is read-only at `/builder-client`, limited to
  `tls.crt`/`tls.key`; the CA projection is read-only at `/buildkit-ca/ca.crt`.
  Only fixed global buildctl arguments use these paths:
  `--tlscert`, `--tlskey`, `--tlscacert`, and `--tlsservername`. Neither projection
  is beneath `--local context` or `--local dockerfile`, and neither is mounted
  into subject Pods or the daemon's build LLB.
- CA/client Secret UID and resourceVersion metadata are pinned in the receipt
  and protected Job/Pod/anchor/ledger annotations before submission. They are
  rechecked immediately before Job creation and before/after termination
  observation. Credential bytes are not hashed, serialized into inputs/receipts,
  logged, or included in diagnostics/termination messages. Changing only Secret
  metadata does not change `InputDigest`, but invalidates observation of an
  existing operation. Cleanup still permits exact-UID deletion after rotation
  and never deletes the operator's TLS Secrets.
- Default worker resources are 250m CPU / 256 MiB memory, with configurable
  ceilings of 4 CPU / 8 GiB memory. The workspace is a size-bounded private
  `emptyDir`. The worker is UID/GID 65532, read-only root, RuntimeDefault seccomp,
  no capabilities, no privilege escalation, and no service-account token.
- The Linux worker caps its process/file limits at 128 / 1024 without increasing
  existing lower limits. The Job never retries a failed container. Candidate
  compilation resource limits belong to the separate daemon.
- The worker creates an exclusive private tree and stages regular mode-0600
  source files with confined `os.Root` operations and `O_NOFOLLOW`. Source bytes
  are data, never evaluated by a shell. Only `/usr/bin/buildctl` is executed.
  No ambient environment or registry credentials are inherited.
- For authenticated publication, `RegistrySecretName` selects an immutable
  `kubernetes.io/dockerconfigjson` Secret in the build namespace with exactly
  `.dockerconfigjson`. Its only projection is a read-only
  `/home/worker/.docker/config.json` in the trusted client container. Buildctl
  receives fixed `HOME=/home/worker` and `DOCKER_CONFIG=/home/worker/.docker`;
  neither location is a local LLB context or a subject mount.
- Before exec, the worker bounds the file to 64 KiB and requires exactly one
  `auths` entry whose key is the exact host/port of `OutputRepository` (for example,
  `localhost:5000`). Only basic `auth` or `username`/`password` is supported;
  optional `email` is inert metadata. Conflicting credentials, extra registries,
  URL/path aliases, duplicate keys, `credsStore`, `credHelpers`, token providers,
  command execution, custom headers, and unknown fields are rejected. Invalid
  config produces a generic infrastructure failure without invoking buildctl or
  reflecting the config.
- Registry Secret UID/resourceVersion is frozen outside `InputDigest`, bound to
  the Job/receipt, and checked with the mTLS references before submission and
  result acceptance. No authentication data or data-derived credential hash
  enters the input, configuration digest, journal, logs, diagnostics, or worker
  termination result. Cleanup deletes only operation-owned resources, not the
  operator's registry Secret.
- Buildctl stdout/stderr is fully drained into a bounded in-memory tail; reaching
  the retention limit does **not** kill a verbose build. Worker stdout contains
  only fixed phase names and counts. Full private logs are not persisted.
- Metadata is accepted only from a bounded regular, single-link, no-follow file
  outside the LLB context, with an unambiguous `containerimage.digest`.
- Buildctl receives fixed `--ref-file /workspace/build/build.ref`. In the pinned
  v0.31.1 implementation that file is written in a deferred return path, **not**
  before solving. Cancellation therefore sends SIGTERM to the owned buildctl
  process group and waits up to five seconds before forced termination. The
  worker then uses an independent bounded context (default ten seconds, maximum
  twenty) and the same fixed mTLS endpoint/options to run read-only
  `debug histories --format ...`. Its Go template filters the exact ref and emits
  only that ref and whether `Record.CompletedAt` is present. Full history events,
  credentials, and history stderr are not retained or forwarded.
- Only a successful history RPC with a matching completed record sets
  `WorkerResult.DaemonSettled`. Missing ref files, missing/pending history records,
  mismatched refs, malformed output, RPC failures, and timeouts remain explicitly
  unsettled. Metadata/buildctl success alone is not promoted into receiving-daemon
  completion. A 40-second Pod termination grace period leaves room for the
  bounded client shutdown, history lookup, and termination-message write.
- `debug ctl delete` is never used as cancellation: the pinned CLI has no cancel
  verb. SIGKILL/OOM before trusted completion evidence, forced Pod deletion, or
  a Job with no retained worker evidence leaves cleanup blocked with `ErrCleanup`
  or an identity/unknown error. There is no success-shaped fallback. Daemon
  history must remain enabled and retained long enough for these checks.
- The termination result is at most 4096 bytes. Diagnostics contain only known
  relative source paths and bounded line/column numbers, never source snippets
  or error text. `Symbol` is reserved and is not populated from untrusted stderr.
  Supply the trusted source inventory in `Policy.SourcePaths` when actual
  compiler paths are not among the supplied recipe/patch files.

## Required deployment preflight — parent/operator owned

The package does **not** install a namespace, NetworkPolicy, CNI, BuildKit
daemon, registry, runtime isolation, or admission rules. It does not treat their
existence as proof that isolation works. Before enabling it:

1. Pre-provision a dedicated, trusted build namespace. Deny subjects, candidate
   workloads, and model agents all API writes and network access to it. In
   particular, they must not create Pods or modify Pod status, Job templates,
   ledger/Secret data or annotations, owner references, finalizers, or CA material.
2. Validate the actual BuildKit Service/endpoints: no `ExternalName`, unexpected
   selectors, hostile DNS routing, privileged entitlements, or host execution.
   Use the preapproved isolated daemon. Its resource/time/pid limits and
   cancellation behavior are independent of the client Job's limits.
   Require mTLS authorization on the daemon; server authentication alone does
   not authorize a caller on a shared network. Create the immutable CA/client
   Secrets before submission. Use versioned names and never reuse a name while
   a referenced Job is live: Kubernetes Secret volumes reference names, not UIDs,
   so metadata checks cannot make projection and Secret replacement atomic.
   Secret changes fail closed for result acceptance; keep old named versions and
   frozen operator configuration available until their Jobs are cleaned.
3. Verify enforcing network policy: only trusted clients reach the BuildKit
   service; worker egress is restricted to approved DNS and that endpoint.
   Candidate/subject workloads cannot reach the namespace. Dalec's default or
   explicit `network_mode: none` is required; this is not a claim that frontend/source fetching,
   the registry exporter, or the daemon control plane is air-gapped.
4. Configure atomic namespace ResourceQuota/LimitRange and kubelet
   `podPidsLimit`. The adapter's per-run count check is an admission guard, not an
   atomic concurrent cluster-wide quota. Configure no service-mesh, credential,
   or sidecar injections for these Pods and no ambient default-SA pull secrets.
5. Use a trusted **single-platform** client image digest. The CRI must report the
   pinned digest in `ContainerStatus.ImageID`; an index/config-digest substitution
   fails closed. Test this on the actual intended runtime.
6. Preapprove frontend/worker pulls and the output repository, plus
   the daemon's source-fetch policy. Restricted-report execution must require
   the authenticated registry reference; an anonymous synthetic pass is not
   evidence of private-image confidentiality. The operator owns registry HTTPS,
   basic-auth repository permissions, BuildKit daemon registry CA configuration,
   and node/runtime trust and image-pull configuration. The worker does not add
   insecure-registry flags or general credential-provider routing.
   Do not put credentials in recipes, patches,
   build arguments, stdout, or the local context. Restrict Secret access and
   configure API-server encryption at rest; `Secret` is not itself encryption.
7. Grant only the adapter's required API operations in that namespace:
   - Namespaces: `get` on the dedicated namespace, to fence its UID.
   - ConfigMaps: `get`, `list`, `create`, `update` for operation ledgers and
     cleanup acknowledgements; no adapter ledger deletion.
   - Secrets: `get`, `create`, `update`, `delete` for immutable inputs and
     metadata/finalizer transitions.
   - Jobs: `get`, `create`, `update`, `delete` for execution and retention release.
   - Pods: `get`, `list`, `update`, `delete` for observation, exact cancellation,
     and retaining/releasing termination evidence through the settlement finalizer.
   - Owner-reference/finalizer admission must permit the Job's exact
     `blockOwnerDeletion` reference and the adapter's retention finalizers.
   The worker itself needs **no Kubernetes API permissions**.
8. Keep Kubernetes GC, Job-controller, kubelet, and node-liveness monitoring
   healthy. Cleanup requires both authoritative API disappearance and the trusted
   worker's exact-ref receiving-daemon completion proof. It does not prove
   physical power-off of a partitioned node or cache garbage collection. Do not
   force-remove evidence finalizers or treat history deletion as stopping a solve.
   Parent live qualification must confirm the actual buildctl/daemon cancellation
   and history behavior; unit subprocess fixtures are not a live claim.

The parent should persist the terminal result before calling cleanup and require
the cleanup receipt before final verification. A compile failure still needs
cleanup. Loss of a node, an indeterminate submit, or inability to confirm cleanup
must block final verification rather than manufacture success.

## Image and scoped verification

The Dockerfile is `cmd/orka-remediation-build-worker/Dockerfile`. It copies
`buildctl` from the approved BuildKit digest
`sha256:1ecb6f4906eb57f47e53ad9fa500c80959574a6c6326aad281f225cb9b5c1693`
and the Go worker into a digest-pinned distroless image.

```sh
mkdir -p bin/buildjob-work
export TMPDIR="$PWD/bin/buildjob-work" GOTMPDIR="$PWD/bin/buildjob-work"
go test -race ./internal/remediation/buildjob ./cmd/orka-remediation-build-worker
bin/golangci-lint run --timeout=3m ./internal/remediation/buildjob/... ./cmd/orka-remediation-build-worker/...
```

Tests use client-go's fake API with explicit UID/resource-version, immutable-data,
finalizer, and delete-precondition mechanics, and real subprocesses standing in
for `buildctl`. They test evidence validation, not a mock that always asserts
build success. **They are not live build, registry publication, CNI, actual Job
controller, image-runtime, or daemon-isolation qualification.** Deployment
preflight and live qualification remain parent/operator work.
