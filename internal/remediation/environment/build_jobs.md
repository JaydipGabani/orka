# Environment adapter: durable build Jobs

`Config.BuildJobs *BuildJobsConfig` opts `Adapter.Build` into the durable
`buildjob` backend. A nil value preserves the existing local BuildKit path,
including its wire/config digest shape. If both builders are configured, Jobs
take precedence.

The operator-only, JSON-copyable configuration is:

```go
BuildJobs: &environment.BuildJobsConfig{
    Namespace:        "remediation-build",
    WorkerImage:      approvedClientImage,
    BuildKitAddress:  "tcp://buildkit.remediation-build.svc:1234",
    OutputRepository: approvedPrivateRepository,
    RegistrySecretName: "private-registry-v1",
    WorkerContext:    "dalec-azlinux3-worker",
    TLS:              approvedBuildKitMutualTLSReferences,
    Limits:           approvedJobLimits,
    Args:             approvedReproducibilityArguments,
},
```

`Namespace`, `WorkerImage`, `BuildKitAddress`, `OutputRepository`, `WorkerArg`,
`WorkerContext`, and `RegistrySecretName` are strings; `TLS` is `*buildjob.TLS`, `Limits` is
`buildjob.Limits`, and `Args` is `map[string]string`. There is no Kubernetes
client, shell command, environment variable vector, registry token, or other
credential material in the frozen configuration. `TLS` must reference the
operator-created immutable CA/client Secrets and exact BuildKit server name;
only the trusted worker mounts client authentication material. Restricted/private
reports require the operator's **private internal HTTPS/basic-auth registry**
and `RegistrySecretName`; nil/empty registry authentication is only for synthetic
or public fixtures. Registry credential values are never copied into this config.

Choose exactly one of `WorkerContext` and `WorkerArg`. The former supplies the
actual Dalec named context:

```text
--opt context:dalec-azlinux3-worker=docker-image://<pinned-worker-image>
```

The latter is only for a different approved frontend with a known build-argument
contract; it is not a fallback when the named-context selector is required.

## Parent constructor and automatic-catalog integration

The parent installs the authenticated, dedicated client on `a.kube` through its
constructor wiring. Call `a.ValidateBuildJobs()` after assigning that client to
validate every catalog tuple without creating workloads. Each build reconstructs
a backend from that same client and frozen operator settings; it never loads
credentials or changes endpoint/TLS configuration from a model response.

Use `a.HasDurableBuildBackend()` as a required guard for **automatic** catalog
execution. Local `BuildKit` remains an explicit compatibility path, not a
restart-safe automatic provider. Neither method proves infrastructure isolation.
Constructor and service/catalog wiring are deliberately outside these files.
For restricted reports, also require `a.HasBuildRegistrySecret()` in the parent
pipeline gate; neither a configured reference nor synthetic tests independently
prove registry confidentiality. Registry TLS, auth permissions, and node image
pull trust/configuration remain operator-owned.

The worker preserves the existing `readRecipe` guard: the operator-approved,
pinned Dalec frontend's omitted network mode means `none`, and an explicit
override must also be `none`. Shared cache mounts are rejected. This integration
does not rewrite approved recipe bytes merely to insert a default, and it does
not require a provenance-schema change for recipes that use the default.

## State and recovery

- Preserve the exact `recipeSnapshot` file map. Existing vendor patches remain
  in their original order and bytes; candidates retain the existing final-patch
  append operation. Published originals are not rebuilt. Control/candidate roles,
  patch digests, source commits, recipe identities, and operation IDs remain
  separately bound.
- Validate the complete input against configured Job bounds before recording a
  submission. Store a frozen descriptor and consistency digest, provenance
  metadata, environment/configuration digests, and canonical input digest in
  `buildRecord.Job`. Do not store the file-map bodies in the run journal.
- Save submission intent before calling `Start`, and save any returned partial
  receipt, including accepted UIDs, even when `Start` returns an error or the
  caller is cancelled.
- A complete receipt resumes directly through `Observe`. Lost acknowledgement
  recovery calls `Start` with `RequireExisting`; it cannot create another Job.
  Re-materialized source bytes must match the already-frozen input digest.
- Poll without holding the run lock between observations. Cancelling the
  polling context leaves accepted work and the `started` record intact for the
  next leader; it does not invoke cleanup.
- Save terminal worker evidence before cleanup. `started` remains the state
  until the backend's explicit cleanup acknowledgement has `Stopped`,
  `SubmissionSettled`, and `DaemonSettled`, the exact bound receipt, and a valid consistency digest.
  No image or compile diagnostics are returned before that acknowledgement.
- Recovery after partial cleanup uses the saved terminal evidence, not a deleted
  Pod. Completed results are derived from the frozen base and measured outcome;
  input/configuration mismatches and altered cleanup evidence fail closed.

`BuildResult.CommandDigest` binds the frozen Job request descriptor.
`WorkerEvidenceDigest` and `MetadataDigest` identify the measured, UID-bound
backend result; they do not elevate partial source/image provenance into a
verified attestation. Only structured compiler path/line/column/symbol fields are
forwarded. No raw compiler output or source text is returned. The diagnostic
inventory is limited to supplied files and canonical paths named by the already
admitted patch series.

## Explicit cancellation

```go
err := adapter.CancelBuild(ctx, runID, operationID, frozenPlan)
```

This persists cancellation intent, finds only matching journaled build roles,
and cleans their exact Kubernetes identities. It can stop an active build while
the original caller is still polling. Missing operations, unavailable receipts,
and indeterminate submission settlement return an error and remain pending;
they never manufacture a cleanup acknowledgement or start work to cancel it.
Cleanup-only adapters may have an empty catalog and missing or changed recipe
files. `CancelBuild` validates the saved plan/checks digest, journal/source/recipe
binding, immutable request descriptor, frozen backend configuration, and exact
receipt without invoking current admission or reading recipe bytes. It does not
call `Build`, materialize a snapshot, or submit work to reconstruct missing
cleanup evidence.
Job or Pod disappearance alone is insufficient: the backend retains the trusted
worker's termination evidence and requires exact-ref BuildKit history completion.
SIGKILL before that evidence remains unsettled and must not yield a verified image.

Completed images and compile failures remain gated on persisted cleanup evidence.
A failed save after physical cleanup is still an error; the next leader can
recover the backend's retained metadata-ledger acknowledgement.

See [`../buildjob/README.md`](../buildjob/README.md) for mandatory namespace,
admission, ResourceQuota, image, network, runtime, and daemon-settlement
preconditions. Unit tests and receipt checks are not live qualification.
