---
slug: /patch-verification
description: "Run supplied-report validation and patch comparison in isolated Kubernetes Jobs."
---

# Report validation and patch verification on Kubernetes

The opt-in Kubernetes backend runs the same frozen checks and evidence
adjudication as the local `patchverify` POC, using actual Orka Tasks and
one disposable Job per check. It does not run Docker inside Kubernetes.
The feature remains experimental: validate your node image, container runtime,
admission policies, storage, and network-policy enforcement before enabling it.

## Architecture

```text
Authenticated caller
  -> POST /api/v1/validations
  -> namespace-scoped input preparation and durable submission
  -> leader-owned recovery loop
  -> original Task UID [and patched Task UID]
  -> immutable source/check bundle + per-check Job
  -> trusted supervisor / unprivileged checked program
  -> controller-observed Job, Pod and container identities
  -> dedicated SQLite evidence, per-check results and one-time seal
  -> Job/Pod/ConfigMap/NetworkPolicy cleanup; evidence remains
```

`validate-report` finishes after the original checks. `verify-patch` requires
every original reproduction and required normal-use check before starting
the patched arm. A completed earlier validation supplies frozen checks and
context; the new verification still executes both versions. Job success
is not a claim that a report was reproduced or a patch was verified.

The controller persists preparation and dispatch identities before progressing.
After a restart it observes the same Task/Job instead of creating a replacement
check attempt. Cancellation is durably fenced against finalization. Cleanup
uses exact owners and UIDs, and does not delete the evidence record.

## Standard AKS node requirements

No custom node-local seccomp profile, Landlock, Docker socket, privileged
validation Pod, host filesystem mount, or alternate RuntimeClass is required.
This is a shared-kernel process sandbox, not a virtual-machine boundary.

| Requirement | Reason |
| --- | --- |
| Linux amd64 or arm64 node pool and matching pinned images | The helper checks the native architecture; emulation is not part of the result. |
| Container `RuntimeDefault` seccomp and ordinary process seccomp support | The trusted guard installs an additional inherited syscall policy before running checked code. Unsupported isolation fails closed. |
| A namespace permitting the Kubernetes **Baseline** Pod Security Standard | The supervisor starts as UID 0 with only `CHOWN`, `FOWNER`, `KILL`, `SETGID`, and `SETUID`; checked code and fixtures run under separate unprivileged identities with no capabilities. This template does **not** satisfy Restricted admission. |
| Enforcing NetworkPolicy for local-service checks | All Pod ingress and egress is denied. Only loopback fixture traffic inside the Pod is needed. Simply creating a NetworkPolicy object is insufficient. |
| A controller-reachable numeric TCP canary for local services | The controller confirms reachability; the worker must observe a connection timeout before starting checked code. Refusal, routing errors, or successful connections are not accepted as proof of isolation. |
| Persistent controller SQLite volume and stable snapshot key Secret | Evidence and control state must survive controller Pod replacement. Use one controller replica and `Recreate` with the current SQLite backend. |
| Operator-provisioned, read-only source/check input volume | Requests currently reference local paths below one namespace root. Repository acquisition is not delegated to untrusted workloads. |
| Controller image containing Git and `/usr/bin/prlimit` | Source preparation imports exact Git objects under resource limits. The normal distroless controller image lacks these tools. |

AKS enables [Pod Security Admission](https://learn.microsoft.com/en-us/azure/aks/use-psa).
An enterprise policy may reject this supervisor even when namespace PSA is
Baseline; do not bypass that rejection by using privileged Pods or adding
broader capabilities. An approved namespace-specific policy is required.

For local services, use an AKS configuration with an
[enforcing network-policy engine](https://learn.microsoft.com/en-us/azure/aks/use-network-policies),
such as Azure CNI powered by Cilium. Policies must enforce all enabled address
families. The single canary is an enforcement sanity check, not proof that
every destination or network-policy configuration is safe. Do not place
unrelated workloads or broad allow-all policies in the validation namespace.

## Images and configuration

Build and publish the helper image from
[`workers/validation/Dockerfile`](../../../workers/validation/Dockerfile)
to an approved registry such as ACR. It contains the static supervisor and
process guard, not project dependencies. Publish a tool image containing the
project's build/test tools and dependencies. Pin both by digest; the worker
does not install tools or fetch dependencies at runtime.
Use the AKS node/kubelet identity's registry-pull permission for ACR; do not
mount Azure credentials, repository credentials, or publication tokens into
the validation worker.

The development controller image is provided separately under
[`config/development/patch-verification/`](../../../config/development/patch-verification/).
It packages a prebuilt controller in a pinned Alpine base with Git and
`prlimit`. It is intentionally not substituted for Orka's normal distroless
image. For a production image, retain the required preparation tools, the
non-root controller user, read-only root filesystem and writable bounded
temporary storage; review and pin the resulting image independently.

Required validation flags:

```text
--validation-enabled=true
--validation-input-root=/validation
--validation-helper-image=REGISTRY/helper@sha256:DIGEST
--validation-tool-image=REGISTRY/tool@sha256:DIGEST
--validation-tool-image-id=EXPECTED_CRI_IMAGE_ID
--validation-platform=linux/amd64
--validation-profile=offline
```

The default node selector is `kubernetes.io/os=linux`; the Job also selects
the frozen architecture. The expected runtime image identity must match the
platform-specific identity observed by the CRI, not an assumed tag or a
multi-platform index identity.

For local services, additionally configure:

```text
--validation-profile=local-services
--validation-local-services-enabled=true
--validation-network-canary=CANARY_IP:PORT
```

The Job has no ServiceAccount token, no host mounts or host namespaces, a
read-only root filesystem, bounded resources and writable disposable volumes.
Its init container installs the trusted helper. The supervisor makes sources
and checks read-only and creates separate private scratch directories.
Checks must use `$TMPDIR`, not assume that `/tmp` is a shared writable directory.
See the [worker contract](../../../workers/validation/README.md).

Do not change images, checks, input bytes or test setup to rescue a passing
result. Submit a new run. A linked run cannot silently change the frozen
environment of its earlier validation.

## API and authorization

The current API supports Kubernetes TokenReview identities only. Direct OIDC
and transaction-token validation access are rejected rather than treated as
implicitly authorized. Namespace isolation and exact SubjectAccessReviews
apply to every operation:

| Operation | Permission in `core.orka.ai` |
| --- | --- |
| `POST /api/v1/validations?namespace=NS` | `create` on `validations` |
| `GET /api/v1/validations/REQUEST_ID?namespace=NS` | `get` on that `validations` name |
| `GET /api/v1/validations/REQUEST_ID/evidence?namespace=NS` | `get` on that `validations/evidence` name |
| `GET /api/v1/validations/REQUEST_ID/evidence/DIGEST?namespace=NS` | Same evidence permission |
| `POST /api/v1/validations/REQUEST_ID/cancel?namespace=NS` | `update` on that `validations/cancel` name |

`earlierValidation` is the completed report's **run ID**, not its request ID.
The API resolves it within the same namespace and authorizes the exact earlier
request's evidence before preparing a new run. A link to another namespace or
an inaccessible record cannot supply evidence.

Progress includes submission state, run/task/attempt identity, required and
recorded check counts, and the effective assessment. Read the evidence endpoint
for the frozen manifest, observation metadata, incidents, and seal.
Captured bytes are retrieved by digest. `terminal` is orchestration state;
the assessment distinguishes verification, remaining problems, regressions,
and inability to reach a conclusion.

## Local Kind validation

Use a dedicated worktree-scoped cluster; do not switch the global kubeconfig.
The bootstrap requires Docker, Go, Kind, kubectl, Python 3, jq and the repository
Kustomize binary. Use a Kind version compatible with the selected node image.

```bash
bash scripts/patch-verification-kind-e2e.sh
```

This installs CRDs and the development validation deployment, builds and loads
the controller/helper/tool images, assigns immutable local containerd
references, and writes a private artifact directory under `bin/validation-e2e/`.
That directory includes a short-lived caller credential; never publish it.
The script does not install or weaken cluster-wide admission/network controls.

The ordinary Kind CNI does not enforce NetworkPolicy. To exercise successful
local-service checks, first install an appropriate policy engine in this
dedicated cluster. Without enforcement the canary check must prevent
execution. Do not interpret an unavailable HTTP connection as a repaired bug.

In another terminal, using the same tag:

```bash
.agents/skills/kindctl/bin/kindctl kubectl --tag validation-542 \
  -n orka-validation port-forward --address 127.0.0.1 service/validation-api 8080:8080

python3 scripts/patch_verification_kube_conformance.py \
  --artifacts bin/validation-e2e/ACTUAL_RUN_DIRECTORY \
  --url http://127.0.0.1:8080 --profile offline
```

The conformance driver creates operator-owned fixture Git inputs in the input
PVC, submits authenticated API requests, and asserts exact conclusions and
observed Kubernetes identities. It checks both source/patch forms, repeated
reports, linked runs, evidence preservation, cancellation, restart without
Job replay, and runtime cleanup. It does not publish branches or pull requests.

For local services, render the optional
[`canary.yaml`](../../../config/development/patch-verification/canary.yaml)
with the pinned tool image, configure the controller with the canary Service IP
and local-services flags, and run the driver with `--profile local-services`.
This exercises HTTP and the **modeled** configuration lifecycle, including a
temporary setting that reconciliation undoes.

Use temporary build/test directories **outside** the checkout. Go module-wide
generation can discover temporary `.go` files even inside gitignored `bin/`
directories. Only finished build artifacts and retained test reports belong
there.

## Explicit limits and rollout

- Exact local Git commits and local patch files are supported; remote cloning,
  private forge credentials and PR URL resolution are not implemented here.
- Checks are supplied and trusted independently of the patch. Captured output
  is not independent proof that an arbitrary project-defined test is complete.
- Full cluster/controller environments *under test*, external services and
  separate test identities remain unsupported and return action-appropriate
  `Unable` results. Running the runner on Kubernetes does not add those
  environment capabilities.
- Input bundles are bounded (512 KiB compressed); source archives, frozen
  files, outputs and total evidence also have limits. Oversized input is not
  silently truncated into usable evidence.
- The current SQLite deployment is single-replica, not a multi-replica shared
  database/HA design. Monitor its PVC capacity; there is no automatic evidence
  retention deletion in this POC.
- Scope the feature to an isolated namespace, publish immutable images, grant
  only the documented caller permissions, and validate failed setup, rejected
  isolation, cancellation, restart and cleanup on the actual AKS node/CNI
  combination before expanding use.
- To disable the feature safely, stop new submissions and let active runs
  settle or explicitly cancel them while the validation controller is still
  enabled. Verify Jobs/Pods and validation cleanup finalizers are gone before
  disabling the flag. Evidence remains in the persistent store.

Kind conformance demonstrates Kubernetes behavior, not an AKS qualification.
No AKS cluster, ACR registry, Azure identity or production resource is created
by these local scripts.
