# Local Kind operator bootstrap

[`scripts/remediation_local_kind.py`](../../scripts/remediation_local_kind.py)
packages the **local subject-lab** setup for the experimental server-managed
remediation path. It creates a fresh worktree-scoped Kind cluster, a separate
bounded BuildKit daemon with fresh mutual TLS, and a private clone of an
operator-approved policy/catalog. It makes **no model calls, report reads, source
builds, incident writes, or PRs**.

This is not a production installer or a remediation Helm chart. It deliberately
requires an existing private Orka control installation and model gateway, such
as Vekil, in another kindctl-managed cluster in the **same worktree**. It neither
deploys that control plane nor changes its credentials, routes, policy, database,
runs, or cleanup leases. Controller policy integration and end-to-end pipeline
qualification remain separate operator steps.

## Prerequisites and trust boundary

- Linux, Python 3.11+, Docker, Kind, kubectl, Helm, and OpenSSL already installed.
  No Python packages or downloaded helper executables are required.
- The vendored [kindctl](../../.agents/skills/kindctl/README.md) manages both
  cluster tags. Every Kubernetes/Helm command uses it; the global kubeconfig is
  never read, merged, or switched. An existing `.kind/setup.sh` is rejected,
  rather than executing an unrelated repository hook during bootstrap.
- An existing control cluster UID, controller Deployment UID, and gateway Service
  UID approved by the operator. The approved Copilot proxy endpoint must name
  that Service in its approved namespace. Upstream model credentials stay in
  the existing gateway. The tool does not acquire, copy, or rotate them.
- An existing TLS-authenticated registry container on Docker's `kind` network,
  approved by full container/network IDs. The supported output authority is
  `localhost:<registry.port>`; it must already match the approved policy. The
  registry certificate must validate for both `localhost` and its Docker
  container name. No repository rewriting or insecure TLS fallback is provided.
  Supply its **public CA** and private Docker config containing exactly one
  basic-auth `auths` entry for that authority; credential helpers and extra
  registry scopes are rejected.
- Approved, digest-pinned probe, observer, and build-worker images already
  available in that registry. Their paths come from the private approved policy,
  not this example. They must implement the existing Orka probe/build-worker
  contracts, including `/usr/bin/buildctl` and the bounded nonce probe protocol.
  Runtime image digests must match the actual platform image observed by kubelet.
  Registry checks negotiate OCI manifests/indexes and Docker schema-2
  manifests/lists. A `repository:tag@sha256:...` reference is checked through
  its repository and **digest**, never through a tag-bearing repository path;
  malformed or noncanonical repository/tag syntax is rejected offline.
- A local copy of the official Cilium **1.18.2** chart with SHA256
  `39b62a72f0892dd16548bd08ee97d5db2e975f7c1f57155578a144186e22992f`.
  The script checks the chart and fixes its IPAM, CNI image, and
  `policyCIDRMatchMode: [nodes]` settings. Kind's Kubernetes **1.34.0** node and
  BuildKit images are likewise pinned in the script.

BuildKit is a **privileged rootful Docker daemon**, requiring an explicit
additional approval flag. Its state, CA, server key, and client identity are
fresh; it shares only the existing registry's network namespace to preserve the
approved `localhost` output authority. It has no Docker socket, old daemon state,
or old daemon private keys mounted. Limits are 8 GiB memory with no extra swap,
4 CPUs, 2048 PIDs, and two parallel build operations. This is a shared-Docker-host
trust boundary, **not VM isolation or a production multi-tenant guarantee**.
There is no independent disk quota; size and monitor the private storage
filesystem before running separately approved builds.

Monitor the registry's server certificate separately from the lab's fresh
BuildKit certificates. Renewing a registry certificate must preserve its
approved CA and names, or require explicit trust re-onboarding. Restarting the
registry container replaces the network namespace shared by its attached
BuildKit daemons. After stopping new submissions and confirming their current
builds are fully settled, restart those exact owned daemons to reattach them;
retain their storage and TLS identities. Re-run verification before admitting
work. A responsive BuildKit Unix socket alone does not prove it can reach the
registry after that restart.

## Supply approved private inputs

Copy [`local-kind-operator.example.json`](local-kind-operator.example.json) into
an existing mode-0700 private directory outside every checkout. Set the copy to
mode 0600 and replace every placeholder. The example is intentionally
non-executable until completed; it supplies no recipe, provider credentials,
model approval, or default disclosure exemption.

The input policy must contain exactly one previously approved `copilot-acp-v1`
policy and one `dalec-keda-events` adapter for **`keda-event-publishing-v2`**.
Use an approved source profile with its existing cluster/role identity fields,
dedicated-cluster approval, and explicit candidate/model/time/security decisions.
No existing source cluster is accessed or adopted. Bootstrap changes those lab
identity fields only for the new lab. Other adapters, empty recipe catalogs,
legacy/local BuildKit backends, and missing approval decisions fail closed.

The supported catalog is one repository's approved `RecipeRoot`, matching
`approved.catalogRoot`, with no `SourceRoot` checkout. Each recipe must have a
relative `Path`, an optional relative `CatalogDirectory`, an exact SHA256 `Files` map containing the
recipe, and pinned frontend/worker/original images. The tool hashes and copies
**only** these declared files, opaquely, into the new private catalog. It does not
parse recipes, execute them, copy an entire checkout, discover missing inputs,
or inspect reports/candidates. Keep private inputs owner-readable only.

Supply the six required public KEDA CRDs as one approved, digest-pinned JSON
`v1/List`. Each item must contain only `apiVersion`, `kind`, `metadata: {name}`,
and the approved `spec`; no copied UIDs, status, annotations, owner references,
RBAC, or webhook conversion. Required names:

```text
scaledobjects.keda.sh
scaledjobs.keda.sh
triggerauthentications.keda.sh
clustertriggerauthentications.keda.sh
cloudeventsources.eventing.keda.sh
clustercloudeventsources.eventing.keda.sh
```

Obtain that bundle through your approved artifact process; this script does not
copy resources merely because their names match in some existing cluster.
The installed watch ClusterRole is the compiled two-rule read-only contract:
`get/list/watch` on the two cluster-scoped KEDA authentication/event resources.
There is no configurable RBAC override or cluster-admin grant to subject Pods.

Choose a **new, unused** subject tag of at most 16 lowercase DNS-label characters,
a canonical kindctl spelling with no repeated hyphens (for either cluster tag),
a **nonexistent** private root under an existing private parent, and unused
private IPv4 Pod/Service CIDRs. The example CIDRs are suggestions, not a reservation.
The tool checks the selected control nodes and Docker network for overlap; the
operator must also check other lab routes and VPN networks. Existing roots,
tracked tags, kubeconfig files, Docker names, non-owned resources, and occupied
or indeterminately reachable BuildKit ports are not reused.

## Plan, approve, and apply

Run from the checkout containing kindctl. In these commands, `BOOTSTRAP_INPUT`
is your private completed template; **do not put credential values in arguments**.

```bash
python3 -B scripts/remediation_local_kind.py plan --config "$BOOTSTRAP_INPUT"
python3 -B scripts/remediation_local_kind.py validate --config "$BOOTSTRAP_INPUT"
```

`plan` and `validate` are identical **offline, nonmutating** checks: no subprocess,
Docker, Kubernetes, registry, network, directory creation, or approval changes.
They validate local inputs and return a `planDigest`, source/catalog hashes, and
file count. They do not attest online readiness. Do not mistake a public template
or an offline success for an approved runtime policy.

After independently reviewing those inputs and the local privileged boundary:

```bash
python3 -B scripts/remediation_local_kind.py apply \
  --config "$BOOTSTRAP_INPUT" \
  --approve-plan "$PLAN_DIGEST" \
  --approve-existing-control "$CONTROL_CLUSTER_UID" \
  --approve-privileged-buildkit
```

Apply checks the pinned existing control/registry identities before provisioning.
It creates independent containerd/storage mounts; installs Cilium, the six CRDs,
and the exact role; configures kubelet `podPidsLimit: 512`; and creates the
`remediation-builds` namespace, immutable CA/client/registry Secrets, a BuildKit
Service/EndpointSlice, and a narrow build-client NetworkPolicy.

The controller kubeconfig remains a private file with a verified HTTPS endpoint.
Its local administrator authority is for the dedicated lab's trusted operator,
never a subject/model Pod. Trusted build-client probes mount only their new
BuildKit client identity; CNI probes have no credentials or ServiceAccount token.
Secrets are sent through process-private stdin, never literal command arguments,
logs, last-applied annotations, or printed manifests. Error output contains fixed
codes rather than raw subprocess, API, registry, or certificate errors.

## Output and qualification

The new private root contains:

| Path | Purpose |
| --- | --- |
| `operator-data/policy.json` | Cloned controller policy; new name, lab identity, paths, BuildKit endpoint and Secret references only |
| `operator-data/lab.kubeconfig` | Mode-0600 private controller-to-subject credentials |
| `operator-data/catalog/` | Only approved, hash-matching catalog files |
| `operator-data/output/`, `operator-data/scratch/` | Independent controller output/scratch roots |
| `lab/` | Private TLS, registry trust/auth, chart, Kind config, and independent daemon/node storage |
| `ownership.json` | Exact resource/daemon identities, policy hash, phase, and sanitized verification evidence |

Apply reports `ready` only after checking API TLS, authenticated registry access,
the node/CRD/role pins, BuildKit resource/mount boundaries and mTLS (including
no-client rejection), and a trusted Kubernetes build-client connection. It runs
literal-IP nonce probes that measure CNI ingress/egress denial with positive
controls; NetworkPolicy presence alone is insufficient. Probe cleanup uses UID
preconditions and waits for disappearance. It submits **no build or model task**.

Repeat those online probes, without reprovisioning, using `verify` and the same
three approval flags. A verification lock, changed UID/spec/policy, leftover
probe, or incomplete ownership receipt blocks reuse. Once owner, lab ID, and plan
digest are verified **and the prior phase is `needs-verification` or `ready`**,
the receipt is persisted as non-ready before checking the staged policy hash,
probe inventory, or live resources. Those subsequent failures
cannot retain an earlier success. Failures before ownership is established
(including input, approval, or lock failures) do not rewrite the receipt; an old
receipt is historical evidence, not proof of current readiness.

`verification.lock` serializes verification attempts; it is **not** held while
apply provisions resources and records their identities. Verification rejects
`preparing` and every other unsupported phase without writing the receipt or its
staging file. It must not invalidate a stale preparing snapshot over an apply
acknowledgement or collide with apply's `ownership.next.json`. Wait for apply to
reach its verification phase; the lock is not a general apply/recovery mutex.

Retain the completed bootstrap input and **all original approved input paths**
unchanged for later `verify`: policy, catalog files, CRD bundle, registry public
CA/auth, and pinned chart. Verification reloads them before accepting the plan,
even though apply staged private copies. Do not move them, edit their paths or
bytes, or change `KINDCTL_STORE` and expect the same approval to remain valid.
Credential rotation is a separate approved operation, not an automatic replan.

The cloned policy preserves source/recipe/image selection, Copilot image/proxy/
identity references, model/candidate/time budgets, disclosure and plan/test
approval settings, and scenario semantics. Integrate it into the existing private
operator installation **without replacing old policies or persistent data**.
Containerized controllers need the staged paths mounted at their exact configured
locations (catalog/kubeconfig read-only; output/scratch writable). The tool does
not patch the existing Deployment or assume that these paths are already mounted.

Before using the policy, separately:

1. Verify control-to-subject API and observer-Pod routing. The generated node
   address and Pod CIDR are in `ownership.json`; no control routes are changed.
2. Run the actual controller's policy readiness and exact cluster/role pin checks.
3. Obtain fresh **per-run adapter-issued** isolation and cleanup evidence. The
   saved operator preflight is not a reusable per-run authorization receipt.
4. Qualify the current controller pipeline and, when separately approved, the
   model/source-build/end-to-end path.

Client/server certificates last seven days; the private CA lasts fourteen days.
There is no automatic rotation or in-place Secret replacement. Provision or
rotate through a separately reviewed operation before expiry.

## Failure and cleanup policy

Apply is **create-only**, not an adoption/recovery or destruction tool. A failed
apply preserves the fresh root and acknowledged identities for inspection. Do
not rerun apply over it, remove locks blindly, or delete/force-release any old
lab or cleanup lease. Ambiguous create acknowledgements, crashes, and leftover
probes need operator reconciliation using the recorded exact identities.
There is no automated cluster/daemon deletion command; first settle all future
runs, verify ownership independently, then use scoped kindctl and exact Docker
container IDs under your cleanup procedure.

Kind/containerd and rootful BuildKit can leave **root-owned files** inside the
new lab's private bind mounts. Stop and remove only that lab's exact, verified
containers and scoped cluster before removing its storage. Filesystem cleanup
may require local administrator authority; a normal user-level directory removal
is not sufficient. Recheck the canonical private root and reject symlink or mount
escapes before any privileged removal. Never recursively change ownership or
delete a shared parent, registry store, another lab, or an active run's files.
Preserve the ownership/evidence receipt and approved original inputs until
reconciliation and cleanup are complete.

Tests include offline checks against kindctl's actual tag/name derivation,
regression sensitivity for readiness invalidation and registry media/path
handling, plus mocked TLS/registry/daemon identity and resource-boundary checks.
They do **not** execute real certificate handshakes, container creation, Helm/CNI
installation, Kubernetes admission/defaulting, or the full live verification
path. Earlier manual lab setup does not qualify this packaged script. A
separately approved fresh-lab apply/verify/cleanup exercise remains necessary;
these checks are not a replacement for it. Run the safe tests with:

```bash
python3 -B scripts/tests/remediation-local-kind-test.py
python3 -B scripts/remediation_local_kind.py --help
```
