# Isolated AKS remediation verification foundation (approval-gated)

This is a **reviewable development infrastructure template, not a qualified
cloud installer**. It does not install Orka, BuildKit, KEDA, candidates, model
credentials, or incidents. `scripts/remediation_local_kind.py` remains local-only.
Do not point that installer at AKS.

## Fixed scope

- One **new** resource group and one AKS-created node resource group, named from
  `orka-verify-<suffix>`. Do not reuse or pre-create the node resource group.
- AKS **1.35.8**, Free control-plane tier, **two Standard_D4s_v5 Linux nodes**
  (4 vCPU / 16 GiB each), one fixed pool, no autoscaling. AKS requires System-pool
  upgrade metadata `maxSurge=1`, `maxUnavailable=0`; this is not approval to create
  a third node. No manual upgrade or scale-up is allowed during this 24-hour lab.
  No zones, SKU fallbacks, automatic upgrades, or other regions.
- Azure CNI **Overlay / Cilium**, private API, no public API FQDN, no AKS Run
  Command, managed Entra authentication, local accounts disabled, OIDC and
  workload identity enabled. Azure RBAC is initially enabled only for the
  temporary operator bootstrap; the new verification cluster must switch to
  native Kubernetes RBAC before application admission. The existing control
  cluster's authorization mode is unchanged. No managed KEDA, ingress, or
  monitoring add-ons.
- Every build/test-eligible node is in that one pool. ARM `kubeletConfig.podMaxPids`
  is **512** (the API setting corresponding to kubelet `podPidsLimit`). Verify the
  effective kubelet configuration before accepting workloads.
- One **Standard_D4s_v5** Linux builder VM, no public IP or managed identity.
  One 64-GiB Standard SSD OS disk and one independent 64-GiB Standard SSD state
  disk. AKS node OS disks are each 64 GiB; their storage SKU is AKS-managed.
- New VNet, two subnet NSGs, **one NAT gateway and one egress-only public IP**.
  Explicit NAT is necessary for the VM; an AKS load balancer's SNAT does not
  automatically cover an unrelated VM. No workload public ingress is created.
  Keep these network/storage costs in the approved daily estimate.
- One temporary **Basic ACR** in the exact verification group, approximately
  **$0.1666/day plus storage/traffic**, removed with that group. Its globally
  unique name is `orkaverif<suffix>` (alphanumeric, 5–50 characters), checked
  before arming. Public connectivity is authenticated, images are private,
  admin/anonymous access is disabled, and `LegacyRegistryPermissions` is
  explicit and read back so `AcrPull` is effective. No ACR Tasks, webhooks,
  replications, tokens, scope maps, or extra storage are created.
- Only the actual existing control kubelet and actual new verification kubelet
  receive `AcrPull`, scoped solely to that new registry. Object IDs are read
  from the exact AKS resources and audited; client IDs are not substituted.
  No existing registry settings or IAM are changed. Image copies, repository
  names, and repository-scoped expiring build credentials/Secrets remain the
  parent's responsibility. No push/provisioning credentials go to the VM,
  candidate, Copilot, or Orka runtime.

## One bounded approval proposal — not an authorization to apply

There are three approval items. No scheduler, registration, role grant, peering,
DNS link, or trusted setup Job is created by this template or the planner.

1. **Independent cleanup service and explicitly approved built-in authority.**
   A CronJob on a single-node control cluster has durable desired state but cannot
   execute when that node is unavailable. It is not sufficient as the sole
   24-hour reaper; do not resize the control cluster to solve this.

   Proposed resources in one separate `rg-orka-verify-<suffix>-cleanup` group:
   one Azure Automation account with a system-assigned identity, one PowerShell
   7.4 runtime environment, one published runbook, and **two nonrecurring one-shot
   schedules/bindings**. The primary starts at `T0+22h`, with an independent
   catch-up attempt at `T0+23h`; neither starts new verification work. Two
   schedules, rather than a single process retry loop alone, are requested
   explicitly so a stopped/lost first execution still has a durable retry.
   Each run is bounded to 60 minutes, with idempotent ARM operations,
   `Retry-After`/backoff handling and recorded terminal success/failure. No Hybrid
   Worker, VM, Storage account, Log Analytics workspace, webhook, recurring
   schedule, or reaper permission to create more jobs is proposed.

   Public retail runtime pricing is approximately **$0.002/minute** after the
   subscription-shared first 500 free minutes/month. Do not assume unused free
   minutes. Two 60-minute attempts plus a 10-minute read-only preflight cost at
   most **$0.26** at that rate. If application time bounds fail, Azure's
   three-hour fair-share limit for ordinary PowerShell jobs gives a conservative
   **$1.08** for those three executions; do not use a restartable Workflow
   runbook. This is a separately approved small control-plane cost, not another
   management cluster. Confirm current prices in the private receipt.

   If `Microsoft.Automation` is unregistered, its registration on the explicitly
   approved subscription is also an approval item within this cleanup step.
   Only the trusted provisioner performs provider registration. The
   `builtin-group-cleanup-v1` permission model creates **no custom Azure role
   definitions** and is not equivalent to the previous delete-only custom roles.
   Explicitly approve these assignments to the dedicated cleanup identity:

   | Built-in role | Exact scope | Permission trade-off |
   | --- | --- | --- |
   | Resource Group Contributor (`94877a25-7520-40c5-9c42-68e02e4758bd`) | Only the owned verification group and, after creation, its owned node group | Group read/write/delete; not individual VM/AKS management |
   | Reader (`acdd72a7-3385-48ef-bd42-f606fba81ae7`) | The approved subscription | All control-plane `*/read`, broader than group/peering metadata |
   | Network Contributor (`4d97b98b-1d4f-4787-a291-c67834d212e7`) | Only the exact newly created control-side peering | Network read/write/delete within that child scope, not the control VNet or NSGs |

   The operator reads back each built-in role's ID, type and complete action set,
   checks its lack of data actions and exclusions, and audits all assignments
   visible for the cleanup principal. Extra grants, different scopes, conditions,
   duplicated bindings, or unrecorded existing assignments fail closed. The
   post-grant list audit waits at most 120 seconds when the observed bindings
   are only a strict subset of the exact recorded set. Extra or changed
   bindings, conditions, malformed results and pagination are never retried
   as missing data. This is a read-only consistency wait, not another grant.
   The
   runbook requires an explicit version-2 manifest and verifies the exact
   effective group-cleanup action set during preflight; it does not simply
   disable the former wildcard guard.

   Resource Group Contributor permits group writes as well as deletion. Reader
   exposes other resource configuration in this subscription. Neither grants
   IAM mutation, workload Kubernetes administration or data-plane credentials.
   The cleanup identity cannot modify its own Automation account or delete its
   cleanup group. The trusted provisioner retires only the recorded assignments
   and cleanup group; **it never deletes built-in or shared role definitions**.

   Prepare the owned empty verification group and cleanup service before
   billable foundation resources. Perform a read-only identity/permission
   preflight, set `T0`, publish and read back **both** enabled UTC schedules,
   runbook/code digest, bindings, parameters and target scopes, then start the
   maximum 24-hour foundation lifetime. Node-group and peering grants follow
   their exact resource creation and must be read back before workloads begin;
   the primary AKS/group delete path must already be armed for partial creation
   failures. The node group must never be pre-created or reused.

   At cleanup, validate exact IDs, ownership/expiry/cleanup-receipt tags and the
   AKS-to-node-group relationship. Read and validate the known AKS/VM children,
   then request deletion of the exact owned verification group. Azure performs
   cascading resource deletion; no individual VM/AKS delete operation is
   authorized or issued. Poll the containing group until authoritative absence
   before attempting the owned residual node group and exact control-side
   peering, but **an ungranted or removed residual read
   scope must not retain the owned main group's billable NAT/disks**. Continue
   main-group deletion even if an independent residual read is 403 or its
   ownership proof is refused. Keep per-target evidence and report incomplete/
   failed verification rather than success when a residual remains ambiguous.
   A catch-up can clean a positively identified residual after the main group
   is gone. Never interpret 403 as absence; only a resource GET 404 or terminal
   DELETE 204/404 establishes absence in that attempt. A 202 acceptance alone
   is not deletion proof.
   A residual node group requires its recorded ownership proof and approved exact
   scope. Never delete an unrelated or inherited assignment or a resource based
   on a tag alone.

   Resource-scoped assignments can disappear with their targets. The explicitly
   approved subscription Reader survives those deletions. The managed-identity
   preflight proves authoritative 404 reads of the not-yet-
   created node group/peering before the clock. Child resource GETs stop when
   their containing group is authoritatively absent. Denied/uncertain reads
   still fail closed and never become success. The trusted `retire` phase
   records physical absence and removes the exact assignments before retiring
   the cleanup account/group.

   Automation retains job status/output for up to 30 days independently of the
   control cluster. A named operator must check the durable status after each
   scheduled start and before `T0+24h`, and act on Failed/Stopped/Suspended,
   missing-start or residual-resource signals. No paid alert service is silently
   assumed. Azure scheduler/ARM availability can still delay deletion: this is
   an automated cleanup strategy with recovery, **not a hard billing cap or a
   proven deadline guarantee**. Provider authorization, async polling scopes,
   actual dispatch and delete behavior remain unverified until qualified.

2. **Private connectivity and one trusted setup Job.** Approve the two VNet peerings (one writes the existing
   control VNet) and a link from the new AKS private DNS zone to the control VNet.
   Peerings need virtual-network access only: no forwarded traffic, gateway
   transit, or remote gateways, and **no existing NSG changes**. The new node NSG
   permits control-node-to-verification TCP 443, denies other control-VNet
   ingress and verification-initiated control-VNet connections. The builder NSG
   permits only trusted control-node mTLS clients on TCP 1234. Check effective
   routes, private-endpoint behavior and policy-injected NSG rules before any
   network enforcement claim.
   Do not add an `Allow` rule for `AzurePlatformDNS`: platform service tags are
   deny-only opt-outs. [Azure's 168.63.129.16 documentation](https://learn.microsoft.com/azure/virtual-network/what-is-ip-address-168-63-129-16#scope-of-azure-ip-address-1686312916)
   states that platform DNS on TCP/UDP 53 bypasses NSGs unless explicitly denied
   with that tag; host-agent WireServer TCP 80/32526 also bypasses NSGs.
   Removing the invalid DNS allow does not relax the builder's lateral deny,
   HTTPS-only ordinary outbound allowance, ingress boundary, or independent
   guest CNI/nftables IMDS and WireServer controls.
   No peering or existing-network DNS mutation is included in this template.
   Use one nonprivileged, bounded trusted setup Job/ServiceAccount in the existing
   control namespace, reached through that cluster's already working public API,
   for private DNS/API/mTLS checks. With separate explicit approval, the same
   restricted Job can provide an operator-only TCP tunnel reached through a
   loopback-only port-forward. It forwards opaque TLS to only the exact private
   AKS endpoint, has no public Service, and receives no operator credentials.
   The operator retains Entra authentication and validates the original API
   hostname and CA. Remove the tunnel/Job after bootstrap.
   Application clients use the standard private AKS FQDN and explicit native
   workload identity configuration; no proxy origin or ambient identity
   fallback. No VPN, Bastion, jump VM, SSH route, new management
   cluster, public verification API, or privileged builder on control nodes is
   requested. VM daemon bootstrap remains separately staged: this Job is not
   permission to enable VM extensions or grant it guest administration.

3. **AKS service-managed authority.** Azure documents a **Contributor** grant on
   the managed node group for the control-plane identity. It contains wildcard
   actions and requires an explicit exception for that identity and exact new
   node group; a what-if need not list this provider side effect. Separately,
   the template assigns built-in Network Contributor to the new AKS identity
   on only its new VNet, node NSG and NAT gateway. It never creates a network
   custom-role definition. Do not grant Owner, change the existing cluster
   identity, or assign these management roles to Orka or candidate workloads.

## Traffic and identity boundaries

| Caller | Destination | Required path |
| --- | --- | --- |
| Trusted control controller / observer | Verification Kubernetes API, TCP 443 | Peered VNet + private DNS; Azure workload identity and **separately reviewed** Kubernetes RBAC |
| Trusted build client Job on control nodes | Builder private IP, TCP 1234 | Peered VNet + mTLS; source is the control **node** subnet after overlay SNAT |
| Trusted operator | Verification API, TCP 443 | Explicitly approved temporary loopback-only TCP tunnel through the restricted setup Job; end-to-end TLS/Entra authentication, no public API proxy |
| Observer operations | Verification Pods/Services | Kubernetes API-mediated watches/logs/exec/proxy as authorized; **not** cross-cluster Pod IP or Service IP routing |
| Untrusted build steps | Public registry/package endpoints, TCP 443 | Explicit guest CNI bridge; guest forwarding denies IMDS and non-DNS WireServer; no host-network entitlement |
| Trusted VM platform agents | Azure IMDS / WireServer | Host access remains available for cloud-init and every boot; VM has no managed identity |

No observer endpoint, Service, or public ingress is installed here. Confirm the
parent's observer uses an API-mediated path; a required direct callback needs a
separate reviewed private endpoint and rules, not an implicit Pod-CIDR route.

Use distinct identities for the trusted provisioner, AKS control plane, controller
Kubernetes API access, kubelet ACR pull, and trusted publication ACR push. This
template does not configure controller federation or registry push grants. Its
only registry permissions are the two approved kubelet `AcrPull` assignments on
the isolated registry. The parent handles any repository-scoped build access
without enabling registry admin access, altering the registry mode/networking,
or forwarding an Azure identity into BuildKit.
Workload identity enablement does not grant model or incident-system access.

The parent's native controller Kubernetes client requires the standard AKS
`*.azmk8s.io` HTTPS origin on port 443, including a standard private AKS FQDN.
Preserve that endpoint and its embedded CA: do not substitute a custom API
proxy, loopback URL, IP address, or tunnel endpoint. Its dedicated kubeconfig
contains an **empty user**, not an exec plugin, admin credentials, or an ambient
Azure login. Federation must bind only the approved trusted control ServiceAccount
subject and its exact OIDC issuer to a separate controller identity on the new
resources; token audience is `api://AzureADTokenExchange`. Tenant/client/projected
token-file wiring and the enumerated Kubernetes data permissions are the parent's
scope. The operator's separate Entra login is not that workload identity.

## Plan / what-if (non-mutating)

Use Azure CLI + its Bicep compiler. Keep actual subscription IDs, public SSH keys,
parameters, outputs, approval receipts, and kubeconfigs in a private persistent
directory **outside Git**. Never use a global kubeconfig or `--admin`. The example
parameters intentionally contain invalid placeholders and cannot be deployed.

1. Read the exact existing control network, subnets, NSGs, route tables, registry
   mode, Dsv5-family/regional-core quotas, SKU restrictions, and AKS versions.
   Confirm 12 additional vCPUs fit both quotas. Non-zonal D4s_v5 availability does
   not reserve capacity; unavailable capacity is a stop, not a fallback trigger.
2. Choose a fresh suffix; `az group exists` must be false for **both** groups.
   The VNet, pod, and Service CIDRs must be disjoint from each other and all
   control, peered, and operator networks. This template expects three RFC1918
   `/16`s. The node subnet is the first `/22`; builder subnet is `/27` index 128.
   Pin a published `Canonical:ubuntu-24_04-lts:server:<version>` image, never
   `latest`. Use only an operator **public** SSH key in the template. A separately
   approved ephemeral keypair must remain private and must never appear in logs.
3. Copy the parameter example privately and replace placeholders. For planning
   only, mark the cleanup receipt `UNAPPROVED-PLAN-ONLY` and record that plan
   timestamps do **not** start a lifetime. Recreate the plan with actual armed
   cleanup and start/expiry metadata before a later approved apply.
4. From the private directory, with the script path supplied in `PLANNER`,
   `PARAMETERS` pointing at the private parameter file, an unused private output
   directory, and **explicit approved** subscription/control resource IDs:

   ```bash
   umask 077
   python3 "$PLANNER" --subscription "$APPROVED_SUBSCRIPTION" \
     --control-vnet-id "$CONTROL_VNET_ID" --control-aks-id "$CONTROL_AKS_ID" \
     --parameters "$PARAMETERS" --output-dir "$PRIVATE_PLAN_DIR"
   ```

   The planner requires a full subscription UUID, explicitly scopes every Azure
   management command, verifies the returned account, rejects foreign IDs
   (including nested identity keys) and refuses changes outside the exact new
   group. It has **no apply mode**. All handoff IDs and cleanup command flags must
   come from `scoped-plan.json.targets` and pass the same scope validator; never
   derive them from unscoped `az account show`, an ambient subscription variable,
   or a default Azure context. `--subscription` is mandatory even if the current
   Azure account happens to be correct. Do not change the global account.

   Static `Template` validation is **not** provider, permission, capacity, or
   runtime validation. When all approvals and real public-key parameters are
   present, run a fresh `Provider` what-if before applying. Reject any unexpected
   modification/delete or resource outside the exact approved scopes, and retain
   evidence of all nested changes. Account separately for AKS-created node-group
   resources and role assignments that what-if cannot enumerate.

## Explicit apply — NOT authorized by a plan

`scripts/remediation_aks_apply.py` is a fixed-scope, review-gated orchestrator,
separate from the initial new-only planner. It compiles the cleanup, access,
compute and exact peering/DNS templates privately. Its explicit phases are:

```bash
python3 "$APPLY" plan --subscription "$APPROVED_SUBSCRIPTION" \
  --control-vnet-id "$CONTROL_VNET_ID" --control-aks-id "$CONTROL_AKS_ID" \
  --parameters "$PARAMETERS" --public-key-file "$PRIVATE_PUBLIC_KEY_FILE" \
  --work-dir "$PRIVATE_BUNDLE_DIR"
# Independent source/compiled-plan review must close before any following phase.
# Each phase also requires the same explicit subscription/control IDs/work dir.
# --reviewed-source-sha256 must match the exact approved bundle source digest.
python3 "$APPLY" bootstrap ... --reviewed-source-sha256 "$REVIEWED_DIGEST"
python3 "$APPLY" arm       ... --reviewed-source-sha256 "$REVIEWED_DIGEST"
python3 "$APPLY" compute   ... --reviewed-source-sha256 "$REVIEWED_DIGEST"
python3 "$APPLY" connect   ... --reviewed-source-sha256 "$REVIEWED_DIGEST"
# After authoritative absence, trusted operator only:
python3 "$APPLY" retire    ... --reviewed-source-sha256 "$REVIEWED_DIGEST"
```

`bootstrap` requires all three group names to be unused and the approved
built-in role definitions to match the pinned permission contract. It creates
the owned empty verification/cleanup groups, configures only the reviewed
cleanup assignments, publishes the exact runbook, and executes a
read-only managed-identity/delete-authority preflight. The operator's bounded
wait allows ten minutes of queue/start delay plus ten minutes of job execution;
it does not increase runbook runtime or create another job. Only that preflight retries
initial 403 propagation and strict subsets of the expected permission set,
bounded to the same ten-minute deadline. Any extra action, exclusion or data
permission fails immediately; missing actions have a distinct failure code.
Cleanup never treats 403 as
absence or switches identity. `arm` verifies receipts,
both groups' ownership/source tags, the empty verification group, and the actual
public key; chooses a future UTC `T0`; and performs **Provider** what-if using
the exact template and parameter bytes later used for compute. Only the
prepared group's expected ownership/budget tag transition is allowed; every
other template resource must be Create. Changing a tag, parameter, template,
receipt, identity or target fails closed.

The two schedules and bindings must be read back before `T0`. Compute waits
until `T0`, rechecks arming/identity/quota and the exact validated hashes before
the first billable apply, and never extends the deadline. `main.bicep` preserves
the arming source/owner/receipt tags when it updates the prepared group. Later
node-group and peering permissions are scoped to the exact created resources.
Schedule bindings are immutable; they are not replaced to extend lifetime.
Once owned main-group deletion is accepted, cleanup polls that group without
re-reading its already-validated AKS/VM children under disappearing group-level
permissions. Completion still requires authoritative group absence.
The control-side peering and its child-scoped role assignment use direct exact-ID
ARM PUTs rather than group deployments, so no deployment records are created in
the existing control resource group. Schedules include their required name.
Cleanup bootstrap, cleanup-access grants and registry-pull grants each run
**Provider-level validation immediately before create**, with the same compiled
template and parameter hashes. Static Bicep compilation is not RP validation.

### Automation parameter wire format

Automation deserializes each job parameter value before binding it to the
published PowerShell parameter type. Serialize **each value** as JSON, in
addition to encoding the outer ARM request. In particular, the string that
contains the manifest JSON needs this additional string-encoding layer; sending
the manifest text directly can arrive as a different PowerShell string and
fail `Read-CleanupManifest`. `Mode` is encoded the same way.

Preflight jobs and both cleanup job-schedule bindings share this encoder.
It matches the official Azure PowerShell client's
[`ProcessRunbookParameters`](https://github.com/Azure/azure-powershell/blob/cd392c7ebd14264312318eb463b1c8a22b305eb0/src/Automation/Automation/Common/AutomationPSClient.cs#L2477),
used by both `StartRunbook` and `RegisterScheduledRunbook`. Tests verify the
actual request bodies: one service-side JSON decode must produce the exact
original manifest **string**, not a dictionary. Preserve the original failed
jobs and diagnostic receipts; a parameter fix does not retroactively qualify
their preflight results.

### Preserved child-recovery history

The live Automation RP rejected both seven runtime-environment tags and a
20-character tag key, despite successful Provider validation. Rather than guess
further count/key/value limits, **runtime and runbook tags are omitted entirely**
in both normal bootstrap and recovery. Their authority never depended on child
tags: the exact parent-account/group IDs, principal and full seven-tag
ownership/source/clock sets remain guarded. Optional child descriptions are
omitted because no readback contract uses them; runtime, logging and publication
settings remain explicit.

Provider validation is still mandatory but **is not proof of RP acceptance**.
The preview accepts only absent tags or `{}`, never any tagged child or
unexpected child property. Compiled JSON tests assert zero encoded tag count,
keys and values, including regressions for both previously rejected forms.

The historical recovery link pins **both** failed bundles/receipts, the failed recovery's
approved link and exact deployment identity, original principal, and ownership
proof. It rechecks the original tag-count failure and the subsequent exact
runtime tag-key-length failure and allows only creation of the two missing
children. This is not a recursive recovery path for arbitrary later failures.
Its separate `bounded-cleanup-zero-tags` deployment name preserves the failed
three-tag deployment record; the plan refuses an already-attempted zero-tag
deployment rather than replaying it.
The child-only recovery template never
PUTs the existing Automation account: replaying account creation produces
ambiguous what-if deletions for provider-added encryption/runtime defaults.
An `Ignore` entry for that exact already-owned account is allowed; Modify,
Delete, or Create of the account is not.
After child creation, a metadata-only tag merge updates the reviewed source
digest on **only the two owned groups**, with their complete ownership-tag sets
read back unchanged otherwise. The existing Automation account is entirely
untouched and retains all seven original tags, including its original source
digest. It rejects all other adoption or scope changes. All original owner/
receipt tags, group/account IDs and system identity remain unchanged.
It writes a **new** intent receipt linking both failures; it never edits either
failed receipt or disables `bootstrap`'s fresh-state guard.
Recovery completes only the cleanup bootstrap/preflight, not arming or compute.
Those archived bundles remain immutable audit inputs, not authorization to
replay them under a different permission model. Current bundle loading requires
the explicit built-in model and current reviewed source.

### Bounded custom-role-quota transition

If zero-tag child creation completed but cleanup access stopped at exactly
`RoleDefinitionLimitExceeded`, the operator may prepare a separate transition:

```bash
python3 "$APPLY" plan-builtin-resume --subscription "$APPROVED_SUBSCRIPTION" \
  --control-vnet-id "$CONTROL_VNET_ID" --control-aks-id "$CONTROL_AKS_ID" \
  --previous-work-dir "$STOPPED_ZERO_TAG_BUNDLE_DIR" \
  --work-dir "$BUILTIN_BUNDLE_DIR"
# Review the source and permission trade-offs; approve the exact authorization link.
python3 "$APPLY" resume-builtin-bootstrap ... \
  --reviewed-source-sha256 "$REVIEWED_DIGEST" \
  --approved-authorization-sha256 "$AUTHORIZATION_LINK_DIGEST"
```

This path requires the exact stopped receipt and all preceding bundle/receipt
hashes, unchanged ownership and system identity, a still-empty verification
group, the expected runtime and **unpublished** runbook, no jobs/schedules,
no legacy cleanup role definitions and **zero** assignments to the cleanup
identity. The live stopped state and all built-in permissions are revalidated.
The transition updates only the two groups' source tags and writes a new intent
receipt before granting the explicitly approved built-in assignments. It does
not recreate or modify the Automation account, replay child creation, start
compute, or edit earlier receipts. The new access deployment uses a different
name so the original quota-failure deployment record remains available.

If those two exact built-in assignments were created and recorded but the
post-grant list audit stopped before publication, use a new private bundle
and explicitly select the prepublication continuation:

```bash
python3 "$APPLY" plan-builtin-resume --subscription "$APPROVED_SUBSCRIPTION" \
  --control-vnet-id "$CONTROL_VNET_ID" --control-aks-id "$CONTROL_AKS_ID" \
  --previous-work-dir "$STOPPED_BUILTIN_BUNDLE_DIR" \
  --continue-granted-bootstrap --work-dir "$CONTINUATION_BUNDLE_DIR"
# Review and approve the new source and authorization-link digests.
python3 "$APPLY" resume-builtin-bootstrap ... \
  --reviewed-source-sha256 "$REVIEWED_DIGEST" \
  --approved-authorization-sha256 "$AUTHORIZATION_LINK_DIGEST"
```

This continuation requires the original built-in transition link and every
preceding failed receipt to remain unchanged, exactly the two recorded
verification-group/subscription-reader assignments with successful individual
readbacks and a complete list audit, a still-unpublished runbook, no jobs or
schedules, an empty verification group, and no node group or clock. It cannot
adopt unrelated grants, change scope/compute inputs, repeat a preflight job or
recursively continue another continuation. Only a new intent receipt is
updated; the stopped receipt remains immutable. The same approved assignments
are carried into the new receipt before the idempotent access/publish/preflight
path, so existing recorded grants are not mistaken for unrelated permissions.

### Adopt a separately qualified original preflight

If that continuation published the original runbook but its first preflight
failed, **do not edit its intent receipt or replay bootstrap**. After a separately
reviewed parameter-wire correction and an explicitly approved successful
**original** preflight, prepare a current-source handoff:

```bash
python3 "$APPLY" plan-qualified-bootstrap --subscription "$APPROVED_SUBSCRIPTION" \
  --control-vnet-id "$CONTROL_VNET_ID" --control-aks-id "$CONTROL_AKS_ID" \
  --previous-work-dir "$FAILED_PREFLIGHT_BUNDLE_DIR" \
  --qualified-preflight-work-dir "$CORRECTED_ORIGINAL_PREFLIGHT_DIR" \
  --diagnostic-work-dir "$DIAGNOSTIC_EXECUTION_DIR" \
  --work-dir "$QUALIFIED_BUNDLE_DIR"
# Review the NEW source/BOM and authorization-link.json. Planning is GET-only.
python3 "$APPLY" adopt-qualified-bootstrap \
  --subscription "$APPROVED_SUBSCRIPTION" \
  --control-vnet-id "$CONTROL_VNET_ID" --control-aks-id "$CONTROL_AKS_ID" \
  --work-dir "$QUALIFIED_BUNDLE_DIR" \
  --reviewed-source-sha256 "$NEW_REVIEWED_SOURCE_DIGEST" \
  --approved-authorization-sha256 "$QUALIFIED_HANDOFF_LINK_DIGEST"
```

This intentionally supports only the recorded failed original preflight, the
reviewed `ExactFoundationPreflightDiag542` diagnostic, and the corrected original
preflight: exactly three jobs and two published runbooks. Diagnostic success is
not an original-preflight proof. The handoff binds the old bundle/receipt/link and
the corrected plan/request/output/receipt by file hash. Live GETs must match each
job's ARM identity, runbook, status and parameters. The successful original job
must have the exact per-value JSON-encoded parameters, decoding to the old
approved manifest, and the exact five-field original success output. Its actual
UTC completion time, not adoption time, becomes the new `preflightCompleted`.
ARM job resource names and the service's separate `properties.jobId` are both
recorded; they are not assumed to be the same identifier.

Complete inventories must show empty verification resources, no node group,
no schedules or job-schedule bindings, no unapproved Automation assets, the
unchanged system identity/ownership/pending-clock tags, and only the two exact
recorded built-in grants. The runtime catalogue permits only `PowerShell74` plus
Azure's [six documented system-generated, non-editable runtime projections](https://learn.microsoft.com/azure/automation/runtime-environment-overview#system-generated-runtime-environments).
Their definitions are bound into the reviewed proof; an extra runtime or changed
catalogue fails closed. Published content must match the reviewed original and
diagnostic source, allowing only CRLF normalization and one transport-added final
newline. No code changes or publication are performed by this phase.

Current templates are recompiled and must retain all seven approved compiled
hashes. Only `sourceDigest` may change in compute inputs. Adoption rechecks the
live proof, writes a **new** intent receipt, and merges only that new handoff
bundle's source digest into the two owned resource groups, with individual
readbacks and a final complete recheck. The account, old receipts, grants,
runbooks, jobs and schedules are untouched. Only then is the new receipt marked
`bootstrap-ready`.

An interrupted adoption may be explicitly retried with the **same reviewed
source, bundle, approval link and approval digest**, but only if `receipt.json`
is byte-for-byte the expected `qualified-bootstrap-intent` for those inputs,
without completion or clock fields. Do not edit or reformat that receipt. A
retry performs the entire pre-merge proof again, permitting each of the two
groups' source tags independently to be either the old or approved new digest;
every other tag and resource must remain unchanged. Only groups still carrying
the old digest are merged. Already-promoted groups are never merged again.
Both groups must have the new digest and the final complete proof, including
unchanged runtime definitions, jobs, schedules and diagnostic output, must pass
before finalization. A changed intent, unrelated tag value, changed projection
or other drift fails closed rather than gaining a new approval or fallback.
Fresh adoption without an intent still requires both old source tags.

This phase creates no clock or compute. The existing `arm` phase still performs
the explicit live JobSchedule wire-parameter readback gate before compute; the
two-node/one-builder/Basic-ACR footprint and 22h/23h/24h cleanup budget are unchanged.

### Minute-aligned arming after an approved unarmed rollback

Automation stores schedule times at whole-minute precision. `arm` therefore
chooses **the current UTC minute boundary plus eleven minutes**, leaving at
least ten minutes of lead time even at second 59. The provider preview's
`budgetStartUtc`, primary cleanup at +22h, catch-up at +23h and deadline at +24h
all derive from that single minute-aligned `T0`. Schedule readback remains exact:
early, rounded or shifted instants are rejected, not tolerated. Both the schedule
name and deterministic binding ID must still return 404 immediately before each
PUT pair. The runbook's `cleanup-not-due` check and compute's 30-minute freshness
gate are unchanged.

Only the explicitly abandoned **non-minute, unarmed** arming intent may use the
existing qualified handoff to prepare a fresh bootstrap-ready receipt after the
operator-approved partial-schedule rollback:

```bash
python3 "$APPLY" plan-qualified-bootstrap --subscription "$APPROVED_SUBSCRIPTION" \
  --control-vnet-id "$CONTROL_VNET_ID" --control-aks-id "$CONTROL_AKS_ID" \
  --previous-work-dir "$FAILED_PREFLIGHT_BUNDLE_DIR" \
  --qualified-preflight-work-dir "$CORRECTED_ORIGINAL_PREFLIGHT_DIR" \
  --diagnostic-work-dir "$DIAGNOSTIC_EXECUTION_DIR" \
  --abandoned-arming-work-dir "$ABANDONED_QUALIFIED_BUNDLE_DIR" \
  --arming-rollback-work-dir "$VERIFIED_PARTIAL_ROLLBACK_DIR" \
  --work-dir "$MINUTE_REARM_BUNDLE_DIR"
```

This does **not** roll back Azure resources, reset an old receipt, arm a clock or
automatically extend a lifetime. The two optional directories are mandatory as a
pair. Their input hashes bind the earlier qualified link/BOM, its exact
`arming-intent`, the byte-identical archived failed receipt and the verified
rollback receipt. The only accepted rollback records deletion of the exact
PrimaryCleanup binding followed by PrimaryCleanup, with `noComputeExisted:
true`. The original provider-preview parameters/template must match the
abandoned clock. Any armed-readback marker, armed/compute/later phase, different
clock/receipt/rollback ID or recursively abandoned rearm is refused.

Live proof still requires zero schedules and bindings, individual 404s for both
rolled-back IDs, the same three jobs/two books/runtime definitions, empty
verification resources, no node group, pending budget tags and unchanged
identity/grants/account. Only the existing two resource-group source-tag merges
are permitted by a separately reviewed `adopt-qualified-bootstrap` invocation.
It creates a **new** ready receipt referencing the existing successful original
preflight; all older clocks and records stay immutable. Only a subsequent,
explicitly approved `arm` can mint the fresh minute-aligned 24-hour window.

This is not a generic resume/adoption framework. Outside the exact same-link
handoff retry above, a partially failed phase stops with a private intent receipt
and requires bounded operator recovery; never silently reuse an existing name
or extend its lifetime.

### Read-only platform-DNS compute-repair proposal

A compute deployment rejected at the builder NSG with
`SecurityRuleInvalidAccessType` is **not** an unarmed rollback. Once compute has
started, preserve its original `T0`, primary/catch-up schedules, encoded cleanup
bindings and 24-hour deadline. Do not edit the old `compute-intent`, rerun `arm`,
or invoke the normal creation-only path against partial resources.

The DNS correction removes only the invalid `AzurePlatformDNS` allow rule.
`validate_platform_dns_repair_template` requires that single compiled-template
change (apart from generated template hashes); the normal
`validate_armed_preview` remains creation-only. The dedicated
`validate_compute_repair_preview` accepts Create only for the exact missing
original resources, NoChange for the two existing network-role bindings, and
NoChange or an explicitly reviewed source-digest-only tag delta for the owned
resource group and five succeeded resources. Any existing property, principal,
rule-array, replacement, deletion, foreign resource or incomplete preview blocks
the proposal. Provider what-if differences are not automatically dismissed as
defaults or expression-resolution artifacts.

A candidate repair must bind the old full compute parameters/BOM/receipt,
original published cleanup content and active schedules, exact failed
deployment/NSG error, and live owned partial-resource properties and role
principals. It needs a new current-source bundle and explicit review/approval,
not a source-drift bypass. The proposed repair start cutoff is two hours before
the unchanged primary cleanup, with at most one hour of allocation observation.
A client wait timeout is **not** proof that Azure allocation stopped:
cancellation/settlement behavior must be reviewed before enabling execution.
The initial compute path's 30-minute freshness check is unchanged.

If Provider what-if reports unapproved existing-resource or role changes, stop.
Keep the independent cleanup backstop armed against the partial billable
resources and report the exact rejected delta paths. The initial full-template
proposal was blocked for precisely this reason; those deltas are never ignored.

### Create-only continuation of the same armed compute attempt

`compute-core.bicep` is both the canonical full stack's compute module and the
standalone repair template. It declares the exact ACR, PIP, NAT, node NSG and
control-plane UAMI as `existing`; only the builder NSG, VNet, VNet-scoped Network
Contributor binding, AKS, builder NIC and builder VM appear as creates. The two
existing network-role bindings are never PUT. The actual UAMI principal GUID is
read, pinned and supplied explicitly, and an unresolved/different what-if
principal is rejected. The existing 2×D4 nodes, 1×D4 builder, Basic ACR, private
API, fixed version and disabled autoscaling/upgrades remain canonical.

```bash
python3 "$APPLY" plan-create-only-compute-repair \
  --subscription "$APPROVED_SUBSCRIPTION" \
  --control-vnet-id "$CONTROL_VNET_ID" --control-aks-id "$CONTROL_AKS_ID" \
  --previous-work-dir "$FAILED_ARMED_COMPUTE_DIR" \
  --blocked-compute-repair-work-dir "$FROZEN_BLOCKED_DNS_PROPOSAL_DIR" \
  --work-dir "$CREATE_ONLY_REPAIR_DIR"
# Root review must approve the exact current source and compute-repair-link.json.
python3 "$APPLY" allocate-create-only-compute-repair ... \
  --reviewed-source-sha256 "$REPAIR_SOURCE_DIGEST" \
  --approved-compute-repair-sha256 "$REPAIR_LINK_DIGEST"
```

The operating bundle is current-source qualified. Existing resource tags retain
their frozen original source digest; newly created resources carry the repair
source digest. `resourceOriginSourceDigest` and `repairOf` record both identities
without rewriting the old receipt, old inputs, `T0`, schedules, bindings or
deadline. The repair starts no later than two hours before the original primary
cleanup. One new, digest-reserved group deployment is PUT at most once. Its
controller allocation budget is one hour, including submission and polling.
Both the recorded absolute UTC limit and a monotonic limit are enforced:
host/WSL suspension cannot stretch the allocation window. The original eastus2
DSv5-family **and total-core** quota checks require at least 12 free cores after
the live proof and before writing an intent or making the PUT. A quota shortfall
does not consume the attempt. An ambiguous submit is observed, never replayed.

At the bound, the controller attempts cancellation of **only that new repair
deployment**, then records deployment state and a fresh partial-resource/node
inventory. ARM cancellation is best-effort and does not prove already-issued
resource-provider operations have stopped. Timeout, failure and uncertain
outcomes do not qualify readiness or permit a new allocation; the independent
original cleanup backstop remains armed. There is no hard cloud-kill claim.

A timely Succeeded observation is durably marked `compute-repair-provisioned`
**before** inventory or schedule follow-up GETs. If those reads fail, the
successful receipt remains usable for the separately gated qualification.
Receipt replacement is atomic, so interruption leaves the prior complete
intent or the complete new state, not a partially rewritten JSON receipt.
Interruptions leave the durable intent rather than triggering an early cancel.
Ctrl-C records the interruption; abrupt termination may leave just the intent.
Use the same source, approval, deployment ID and recorded UTC window to observe
that existing attempt:

```bash
python3 "$APPLY" reconcile-create-only-compute-repair ... \
  --reviewed-source-sha256 "$REPAIR_SOURCE_DIGEST" \
  --approved-compute-repair-sha256 "$REPAIR_LINK_DIGEST"
```

Reconciliation never PUTs a deployment and does not replay the pre-allocation
exact snapshot proof: legitimate subnet attachments change the NAT/NSG GET
bodies. It uses GETs, except for the **single durable cancellation attempt** at
the original recorded limit if work is still nonterminal. A previously recorded
cancel is never replayed. Success observed within the UTC window can be
reconciled to provisioned; late success is fail-closed, not backdated from
unverified ARM timestamps. A durable timely completion remains valid after a
follow-up failure, but qualification still requires that completion timestamp
to be within the original one-hour window and runs before primary cleanup.
Neither process restart nor reconciliation changes any clock.

Successful allocation produces `compute-repair-provisioned`, not a false
`compute-ready`. The original post-compute readbacks, node-group cleanup grant
and two registry pull assignments remain a separate explicit gate:

```bash
python3 "$APPLY" qualify-create-only-compute-repair ... \
  --reviewed-source-sha256 "$REPAIR_SOURCE_DIGEST" \
  --approved-compute-repair-sha256 "$REPAIR_LINK_DIGEST" \
  --approved-compute-qualification-sha256 "$ORIGINAL_QUALIFICATION_SCOPE_DIGEST"
```

Review that qualification digest separately: it permits only the original
node-RG cleanup and isolated-registry scopes, with identity readback before
grants. These assignments are not performed during allocation. Once qualified,
the normal `connect`/`retire` paths consume the current-source receipt without a
source-guard bypass. No repair operation resets the original lifetime.

If deployment partially fails, the armed cleanup deadline still applies. Do not
retry using another SKU/region or reuse an unrelated resource group. Preserve
resource IDs, provisioning/power state and operations privately; record the
AKS-derived node-group identity and propagate ownership/expiry tags to that group
after checking ownership. No private keys or token values belong in receipts.

## Builder bootstrap boundary

The BuildKit config, unit, launcher and preflight scripts are **staged inputs only**, not a
working installation. No binaries, images, daemon, certificates, disk formatting,
or clients are installed by this template. Before untrusted builds:

- Independently verify/pin BuildKit, runc and their installation artifacts.
  Prepare the empty data disk as a filesystem, mount it persistently at
  `/var/lib/orka-buildkit`, and verify the exact disk identity. The unit refuses
  to start if that path is not a mountpoint. Never use a control node or host
  Docker socket.
- Install mTLS server material privately, with the server SAN matching the
  approved private address/name. The VM receives only its server key/certificate
  and the client CA's **public** certificate. Keep CA private keys and client
  private keys off the VM; trusted client credentials are the parent's scope.
  Production exposes only mTLS TCP 1234. Trusted qualification temporarily uses
  `qualification.toml` and a root-owned Unix socket; it never opens a TCP
  listener or permits host networking. No containerd/Docker socket is used.
- The staged daemon is rootful **inside the disposable isolated VM only**.
  Physical VM bounds are 4 vCPU / 16 GiB, state disk 64 GiB; its service also sets
  4 CPU / 12 GiB / 512 tasks and one concurrent OCI worker. GC is not a hard disk
  quota. `DelegateSubgroup=supervisor` plus a private mount/cgroup namespace
  roots the daemon's cgroup view inside its bounded service. The pre-created
  `/workloads` cgroup is the default parent; an LLB parent override cannot select
  a host ancestor through that mount. The host systemd D-Bus socket is
  inaccessible. `KillMode=control-group` and a bounded stop kill descendants,
  not merely the BuildKit daemon.
- Keep host IMDS available: Ubuntu cloud-init uses it on first and subsequent
  boots. The VM still has no Azure identity or credentials. Enforce the build
  boundary in `buildkit-network.nft` on **forwarded bridge traffic**, not a
  whole-VM metadata NSG deny. `cni.json` supplies one explicit bridge/subnet;
  untrusted steps cannot use host-network entitlements. Bridge-to-host traffic,
  IMDS, and non-DNS WireServer access are denied. DNS TCP/UDP 53 remains usable.
- Before any daemon starts, `buildkit-preflight.py host` checks effective guest
  firewall rules, explicit CNI, cgroup v2 delegation and actual kernel limits.
  Under a trusted operator-only qualification environment
  (`ORKA_BUILDKIT_QUALIFICATION=1`), run a harmless digest-pinned build that remains
  alive long enough to capture its **actual host RUN PID**. Also exercise an
  explicit cgroup-parent override. Run
  `buildkit-preflight.py run-pid --pid PID --case default` and then `--case override`
  from the trusted host: it checks host `/proc/PID/cgroup`, a distinct network
  namespace, and connect-only IMDS/WireServer denial without requesting tokens.
  Stop the service, then run `buildkit-preflight.py stopped` to verify that no
  descendant remains and both recorded RUN process identities are gone.
  Production startup requires this same-boot, unchanged-
  config certificate of qualification; reboot/config changes require reproof.
  Source assertions are not live qualification.
- VM extension operations default disabled. A separately approved temporary
  **operator-only** Azure Run Command bootstrap may enable that path on the exact
  new VM to install pinned binaries/files and perform these checks. It must not
  transmit secrets in ordinary parameters or output; return only safe proof and
  digests, never keys/tokens/metadata bodies. Disable Run Command/extension access
  afterward. No public IP, SSH port, extra VM identity, or provisioner credential
  in the guest is authorized by this procedure.

The node subnet requests `privateEndpointNetworkPolicies:
NetworkSecurityGroupEnabled`. AKS may rewrite this setting: read back the actual
subnet and effective private-endpoint policy after provisioning. A template
property or NSG rule alone is not proof that the private API traffic is filtered.

ARM Owner/Contributor does not grant Kubernetes access. The new cluster starts
with Azure RBAC enabled for the explicitly approved temporary **operator-only**
AKS RBAC Cluster Admin assignment. The operator installs native Kubernetes
bindings, verifies the transition on the **new** cluster, disables its Azure
RBAC authorization and revokes the temporary Azure assignment. Entra
authentication and disabled local accounts remain in force. Do not change the
existing control cluster's mode or fetch admin credentials.
No application receives cluster-admin or Azure infrastructure management roles.
Native application permissions, privilege-escalation controls and authenticated
native-client proof are separate workload-admission prerequisites, not implied
by this foundation's compute/connect receipts.

## Receipts, cleanup, and qualification

Capture ARM resource IDs, image/version, SKU/count, provisioning and power states,
owner/start/expiry/cleanup tags, private API/network configuration, role scopes,
and immutable BuildKit identities when installed. Check AKS Ready nodes and
effective kubelet PID limits via the explicitly selected **non-admin** private
kubeconfig. Do not equate resource existence with Cilium enforcement, workload
identity, mTLS, runtime, observer, or build qualification.
Before workloads are admitted, the parent must also prevent unapproved
LoadBalancer/Ingress provisioning and additional cloud resources; fixed IaC
counts are not an admission policy or an Azure billing cap.

The physical cleanup path uses the reviewed equivalent of these exact-ID
operator recovery commands; neither command runs as part of planning.
Assignment retirement remains a separate trusted-provisioner action:

```bash
az group delete --subscription "$APPROVED_SUBSCRIPTION" --name "$VERIFY_RG" --yes
# Wait for the containing group and AKS-managed node group to disappear.
# Only an exact positively owned residual node group can be deleted afterward.
# After physical absence is recorded, the trusted provisioner retires only
# this deployment's remaining assignments and cleanup group, never role definitions.
```

Verify both groups and their resources are gone; record final absence and any
remaining resources and charges (disks, snapshots, public IPs, NAT). VM
deallocation or AKS stop alone leaves billable storage/network resources. Never
delete a resource based on a tag alone, or use a broad `rg-orka-*` cleanup filter.

Focused source-contract checks (Python 3.11+ and Azure CLI's Bicep compiler):

```bash
python3 scripts/tests/remediation-aks-template-test.py
python3 scripts/tests/remediation-aks-cleanup-test.py
```

References: [AKS managed identities](https://learn.microsoft.com/azure/aks/use-managed-identity),
[private AKS clusters](https://learn.microsoft.com/azure/aks/private-clusters),
[custom kubelet configuration](https://learn.microsoft.com/azure/aks/custom-node-configuration),
[AKS outbound networking](https://learn.microsoft.com/azure/aks/egress-outboundtype),
[Automation execution limits/status](https://learn.microsoft.com/azure/automation/automation-runbook-execution),
[Automation one-time schedules](https://learn.microsoft.com/azure/automation/shared-resources/schedules),
[Azure retail pricing API](https://learn.microsoft.com/rest/api/cost-management/retail-prices/azure-retail-prices).
