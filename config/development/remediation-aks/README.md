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
  Command, managed Entra / Azure RBAC, local accounts disabled, OIDC and workload
  identity enabled. No managed KEDA, ingress, or monitoring add-ons.
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

1. **Independent cleanup service and narrowly scoped delete authority.**
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
   Only the trusted provisioner performs it; the reaper receives no provider
   registration, resource creation, Owner, Contributor, or wildcard permission.

   The proposed **resource cleanup custom role**, assigned only to the new
   verification group and, once AKS creates it, its exact new managed node group:

   ```text
   Microsoft.Resources/subscriptions/resourceGroups/read
   Microsoft.Resources/subscriptions/resourceGroups/delete
   Microsoft.Resources/subscriptions/resourceGroups/resources/read
   Microsoft.Resources/deployments/read
   Microsoft.Resources/deployments/operations/read
   Microsoft.ContainerService/managedClusters/read
   Microsoft.ContainerService/managedClusters/delete
   Microsoft.Compute/virtualMachines/read
   Microsoft.Compute/virtualMachines/instanceView/read
   Microsoft.Compute/virtualMachines/delete
   Microsoft.Authorization/permissions/read
   ```

   A separate **peering cleanup custom role**, assigned only to the exact newly
   approved peering child resource on the existing control VNet:

   ```text
   Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read
   Microsoft.Network/virtualNetworks/virtualNetworkPeerings/delete
   ```

   These are proposals, **not grants made here**. Custom-role definitions may be
   subscription-level catalog objects; their assignments are **not**
   subscription-wide for deletion. The separately approved metadata-only readers
   below are explicit exceptions, not broader delete authority. Assignable scopes
   and assignment IDs must be captured
   explicitly. The reaper has no permissions on the existing control resource
   group as a whole, no NSG write permission, no direct VMSS mutation, and no
   IAM mutation or permission to delete its own Automation account. The trusted
   provisioner retires recorded custom definitions/remaining bindings and the
   cleanup group separately after reviewing receipts; the reaper must not gain
   subscription-wide role-definition delete authority for that housekeeping.

   Prepare the owned empty verification group and cleanup service before
   billable foundation resources. Perform a read-only identity/permission
   preflight, set `T0`, publish and read back **both** enabled UTC schedules,
   runbook/code digest, bindings, parameters and target scopes, then start the
   maximum 24-hour foundation lifetime. Node-group and peering grants follow
   their exact resource creation and must be read back before workloads begin;
   the primary AKS/group delete path must already be armed for partial creation
   failures. The node group must never be pre-created or reused.

   At cleanup, validate exact IDs, ownership/expiry/cleanup-receipt tags and the
   AKS-to-node-group relationship. Delete the dedicated VM and AKS and settle
   those exact resources. Independently attempt the owned residual node group
   and exact control-side peering, but **an ungranted or removed residual read
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

   Resource-scoped read assignments can disappear with their targets. The
   separately approved post-delete readers are therefore **two single-action
   custom roles**, only for the new cleanup identity:

   - `Microsoft.Resources/subscriptions/resourceGroups/read` at the exact
     subscription. This exposes group names/tags/locations, not resource contents.
   - `Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read` assigned only
     to the exact existing control VNet. The definition's assignable scope is the
     control resource group; it is not an assignment on that whole group.

   These add no create/write/delete, wildcard or application permissions.
   Definitions, assignment scopes and principal IDs are read back, and the
   managed-identity preflight proves authoritative 404 reads of the not-yet-
   created node group/peering before the clock. Child resource GETs stop when
   their containing group is authoritatively absent. Denied/uncertain reads
   still fail closed and never become success. The trusted `retire` phase
   records physical absence and removes the exact reader assignments and
   definitions before retiring the cleanup account/group.

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
   No peering or existing-network DNS mutation is included in this template.
   Use one nonprivileged, bounded trusted setup Job/ServiceAccount in the existing
   control namespace, reached through that cluster's already working public API,
   for private DNS/API/mTLS checks. It uses the standard private AKS FQDN and the
   parent's explicit native workload identity configuration; no proxy origin or
   ambient identity fallback. No VPN, Bastion, jump VM, SSH route, new management
   cluster, public verification API, or privileged builder on control nodes is
   requested. VM daemon bootstrap remains separately staged: this Job is not
   permission to enable VM extensions or grant it guest administration.

3. **AKS service-managed authority.** Azure documents a **Contributor** grant on
   the managed node group for the control-plane identity. It contains wildcard
   actions and is **not equivalent to the enumerated role in this template**.
   Do not assume a what-if lists this resource-provider side effect. Under a
   no-wildcard-grants authorization, creation stays blocked until an explicit
   exception for this exact new node group is approved, or an Azure-supported,
   verified exact-action alternative is established. Do not grant Owner, change
   the existing cluster identity, or grant broad access and remove it afterward.

## Traffic and identity boundaries

| Caller | Destination | Required path |
| --- | --- | --- |
| Trusted control controller / observer | Verification Kubernetes API, TCP 443 | Peered VNet + private DNS; Azure workload identity and **separately reviewed** Kubernetes RBAC |
| Trusted build client Job on control nodes | Builder private IP, TCP 1234 | Peered VNet + mTLS; source is the control **node** subnet after overlay SNAT |
| Trusted operator | Verification API, TCP 443 | Trusted setup Job on control nodes, accessed through the existing control public API; no custom verification API proxy |
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

`bootstrap` requires all three group names and both role-definition IDs to be
unused, creates the owned empty verification/cleanup groups, configures only the
reviewed cleanup identity/roles, publishes the exact runbook, and executes a
read-only managed-identity/delete-authority preflight. The operator's bounded
wait allows ten minutes of queue/start delay plus ten minutes of job execution;
it does not increase runbook runtime or create another job. Only that preflight retries
initial 403 propagation, bounded to ten minutes; cleanup never treats 403 as
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
re-reading its already-settled AKS/VM children under disappearing group-level
permissions. Completion still requires authoritative group absence.
The control-side peering and its child-scoped role assignment use direct exact-ID
ARM PUTs rather than group deployments, so no deployment records are created in
the existing control resource group. Schedules include their required name.

This is not a generic resume/adoption framework. A partially failed phase stops
with a private intent receipt and requires bounded operator recovery; never
silently reuse an existing name or extend its lifetime.

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

Keep AKS Azure RBAC enabled. ARM Owner/Contributor does not grant Kubernetes
access. If explicitly approved, temporary **operator-only** AKS RBAC Cluster
Admin is scoped to the new cluster and revoked after bootstrap. It is never
assigned to Orka, Copilot, BuildKit, the reaper, or the controller/setup application
identity. The parent owns separate enumerated application authorization and
native-client proof; do not switch authorization modes or fetch admin credentials.

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
operator recovery commands; neither command runs as part of planning. IAM
catalog housekeeping remains a separate trusted-provisioner action:

```bash
az aks delete --subscription "$APPROVED_SUBSCRIPTION" --resource-group "$VERIFY_RG" \
  --name "$VERIFY_AKS" --yes
# Wait for AKS and its recorded managed node group to disappear. On leftovers:
# stop and use only the separately approved exact-node-group cleanup permission.
az group delete --subscription "$APPROVED_SUBSCRIPTION" --name "$VERIFY_RG" --yes
# After physical absence is recorded, the trusted provisioner retires only
# this deployment's remaining authorization catalog entries and cleanup group.
```

Verify both groups and their resources are gone; record final absence and any
remaining charges (disks, snapshots, public IPs, NAT, role definitions). VM
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
