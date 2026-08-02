# Orka Helm chart

This chart is generated from `cmd/build/helmify`; edit the generator inputs and
run `make manifests` rather than editing generated chart copies directly. It
packages all twenty canonical Orka CRDs under `crds/`.

## Fresh install

A normal install creates the CRDs before the templated release resources:

```bash
helm install orka charts/orka \
  --namespace orka-system \
  --create-namespace \
  --wait
```

CRDs are cluster-scoped and shared by every Orka release. Use `--skip-crds`
only when a designated platform or GitOps workflow already manages compatible
Orka CRDs for the cluster.

Controller Services, worker ServiceAccounts, and worker RBAC are scoped to the
Helm release name. Run only one Orka controller release per namespace. If a
cluster has multiple releases, every release (including the first) must use a
cluster-unique release name or `fullnameOverride`, a separate controller
namespace, and a distinct, non-empty `controller.watchNamespace`. Do not mix a
cluster-wide watcher with namespace-scoped releases: gateway admission policies
would overlap. All releases share the same cluster-scoped CRDs.

## Remote memory control plane

`controller.memoryBackend.enabled` is disabled by default. Enabling it requires a
stable `controller.memoryBackend.clusterId` and durable controller storage. On an
upgrade, apply the exact target `MemoryBackend` CRD first; Helm does not upgrade
files under `crds/`. The controller stays disabled until the CRD schema marker is
observed unless `crdsReadyOverride=true` is used after independent verification.

`controller.memoryBackend.activationEnabled` is the separate second-release
cutover gate. The foundation chart and controller artifacts reject activation
even when this value or the matching runtime environment variable is forced.
The foundation controller advertises feature epoch 1; only a later source-gated
activation artifact may advertise epoch 2 and accept the activation value.
While the durable authority remains SQLite, enabling MemoryBackend support also
requires `controller.replicas: 1`. The controller Deployment uses `Recreate`, so
the foundation replica stops before the activation artifact starts; activation
also requires durable evidence that a lower feature epoch was previously
observed and that every live heartbeat supports the activation epoch.
Creating `MemoryBackend/default` in `Staged` validates without changing SQLite
authority. Activation, decommission, force-orphan, and restore-legacy remain
explicit audited API/CLI actions. Dispatcher concurrency, sustained rate, and
burst controls are configured under `controller.memoryBackend.dispatcher*`; the
defaults bound both global and per-namespace work.

The chart always installs fail-closed admission policies that reserve Orka task
Job/Pod provenance for the owning controllers and require
`memorybackends/finalizers` update authorization before the backend protection
finalizer can be removed. Do not disable these policies or grant their protected
status/finalizer permissions to untrusted namespace writers.

Helm uses release-scoped pre-install/pre-upgrade RBAC and provenance policy hooks
before rolling the controller Deployment, then installs the retained
steady-state policies. This closes the Helm kind-ordering gap while allowing the
old controller and Kubernetes Job controller to create legacy-format work during
the upgrade. Helm removes the release-scoped preflight RBAC after each successful
hook run. If a later hook aborts the release, pre-delete hooks replace any
leftover grants with inert, subject-free/rule-free tombstones during uninstall.
Intentionally retained steady-state controls remain in place. The raw installer
likewise places the task provenance policies and bindings after their RBAC grants
but before either Deployment.

The chart-created controller store PVC is annotated `helm.sh/resource-policy:
keep`, and `store.persistence.existingClaim` may select an operator-managed PVC.
The MemoryBackend finalizer policy and binding are also retained on uninstall so
surviving `MemoryBackend` objects cannot have their lifecycle barrier stripped.
Delete retained resources manually only after every backend is safely
decommissioned or force-orphaned and a matched recovery set is verified.

Example foundation values:

```yaml
controller:
  memoryBackend:
    enabled: true
    activationEnabled: false
    clusterId: production-cluster-a
    crdsReadyOverride: true # only after separately applying/verifying target CRDs
store:
  persistence:
    enabled: true
```

## Optional OMS KD6 adapter

The chart can deploy the durable `orka.oms.v0alpha1` KD6 adapter, but it is
**disabled by default**. Enabling it creates only a single-replica Deployment,
an optional Service, and a retained PVC (unless `persistence.existingClaim` is set).
Chart-created adapter PVCs carry `helm.sh/resource-policy: keep` so uninstall cannot
discard routing fences, receipts, or tombstones. The chart never creates a
`MemoryBackend`; backend activation and lifecycle changes
remain explicit operator actions.

The adapter is deliberately fail-closed:

- `omsKd6Adapter.replicas` must be exactly `1` because the durable SQLite control
  state is single-writer.
- `omsKd6Adapter.persistence.enabled` must remain `true`.
- inbound OMS authentication, serving TLS, and KD6 authentication must use
  pre-created Secrets. No token or certificate Secret is rendered by the chart.
- at least one immutable OMS store-name to KD6 provider-store mapping is required.
- the KD6/proxy endpoint must be an absolute HTTPS URL.

Example values:

```yaml
omsKd6Adapter:
  enabled: true
  auth:
    existingSecret: orka-oms-inbound
    tokenKey: token
  tls:
    existingSecret: orka-oms-tls
    certKey: tls.crt
    keyKey: tls.key
    reloadInterval: 1s
  kd6:
    endpoint: https://kd6.example.com
    auth:
      existingSecret: orka-kd6-auth
      tokenKey: token
    storeMappings:
      default: provider-store-id
  persistence:
    enabled: true
    size: 1Gi
  service:
    enabled: true
    type: ClusterIP
```

The inbound token Secret is intentionally operator-managed. A `MemoryBackend`
requires exact labels and annotations bound to the final backend UID, namespace
UID, canonical public endpoint, tenant identity, and store name, so those values
cannot be safely generated by this chart. The Secret data key mounted into the
adapter must contain the same bearer token referenced by the `MemoryBackend`.

The chart Service is only a backend for separately managed external exposure.
A ClusterIP, private IP, Kubernetes Service DNS name, or `*.svc` hostname is
**not** eligible for `MemoryBackend.spec.deployment.mode=external-endpoint` and
will be rejected by the controller. Expose the adapter through a public HTTPS
load balancer or ingress with a publicly resolvable hostname and valid TLS
identity, then put that public URL in the `MemoryBackend`. The chart does not
create an Ingress or LoadBalancer configuration automatically; set
`omsKd6Adapter.service.enabled=false` when another mechanism targets the Pod
directly.

Secret data is mounted read-only and the adapter root filesystem is read-only;
only `/data` (PVC) and `/tmp` (`emptyDir`) are writable. The inbound OMS token is
re-read for every authenticated request, the KD6 token is re-read before every
outbound request, and the serving certificate/key pair is reloaded after the
bounded `tls.reloadInterval` cache (accepted range: `100ms` through `1m`). After
Kubernetes projects a Secret update into the mounted volume, old bearer tokens
stop working on the next request and the new certificate is served without a
Pod restart. Invalid or unreadable rotated material fails closed and no Secret
values are rendered into the Deployment or logged by the adapter.

## Upgrade

Helm installs files from `crds/` only during installation. It does not create or
update them during `helm upgrade`, including when upgrading from an older Orka
chart that installed no CRDs.

Apply the exact CRD specs from the target chart before upgrading the
controller. The first apply creates missing CRDs and transfers ownership of
present fields; the guarded JSON Patch then replaces each `spec` so fields
removed by the target version do not remain from an older Helm manager:

```bash
set -euo pipefail

TARGET_CHART=/absolute/path/to/orka-<version>.tgz
TARGET_CONTEXT=replace-with-context
TARGET_CRDS="$(mktemp)"
trap 'rm -f "$TARGET_CRDS"' EXIT

helm show crds "$TARGET_CHART" > "$TARGET_CRDS"
kubectl --context "$TARGET_CONTEXT" apply \
  --server-side \
  --force-conflicts \
  --field-manager=orka-crd-lifecycle \
  -f "$TARGET_CRDS"

kubectl --context "$TARGET_CONTEXT" create --dry-run=client -f "$TARGET_CRDS" -o json | \
  jq -c '{name: .metadata.name, spec: .spec}' | \
  while IFS= read -r target; do
    name="$(jq -er '.name' <<< "$target")"
    spec="$(jq -ec '.spec' <<< "$target")"
    resource_version="$(kubectl --context "$TARGET_CONTEXT" get crd "$name" -o jsonpath='{.metadata.resourceVersion}')"
    patch="$(jq -cn --arg rv "$resource_version" --argjson spec "$spec" \
      '[{"op":"test","path":"/metadata/resourceVersion","value":$rv},{"op":"replace","path":"/spec","value":$spec}]')"
    kubectl --context "$TARGET_CONTEXT" patch crd "$name" --type=json -p "$patch"
    kubectl --context "$TARGET_CONTEXT" wait --for=condition=Established --timeout=60s "crd/$name"
  done

helm upgrade orka "$TARGET_CHART" \
  --namespace orka-system \
  --kube-context "$TARGET_CONTEXT" \
  --wait
```

A matching Orka source checkout provides the same guarded flow as
`scripts/apply-helm-crds.sh "$TARGET_CHART" "$TARGET_CONTEXT"`. Do not run
competing CRD apply workflows for the same cluster.

If another system owns the CRDs, perform the CRD-first step through that system,
wait for all twenty CRDs to become `Established`, and then upgrade Orka.

If a previous release was uninstalled, update its retained CRDs first and install
the replacement release with `--skip-crds`.

## Uninstall and deletion

`helm uninstall` removes release resources but retains Orka's CRDs and custom
resources. This is Helm's standard `crds/` behavior and is not controlled by a
chart value.

Deleting a CRD also deletes every custom resource stored under that kind. Delete
Orka CRDs only as an explicit cluster-wide data-destruction operation after the
resources have been removed or backed up.
