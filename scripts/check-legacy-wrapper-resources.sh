#!/usr/bin/env bash
# Mode-aware guard for live harness-wrapper resources.
#
# Default (v2-only hard cutover): fail when any legacy harness-wrapper
# Deployment, Service, or Secret still exists in the cluster.
#
# COEXISTENCE=1 (harness v1/v2 coexistence): wrapper resources are expected and
# never a failure by themselves. Instead, verify that every wrapper Deployment
# keeps the coexistence upgrade contract: `strategy: Recreate` and a durable
# admission-ledger volume named "ledger" backed by a PersistentVolumeClaim
# (see docs/harness-v1-v2-coexistence-plan.md sections 9.2 and 9.4).
set -Eeuo pipefail

kubectl_bin="${KUBECTL:-kubectl}"
command -v "${kubectl_bin}" >/dev/null 2>&1 || {
  echo "required command not found: ${kubectl_bin}" >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  echo "required command not found: jq" >&2
  exit 1
}

inventory="$(${kubectl_bin} get deployments.apps,services,secrets -A -o json)"

# Shared selection of harness-wrapper resources; program tails are appended as
# single-quoted strings so only this fragment is interpolated.
wrapper_filter='
  .items[]?
  | select(
      .metadata.labels["app.kubernetes.io/component"] == "agent-harness-wrapper"
      or ((.kind == "Deployment" or .kind == "Service") and (.metadata.name == "agent-harness-wrapper" or (.metadata.name | endswith("-agent-harness-wrapper"))))
      or (.kind == "Secret" and (.metadata.name == "harness-wrapper-auth" or (.metadata.name | endswith("-harness-wrapper-auth"))))
    )
'

if [[ "${COEXISTENCE:-0}" == "1" ]]; then
  violations="$(jq -r "${wrapper_filter}"'
    | select(.kind == "Deployment")
    | . as $d
    | [
        (if ($d.spec.strategy.type // "") != "Recreate" then "strategy is not Recreate" else empty end),
        (if ([$d.spec.template.spec.volumes[]? | select(.name == "ledger" and (.persistentVolumeClaim.claimName // "") != "")] | length) == 0 then "missing PVC-backed ledger volume" else empty end)
      ]
    | select(length > 0)
    | [$d.metadata.namespace, $d.metadata.name, join("; ")] | @tsv
  ' <<<"${inventory}")"
  if [[ -n "${violations}" ]]; then
    echo "harness-wrapper Deployments violate the coexistence contract (Recreate strategy + durable ledger volume):" >&2
    printf '%s\n' "${violations}" >&2
    exit 1
  fi
  echo "coexistence mode: wrapper resources are allowed; present wrapper Deployments keep Recreate + durable ledger."
  exit 0
fi

legacy="$(jq -r "${wrapper_filter}"'
  | [.kind, .metadata.namespace, .metadata.name] | @tsv
' <<<"${inventory}")"
if [[ -n "${legacy}" ]]; then
  echo "legacy harness-wrapper resources remain:" >&2
  printf '%s\n' "${legacy}" >&2
  exit 1
fi
