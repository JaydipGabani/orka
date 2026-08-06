#!/usr/bin/env bash
# Source-release-aware one-time classification of built-in Agents for the
# harness v1/v2 coexistence bridge. The selector is immutable once set and a
# missing selector is never interpreted as either protocol, so stamping is an
# explicit operator action backed by a source-release assertion.
#
# Usage:
#   KUBECTL=kubectl scripts/coexistence-stamp-agents.sh --list
#   KUBECTL=kubectl scripts/coexistence-stamp-agents.sh \
#     --contract orka.harness.v2 --source-release v0.9.3-acp --yes [--namespace ns] [--include-opencode]
#
# OpenCode Agents exist in both protocols and are never classified from the
# runtime type alone: they are skipped unless --include-opencode is passed,
# which asserts that the supplied source release is authoritative for them too.
set -euo pipefail

KUBECTL=${KUBECTL:-kubectl}
CONTRACT=""
SOURCE_RELEASE=""
NAMESPACE=""
CONFIRM=0
LIST_ONLY=0
INCLUDE_OPENCODE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) LIST_ONLY=1 ;;
    --contract) CONTRACT="$2"; shift ;;
    --source-release) SOURCE_RELEASE="$2"; shift ;;
    --namespace) NAMESPACE="$2"; shift ;;
    --include-opencode) INCLUDE_OPENCODE=1 ;;
    --yes) CONFIRM=1 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

scope=(--all-namespaces)
if [[ -n "${NAMESPACE}" ]]; then
  scope=(-n "${NAMESPACE}")
fi

# Built-in Agents lacking the selector: spec.runtime.type set, contractVersion absent.
unclassified=$(${KUBECTL} get agents.core.orka.ai "${scope[@]}" -o json | jq -r '
  .items[]
  | select(.spec.runtime.type != null)
  | select(.spec.runtime.contractVersion == null)
  | [.metadata.namespace, .metadata.name, .spec.runtime.type] | @tsv')

if [[ -z "${unclassified}" ]]; then
  echo "no unclassified built-in Agents found"
  exit 0
fi

echo "unclassified built-in Agents:"
printf '%s\n' "${unclassified}" | awk -F'\t' '{printf "  %s/%s (runtime.type=%s)\n", $1, $2, $3}'

if [[ ${LIST_ONLY} -eq 1 ]]; then
  exit 0
fi

case "${CONTRACT}" in
  orka.harness.v1|orka.harness.v2) ;;
  *) echo "--contract must be orka.harness.v1 or orka.harness.v2" >&2; exit 2 ;;
esac
if [[ -z "${SOURCE_RELEASE}" ]]; then
  echo "--source-release is required: classification must record the verified source release" >&2
  exit 2
fi
if [[ ${CONFIRM} -ne 1 ]]; then
  echo "refusing to stamp without --yes; the selector is immutable once set" >&2
  exit 2
fi

stamped=0
skipped_opencode=0
while IFS=$'\t' read -r ns name runtime_type; do
  [[ -z "${name}" ]] && continue
  if [[ "${runtime_type}" == "opencode" && ${INCLUDE_OPENCODE} -ne 1 ]]; then
    echo "skipping ${ns}/${name}: opencode exists in both protocols; rerun with --include-opencode to assert the source release covers it"
    skipped_opencode=$((skipped_opencode + 1))
    continue
  fi
  ${KUBECTL} -n "${ns}" annotate agent.core.orka.ai "${name}" \
    "orka.ai/contract-classified-from=${SOURCE_RELEASE}" --overwrite >/dev/null
  ${KUBECTL} -n "${ns}" patch agent.core.orka.ai "${name}" --type=merge \
    -p "{\"spec\":{\"runtime\":{\"contractVersion\":\"${CONTRACT}\"}}}" >/dev/null
  echo "stamped ${ns}/${name} -> ${CONTRACT}"
  stamped=$((stamped + 1))
done <<< "${unclassified}"

echo "stamped ${stamped} Agent(s); skipped ${skipped_opencode} OpenCode Agent(s)"
if [[ ${skipped_opencode} -gt 0 ]]; then
  exit 3
fi
