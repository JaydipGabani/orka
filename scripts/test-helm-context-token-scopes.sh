#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chart_dir="${repo_root}/charts/orka"
helm_bin="${HELM_BIN:-helm}"

if ! command -v "${helm_bin}" >/dev/null 2>&1; then
  echo "required command not found: ${helm_bin}" >&2
  exit 1
fi

scope_mappings=(
  "taskCreate|context-token-task-create-scopes"
  "taskRead|context-token-task-read-scopes"
  "taskList|context-token-task-list-scopes"
  "taskDelete|context-token-task-delete-scopes"
  "taskUpdate|context-token-task-update-scopes"
  "toolRead|context-token-tool-read-scopes"
  "toolUse|context-token-tool-use-scopes"
  "providerUse|context-token-provider-use-scopes"
  "secretRead|context-token-secret-read-scopes"
  "secretCredentialRead|context-token-secret-credential-read-scopes"
  "configMapRead|context-token-configmap-read-scopes"
  "agentRead|context-token-agent-read-scopes"
  "agentWrite|context-token-agent-write-scopes"
  "memoryRead|context-token-memory-read-scopes"
  "memoryWrite|context-token-memory-write-scopes"
  "sessionRead|context-token-session-read-scopes"
  "sessionWrite|context-token-session-write-scopes"
  "securityRead|context-token-security-read-scopes"
  "securityWrite|context-token-security-write-scopes"
  "monitorRead|context-token-monitor-read-scopes"
  "monitorWrite|context-token-monitor-write-scopes"
  "monitorOperate|context-token-monitor-operate-scopes"
  "skillRead|context-token-skill-read-scopes"
  "skillWrite|context-token-skill-write-scopes"
  "gatewayRead|context-token-gateway-read-scopes"
  "gatewayOperate|context-token-gateway-operate-scopes"
)

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/orka-helm-context-token-scopes.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

default_render="${tmp_dir}/default.yaml"
empty_scopes_render="${tmp_dir}/empty-scopes.yaml"
all_scopes_render="${tmp_dir}/all-scopes.yaml"
expected_args="${tmp_dir}/expected-args.txt"
actual_args="${tmp_dir}/actual-args.txt"
expected_flags="${tmp_dir}/expected-flags.txt"
controller_flags="${tmp_dir}/controller-flags.txt"

"${helm_bin}" template orka "${chart_dir}" \
  --show-only templates/deployment.yaml >"${default_render}"

if grep -Eq -- '--context-token-[a-z0-9-]+-scopes=' "${default_render}"; then
  echo "default render unexpectedly contains context-token authorization scope flags" >&2
  grep -E -- '--context-token-[a-z0-9-]+-scopes=' "${default_render}" >&2
  exit 1
fi

"${helm_bin}" template orka "${chart_dir}" \
  --show-only templates/deployment.yaml \
  --set-json controller.contextToken.scopes=null >"${empty_scopes_render}"

if grep -Eq -- '--context-token-[a-z0-9-]+-scopes=' "${empty_scopes_render}"; then
  echo "empty scopes render unexpectedly contains context-token authorization scope flags" >&2
  grep -E -- '--context-token-[a-z0-9-]+-scopes=' "${empty_scopes_render}" >&2
  exit 1
fi

helm_args=(template orka "${chart_dir}" --show-only templates/deployment.yaml)
for mapping in "${scope_mappings[@]}"; do
  key="${mapping%%|*}"
  flag="${mapping#*|}"
  value="scope-${key}"

  if [[ "$(grep -Fxc "      ${key}: \"\"" "${chart_dir}/values.yaml")" -ne 1 ]]; then
    echo "expected exactly one empty default for controller.contextToken.scopes.${key}" >&2
    exit 1
  fi

  helm_args+=(--set-string "controller.contextToken.scopes.${key}=${value}")
  printf '%s\n' "--${flag}=${value}" >>"${expected_args}"
  printf '%s\n' "${flag}" >>"${expected_flags}"
done

"${helm_bin}" "${helm_args[@]}" >"${all_scopes_render}"

grep -oE -- '--context-token-[a-z0-9-]+-scopes=[^"[:space:]]+' "${all_scopes_render}" \
  | sort -u >"${actual_args}"
sort -u "${expected_args}" -o "${expected_args}"

if ! diff -u "${expected_args}" "${actual_args}"; then
  echo "rendered context-token scope arguments do not match the chart mapping" >&2
  exit 1
fi

grep -oE '"context-token-[a-z0-9-]+-scopes"' "${repo_root}/cmd/main.go" \
  | tr -d '"' \
  | sort -u >"${controller_flags}"
sort -u "${expected_flags}" -o "${expected_flags}"

if ! diff -u "${controller_flags}" "${expected_flags}"; then
  echo "chart context-token scope flags are not in parity with controller flags" >&2
  exit 1
fi

printf 'verified %d context-token scope mappings and empty defaults\n' "${#scope_mappings[@]}"
