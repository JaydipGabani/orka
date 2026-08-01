#!/usr/bin/env bash

set -euo pipefail

fail() {
  printf 'release KD6 conformance: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

for command_name in curl docker openssl python3; do
  require_command "${command_name}"
done

adapter_image=${OMS_KD6_ADAPTER_IMAGE:-}
conformance_bin=${ORKA_OMS_CONFORMANCE_BIN:-}
kd6_commit=${ORKA_RELEASE_KD6_COMMIT:-}
kd6_endpoint=${ORKA_RELEASE_KD6_ENDPOINT:-}
kd6_test_image=${ORKA_RELEASE_KD6_TEST_IMAGE:-}
kd6_store_id=${ORKA_RELEASE_KD6_STORE_ID:-}
kd6_token=${ORKA_RELEASE_KD6_BEARER_TOKEN:-}
kd6_ca_cert=${ORKA_RELEASE_KD6_CA_CERT_PEM:-}
run_id=${ORKA_RELEASE_CONFORMANCE_RUN_ID:-release-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}}
readonly pinned_kd6_commit=042cff94bf82e92dea3a47f181121fd9cdcbc434
readonly kd6_test_profile=orka-kd6-contentstore-v1

[[ "${adapter_image}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] ||
  fail "OMS_KD6_ADAPTER_IMAGE must be an exact sha256 digest reference"
[[ "${kd6_test_image}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] ||
  fail "ORKA_RELEASE_KD6_TEST_IMAGE must be an exact sha256 digest reference"
[[ "${kd6_commit}" == "${pinned_kd6_commit}" ]] ||
  fail "ORKA_RELEASE_KD6_COMMIT must equal the pinned commit ${pinned_kd6_commit}"
[[ -n "${conformance_bin}" && -x "${conformance_bin}" ]] ||
  fail "ORKA_OMS_CONFORMANCE_BIN must name an executable conformance binary"
[[ "${run_id}" =~ ^[a-z0-9-]{1,48}$ ]] ||
  fail "ORKA_RELEASE_CONFORMANCE_RUN_ID must contain 1-48 lowercase letters, digits, or hyphens"

export ORKA_RELEASE_KD6_ENDPOINT="${kd6_endpoint}"
export ORKA_RELEASE_KD6_STORE_ID="${kd6_store_id}"
export ORKA_RELEASE_KD6_BEARER_TOKEN="${kd6_token}"
python3 - <<'PY'
import os
import sys
from urllib.parse import urlsplit

endpoint = os.environ["ORKA_RELEASE_KD6_ENDPOINT"]
store_id = os.environ["ORKA_RELEASE_KD6_STORE_ID"]
token = os.environ["ORKA_RELEASE_KD6_BEARER_TOKEN"]

parsed = urlsplit(endpoint)
if (
    parsed.scheme != "https"
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.query
    or parsed.fragment
):
    sys.exit("ORKA_RELEASE_KD6_ENDPOINT must be an absolute HTTPS URL without credentials, query, or fragment")
if any(ord(char) < 32 or ord(char) == 127 for char in endpoint):
    sys.exit("ORKA_RELEASE_KD6_ENDPOINT must not contain control characters")
if not store_id or len(store_id) > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in store_id):
    sys.exit("ORKA_RELEASE_KD6_STORE_ID must contain 1-1024 characters without controls")
if not token or len(token) > 4096 or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in token):
    sys.exit("ORKA_RELEASE_KD6_BEARER_TOKEN must contain 1-4096 characters without whitespace or controls")
PY
unset ORKA_RELEASE_KD6_BEARER_TOKEN

work_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/orka-oms-kd6-release.XXXXXX")
data_dir=${work_dir}/data
tls_dir=${work_dir}/tls
secret_dir=${work_dir}/secrets
checkpoint=${work_dir}/checkpoint.json
container_name="orka-oms-kd6-release-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
container_name=${container_name//[^A-Za-z0-9_.-]/-}
container_id=

cleanup() {
  local status=$?
  if [[ -n "${container_id}" ]]; then
    if ((status != 0)); then
      docker logs "${container_name}" >&2 2>/dev/null || true
    fi
    docker rm --force "${container_name}" >/dev/null 2>&1 || true
  fi
  rm -rf "${work_dir}"
  return "${status}"
}
trap cleanup EXIT

umask 077
mkdir -p "${data_dir}" "${tls_dir}" "${secret_dir}"
# The distroless adapter runs as uid 65532 and needs to create SQLite state here.
chmod 0777 "${data_dir}"
printf '%s' "${kd6_token}" > "${secret_dir}/kd6-token"
oms_token=$(openssl rand -hex 32)
if [[ ${GITHUB_ACTIONS:-} == true ]]; then
  printf '::add-mask::%s\n' "${oms_token}"
fi
printf '%s' "${oms_token}" > "${secret_dir}/oms-token"
chmod 0444 "${secret_dir}/kd6-token" "${secret_dir}/oms-token"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=Orka release conformance CA' \
  -keyout "${tls_dir}/ca.key" -out "${tls_dir}/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes \
  -subj '/CN=127.0.0.1' \
  -keyout "${tls_dir}/tls.key" -out "${tls_dir}/tls.csr" >/dev/null 2>&1
cat > "${tls_dir}/tls.ext" <<'CERT_EXTENSIONS'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
CERT_EXTENSIONS
openssl x509 -req -sha256 -days 1 \
  -in "${tls_dir}/tls.csr" \
  -CA "${tls_dir}/ca.crt" -CAkey "${tls_dir}/ca.key" -CAcreateserial \
  -extfile "${tls_dir}/tls.ext" \
  -out "${tls_dir}/tls.crt" >/dev/null 2>&1
chmod 0444 "${tls_dir}/tls.crt" "${tls_dir}/tls.key"

if [[ -n "${kd6_ca_cert}" ]]; then
  printf '%s\n' "${kd6_ca_cert}" > "${secret_dir}/kd6-ca.crt"
  openssl x509 -in "${secret_dir}/kd6-ca.crt" -noout >/dev/null 2>&1 ||
    fail "ORKA_RELEASE_KD6_CA_CERT_PEM is not a PEM-encoded certificate"
  chmod 0444 "${secret_dir}/kd6-ca.crt"
fi
unset kd6_ca_cert

docker pull "${adapter_image}" >/dev/null
docker pull "${kd6_test_image}" >/dev/null

kd6_image_commit=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "${kd6_test_image}")
[[ "${kd6_image_commit}" == "${pinned_kd6_commit}" ]] ||
  fail "KD6 test image revision ${kd6_image_commit:-missing} does not match ${pinned_kd6_commit}"
kd6_image_profile=$(docker image inspect --format '{{ index .Config.Labels "ai.orka.kd6-test.profile" }}' "${kd6_test_image}")
[[ "${kd6_image_profile}" == "${kd6_test_profile}" ]] ||
  fail "KD6 test image profile ${kd6_image_profile:-missing} does not match ${kd6_test_profile}"

kd6_identity_file=${work_dir}/kd6-release-identity.json
kd6_curl_args=(
  --silent --show-error --fail
  --header "Authorization: Bearer ${kd6_token}"
)
if [[ -f "${secret_dir}/kd6-ca.crt" ]]; then
  kd6_curl_args+=(--cacert "${secret_dir}/kd6-ca.crt")
fi
curl "${kd6_curl_args[@]}" "${kd6_endpoint%/}/v1/release-identity" >"${kd6_identity_file}"

export ORKA_RELEASE_KD6_IDENTITY_FILE="${kd6_identity_file}"
export ORKA_RELEASE_KD6_EXPECTED_COMMIT="${pinned_kd6_commit}"
export ORKA_RELEASE_KD6_EXPECTED_DIGEST="${kd6_test_image##*@}"
export ORKA_RELEASE_KD6_EXPECTED_PROFILE="${kd6_test_profile}"
python3 - <<'PY'
import json
import os
import pathlib
import sys

identity_path = pathlib.Path(os.environ["ORKA_RELEASE_KD6_IDENTITY_FILE"])
try:
    identity = json.loads(identity_path.read_text())
except (OSError, json.JSONDecodeError) as exc:
    sys.exit(f"KD6 release identity is not valid JSON: {exc}")

expected_fields = {"commit", "imageDigest", "profile"}
if not isinstance(identity, dict) or set(identity) != expected_fields:
    sys.exit("KD6 release identity must contain exactly commit, imageDigest, and profile")
for field, environment_name in {
    "commit": "ORKA_RELEASE_KD6_EXPECTED_COMMIT",
    "imageDigest": "ORKA_RELEASE_KD6_EXPECTED_DIGEST",
    "profile": "ORKA_RELEASE_KD6_EXPECTED_PROFILE",
}.items():
    expected = os.environ[environment_name]
    if identity[field] != expected:
        sys.exit(f"KD6 release identity {field}={identity[field]!r}, expected {expected!r}")
PY
unset ORKA_RELEASE_KD6_IDENTITY_FILE ORKA_RELEASE_KD6_EXPECTED_COMMIT
unset ORKA_RELEASE_KD6_EXPECTED_DIGEST ORKA_RELEASE_KD6_EXPECTED_PROFILE
unset kd6_token

adapter_endpoint=
start_adapter() {
  local docker_args=(
    run --detach --rm
    --name "${container_name}"
    --publish 127.0.0.1::8091
    --read-only
    --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=64m"
    --cap-drop ALL
    --security-opt no-new-privileges
    --mount "type=bind,src=${data_dir},dst=/data"
    --mount "type=bind,src=${tls_dir}/tls.crt,dst=/run/tls/tls.crt,readonly"
    --mount "type=bind,src=${tls_dir}/tls.key,dst=/run/tls/tls.key,readonly"
    --mount "type=bind,src=${secret_dir}/oms-token,dst=/run/secrets/oms-token,readonly"
    --mount "type=bind,src=${secret_dir}/kd6-token,dst=/run/secrets/kd6-token,readonly"
  )
  if [[ -f "${secret_dir}/kd6-ca.crt" ]]; then
    docker_args+=(
      --mount "type=bind,src=${secret_dir}/kd6-ca.crt,dst=/run/secrets/kd6-ca.crt,readonly"
      --env SSL_CERT_FILE=/run/secrets/kd6-ca.crt
    )
  fi

  container_id=$(docker "${docker_args[@]}" "${adapter_image}" \
    --listen :8091 \
    --tls-cert-file /run/tls/tls.crt \
    --tls-key-file /run/tls/tls.key \
    --inbound-token-file /run/secrets/oms-token \
    --control-db /data/oms-control.db \
    --kd6-endpoint "${kd6_endpoint}" \
    --kd6-token-file /run/secrets/kd6-token \
    --enable-conformance-failpoints \
    --store-mapping "release-conformance=${kd6_store_id}")

  local configured_image
  configured_image=$(docker inspect --format '{{.Config.Image}}' "${container_name}")
  [[ "${configured_image}" == "${adapter_image}" ]] ||
    fail "adapter container did not retain the exact digest reference"

  local host_mapping host_port
  host_mapping=$(docker port "${container_name}" 8091/tcp)
  host_port=${host_mapping##*:}
  [[ "${host_mapping}" == 127.0.0.1:* && "${host_port}" =~ ^[0-9]+$ ]] ||
    fail "adapter container was not bound to an ephemeral loopback port"
  adapter_endpoint="https://127.0.0.1:${host_port}"

  local attempt
  for ((attempt = 1; attempt <= 60; attempt++)); do
    if curl --silent --fail --cacert "${tls_dir}/ca.crt" \
      --header "Authorization: Bearer ${oms_token}" \
      "${adapter_endpoint}/v1/health" >/dev/null; then
      return 0
    fi
    if [[ $(docker inspect --format '{{.State.Running}}' "${container_name}" 2>/dev/null || true) != true ]]; then
      fail "adapter container exited before becoming ready"
    fi
    sleep 1
  done
  fail "adapter container did not become ready within 60 seconds"
}

stop_adapter() {
  docker stop --time 30 "${container_name}" >/dev/null
  container_id=
}

run_conformance_phase() {
  local phase=$1
  SSL_CERT_FILE="${tls_dir}/ca.crt" \
  ORKA_OMS_BEARER_TOKEN="${oms_token}" \
    "${conformance_bin}" \
      --endpoint "${adapter_endpoint}" \
      --phase "${phase}" \
      --state-file "${checkpoint}" \
      --run-id "${run_id}" \
      --cluster-id "release-${GITHUB_REPOSITORY_ID:-local}" \
      --namespace-uid "namespace-${run_id}" \
      --backend-uid "backend-${run_id}" \
      --store-name release-conformance \
      --provider-commit-gap-proof \
      --timeout 30s \
      --overall-timeout 10m
}

start_adapter
first_container_id=${container_id}
run_conformance_phase prepare
stop_adapter

start_adapter
[[ "${container_id}" != "${first_container_id}" ]] ||
  fail "adapter restart reused the original container"
run_conformance_phase verify

printf 'Live prepare/restart/verify KD6 conformance passed for adapter %s against %s at %s.\n' \
  "${adapter_image}" "${kd6_test_image}" "${pinned_kd6_commit}"
