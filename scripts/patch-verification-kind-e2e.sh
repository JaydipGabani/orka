#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$root"
kindctl="$root/.agents/skills/kindctl/bin/kindctl"
tag=${VALIDATION_KIND_TAG:-validation-542}
namespace=orka-validation
tool_tag=golang:1.26.5-trixie
tool_pin=golang@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43
export PATH="$root/bin/kind-tools:$PATH"
for command in docker go jq python3 kubectl kind; do
  command -v "$command" >/dev/null || { printf 'Missing command: %s\n' "$command" >&2; exit 2; }
done
mkdir -p bin/validation bin/validation-e2e
artifact_dir=$(mktemp -d "$root/bin/validation-e2e/run.XXXXXX")
chmod 0700 "$artifact_dir"
if ! "$kindctl" path --tag "$tag" >/dev/null 2>&1; then
  "$kindctl" create --tag "$tag" --k8s-version v1.34.0
fi
"$kindctl" kubectl --tag "$tag" wait --for=condition=Ready nodes --all --timeout=120s
"$kindctl" kubectl --tag "$tag" apply --server-side -k config/crd >"$artifact_dir/crds.log"

# This harness uses standard Kind networking. Local-services must either have
# an enforcing CNI installed by the operator or fail the negative canary probe.
docker image inspect "$tool_pin" >/dev/null 2>&1 || docker pull "$tool_pin"
docker tag "$tool_pin" "$tool_tag"
CGO_ENABLED=0 go build -p 2 -o bin/validation/manager ./cmd
docker build -f config/development/patch-verification/Dockerfile -t orka-validation-controller:issue542 bin/validation
docker build -f workers/validation/Dockerfile -t orka-validation-helper:issue542 .
for image in "$tool_tag" orka-validation-controller:issue542 orka-validation-helper:issue542; do
  "$kindctl" load --tag "$tag" "$image"
done
kubeconfig=$("$kindctl" path --tag "$tag")
cluster=$(KUBECONFIG="$kubeconfig" kubectl config current-context)
cluster=${cluster#kind-}
node="${cluster}-control-plane"
pin_loaded_image() {
  local image="$1" digest
  digest=$(docker exec "$node" ctr -n k8s.io images list |
    awk -v image="$image" '$1 == image {print $3}')
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'Image digest unavailable: %s\n' "$image" >&2; return 1; }
  docker exec "$node" ctr -n k8s.io images tag --force "$image" "${image%:*}@$digest" >/dev/null
  printf '%s@%s\n' "${image%:*}" "$digest"
}
tool_image=$(pin_loaded_image docker.io/library/golang:1.26.5-trixie)
controller_image=$(pin_loaded_image docker.io/library/orka-validation-controller:issue542)
helper_image=$(pin_loaded_image docker.io/library/orka-validation-helper:issue542)
export VALIDATION_TOOL_IMAGE="$tool_image" VALIDATION_CONTROLLER_IMAGE="$controller_image" VALIDATION_HELPER_IMAGE="$helper_image"

bin/kustomize build --load-restrictor LoadRestrictionsNone config/development/patch-verification |
  python3 -c 'import os,sys
text=sys.stdin.read().replace("validation-controller:development",os.environ["VALIDATION_CONTROLLER_IMAGE"])
text=text.replace("REPLACE_WITH_HELPER_DIGEST",os.environ["VALIDATION_HELPER_IMAGE"])
text=text.replace("golang@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43",os.environ["VALIDATION_TOOL_IMAGE"])
sys.stdout.write(text)' >"$artifact_dir/deployment.yaml"
"$kindctl" kubectl --tag "$tag" apply -f "$artifact_dir/deployment.yaml" >"$artifact_dir/apply.log"
umask 077
if ! "$kindctl" kubectl --tag "$tag" -n "$namespace" get secret validation-snapshot >/dev/null 2>&1; then
  head -c 32 /dev/urandom >"$artifact_dir/snapshot-key"
  "$kindctl" kubectl --tag "$tag" -n "$namespace" create secret generic validation-snapshot --from-file=key="$artifact_dir/snapshot-key" >/dev/null
  rm -- "$artifact_dir/snapshot-key"
fi
"$kindctl" kubectl --tag "$tag" -n "$namespace" rollout status deployment/validation-controller --timeout=180s
"$kindctl" kubectl --tag "$tag" -n "$namespace" create token validation-caller --duration=2h >"$artifact_dir/caller-token"

printf '%s\n' "$tool_image" >"$artifact_dir/tool-image"
printf '%s\n' "$kubeconfig" >"$artifact_dir/kubeconfig-path"
printf 'Prepared isolated controller and images; artifacts: %s\n' "$artifact_dir"
printf 'Run the Python conformance driver after starting a scoped API port-forward:\n'
printf 'python3 scripts/patch_verification_kube_conformance.py --artifacts %q --url http://127.0.0.1:8080\n' "$artifact_dir"
