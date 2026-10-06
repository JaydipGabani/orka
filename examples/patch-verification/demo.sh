#!/usr/bin/env bash
set -euo pipefail

project=${1:-go}
variant=${2:-fixed}
mode=${3:-patch}
action=${4:-verify-patch}
case "$project" in go|c|http|config) ;; *) printf 'project must be go, c, http, or config\n' >&2; exit 2 ;; esac
case "$variant" in fixed|notfixed|partial|regression) ;; temporary) [[ "$project" == config ]] || exit 2 ;; *) printf 'unknown patch variant\n' >&2; exit 2 ;; esac
case "$mode" in patch|commit) ;; *) printf 'mode must be patch or commit\n' >&2; exit 2 ;; esac
case "$action" in validate-report|verify-patch) ;; *) printf 'unknown action\n' >&2; exit 2 ;; esac
[[ $# -le 4 ]] || exit 2
command -v git >/dev/null
command -v jq >/dev/null
fixture_base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
fixture_dir="$fixture_base/$project"
root=$(mktemp -d /tmp/patchverify-demo.XXXXXX)
mkdir -m 700 "$root/repo"
mkdir -m 700 "$root/checks"
for source in "$fixture_dir"/original/*; do
  install -m 0644 "$source" "$root/repo/$(basename "$source")"
done
for check in "$fixture_dir"/checks/*; do
  permissions=0644
  [[ "$check" != *.sh ]] || permissions=0755
  install -m "$permissions" "$check" "$root/checks/$(basename "$check")"
done
if [[ "$project" == config ]]; then
  install -m 0644 "$fixture_dir/original/policy.json" "$root/checks/affected-policy.json"
  install -m 0644 "$fixture_base/http/checks/service.c" "$root/checks/service.c"
  install -m 0755 "$fixture_base/http/checks/service.sh" "$root/checks/service.sh"
fi

fixture_git() {
  env -i PATH="$PATH" HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_AUTHOR_NAME='Patch verification fixture' GIT_AUTHOR_EMAIL=fixture@example.invalid \
    GIT_COMMITTER_NAME='Patch verification fixture' GIT_COMMITTER_EMAIL=fixture@example.invalid \
    git -c core.hooksPath=/dev/null -c commit.gpgsign=false -c protocol.allow=never -C "$root/repo" "$@"
}

fixture_git init --quiet --initial-branch=fixture --template=
fixture_git add --all
fixture_git commit --quiet -m 'Disposable original fixture'
original=$(fixture_git rev-parse HEAD)
patch="$fixture_dir/$variant.patch"
patched=""
if [[ "$action" == verify-patch ]]; then
  fixture_git apply --check -- "$patch"
  if [[ "$mode" == commit ]]; then
    fixture_git apply -- "$patch"
    fixture_git add --all
    fixture_git commit --quiet -m 'Disposable patched fixture'
    patched=$(fixture_git rev-parse HEAD)
  fi
fi
platform=${PATCHVERIFY_PLATFORM:-linux/amd64}
case "$platform" in linux/amd64|linux/arm64) ;; *) printf 'unsupported platform\n' >&2; exit 2 ;; esac
jq -n --arg project "$project" --arg action "$action" --arg repository "$root/repo" \
  --arg original "$original" --arg patched "$patched" --arg patch "$patch" \
  --arg checks "$root/checks" --arg platform "$platform" '
  {
    action: $action,
    problem: "Order quantity outside 1 through 100 is accepted",
    scope: ["normal quantity 5", "negative quantity -1", "oversized quantity 101"],
    gaps: ["caller-controlled demonstration, not arbitrary test attestation", "production Task/Job/controller/auth API not wired"],
    repository: $repository, originalCommit: $original, checksDir: $checks,
    image: "golang@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43",
    platform: $platform, profile: (if $project == "http" then "local-services" else "offline" end),
    variables: {CGO_ENABLED: "0", GOMAXPROCS: "2"},
    requiredEnvironment: ([{kind: "process", name: "quantity-checks"}] +
      (if $project == "http" then [{kind: "local-services", name: "inventory"}] else [] end)),
    dependencies: {"fixture.toolchain": "preinstalled Go and gcc in the pinned image"},
    services: (if $project == "http" then [{id: "inventory", command: ["/checks/service.sh"], port: 18080, readyOutput: "ready\n"}] else [] end),
    checks: [
      {id: "normal", kind: "normal", go: "TestNormal", arg: "5"},
      {id: "problem-one", kind: "reproduction", go: "TestLow", arg: "-1"},
      {id: "problem-two", kind: "reproduction", go: "TestHigh", arg: "101"}
    ] | map(. as $case | {
      id: .id, kind: .kind, timeoutSeconds: 90,
      command: ["/checks/check.sh", (if $project == "go" then .go else .arg end)],
      healthy: {exitCode: 0, stdout: (if $project == "http" then (if .kind == "normal" then "accepted\n" else "rejected\n" end) else "healthy\n" end)},
      failure: {exitCode: 0, stdout: (if $project == "http" then (if .kind == "normal" then "rejected\n" else "accepted\n" end) else "broken\n" end)}
    } | if $project == "http" then
      .healthy.services = {inventory: (if $case.kind == "normal" then "ready\nreserve\n" else "ready\n" end)} |
      .failure.services = {inventory: (if $case.kind == "normal" then "ready\n" else "ready\nreserve\n" end)}
    else . end)
  } | if $project == "config" then
    .problem = "A managed policy permits anonymous requests after settings are reapplied or existing state is upgraded" |
    .scope = ["modeled install", "managed reconciliation", "manager restart", "upgrade retaining existing data", "authenticated normal use"] |
    .gaps += ["Process model only; no real cluster, deployment, or Kubernetes controller is exercised"] |
    .profile = "local-services" |
    .requiredEnvironment = [{kind:"process", name:"modeled-configuration-manager"}, {kind:"local-services", name:"inventory"}] |
    .services = [{id:"inventory", command:["/checks/service.sh"], port:18080, readyOutput:"ready\n"}] |
    .checks = ["normal", "install", "reconcile", "restart", "upgrade"] | .checks |= map(. as $step | {
      id:$step, kind:(if $step == "normal" then "normal" else "reproduction" end),
      command:["/checks/check.sh", $step], timeoutSeconds:30,
      lifecycle:(if $step == "normal" then ["install", "reconcile", "restart", "upgrade"]
                 elif $step == "install" then ["install"] else ["install", $step] end),
      healthy:{exitCode:0, stdout:(if $step == "normal" then "authenticated=accepted\nretained=fixture-order\n"
                else "step=" + $step + "\neffective.allowAnonymous=false\nrequest=rejected\nretained=fixture-order\n" end),
               services:{inventory:(if $step == "normal" then "ready\nreserve\n" else "ready\n" end)}},
      failure:{exitCode:0, stdout:(if $step == "normal" then "authenticated=rejected\nretained=fixture-order\n"
                else "step=" + $step + "\neffective.allowAnonymous=true\nrequest=accepted\nretained=fixture-order\n" end),
               services:{inventory:(if $step == "normal" then "ready\n" else "ready\nreserve\n" end)}}
    })
  else . end |
  if $action == "validate-report" then . else
    .declaredChanges = [{kind: "source", description: "Change the accepted quantity range",
      paths: [(if $project == "go" then "order.go" elif $project == "c" then "order.c" else "client.go" end)]}] |
    (if $project == "config" then .declaredChanges = [
      {kind:"configuration", paths:["policy.json"], description:"Change managed policy and retained-state migration settings"},
      {kind:"permission", paths:["policy.json"], description:"Change anonymous access while retaining authenticated use"}
    ] else . end) |
    if $patched == "" then .patchFile = $patch else .patchedCommit = $patched end
  end
' > "$root/request.json"
chmod 0600 "$root/request.json"
printf '%s\n' "$root/request.json"
