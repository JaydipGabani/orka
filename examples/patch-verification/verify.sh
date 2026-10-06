#!/usr/bin/env bash
set -euo pipefail

project=${1:?project must be go, c, http, or config}
output=${2:?absolute evidence directory is required}
case "$project" in go|c|http|config) ;; *) exit 2 ;; esac
[[ "$output" == /* && $# -eq 2 ]] || exit 2
command -v jq >/dev/null
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
binary="$root/bin/patchverify"
[[ -x "$binary" ]] || { printf 'Build bin/patchverify first\n' >&2; exit 2; }
mkdir -p -m 0700 "$output"
[[ ! -e "$output/$project-summary.jsonl" ]] || { printf 'Use a new evidence directory\n' >&2; exit 2; }
launcher=()
if [[ "$project" == http || "$project" == config ]]; then
  [[ -x "$root/bin/network-launcher" ]] || { printf 'Build the trusted network launcher first\n' >&2; exit 2; }
  launcher=(--network-launcher "$root/bin/network-launcher" --network-launcher-sha256 "sha256:$(sha256sum "$root/bin/network-launcher" | cut -d ' ' -f 1)")
fi
variants=(fixed notfixed partial regression)
[[ "$project" != config ]] || variants+=(temporary)

for mode in patch commit; do
  for variant in "${variants[@]}"; do
    case "$variant" in
      fixed) expected='Verified for these checks'; expected_status=0 ;;
      notfixed) expected='Not fixed'; expected_status=1 ;;
      partial|temporary) expected='Partially fixed'; expected_status=1 ;;
      regression) expected='Introduces a regression'; expected_status=1 ;;
    esac
    request=$(bash "$root/examples/patch-verification/demo.sh" "$project" "$variant" "$mode")
    count=$(jq '.checks | length * 2' "$request")
    prefix="$output/$project-$mode-$variant"
    printf '%s\n' "$request" > "$prefix-request-path.txt"
    status=0
    "$binary" start --request "$request" --db "$output/$project.db" "${launcher[@]}" > "$prefix-start.jsonl" || status=$?
    if [[ "$status" -ne "$expected_status" ]]; then
      printf 'FAIL %s %s %s: exit %s, expected %s\n' "$project" "$mode" "$variant" "$status" "$expected_status" >&2
      exit 1
    fi
    run=$(jq -er 'select(.jobStatus != "running") | .runID' "$prefix-start.jsonl")
    "$binary" get --db "$output/$project.db" --run "$run" > "$prefix-result.json"
    jq -e --arg expected "$expected" --argjson count "$count" '.executionBackend == "local-docker" and .jobStatus == "completed" and .state == "finalized" and .overall.conclusion == $expected and .progress.required == $count and .progress.recorded == $count and .progress.accepted == $count and .progress.rejected == 0 and .incidents == 0' "$prefix-result.json" >/dev/null
    "$binary" evidence --db "$output/$project.db" --run "$run" > "$prefix-evidence.json"
    jq -e --arg mode "$mode" --argjson count "$count" '
      .record as $record |
      $record.manifest.action == "verify-patch" and
      ($record.manifest.reportDigest | startswith("sha256:")) and
      ($record.manifest.declaredChanges | length > 0) and
      ($record.seal.digest | startswith("sha256:")) and
      ($record.binding.manifestDigest | startswith("sha256:")) and
      ($record.manifest.sources.original.commit | test("^[a-f0-9]{40}$")) and
      ($record.manifest.sources.original.tree | test("^[a-f0-9]{40}$")) and
      ($record.manifest.sources.patched.tree | test("^[a-f0-9]{40}$")) and
      (if $mode == "patch" then ($record.manifest.sources.patchDigest | startswith("sha256:")) else ($record.manifest.sources.patched.commit | test("^[a-f0-9]{40}$")) end) and
      ($record.evidence | length == $count) and
      all($record.evidence[];
        .observation.runID == $record.binding.runID and
        .observation.attemptID == $record.binding.attemptID and
        .observation.manifestDigest == $record.binding.manifestDigest and
        .observation.origin == "runner" and .observation.executed and
        (.observation.containerID | length == 64) and
        (.observation.stdoutDigest | startswith("sha256:")))
    ' "$prefix-evidence.json" >/dev/null
    if [[ "$project" == config && "$variant" == temporary ]]; then
      jq -e 'any(.overall.checks[]; .checkID == "install" and .outcome == "passed") and all(.overall.checks[] | select(.checkID == "reconcile" or .checkID == "restart" or .checkID == "upgrade"); .outcome == "not-fixed")' "$prefix-result.json" >/dev/null
    elif [[ "$project" == config && "$variant" == partial ]]; then
      jq -e 'any(.overall.checks[]; .checkID == "upgrade" and .outcome == "not-fixed") and all(.overall.checks[] | select(.checkID != "upgrade"); .outcome == "passed")' "$prefix-result.json" >/dev/null
    fi
    digest=$(jq -er '.record.evidence[0].observation.stdoutDigest' "$prefix-evidence.json")
    "$binary" evidence --db "$output/$project.db" --run "$run" --digest "$digest" > "$prefix-capture.json"
    jq -c --arg project "$project" --arg mode "$mode" --arg variant "$variant" '. + {project:$project, inputMode:$mode, variant:$variant}' "$prefix-result.json" >> "$output/$project-summary.jsonl"
    printf 'PASS %s %s %s: %s (%s)\n' "$project" "$mode" "$variant" "$expected" "$run"
  done
done
