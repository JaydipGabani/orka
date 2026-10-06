#!/usr/bin/env bash
set -euo pipefail

project=${1:?project must be go, c, http, or config}
output=${2:?absolute evidence directory is required}
case "$project" in go|c|http|config) ;; *) exit 2 ;; esac
[[ "$output" == /* && $# -eq 2 ]] || exit 2
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
binary="$root/bin/patchverify"
[[ -x "$binary" ]] || exit 2
mkdir -p -m 0700 "$output"
[[ ! -e "$output/$project-validation-summary.jsonl" ]] || { printf 'Use a new evidence directory\n' >&2; exit 2; }
database="$output/$project-validation.db"
launcher=()
if [[ "$project" == http || "$project" == config ]]; then
  launcher=(--network-launcher "$root/bin/network-launcher" --network-launcher-sha256 "sha256:$(sha256sum "$root/bin/network-launcher" | cut -d ' ' -f 1)")
fi

run_case() {
  local name=$1 expected=$2 expected_status=$3 request=$4 expected_count=$5
  local prefix="$output/$project-$name" status=0 run
  "$binary" start --request "$request" --db "$database" "${launcher[@]}" > "$prefix-start.jsonl" || status=$?
  [[ "$status" -eq "$expected_status" ]] || { printf 'FAIL %s: exit %s\n' "$name" "$status" >&2; exit 1; }
  run=$(jq -er 'select(.jobStatus != "running") | .runID' "$prefix-start.jsonl")
  "$binary" get --db "$database" --run "$run" > "$prefix-result.json"
  "$binary" evidence --db "$database" --run "$run" > "$prefix-evidence.json"
  jq -e --arg expected "$expected" --argjson count "$expected_count" '.state == "finalized" and .overall.conclusion == $expected and .progress.recorded == $count and .incidents == 0' "$prefix-result.json" >/dev/null
  jq -c --arg scenario "$name" '. + {scenario:$scenario}' "$prefix-result.json" >> "$output/$project-validation-summary.jsonl"
  printf 'PASS %s %s: %s (%s)\n' "$project" "$name" "$expected" "$run"
}

base=$(bash "$root/examples/patch-verification/demo.sh" "$project" fixed commit)
check_count=$(jq '.checks | length' "$base")
jq '.action = "validate-report" | del(.patchedCommit, .patchFile, .declaredChanges)' "$base" > "$output/$project-report.json"
run_case reproduced 'Reproduced' 0 "$output/$project-report.json" "$check_count"
earlier=$(jq -r '.runID' "$output/$project-reproduced-result.json")
jq -e '.record.manifest.action == "validate-report" and .record.manifest.reportDigest != "" and (.record.binding.patchedTaskID // "") == "" and all(.record.evidence[]; .observation.side == "original")' "$output/$project-reproduced-evidence.json" >/dev/null

jq '.action = "validate-report" | .originalCommit = .patchedCommit | del(.patchedCommit, .patchFile, .declaredChanges)' "$base" > "$output/$project-clean-report.json"
run_case not-reproduced 'Not reproduced under these conditions' 0 "$output/$project-clean-report.json" "$check_count"
jq -e 'all(.overall.checks[]; .outcome == "passed" or .outcome == "not-reproduced")' "$output/$project-not-reproduced-result.json" >/dev/null

jq '.requiredEnvironment += [{kind:"cluster", name:"real-cluster", description:"Complete installation, not a local substitute"}]' "$output/$project-report.json" > "$output/$project-unsupported-report.json"
run_case unsupported-report 'Unable to validate' 2 "$output/$project-unsupported-report.json" 0
jq -e '.overall.reason | contains("real-cluster")' "$output/$project-unsupported-report-result.json" >/dev/null
jq '.requiredEnvironment += [{kind:"controller", name:"real-controller", description:"Actual controller reconciliation required"}]' "$base" > "$output/$project-unsupported-patch.json"
run_case unsupported-patch 'Unable to verify' 2 "$output/$project-unsupported-patch.json" 0
jq -e '.overall.reason | contains("real-controller")' "$output/$project-unsupported-patch-result.json" >/dev/null

checks=$(jq -r '.checksDir' "$base")
mv "$checks" "$checks.saved-after-validation"
for mode in commit patch; do
  jq --arg earlier "$earlier" --arg mode "$mode" --arg patch "$root/examples/patch-verification/$project/fixed.patch" '
    {action:"verify-patch", earlierValidation:$earlier, declaredChanges:.declaredChanges} +
    (if $mode == "commit" then {patchedCommit:.patchedCommit} else {patchFile:$patch} end)
  ' "$base" > "$output/$project-linked-$mode.json"
  run_case "linked-$mode" 'Verified for these checks' 0 "$output/$project-linked-$mode.json" "$((check_count * 2))"
  jq -e --slurpfile earlier "$output/$project-reproduced-evidence.json" '
    .record as $record | $earlier[0].record as $previous |
    $record.manifest.earlierValidation.runID == $previous.binding.runID and
    $record.manifest.earlierValidation.sealDigest == $previous.seal.digest and
    $record.manifest.reportDigest == $previous.manifest.reportDigest and
    $record.manifest.checks == $previous.manifest.checks and
    $record.manifest.files == $previous.manifest.files and
    $record.binding.attemptID != $previous.binding.attemptID and
    $record.binding.originalTaskID != $previous.binding.originalTaskID and
    ([$record.evidence[].observation.side] | map(select(. == "original")) | length) == ($previous.manifest.checks | length)
  ' "$output/$project-linked-$mode-evidence.json" >/dev/null
done
"$binary" evidence --db "$database" --run "$earlier" > "$output/$project-earlier-after-links.json"
cmp "$output/$project-reproduced-evidence.json" "$output/$project-earlier-after-links.json"
