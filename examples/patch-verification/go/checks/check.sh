#!/bin/bash
set -euo pipefail
case "${1:-}" in TestNormal|TestLow|TestHigh) ;; *) exit 125 ;; esac
scratch="${TMPDIR:-/tmp}"
mkdir -p "$scratch/subject"
cp /src/order.go /checks/order_test.go "$scratch/subject/"
cd "$scratch/subject"
status=0
GO111MODULE=off go test -tags patchverify_fixture -count=1 -run "^$1$" . >"$scratch/test-output" 2>"$scratch/test-diagnostics" || status=$?
[[ ! -s "$scratch/test-diagnostics" ]] || exit 125
if [[ "$status" == 0 ]]; then
  printf 'healthy\n'
elif grep -q 'POC assertion failed' "$scratch/test-output"; then
  printf 'broken\n'
else
  exit 125
fi
